/**
 * LLM 评分复核（高分资产认定）
 *
 * 问题：base 分由角色决定（admin=85），角色可能是规则或 LLM 分类给的，
 * 分数本身没人复核 —— 会出现"90 分高得莫名其妙"。
 *
 * 方案：规则评分达到阈值（默认 70）的 webapp，必须过 LLM 复核：
 *   1. roleConfirmed：角色分类是否合理（不合理则给 suggestedRole）
 *   2. scoreAdjustment：分数调整（-15 ~ +15）
 *   3. isHighValue：是否认定为高价值资产（决定门控与深挖投入）
 *
 * 应用规则：
 *   - score = clamp(规则分 + adjustment, 0, 100)，breakdown 追加 "llm_review" 项
 *   - isHighValue=false 时即使分数 ≥ 阈值，也不升级为 L2/L3（防止虚高）
 *   - 角色被推翻（roleConfirmed=false 且 suggestedRole 合法）→ 用建议角色重算基础分
 *
 * 缓存：score_reviews 表（webapp_id + provider + model UNIQUE）
 * 失败：返回 null → 保留规则评分（fail-safe），但 isHighValue 不认定
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';
import type { AssetRole } from './roles.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface ScoreReviewInput {
	webappId: string;
	url: string;
	host: string;
	path: string;
	title?: string | null;
	tech: string[];
	fingerprints: string[];
	webserver?: string | null;
	bodyPreview?: string | null;
	role: AssetRole;
	roleSource: string;
	score: number;
	breakdown: Array<{ name: string; delta: number; reason: string }>;
}

export interface ScoreReviewResult {
	roleConfirmed: boolean;
	suggestedRole: AssetRole | null;
	scoreAdjustment: number;
	isHighValue: boolean;
	reasoning: string;
	fromLlm: boolean;
	provider: string;
	model: string;
}

const VALID_ROLES: AssetRole[] = [
	'admin',
	'backend',
	'business',
	'api',
	'dev',
	'middleware',
	'static',
	'unknown',
];

// =============================================================================
// 缓存
// =============================================================================

async function getCached(
	webappId: string,
	provider: string,
	model: string,
): Promise<Omit<ScoreReviewResult, 'fromLlm' | 'provider' | 'model'> | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT role_confirmed, suggested_role, score_adjustment, is_high_value, reasoning
     FROM score_reviews
     WHERE webapp_id = $1 AND provider = $2 AND model = $3
     ORDER BY created_at DESC LIMIT 1`,
		[webappId, provider, model],
	);
	if (rows.length === 0) return null;
	return {
		roleConfirmed: rows[0].role_confirmed,
		suggestedRole: rows[0].suggested_role as AssetRole | null,
		scoreAdjustment: rows[0].score_adjustment,
		isHighValue: rows[0].is_high_value,
		reasoning: rows[0].reasoning ?? '',
	};
}

async function saveCache(
	webappId: string,
	provider: string,
	model: string,
	result: Omit<ScoreReviewResult, 'fromLlm' | 'provider' | 'model'>,
	rawResponse: unknown,
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO score_reviews (webapp_id, provider, model, role_confirmed, suggested_role, score_adjustment, is_high_value, reasoning, raw_response)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (webapp_id, provider, model) DO UPDATE
       SET role_confirmed = EXCLUDED.role_confirmed,
           suggested_role = EXCLUDED.suggested_role,
           score_adjustment = EXCLUDED.score_adjustment,
           is_high_value = EXCLUDED.is_high_value,
           reasoning = EXCLUDED.reasoning,
           raw_response = EXCLUDED.raw_response,
           created_at = now()`,
		[
			webappId,
			provider,
			model,
			result.roleConfirmed,
			result.suggestedRole,
			result.scoreAdjustment,
			result.isHighValue,
			result.reasoning,
			JSON.stringify(rawResponse ?? null),
		],
	);
}

// =============================================================================
// Prompt 与解析
// =============================================================================

function buildPrompt(input: ScoreReviewInput): { system: string; user: string } {
	const system = `你是网络安全资产价值评估专家。给定一个 Web 资产的特征和规则引擎的评分明细，复核：
1. 角色分类是否合理（规则或另一个 LLM 分的）
2. 评分是否虚高/偏低
3. 是否认定为高价值资产（值得深挖投入）

角色定义：
- admin: 管理系统（admin/manage/console/dashboard 路径或子域）
- backend: 已知后台框架（WordPress/Drupal/Discuz）
- api: API 服务（api./graphql/swagger）
- dev: 开发设施（Jenkins/GitLab/Grafana/Nacos）
- middleware: 中间件管理（Tomcat/WebLogic/phpMyAdmin）
- business: 业务系统
- static: 静态站
- unknown: 无法判断

输出 JSON：
{
  "roleConfirmed": true|false,
  "suggestedRole": "admin"|"backend"|"api"|"dev"|"middleware"|"business"|"static"|null,
  "scoreAdjustment": -15到15的整数,
  "isHighValue": true|false,
  "reasoning": "简短理由（50字内）",
  "probePaths": ["需要进一步验证的路径，如 /wp-admin、/api、/login，最多3个；证据不足时才提议，否则空数组"]
}

判断要点：
1. roleConfirmed：特征与角色明显不符才 false，模糊时保持 true
2. scoreAdjustment：只有明确依据才调整（如静态站被分成 admin 应大调；证据不足保持 0）
3. isHighValue：管理后台/API 服务/开发设施/有敏感特征 → true；纯静态/低价值 → false
4. 宁缺毋滥：无法判断高价值时 isHighValue=false
5. probePaths：如果你认为"证据不足需要实际请求网站验证"（如怀疑是 CMS 但没看到后台入口、怀疑是 API 但没有接口证据），提议 1-3 个相对路径（以 / 开头），系统会用受控请求验证后给你反馈。证据够时给空数组。

只输出 JSON。`;

	const user = JSON.stringify(
		{
			url: input.url,
			host: input.host,
			path: input.path,
			title: input.title ?? null,
			tech: input.tech.slice(0, 10),
			fingerprints: input.fingerprints.slice(0, 10),
			webserver: input.webserver ?? null,
			bodyPreview: (input.bodyPreview ?? '').slice(0, 300),
			ruleRole: input.role,
			roleSource: input.roleSource,
			ruleScore: input.score,
			breakdown: input.breakdown.slice(0, 15),
		},
		null,
		2,
	);
	return { system, user };
}

export function parseScoreReviewResponse(content: string): {
	roleConfirmed: boolean;
	suggestedRole: AssetRole | null;
	scoreAdjustment: number;
	isHighValue: boolean;
	reasoning: string;
	probePaths: string[];
	parseError: boolean;
} {
	const fallback = {
		roleConfirmed: true,
		suggestedRole: null,
		scoreAdjustment: 0,
		isHighValue: false,
		reasoning: '',
		probePaths: [],
		parseError: true,
	};
	let obj: {
		roleConfirmed?: unknown;
		suggestedRole?: unknown;
		scoreAdjustment?: unknown;
		isHighValue?: unknown;
		reasoning?: unknown;
		probePaths?: unknown;
	};
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}
	let adjustment = Number(obj.scoreAdjustment ?? 0);
	if (!Number.isFinite(adjustment)) adjustment = 0;
	adjustment = Math.max(-15, Math.min(15, Math.round(adjustment)));
	const suggested =
		typeof obj.suggestedRole === 'string' &&
		(VALID_ROLES as string[]).includes(obj.suggestedRole.toLowerCase())
			? (obj.suggestedRole.toLowerCase() as AssetRole)
			: null;
	return {
		roleConfirmed: obj.roleConfirmed !== false,
		suggestedRole: suggested,
		scoreAdjustment: adjustment,
		isHighValue: obj.isHighValue === true,
		reasoning: typeof obj.reasoning === 'string' ? obj.reasoning.slice(0, 200) : '',
		probePaths: Array.isArray(obj.probePaths)
			? obj.probePaths
					.filter((p): p is string => typeof p === 'string' && p.startsWith('/') && p.length > 1)
					.slice(0, 3)
			: [],
		parseError: false,
	};
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * LLM 评分复核（高分资产认定）
 *
 * @returns 复核结果；失败/关闭时返回 null（保留规则评分，不认定高价值）
 */
export async function reviewScoreByLlm(
	input: ScoreReviewInput,
	opts: { forceRefresh?: boolean } = {},
): Promise<ScoreReviewResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	// 1. 查缓存
	if (!opts.forceRefresh) {
		try {
			const cached = await getCached(input.webappId, provider, model);
			if (cached) {
				await auditLog({
					actor: `llm:${provider}`,
					action: 'agent_decision',
					target: input.webappId,
					decision: 'info',
					reason: `score_review cache hit: adjust=${cached.scoreAdjustment} highValue=${cached.isHighValue}`,
					meta: { model },
				});
				return { ...cached, fromLlm: false, provider, model };
			}
		} catch {
			// 缓存失败不阻塞
		}
	}

	// 2. 调用
	const { system, user } = buildPrompt(input);
	let raw;
	let errorMsg: string | null = null;
	try {
		// maxTokens 给足：deepseek-v4-flash 是推理模型，reasoning 先消耗输出预算
		raw = await callDeepSeek(system, user, { model, maxTokens: 2400 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'fail',
			reason: `score_review failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	// 3. 解析
	let parsed = parseScoreReviewResponse(raw.choices[0].message.content);
	if (parsed.parseError) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'deny',
			reason: 'score_review parse failed',
			meta: { model },
		});
		return null;
	}

	// 3.5 LLM 受控请求：初判提议 probePaths → 系统带护栏发包 → 证据回填 → LLM 终判
	let finalParsed = parsed;
	if (parsed.probePaths.length > 0) {
		try {
			const { probePaths } = await import('./llm_probe.js');
			const probes = await probePaths(input.url, parsed.probePaths, input.webappId);
			const probeSummary = probes
				.map(
					(p) =>
						`- ${p.path}: HTTP ${p.status ?? '?'}${p.title ? ` title=${p.title}` : ''}${p.error ? ` error=${p.error}` : ''}${p.bodyPreview ? ` body=${p.bodyPreview.slice(0, 200)}` : ''}`,
				)
				.join('\n');
			const finalSystem = `${system}\n\n你之前提议探测的路径已有结果（系统受控请求获取）：\n${probeSummary}\n\n请基于以上新证据输出最终结论（同样的 JSON 格式，probePaths 给空数组）。`;
			const finalRaw = await callDeepSeek(finalSystem, user, { model, maxTokens: 2400 });
			const finalContent = finalRaw?.choices?.[0]?.message?.content;
			if (finalContent) {
				const reParsed = parseScoreReviewResponse(finalContent);
				if (!reParsed.parseError) {
					finalParsed = { ...reParsed, probePaths: [] };
				}
			}
			await auditLog({
				actor: `llm:${provider}`,
				action: 'agent_decision',
				target: input.webappId,
				decision: 'allow',
				reason: `score_review probe: ${probes.filter((p) => p.status !== null).length}/${probes.length} reachable → 终判 highValue=${finalParsed.isHighValue}`,
				meta: { model, probes, final: finalParsed },
			});
		} catch (err) {
			console.warn('[score_review] probe failed (non-blocking, use initial judgment):', err);
		}
	}
	parsed = finalParsed;

	const result: ScoreReviewResult = {
		...parsed,
		fromLlm: true,
		provider,
		model,
	};

	// 4. 审计 + 缓存
	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.webappId,
		decision: 'allow',
		reason: `score_review: roleConfirmed=${result.roleConfirmed} adjust=${result.scoreAdjustment} highValue=${result.isHighValue} (${result.reasoning})`,
		meta: { model, decision: result, usage: raw.usage },
	});
	try {
		await saveCache(input.webappId, provider, model, parsed, raw);
	} catch {
		// 缓存写失败不阻塞
	}

	return result;
}
