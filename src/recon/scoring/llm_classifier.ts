/**
 * M2.4 LLM 兜底分类
 *
 * 当角色规则匹配 confidence < 0.7 时，调用 LLM（DeepSeek）做资产角色分类。
 *
 * 流程：
 * 1. 拼装 prompt（含 webapp 的 url/title/tech/fingerprints/body_preview）
 * 2. 调 DeepSeek API（OpenAI 兼容格式）
 * 3. 解析返回的 JSON { role, confidence, reasoning }
 * 4. 缓存到 llm_classifications 表（同一 webapp + 同一 model 不重复调用）
 *
 * 缓存：
 * - PG 表 llm_classifications（webapp_id + provider + model UNIQUE）
 * - 同一 webapp 不会重复调用 LLM
 *
 * 容错：
 * - LLM 调用失败 → 返回 fallback 'unknown' + confidence 0
 * - JSON 解析失败 → 同上
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { type DeepSeekResponse, callDeepSeek, extractJsonContent } from './llm_client.js';
import type { AssetRole } from './roles.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface LlmClassifyInput {
	webappId: string;
	url: string;
	host: string;
	path: string;
	title?: string | null;
	tech: string[];
	webserver?: string | null;
	fingerprints: string[];
	bodyPreview?: string | null;
	/** 原规则匹配结果（用于 prompt 给 LLM 参考） */
	ruleRole: AssetRole;
	ruleConfidence: number;
}

export interface LlmClassifyResult {
	role: AssetRole;
	confidence: number;
	reasoning: string;
	/** 是否走了 LLM（false 表示缓存命中或调用失败 fallback） */
	fromLlm: boolean;
	/** LLM provider（如 'deepseek'） */
	provider?: string;
	/** LLM model（如 'deepseek-chat'） */
	model?: string;
}

// =============================================================================
// 缓存（PG 表 llm_classifications）
// =============================================================================

async function get_cached(
	webappId: string,
	provider: string,
	model: string,
): Promise<LlmClassifyResult | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT role, confidence, reasoning FROM llm_classifications
     WHERE webapp_id = $1 AND provider = $2 AND model = $3
     ORDER BY created_at DESC LIMIT 1`,
		[webappId, provider, model],
	);
	if (rows.length === 0) return null;
	return {
		role: rows[0].role as AssetRole,
		confidence: Number(rows[0].confidence),
		reasoning: rows[0].reasoning ?? '',
		fromLlm: false,
		provider,
		model,
	};
}

async function save_cache(
	webappId: string,
	provider: string,
	model: string,
	result: LlmClassifyResult,
	rawResponse: unknown,
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO llm_classifications (webapp_id, provider, model, role, confidence, reasoning, raw_response)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (webapp_id, provider, model) DO UPDATE
       SET role = EXCLUDED.role,
           confidence = EXCLUDED.confidence,
           reasoning = EXCLUDED.reasoning,
           raw_response = EXCLUDED.raw_response,
           created_at = now()`,
		[
			webappId,
			provider,
			model,
			result.role,
			result.confidence,
			result.reasoning,
			JSON.stringify(rawResponse ?? null),
		],
	);
}

// =============================================================================
// Prompt 拼装
// =============================================================================

const ROLE_LIST = `'admin', 'backend', 'business', 'api', 'dev', 'middleware', 'static'`;

function buildPrompt(input: LlmClassifyInput): { system: string; user: string } {
	const system = `你是一名专业的资产角色分类助手。给定 Web 资产的特征信息，判断它属于以下哪种角色：

- admin: 管理系统（如 admin/manage/console/dashboard 路径或子域）
- backend: 已知后台框架（如 WordPress/Drupal/Joomla/Discuz）
- api: API 接口服务（如 api./graphql/swagger/openapi）
- dev: 开发设施（如 Jenkins/GitLab/Grafana/Jupyter/Nexus）
- middleware: 中间件默认页/管理（如 Tomcat/WebLogic/phpMyAdmin）
- business: 业务系统（如 www./shop./login 页面）
- static: 静态站（无登录、无动态路径）

输出 JSON 格式：
{"role": <one of ${ROLE_LIST}>, "confidence": <0-1>, "reasoning": "<简短理由>"}

注意：confidence 表示你对这个分类的确定程度，越确定越接近 1。`;

	const fields: string[] = [`URL: ${input.url}`, `Host: ${input.host}`, `Path: ${input.path}`];
	if (input.title) fields.push(`Title: ${input.title}`);
	if (input.webserver) fields.push(`WebServer: ${input.webserver}`);
	if (input.tech.length > 0) fields.push(`Tech: ${input.tech.join(', ')}`);
	if (input.fingerprints.length > 0)
		fields.push(`Fingerprints: ${input.fingerprints.slice(0, 10).join(', ')}`);
	if (input.bodyPreview) {
		// body 截取前 500 字符（避免 prompt 过长）
		const trimmed = input.bodyPreview.slice(0, 500).replace(/\s+/g, ' ').trim();
		fields.push(`Body preview: ${trimmed}`);
	}
	fields.push(
		`(规则引擎预判: role=${input.ruleRole}, confidence=${input.ruleConfidence.toFixed(2)})`,
	);

	const user = `请对以下资产分类：\n${fields.join('\n')}`;
	return { system, user };
}

// =============================================================================
// 解析 LLM 返回
// =============================================================================

const VALID_ROLES: AssetRole[] = [
	'admin',
	'backend',
	'business',
	'api',
	'dev',
	'middleware',
	'static',
];

function parseLlmResponse(content: string): {
	role: AssetRole;
	confidence: number;
	reasoning: string;
} {
	try {
		const obj = JSON.parse(extractJsonContent(content)) as {
			role?: string;
			confidence?: number;
			reasoning?: string;
		};
		const role = (obj.role ?? 'unknown').toLowerCase() as AssetRole;
		if (!VALID_ROLES.includes(role)) {
			return { role: 'unknown', confidence: 0, reasoning: `LLM 返回未知角色: ${obj.role}` };
		}
		const confidence = Math.max(0, Math.min(1, Number(obj.confidence ?? 0)));
		const reasoning = obj.reasoning ?? '';
		return { role, confidence, reasoning };
	} catch {
		// 尝试从文本中提取 role
		for (const r of VALID_ROLES) {
			if (content.toLowerCase().includes(`"role"`) && content.toLowerCase().includes(r)) {
				return {
					role: r,
					confidence: 0.5,
					reasoning: `LLM 返回解析失败，从文本提取: ${content.slice(0, 200)}`,
				};
			}
		}
		return {
			role: 'unknown',
			confidence: 0,
			reasoning: `LLM 返回解析失败: ${content.slice(0, 200)}`,
		};
	}
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * LLM 兜底分类
 *
 * @param input 输入信息
 * @param opts.forceRefresh 强制刷新缓存（默认 false）
 * @returns 分类结果（含 fromLlm 标记）
 */
export async function classifyByLlm(
	input: LlmClassifyInput,
	opts: { forceRefresh?: boolean } = {},
): Promise<LlmClassifyResult> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	// 1. 查缓存
	if (!opts.forceRefresh) {
		try {
			const cached = await get_cached(input.webappId, provider, model);
			if (cached) {
				await auditLog({
					actor: `llm:${provider}`,
					action: 'llm_call',
					target: input.webappId,
					decision: 'info',
					reason: 'cache hit',
					meta: { model, role: cached.role },
				});
				return cached;
			}
		} catch {
			// 缓存查失败不阻塞
		}
	}

	// 2. 拼 prompt
	const { system, user } = buildPrompt(input);

	// 3. 调 LLM
	let raw: DeepSeekResponse | null = null;
	let errorMsg: string | null = null;
	try {
		raw = await callDeepSeek(system, user, { model });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	// 4. 失败 fallback
	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'llm_call',
			target: input.webappId,
			decision: 'fail',
			reason: errorMsg ?? 'empty response',
			meta: { model },
		});
		return {
			role: input.ruleRole, // fallback 用原规则结果
			confidence: input.ruleConfidence,
			reasoning: `LLM 调用失败，回退到规则结果: ${errorMsg ?? 'empty response'}`,
			fromLlm: false,
			provider,
			model,
		};
	}

	// 5. 解析
	const content = raw.choices[0].message.content;
	const parsed = parseLlmResponse(content);

	const result: LlmClassifyResult = {
		role: parsed.role,
		confidence: parsed.confidence,
		reasoning: parsed.reasoning,
		fromLlm: true,
		provider,
		model,
	};

	// 6. 审计 + 写缓存
	await auditLog({
		actor: `llm:${provider}`,
		action: 'llm_call',
		target: input.webappId,
		decision: 'allow',
		meta: {
			model,
			role: result.role,
			confidence: result.confidence,
			usage: raw.usage,
			tokens: raw.usage?.total_tokens,
		},
	});

	try {
		await save_cache(input.webappId, provider, model, result, raw);
	} catch {
		// 缓存写失败不阻塞
	}

	return result;
}
