/**
 * 决策点 2：深挖任务选择 LLM 兜底
 *
 * 当规则技术栈画像（adjustByTechProfile）信息不足时（指纹少 + 框架未知 + 架构未知），
 * 让 LLM 根据 webapp 的实际特征（url/title/tech/指纹/评分/角色）补充建议深挖任务。
 *
 * 安全约束（只增不减）：
 *   - 只采纳 addTasks（与规则结果取并集）
 *   - 忽略 removeTasks（规则保证的任务不允许 LLM 移除），仅记录审计
 *   - 任务名限定现有 4 种：dirscan/jsmining/history_url/source_collect
 *
 * 缓存：task_decisions 表（webapp_id + provider + model UNIQUE）
 * 失败：返回 null，调用方保留规则结果
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import type { SuggestedNext } from '../gate/task_gate.js';
import { getPg } from '../storage/pg.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export const TASK_OPTIONS: SuggestedNext[] = [
	'dirscan',
	'jsmining',
	'history_url',
	'source_collect',
];

export interface TaskSelectInput {
	webappId: string;
	url: string;
	host: string;
	path: string;
	title?: string | null;
	tech: string[];
	fingerprints: string[];
	framework: string[];
	architecture: string | null;
	score: number;
	role: string;
	level: string;
	/** 规则已选定的任务（结果 = 规则 ∪ LLM addTasks） */
	ruleTasks: SuggestedNext[];
}

export interface TaskSelectResult {
	addTasks: SuggestedNext[];
	/** LLM 想移除但被护栏拒绝的任务（仅记录） */
	rejectedRemovals: SuggestedNext[];
	reasoning: string;
	fromLlm: boolean;
	provider: string;
	model: string;
}

// =============================================================================
// 缓存
// =============================================================================

async function getCached(
	webappId: string,
	provider: string,
	model: string,
): Promise<Omit<TaskSelectResult, 'fromLlm' | 'provider' | 'model'> | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT decision, reasoning FROM task_decisions
     WHERE webapp_id = $1 AND provider = $2 AND model = $3
     ORDER BY created_at DESC LIMIT 1`,
		[webappId, provider, model],
	);
	if (rows.length === 0) return null;
	return {
		addTasks: rows[0].decision.addTasks ?? [],
		rejectedRemovals: rows[0].decision.rejectedRemovals ?? [],
		reasoning: rows[0].reasoning ?? '',
	};
}

async function saveCache(
	webappId: string,
	provider: string,
	model: string,
	result: Omit<TaskSelectResult, 'fromLlm' | 'provider' | 'model'>,
	rawResponse: unknown,
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO task_decisions (webapp_id, provider, model, decision, reasoning, raw_response)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (webapp_id, provider, model) DO UPDATE
       SET decision = EXCLUDED.decision,
           reasoning = EXCLUDED.reasoning,
           raw_response = EXCLUDED.raw_response,
           created_at = now()`,
		[
			webappId,
			provider,
			model,
			JSON.stringify({
				addTasks: result.addTasks,
				rejectedRemovals: result.rejectedRemovals,
			}),
			result.reasoning,
			JSON.stringify(rawResponse ?? null),
		],
	);
}

// =============================================================================
// Prompt 与解析
// =============================================================================

function buildPrompt(input: TaskSelectInput): { system: string; user: string } {
	const system = `你是网络侦察任务规划助手。给定一个 web 应用的特征，从候选深挖任务中选出值得执行的任务。

候选任务（全部可选）：
- dirscan: 目录爆破（找后台/隐藏路径/敏感文件）
- jsmining: JS 下载分析（提取接口/参数/密钥）
- history_url: 历史 URL 收集（wayback/gau，找旧接口/已删除功能）
- source_collect: webpack 源码收集（sourcemap 还原）

输出 JSON：
{"addTasks": ["任务名", ...], "removeTasks": ["任务名", ...], "reasoning": "简短理由（30字内）"}

决策原则：
1. addTasks：你认为值得补跑的任务（最多 3 个）
2. removeTasks：你认为不值得跑的任务（可选，最多 2 个；系统会忽略此字段仅做记录）
3. 管理后台/API 站 → 优先 jsmining + dirscan
4. 框架已明确（指纹命中）→ 可省 history_url
5. 静态站/文档站 → 全部不推荐（空数组）
6. 不确定时 addTasks 给空数组

只输出 JSON。`;

	const user = JSON.stringify(
		{
			url: input.url,
			host: input.host,
			path: input.path,
			title: input.title ?? null,
			tech: input.tech.slice(0, 10),
			fingerprints: input.fingerprints.slice(0, 10),
			framework: input.framework,
			architecture: input.architecture,
			score: input.score,
			role: input.role,
			level: input.level,
			ruleSelectedTasks: input.ruleTasks,
		},
		null,
		2,
	);
	return { system, user };
}

export function parseTaskSelectResponse(content: string): {
	addTasks: SuggestedNext[];
	removeTasks: SuggestedNext[];
	reasoning: string;
	parseError: boolean;
} {
	const fallback = { addTasks: [], removeTasks: [], reasoning: '', parseError: true };
	let obj: { addTasks?: unknown; removeTasks?: unknown; reasoning?: unknown };
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}
	const norm = (v: unknown): SuggestedNext[] => {
		if (!Array.isArray(v)) return [];
		return v
			.filter((x): x is string => typeof x === 'string')
			.map((x) => x.toLowerCase())
			.filter((x): x is SuggestedNext => (TASK_OPTIONS as string[]).includes(x))
			.slice(0, 5);
	};
	return {
		addTasks: norm(obj.addTasks),
		removeTasks: norm(obj.removeTasks),
		reasoning: typeof obj.reasoning === 'string' ? obj.reasoning.slice(0, 200) : '',
		parseError: false,
	};
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * LLM 补充建议深挖任务（决策点 2）
 *
 * @returns 补充建议；失败/关闭时返回 null（调用方保留规则结果）
 */
export async function selectTasksByLlm(
	input: TaskSelectInput,
	opts: { forceRefresh?: boolean } = {},
): Promise<TaskSelectResult | null> {
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
					reason: `task_select cache hit: add=[${cached.addTasks.join(',')}]`,
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
		raw = await callDeepSeek(system, user, { model, maxTokens: 800 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'fail',
			reason: `task_select failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	// 3. 解析（护栏：忽略 removeTasks，仅记录）
	const parsed = parseTaskSelectResponse(raw.choices[0].message.content);
	const result: TaskSelectResult = {
		addTasks: parsed.addTasks,
		rejectedRemovals: parsed.removeTasks,
		reasoning: parsed.reasoning,
		fromLlm: true,
		provider,
		model,
	};

	// 4. 审计 + 缓存
	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.webappId,
		decision: parsed.parseError ? 'deny' : 'allow',
		reason: `task_select: add=[${result.addTasks.join(',')}]${result.rejectedRemovals.length > 0 ? ` | 移除建议被护栏忽略: [${result.rejectedRemovals.join(',')}]` : ''}`,
		meta: { model, decision: result, usage: raw.usage },
	});
	try {
		await saveCache(
			input.webappId,
			provider,
			model,
			{
				addTasks: result.addTasks,
				rejectedRemovals: result.rejectedRemovals,
				reasoning: result.reasoning,
			},
			raw,
		);
	} catch {
		// 缓存写失败不阻塞
	}

	if (parsed.parseError) return null;
	return result;
}
