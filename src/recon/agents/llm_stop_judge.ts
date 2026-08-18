/**
 * 决策点 4：停止/继续判断（LLM Stop-Judge）
 *
 * 单站收集的主要步骤完成后，LLM 根据结果摘要判断：
 * 当前收集到的信息是否足以支撑渗透 Agent 使用？
 * 如果明显不足（如接口 0 个、无源码线索），建议追加深挖一轮。
 *
 * 预算控制：
 *   - 每 webapp 最多追加 1 轮（webapp.meta.deep_judge_at 记录，防重复）
 *   - suggestedNext 限定现有任务集（jsmining/source_collect/dirscan/history_url）
 *   - 追加执行仍走确定性步骤函数（同 host 约束不变）
 *
 * 失败：返回 null → 正常收尾不追加，不阻塞流程
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { callDeepSeek, extractJsonContent } from '../scoring/llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface StopJudgeInput {
	webappId: string;
	url: string;
	/** 收集结果摘要 */
	summary: {
		framework: string[];
		language: string[];
		jsFileCount: number;
		jsApiCount: number;
		endpointCount: number;
		secretCount: number;
		sourceAvailable: boolean;
		restoredFiles: number;
	};
	score: number | null;
	role: string | null;
	level: string | null;
}

export interface StopJudgeResult {
	continueDeep: boolean;
	suggestedNext: string | null;
	reasoning: string;
	fromLlm: boolean;
	provider: string;
	model: string;
}

export const STOP_JUDGE_TASKS = ['jsmining', 'source_collect', 'dirscan', 'history_url'] as const;

// =============================================================================
// Prompt 与解析
// =============================================================================

function buildPrompt(input: StopJudgeInput): { system: string; user: string } {
	const system = `你是信息收集质量评估助手。给定一次单站收集的结果摘要，判断是否值得追加一轮深挖。

背景：ck-recon 是纯信息收集系统。主流程已收集：技术栈识别、JS 文件清单与接口提取、目录探测、webpack/sourcemap 探测。
可选追加任务：
- jsmining: 加大 JS 文件数上限重新提取接口
- source_collect: 下载 JS + 尝试 sourcemap 还原（之前可能因文件数上限跳过）
- dirscan: 目录探测（之前可能没跑或结果少）
- history_url: 历史 URL 收集（wayback/gau）

输出 JSON：
{"continueDeep": true|false, "suggestedNext": "任务名"|null, "reasoning": "简短理由（30字内）"}

判断标准：
1. continueDeep=true 的条件（满足任一）：
   - JS 文件数 > 0 但接口提取为 0（有 JS 没挖出接口 → 值得加大文件数重挖）
   - 静态站但存在可疑目录线索（endpointCount > 0 且包含 admin/api 等路径）
   - 有源码线索（sourceAvailable 或 webpack 指纹）但未还原源码
2. continueDeep=false：
   - 纯静态站（framework 空 + JS 少 + 接口 0）→ 追加无意义
   - 结果已经丰富（接口多/源码已还原）→ 已够用
   - score 极低（< 30）→ 不值得投入

只输出 JSON。`;

	const user = JSON.stringify(
		{
			url: input.url,
			summary: input.summary,
			score: input.score,
			role: input.role,
			level: input.level,
		},
		null,
		2,
	);
	return { system, user };
}

export function parseStopJudgeResponse(content: string): {
	continueDeep: boolean;
	suggestedNext: string | null;
	reasoning: string;
	parseError: boolean;
} {
	const fallback = { continueDeep: false, suggestedNext: null, reasoning: '', parseError: true };
	let obj: { continueDeep?: unknown; suggestedNext?: unknown; reasoning?: unknown };
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}
	const next = typeof obj.suggestedNext === 'string' ? obj.suggestedNext.toLowerCase() : '';
	return {
		continueDeep: obj.continueDeep === true,
		suggestedNext: (STOP_JUDGE_TASKS as readonly string[]).includes(next) ? next : null,
		reasoning: typeof obj.reasoning === 'string' ? obj.reasoning.slice(0, 200) : '',
		parseError: false,
	};
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 判断是否追加深挖（决策点 4）
 *
 * @returns 判断结果；失败/关闭时返回 null（正常收尾）
 */
export async function judgeContinueDeep(
	input: StopJudgeInput,
	_opts: { forceRefresh?: boolean } = {},
): Promise<StopJudgeResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

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
			reason: `stop_judge failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	const parsed = parseStopJudgeResponse(raw.choices[0].message.content);
	const result: StopJudgeResult = {
		continueDeep: parsed.continueDeep,
		suggestedNext: parsed.suggestedNext,
		reasoning: parsed.reasoning,
		fromLlm: true,
		provider,
		model,
	};

	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.webappId,
		decision: parsed.parseError ? 'deny' : 'allow',
		reason: `stop_judge: continue=${result.continueDeep} next=${result.suggestedNext ?? '-'} (${result.reasoning})`,
		meta: { model, decision: result, usage: raw.usage },
	});

	if (parsed.parseError) return null;
	return result;
}
