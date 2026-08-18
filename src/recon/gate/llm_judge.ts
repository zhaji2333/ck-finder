/**
 * LLM-as-Judge（M5.4）
 *
 * 架构文档 §一 1.2 风险与对策 #3：
 *   "高危动作（如 nmap -sV、dirsearch 大字典、SQL 注入探测）需 LLM 审批。"
 *
 * 设计：
 *   - 高危动作清单（HIGH_RISK_ACTIONS）：明确列出需要审批的动作
 *   - judgeAction(action, context)：调 DeepSeek 判断 allow/deny/ask_user
 *   - 决策结果写 audit_log（action=scope_decision, decision=allow/deny）
 *   - LLM 失败时默认 deny（fail-closed）
 *
 * 接入点：
 *   - executor.ts 在主动工具（mode='active'）spawn 前可选调用
 *   - pipeline/deep_scan.ts 在跑敏感扫描前调用
 *
 * 注意：MVP 阶段默认关闭（LLM_JUDGE_ENABLED=false），仅做框架 ready。
 */

import { getConfig } from '../config.js';
import { auditLog } from './audit_log.js';

// =============================================================================
// 类型定义
// =============================================================================

export type JudgeDecision = 'allow' | 'deny' | 'ask_user';

export interface JudgeInput {
	/** 动作类型（如 'nmap_sv_scan'、'dirsearch_brute'、'sql_injection_test'） */
	action: string;
	/** 目标 */
	target: string;
	/** 上下文信息（如参数、字典大小、预期影响） */
	context?: Record<string, unknown>;
	/** 已通过 Scope Gate 的匹配规则 */
	scopeMatchedRule?: string;
}

export interface JudgeResult {
	decision: JudgeDecision;
	/** LLM 给出的理由 */
	reasoning: string;
	/** 是否走了 LLM（false 表示规则直接判定或 LLM 失败） */
	fromLlm: boolean;
	/** LLM provider */
	provider?: string;
	/** LLM model */
	model?: string;
	/** 原始动作 */
	action: string;
	/** 目标 */
	target: string;
}

// =============================================================================
// 高危动作清单
// =============================================================================

/**
 * 高危动作清单
 *
 * 命中下列动作的调用需经过 LLM 审批。
 * 其他动作默认放行。
 */
export const HIGH_RISK_ACTIONS = new Set<string>([
	// 主动扫描类
	'nmap_sv_scan', // nmap -sV 服务版本探测
	'nmap_script_scan', // nmap -sC --script 脚本扫描
	'nmap_aggressive', // nmap -A 综合扫描
	'nmap_udp_scan', // nmap -sU UDP 扫描
	// 目录爆破类
	'dirsearch_brute', // dirsearch 大字典爆破
	'dirb_brute', // dirb 爆破
	'gobuster_brute', // gobuster 爆破
	// 漏洞验证类（ck-recon 不做，但 LLM Judge 框架支持）
	'sql_injection_test',
	'xss_test',
	'command_injection_test',
	'unauthorized_access_test',
	// 源码下载类（带宽大）
	'source_download_large', // 大规模源码下载（>50MB）
	// 其他
	'port_scan_high_rate', // 高速端口扫描（>1000pps）
]);

/**
 * 是否为高危动作
 */
export function isHighRiskAction(action: string): boolean {
	return HIGH_RISK_ACTIONS.has(action);
}

// =============================================================================
// 规则预判（不调 LLM）
// =============================================================================

/**
 * 规则预判：明确拒绝的动作
 *
 * ck-recon 是纯信息收集 Agent，以下动作一律拒绝：
 *   - 漏洞验证类（sql_injection_test / xss_test / command_injection_test / unauthorized_access_test）
 *   - 高速端口扫描
 */
function rulePreJudge(input: JudgeInput): JudgeResult | null {
	const action = input.action;

	// 明确拒绝：漏测类动作
	if (
		action === 'sql_injection_test' ||
		action === 'xss_test' ||
		action === 'command_injection_test' ||
		action === 'unauthorized_access_test'
	) {
		return {
			decision: 'deny',
			reasoning: `ck-recon 是纯信息收集 Agent，不做漏洞验证类动作: ${action}`,
			fromLlm: false,
			action,
			target: input.target,
		};
	}

	// 非高危动作直接放行
	if (!isHighRiskAction(action)) {
		return {
			decision: 'allow',
			reasoning: `action ${action} is not in high-risk list`,
			fromLlm: false,
			action,
			target: input.target,
		};
	}

	return null; // 交给 LLM
}

// =============================================================================
// Prompt 拼装
// =============================================================================

function buildJudgePrompt(input: JudgeInput): { system: string; user: string } {
	const system = `你是一名资深的渗透测试安全审批员。你的任务是判断某个信息收集动作是否应该被执行。

判定原则：
1. ck-recon 是纯信息收集 Agent，**不做漏洞验证**（如 SQL 注入、XSS、命令注入、未授权访问测试）
2. 允许：被动信息收集、主动扫描（端口扫描、目录爆破、指纹识别、源码下载）
3. 拒绝：超出授权范围、可能造成服务影响（DoS）、敏感时间窗口、目标关键基础设施
4. 不确定时返回 ask_user，让人工审批

输出 JSON 格式：
{"decision": <"allow"|"deny"|"ask_user">, "reasoning": "<简短理由>"}`;

	const fields: string[] = [`Action: ${input.action}`, `Target: ${input.target}`];
	if (input.scopeMatchedRule) {
		fields.push(`Scope matched: ${input.scopeMatchedRule}`);
	}
	if (input.context) {
		for (const [k, v] of Object.entries(input.context)) {
			fields.push(`${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`);
		}
	}

	const user = `请判断以下动作是否应该执行：\n${fields.join('\n')}`;
	return { system, user };
}

// =============================================================================
// DeepSeek API 调用
// =============================================================================

interface ChatResponse {
	choices: Array<{
		message: { role: string; content: string };
		finish_reason: string;
	}>;
	usage?: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

async function callLlm(
	systemPrompt: string,
	userPrompt: string,
	model: string,
	apiKey: string,
	baseUrl: string,
	timeoutMs = 30_000,
): Promise<ChatResponse> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await fetch(`${baseUrl}/v1/chat/completions`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${apiKey}`,
			},
			body: JSON.stringify({
				model,
				messages: [
					{ role: 'system', content: systemPrompt },
					{ role: 'user', content: userPrompt },
				],
				temperature: 0.1,
				max_tokens: 300,
				response_format: { type: 'json_object' },
			}),
			signal: controller.signal,
		});
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(`LLM API ${resp.status}: ${text.slice(0, 500)}`);
		}
		return (await resp.json()) as ChatResponse;
	} finally {
		clearTimeout(timer);
	}
}

function parseJudgeResponse(content: string): { decision: JudgeDecision; reasoning: string } {
	try {
		const obj = JSON.parse(content) as { decision?: string; reasoning?: string };
		const decision = (obj.decision ?? 'deny').toLowerCase() as JudgeDecision;
		if (decision !== 'allow' && decision !== 'deny' && decision !== 'ask_user') {
			return { decision: 'deny', reasoning: `LLM 返回未知决策: ${obj.decision}` };
		}
		return { decision, reasoning: obj.reasoning ?? '' };
	} catch {
		// 解析失败默认拒绝（fail-closed）
		return {
			decision: 'deny',
			reasoning: `LLM 返回解析失败: ${content.slice(0, 200)}`,
		};
	}
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * LLM-as-Judge：判断动作是否应该执行
 *
 * @param input 动作信息
 * @returns 决策结果
 */
export async function judgeAction(input: JudgeInput): Promise<JudgeResult> {
	// 1. 规则预判
	const preJudged = rulePreJudge(input);
	if (preJudged) {
		await auditLog({
			actor: 'llm_judge',
			action: 'scope_decision',
			target: input.target,
			decision: preJudged.decision === 'allow' ? 'allow' : 'deny',
			reason: preJudged.reasoning,
			meta: {
				action: input.action,
				fromLlm: false,
				rulePreJudged: true,
			},
		});
		return preJudged;
	}

	// 2. 检查是否启用 LLM Judge（config.llm.judgeEnabled，默认 true）
	const enabled = getConfig().llm.judgeEnabled;
	if (!enabled) {
		// 未启用 LLM Judge：高危动作默认放行（仅记录审计）
		const result: JudgeResult = {
			decision: 'allow',
			reasoning: `LLM Judge disabled, high-risk action ${input.action} allowed by default`,
			fromLlm: false,
			action: input.action,
			target: input.target,
		};
		await auditLog({
			actor: 'llm_judge',
			action: 'scope_decision',
			target: input.target,
			decision: 'allow',
			reason: result.reasoning,
			meta: { action: input.action, enabled: false },
		});
		return result;
	}

	// 3. 调 LLM
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.proModel; // 高危判断用 pro 模型

	const { system, user } = buildJudgePrompt(input);

	let raw: ChatResponse | null = null;
	let errorMsg: string | null = null;
	try {
		raw = await callLlm(system, user, model, cfg.apiKey, cfg.baseUrl);
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	// 4. LLM 失败 → fail-closed（拒绝）
	if (!raw || !raw.choices?.[0]?.message?.content) {
		const result: JudgeResult = {
			decision: 'deny',
			reasoning: `LLM 调用失败，fail-closed 拒绝: ${errorMsg ?? 'empty response'}`,
			fromLlm: false,
			provider,
			model,
			action: input.action,
			target: input.target,
		};
		await auditLog({
			actor: `llm:${provider}`,
			action: 'scope_decision',
			target: input.target,
			decision: 'deny',
			reason: result.reasoning,
			meta: { action: input.action, model, failClosed: true },
		});
		return result;
	}

	// 5. 解析 LLM 返回
	const content = raw.choices[0].message.content;
	const parsed = parseJudgeResponse(content);

	const result: JudgeResult = {
		decision: parsed.decision,
		reasoning: parsed.reasoning,
		fromLlm: true,
		provider,
		model,
		action: input.action,
		target: input.target,
	};

	await auditLog({
		actor: `llm:${provider}`,
		action: 'scope_decision',
		target: input.target,
		decision: parsed.decision === 'allow' ? 'allow' : 'deny',
		reason: parsed.reasoning,
		meta: {
			action: input.action,
			model,
			decision: parsed.decision,
			usage: raw.usage,
		},
	});

	return result;
}

/**
 * 断言放行：拒绝时抛错
 */
export async function assertActionAllowed(input: JudgeInput): Promise<JudgeResult> {
	const result = await judgeAction(input);
	if (result.decision === 'deny') {
		throw new Error(
			`action ${input.action} on ${input.target} denied by LLM Judge: ${result.reasoning}`,
		);
	}
	return result;
}
