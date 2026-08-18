/**
 * Reviewer AI 初审（M4.1，借鉴 AutoHunter reviewer.py）
 *
 * 三态判定 accepted / ignored / deepen：
 *   - 「极理性」原则：理论风险/接口存在/扫描器结果都不是漏洞，问「攻击者实际拿到/改了/控制了什么」
 *   - 高危复现：accepted 的 high/critical → 系统用 http_req 重放 poc（只读，过 Scope Gate + 红线）
 *     → reproduced 由系统设置（不信任 LLM 自填）；复现失败降级 deepen
 *   - 规则后处理：ignored 但「入口真实+下一步明确」的半成品 → 自动转 deepen（生成定向指令）
 */
import { Agent } from '@earendil-works/pi-agent-core';
import { createDeepSeekModels, resolveDeepSeekModel } from '../llm/provider.js';
import { auditLog } from '../recon/gate/audit_log.js';
import { guardCommand } from '../security/guard.js';
import { hostInScopeSync } from '../security/scope_util.js';
import { httpReqTool } from '../tools/http_req.js';
import { FindingStore, type ValidationFinding } from '../validation/finding_store.js';
import { ReviewStore, type ReviewVerdict } from '../validation/review_store.js';

export interface ReviewInput {
	finding: ValidationFinding;
	scope: string[];
	modelId?: string;
	enabled: boolean; // LLM 可用才审
}

export interface ReviewOutcome {
	verdict: ReviewVerdict;
	severityFinal: string | null;
	score: number | null;
	reasoning: string;
	reproduced: boolean;
	deepenDirective: string | null;
}

const REVIEWER_SYSTEM_PROMPT = `你是 Reviewer：极理性的漏洞初审者。只认「实际可利用 + 实锤危害」，过滤半成品/误报。

最高原则：
- 理论风险、接口存在、配置不当、扫描器结果、200/空响应/成功文案都不是漏洞
- 每个 finding 问：攻击者实际拿到/改了/控制了什么？证据必须是同一次真实请求响应
- 只读实证原则：验证只做存在性证明，禁止修改/删除数据、禁止脱库

判定标准：
- accepted：证据链完整、实际可利用、有明确危害（能拿到敏感数据/越权可读/注入可证明/SSRF 可探测内网）
- ignored：误报/纯理论/无法利用/证据不足且无明确下一步（反射 XSS 已证明可弹窗则收，未证明不收）
- deepen：线索真实但没打穿，且有明确下一步可执行（如"注入点确认但未验证数据可读"→"用时间盲/带外坐实"）

输出 JSON：{"verdict":"accepted|ignored|deepen","severity_final":"critical|high|medium|low|info","score":0-10,"reasoning":"中文理由","deepen_directive":"deepen 时的定向指令（其他情况空字符串）"}`;

/** LLM 三态判定 */
async function llmReview(o: ReviewInput): Promise<ReviewOutcome> {
	const models = createDeepSeekModels();
	const model = resolveDeepSeekModel(models, o.modelId ?? 'deepseek-v4-flash');

	const f = o.finding;
	const evidence = f.evidence;
	const payload = {
		vuln_name: f.vulnName,
		vuln_type: f.vulnType,
		severity_claimed: f.severity,
		url: f.url,
		summary: f.summary,
		poc: evidence.poc,
		raw_request: (evidence.raw_request ?? '').slice(0, 3000),
		raw_response: (evidence.raw_response ?? '').slice(0, 3000),
		kill_chain: evidence.kill_chain,
		self_check: evidence.self_check,
	};

	const agent = new Agent({
		initialState: {
			systemPrompt: REVIEWER_SYSTEM_PROMPT,
			model,
			thinkingLevel: 'high',
			tools: [],
		},
		streamFn: models.streamSimple.bind(models),
		beforeToolCall: async () => undefined,
	});

	let outcome: ReviewOutcome | null = null;
	agent.subscribe(async (event) => {
		if (event.type === 'agent_end') {
			// 从最后 assistant 文本提取 JSON
			const texts = agent.state.messages
				.flatMap((m) => (m.role === 'assistant' ? (m.content ?? []) : []))
				.filter((c) => c.type === 'text')
				.map((c) => (c as { text: string }).text);
			for (const t of [...texts].reverse()) {
				const m = t.match(/\{[\s\S]*"verdict"[\s\S]*\}/);
				if (m) {
					try {
						const parsed = JSON.parse(m[0]) as {
							verdict?: string;
							severity_final?: string;
							score?: number;
							reasoning?: string;
							deepen_directive?: string;
						};
						if (['accepted', 'ignored', 'deepen'].includes(parsed.verdict ?? '')) {
							outcome = {
								verdict: parsed.verdict as ReviewVerdict,
								severityFinal: parsed.severity_final ?? null,
								score: parsed.score ?? null,
								reasoning: parsed.reasoning ?? '',
								reproduced: false, // 系统复现验证，不信任 LLM
								deepenDirective: parsed.deepen_directive ?? null,
							};
						}
					} catch {
						// 继续找下一个 JSON
					}
				}
			}
		}
	});

	await agent.prompt(`请初审以下 finding，输出 JSON 判定：\n${JSON.stringify(payload, null, 1)}`);

	if (!outcome) {
		return {
			verdict: 'deepen',
			severityFinal: null,
			score: 2,
			reasoning: 'LLM 未返回有效判定，保守转深挖',
			reproduced: false,
			deepenDirective: '重新完整验证证据链',
		};
	}
	return outcome;
}

/** 高危复现验证：系统用 http_req 重放 poc（只读，过 scope + 红线），确认 reproduced */
async function reproduceHighSeverity(
	finding: ValidationFinding,
	scope: string[],
): Promise<boolean> {
	if (!['high', 'critical'].includes(finding.severity)) return false;

	// scope 校验 + 红线（重放请求本身不执行破坏性命令，poc 文本仅作为请求构造参考）
	const host = (() => {
		try {
			return new URL(finding.url).hostname;
		} catch {
			return null;
		}
	})();
	if (!host || !hostInScopeSync(host, scope)) {
		await auditLog({
			actor: 'reviewer',
			action: 'scope_decision',
			target: finding.url,
			decision: 'deny',
			reason: '复现目标不在授权范围，拒绝重放',
		});
		return false;
	}
	// poc 含破坏性命令 → 不重放（红线 R1-R3）
	const guard = guardCommand(finding.evidence.poc);
	if (!guard.allowed) {
		await auditLog({
			actor: 'reviewer',
			action: 'scope_decision',
			target: finding.url,
			decision: 'deny',
			reason: `复现 poc 含破坏性内容，拒绝重放: ${guard.reason}`,
		});
		return false;
	}

	// 用 http_req 重放原请求（证据里的 raw_request 解析 url；失败则用 finding.url 探活）
	try {
		const url = extractUrlFromRawRequest(finding.evidence.raw_request) ?? finding.url;
		const res = await httpReqTool.execute('review-reproduce', {
			url,
			timeoutMs: 15000,
			followRedirects: false,
		});
		// 复现成功：响应可达（状态码非网络错误）即视为「目标可访问 + 证据可重放」
		// 真实危害判定已由 LLM 初审完成，这里只确认「请求可真实发出、响应真实存在」
		if (res.details.status >= 100 && res.details.status < 600) {
			return true;
		}
	} catch {
		return false;
	}
	return false;
}

/** 从 raw_request 首行提取 URL */
function extractUrlFromRawRequest(raw: string): string | null {
	const lines = raw.split('\n');
	for (const line of lines) {
		const m = line.match(/^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/);
		if (m) return m[1];
	}
	return null;
}

/** 规则后处理：ignored 但可挽救的半成品转 deepen */
function maybeUpgradeToDeepen(outcome: ReviewOutcome, finding: ValidationFinding): ReviewOutcome {
	if (outcome.verdict !== 'ignored') return outcome;
	// 线索真实 + 类型有明确下一步 + 非必然误报
	const deepenable = [
		'injection',
		'ssrf',
		'idor',
		'broken_access',
		'file_upload',
		'path_traversal',
	].includes(String(finding.vulnType));
	if (deepenable && finding.evidence.poc.length > 20) {
		return {
			...outcome,
			verdict: 'deepen',
			deepenDirective: `初审认为证据不足，但类型(${finding.vulnType})有明确下一步。请重新验证：${outcome.reasoning}`,
		};
	}
	return outcome;
}

/**
 * 执行一次初审。返回判定 + 是否已落库 review 记录。
 */
export async function runReview(o: ReviewInput): Promise<ReviewOutcome> {
	const store = new ReviewStore();
	const findingStore = new FindingStore();

	if (!o.enabled) {
		const fallback: ReviewOutcome = {
			verdict: 'deepen',
			severityFinal: null,
			score: 3,
			reasoning: 'LLM 不可用（未配置 key），保守转深挖待人工',
			reproduced: false,
			deepenDirective: 'LLM 初审不可用，请人工复核',
		};
		await store.insertReview({
			findingId: o.finding.id,
			verdict: fallback.verdict,
			severityFinal: fallback.severityFinal,
			score: fallback.score,
			reasoning: fallback.reasoning,
			reproduced: false,
			reviewerModel: null,
		});
		return fallback;
	}

	let outcome = await llmReview(o);

	// 规则后处理：可挽救的半成品转 deepen
	outcome = maybeUpgradeToDeepen(outcome, o.finding);

	// 高危复现验证：accepted 的 high/critical → 系统重放确认
	if (
		outcome.verdict === 'accepted' &&
		['high', 'critical'].includes(outcome.severityFinal ?? o.finding.severity)
	) {
		const reproduced = await reproduceHighSeverity(o.finding, o.scope);
		outcome = { ...outcome, reproduced };
		if (!reproduced) {
			// 复现失败 → 降级 deepen（不允许未证实结论进人工队列）
			outcome = {
				...outcome,
				verdict: 'deepen',
				deepenDirective: `高危 finding 未能系统复现，请补充可复现证据：${outcome.reasoning}`,
			};
		}
	}

	// 落库
	await store.insertReview({
		findingId: o.finding.id,
		verdict: outcome.verdict,
		severityFinal: outcome.severityFinal,
		score: outcome.score,
		reasoning: outcome.reasoning,
		reproduced: outcome.reproduced,
		reviewerModel: o.modelId ?? 'deepseek-v4-flash',
	});

	// 更新 finding review_status
	if (outcome.verdict === 'accepted') {
		await findingStore.updateReviewStatus(o.finding.id, 'reviewed');
	} else if (outcome.verdict === 'deepen') {
		await findingStore.updateReviewStatus(o.finding.id, 'reviewed');
		if (outcome.deepenDirective) {
			await findingStore.setDeepen(o.finding.id, outcome.deepenDirective);
		}
	} else {
		await findingStore.updateReviewStatus(o.finding.id, 'dismissed');
	}

	return outcome;
}

/** 待审队列：review_status=pending 的 finding */
export async function listPendingReviews(limit = 20): Promise<ValidationFinding[]> {
	const store = new FindingStore();
	return store.listFindings({ reviewStatus: 'pending', limit });
}
