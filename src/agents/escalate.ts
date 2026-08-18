/**
 * escalate 扩大危害（M4.5，借鉴 AutoHunter escalate.py，按红线 R5 只做读类升级）
 *
 * Reviewer accepted 后，对未授权/越权/注入/SSRF 类 finding 顺着入口打下一层：
 *   信息泄露→越权读→凭证→登后台读。
 * 红线 R5：只做读类升级（禁改删/脱库），只收显著升级（等级跳变/影响面数量级变化）。
 */
import { Agent } from '@earendil-works/pi-agent-core';
import { createDeepSeekModels, resolveDeepSeekModel } from '../llm/provider.js';
import { localReconProvider } from '../recon/provider.js';
import { buildAuditLogger, buildScopeGateChecker } from '../security/gate.js';
import { authBruteTool, dirBruteTool } from '../tools/brute.js';
import { httpReqTool } from '../tools/http_req.js';
import { createReconTools } from '../tools/recon.js';
import { skillLoadTool } from '../tools/skill.js';
import { nucleiScanTool, sqlmapRunTool } from '../tools/validation.js';
import { webFetchTool } from '../tools/web_fetch.js';
import { FindingStore, type ValidationFinding } from '../validation/finding_store.js';
import { createFindingSubmit } from './finding_tools.js';
import {
	AGENT_IDENTITY,
	HUNTING_IRON_RULES,
	SAFETY_RED_LINES,
	SKILL_ROUTING_TABLE,
	TEST_DISCIPLINE,
} from './prompts.js';

/** 触发 escalate 的漏洞类型（读类可升级） */
const ESCALATEABLE_TYPES = new Set([
	'unauthorized_access',
	'idor',
	'broken_access',
	'info_disclosure',
	'ssrf',
	'path_traversal',
	'injection',
	'auth',
]);

export function shouldEscalate(finding: ValidationFinding): boolean {
	return ESCALATEABLE_TYPES.has(String(finding.vulnType));
}

const ESCALATE_SYSTEM_PROMPT = `你是扩大危害专家。基于已确认的漏洞入口，顺打下一层（只做读类升级，红线禁止改删/脱库）：
- 未授权读→换接口/遍历规模/读更敏感数据
- IDOR→从看到读更多资源/换用户
- 凭证泄露→登后台读管理功能（只读）
- 注入→确认注入面（时间盲/报错），不脱库
- SSRF→探测内网可达性（只读，不触发写操作）

${AGENT_IDENTITY}

${TEST_DISCIPLINE}

${SKILL_ROUTING_TABLE}

${HUNTING_IRON_RULES}

${SAFETY_RED_LINES}

升级判定（只收显著升级）：危害等级跳变 / 影响面数量级变化 / 新实质危害。
无显著升级 → 用 finding_submit 说明"未升级"即可退出（安静放弃，不硬编造）。
有显著升级 → finding_submit 提交新 finding（证据五件套完整）。`;

export interface EscalateResult {
	escalated: boolean;
	finding?: ValidationFinding;
	reasoning: string;
}

/**
 * 对确认的 finding 执行一轮扩大危害（每目标最多一轮，防递归）。
 * 返回是否产出显著升级（产出则入库新 finding）。
 */
export async function runEscalate(
	finding: ValidationFinding,
	scope: string[],
	seedId: string,
): Promise<EscalateResult> {
	if (!shouldEscalate(finding)) {
		return { escalated: false, reasoning: `类型 ${finding.vulnType} 不可升级（只做读类）` };
	}

	const models = createDeepSeekModels();
	const model = resolveDeepSeekModel(models, 'deepseek-v4-flash');
	const findingStore = new FindingStore();

	// 与 worker 同款工具集（验证 + finding_submit）
	const tools = [
		...createReconTools(localReconProvider),
		webFetchTool,
		httpReqTool,
		nucleiScanTool,
		sqlmapRunTool,
		dirBruteTool,
		authBruteTool,
		skillLoadTool,
		createFindingSubmit(findingStore),
	];
	const gate = buildScopeGateChecker({ scope, forceEnabled: true });
	const audit = buildAuditLogger(`escalate:${finding.id}`);

	const agent = new Agent({
		initialState: {
			systemPrompt: ESCALATE_SYSTEM_PROMPT,
			model,
			thinkingLevel: 'high',
			tools,
		},
		streamFn: models.streamSimple.bind(models),
		beforeToolCall: async (context) => {
			await audit.onToolStart(context);
			return gate(context);
		},
		afterToolCall: async (context) => {
			await audit.onToolEnd(context);
			return undefined;
		},
	});

	try {
		const input = {
			original_finding: {
				vuln_name: finding.vulnName,
				vuln_type: finding.vulnType,
				severity: finding.severity,
				url: finding.url,
				summary: finding.summary,
				poc: finding.evidence.poc,
			},
			seed_id: seedId,
		};
		await agent.prompt(
			`执行扩大危害（只读类升级，红线 R5 禁改删/脱库）。\n${JSON.stringify(input, null, 1)}\n有显著升级 → finding_submit 提交新 finding（证据五件套，seedId 见上）。无显著升级 → finding_submit 提交一条 summary 说明放弃原因即可。`,
		);

		// 检查是否产出新 finding（排除原 finding 本身）——按 createdAfter 过滤，避免按 severity 排序截断漏掉新低危升级
		const newFindings = await findingStore.listFindings({
			seedId,
			createdAfter: finding.createdAt,
			limit: 50,
		});
		const fresh = newFindings.filter((f) => f.id !== finding.id && !f.supersededBy);
		// 排除"放弃原因"类提交（summary 含放弃/未升级标记）
		const realUpgrade = fresh.filter((f) => !/未升级|放弃|无显著|no.?escalat/i.test(f.summary));
		if (realUpgrade.length > 0) {
			await findingStore.updateReviewStatus(finding.id, 'escalated');
			return {
				escalated: true,
				finding: realUpgrade[0]!,
				reasoning: `升级产出新 finding: ${realUpgrade[0]?.vulnName}`,
			};
		}
		return { escalated: false, reasoning: fresh[0]?.summary ?? '未产出显著升级' };
	} finally {
		// agent 无独立 close（无审计流），无需额外清理
	}
}
