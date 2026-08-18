/**
 * Worker 角色（M2/M3）：执行单条意图
 *
 * 每意图独立 Agent 会话（隔离上下文）：
 *   - 工具：recon_*（进程内消费）+ web_fetch + skill_load + 验证工具（http_req/nuclei/sqlmap/爆破）
 *     + 图工具（graph_store_fact/task_result_submit）+ finding_submit（强制证据）
 *   - 安全：beforeToolCall 接 Scope Gate（全部网络工具目标校验）+ 审计
 *   - 产出：确定性 fact 落图 + 漏洞 finding（证据链完整）+ task_result_submit 终态
 */
import { Agent } from '@earendil-works/pi-agent-core';
import type { ExplorationIntent, ExplorationStore } from '../graph/store.js';
import { createDeepSeekModels, resolveDeepSeekModel } from '../llm/provider.js';
import { localReconProvider } from '../recon/provider.js';
import { buildAuditLogger, buildScopeGateChecker } from '../security/gate.js';
import { authBruteTool, dirBruteTool } from '../tools/brute.js';
import { httpReqTool } from '../tools/http_req.js';
import { createNotesStore, createNotesTool, renderSessionStatus } from '../tools/notes.js';
import { createReconTools } from '../tools/recon.js';
import { skillLoadTool } from '../tools/skill.js';
import { nucleiScanTool, sqlmapRunTool } from '../tools/validation.js';
import { webFetchTool } from '../tools/web_fetch.js';
import { FindingStore } from '../validation/finding_store.js';
import { createFindingSubmit } from './finding_tools.js';
import { createStoreFact, createTaskResultSubmit } from './graph_tools.js';
import {
	AGENT_IDENTITY,
	HIGH_VALUE_ENTRY,
	HUNTING_IRON_RULES,
	OUTPUT_FORMAT,
	SAFETY_RED_LINES,
	SKILL_ROUTING_TABLE,
	TEST_DISCIPLINE,
	VERIFY_METHODS,
} from './prompts.js';

export interface WorkerOptions {
	seedId: string;
	scope: string[];
	modelId?: string;
	store: ExplorationStore;
	intent: ExplorationIntent;
	/** 单意图超时（毫秒），默认 10 分钟 */
	timeoutMs?: number;
	/** 情报库注入块（M4.4：按目标指纹/根域命中才注入） */
	intelBlock?: string | null;
	/** 初始引导提示词（如「重点挖掘 SQL 注入/SSRF，不要挖 XSS」） */
	goal?: string;
	/** 预加载的目标资产快照摘要（endpoints/findings/cve_hints/attack_surface） */
	assetSnapshot?: string | null;
}

function buildWorkerPrompt(o: WorkerOptions): string {
	const intent = o.intent;
	return `${AGENT_IDENTITY}

你是执行者（Worker）：负责执行 planner 派发的一条具体侦察意图。

${TEST_DISCIPLINE}

${SKILL_ROUTING_TABLE}

高价值入口参考：
${HIGH_VALUE_ENTRY}

	${OUTPUT_FORMAT}

${HUNTING_IRON_RULES}

${SAFETY_RED_LINES}

${VERIFY_METHODS}

${o.intelBlock ?? ''}

${o.goal ? `===== 任务引导 GOAL =====\n${o.goal}\n（优先验证「重点」方向，跳过「不要挖」的方向；与安全红线冲突时以红线为准）\n` : ''}${o.assetSnapshot ?? ''}===== 当前意图 =====
类型: ${intent.intentType}
描述: ${intent.description}
意图 ID: ${intent.id}
授权锚点: ${intent.scopeAnchor}

===== 执行纪律 =====
1. 先用 recon_asset_detail / recon_endpoints / recon_findings 吃透目标（进程内本地查询，不重复收集）
2. 需要专项方法论时 skill_load 加载对应技能
3. 每次确认的发现用 graph_store_fact 落图（summary 精炼、带 assetId 锚点）
4. 侦察用 web_fetch；验证用 http_req（手工重放，记录 raw_request/raw_response 原文）
5. 漏洞扫描用 nuclei_scan；注入验证用 sqlmap_run（仅对明确注入点）
6. 目录发现用 dir_brute；弱口令用 auth_brute（授权范围内自动护栏）
7. 确认漏洞后必须用 finding_submit 提交，携带完整证据五件套（poc/raw_request/raw_response/kill_chain/self_check），缺字段会被拒收
8. 完成或确认无法推进时，用 task_result_submit 提交结果（终态）
9. 所有网络工具受授权范围约束，越权目标会被拦截（fail-closed）
10. **源码审计**：若目标有源码包（recon_source 返回 dumps），必须审计源码——硬编码密钥/凭证、隐藏接口、危险函数（eval/exec/反序列化/文件读写）都是高价值线索；用 recon_source_read 追看具体实现坐实，确认后 finding_submit（白盒线索 + 黑盒验证更可信）

===== 覆盖度纪律（防止遗漏攻击面）=====
- 若当前意图是「攻击面遍历」（recon_full 或描述含多类攻击面）：**必须逐类测试并记录**，不要只测 1-2 类就结束
- 每测完一类攻击面，用 graph_store_fact 记录 coverage 事实（如 factType=coverage，summary=[sqli] tested 未发现注入点 / [upload] 发现上传功能待深挖）
- ⚠️ **关键：发现漏洞入口 ≠ 任务完成**。每确认一个真实漏洞（注入/SSRF/XXE/文件读/上传/越权等），**必须调用 finding_submit 提交**（证据五件套：poc/raw_request/raw_response/kill_chain/self_check），不能只记 fact 就完事
- 对已确认的漏洞：skill_load 对应技能 → http_req 构造 payload 坐实（响应差异/盲注时间差/回连）→ finding_submit
- 意图结束时，若还有未测的攻击面（如描述列了 8 类只测了 3 类），**不要直接 task_result_submit 结束**，继续测完；确因无入口无法测的用 coverage fact 标注「无入口」
- 覆盖度事实让 planner 下一轮能判断哪些攻击面还没覆盖，针对性补派`;
}

/**
 * 预加载目标资产快照摘要（endpoints/findings/cve_hints/attack_surface）。
 * 在 worker 提示词里直接注入，省去首轮 recon_asset_detail 往返，并保证不遗漏已收集线索。
 */
async function buildAssetSnapshotBlock(assetId: string): Promise<string | null> {
	try {
		const { generateSnapshot } = await import('../recon/scoring/snapshot.js');
		const snap = (await generateSnapshot(assetId)) as unknown as Record<string, unknown>;
		const { queryFindings } = await import('../recon/storage/models/query.js');
		const { findings } = await queryFindings({ webappId: assetId, limit: 50 });

		const webapp = (snap.webapp ?? {}) as Record<string, unknown>;
		const role = (snap.role ?? {}) as Record<string, unknown>;
		const score = (snap.score ?? {}) as Record<string, unknown>;
		const cve = (snap.known_cve_hints ?? []) as Array<Record<string, unknown>>;
		const endpoints = (snap.endpoints ?? []) as unknown[];
		const jsApis = (snap.js_apis ?? []) as unknown[];
		const params = (snap.params ?? []) as unknown[];
		const attack = snap.attack_surface as Record<string, unknown> | null;

		const lines: string[] = [];
		lines.push(`- URL: ${webapp.url ?? ''}`);
		lines.push(`- 角色: ${role.role ?? '?'} · 评分: ${score.score ?? '?'}`);
		const tech = Array.isArray(webapp.tech) ? (webapp.tech as string[]).join(', ') : '';
		if (tech) lines.push(`- 技术栈: ${tech}`);
		if (cve.length) {
			lines.push(
				`- 已知 CVE 线索 (${cve.length}): ${cve
					.map((c) => `${c.cve ?? ''}(${c.component ?? ''})`)
					.slice(0, 10)
					.join(', ')}`,
			);
		}
		if (endpoints.length) {
			lines.push(`- 端点 (${endpoints.length}): ${JSON.stringify(endpoints.slice(0, 30)).slice(0, 1200)}`);
		}
		if (jsApis.length) {
			lines.push(`- JS 接口 (${jsApis.length}): ${JSON.stringify(jsApis.slice(0, 20)).slice(0, 800)}`);
		}
		if (params.length) {
			lines.push(`- 参数 (${params.length}): ${JSON.stringify(params.slice(0, 30)).slice(0, 800)}`);
		}
		if (findings.length) {
			lines.push(
				`- 已有发现 (${findings.length}): ${findings
					.slice(0, 20)
					.map((f) => `${f.type}(${f.severity})`)
					.join(', ')}`,
			);
		}
		if (attack && Object.keys(attack).length) {
			lines.push(`- 攻击面: ${JSON.stringify(attack).slice(0, 800)}`);
		}

		return `===== 目标资产快照（已预加载）=====\n${lines.join('\n')}\n（上为已收集线索，可直接据此验证；需要完整详情时再 recon_asset_detail 查询）`;
	} catch {
		return null;
	}
}

export interface WorkerRunResult {
	intentId: string;
	status: 'done' | 'failed' | 'timeout';
	factCount: number;
	summary: string;
}

/**
 * 执行一条意图（worker）。
 * 超时保护：超过 timeoutMs 标记意图 failed。
 */
export async function runWorker(o: WorkerOptions): Promise<WorkerRunResult> {
	const store = o.store;
	const intent = o.intent;
	const runId = `intent:${intent.id}`;

	// 标记为 running（campaign 经 claimNext 已置 running；direct-hunt 是 createIntent 后直调，需这里兜底，
	// 否则意图会一直卡在 pending，末尾「current.status==='running'」判定也失效，无法标 done）
	if (intent.status !== 'running') {
		await store.updateIntentStatus(intent.id, 'running');
	}

	// M4.4：情报库注入（按目标 host 指纹/根域，命中才注入零开销）
	let intelBlock = o.intelBlock ?? null;
	if (!intelBlock && intent.assetId) {
		try {
			const { buildIntelBlock } = await import('../validation/intel_harvest.js');
			intelBlock = await buildIntelBlock(intent.scopeAnchor, intent.description);
		} catch {
			intelBlock = null;
		}
	}
	// 预加载目标资产快照摘要（endpoints/findings/cve_hints/attack_surface），省首轮工具往返 + 防遗漏线索
	let assetSnapshot = o.assetSnapshot ?? null;
	if (!assetSnapshot && intent.assetId) {
		assetSnapshot = await buildAssetSnapshotBlock(intent.assetId);
	}
	const workerOptions: WorkerOptions = { ...o, intelBlock, assetSnapshot };

	const models = createDeepSeekModels();
	const model = resolveDeepSeekModel(models, o.modelId ?? 'deepseek-v4-flash');

	// 工具集：recon 消费 + 侦察/验证工具 + 图工具 + finding_submit + 工作笔记（M4.6）
	const findingStore = new FindingStore();
	const notesStore = createNotesStore();
	const tools = [
		...createReconTools(localReconProvider),
		webFetchTool,
		httpReqTool,
		nucleiScanTool,
		sqlmapRunTool,
		dirBruteTool,
		authBruteTool,
		skillLoadTool,
		createNotesTool(notesStore),
		createStoreFact(store),
		createTaskResultSubmit(store),
		createFindingSubmit(findingStore),
	];

	// 安全层：Scope Gate（web_fetch 校验）+ 审计
	const gate = buildScopeGateChecker({ scope: o.scope, forceEnabled: true });
	const audit = buildAuditLogger(runId);

	const agent = new Agent({
		initialState: {
			systemPrompt: buildWorkerPrompt(workerOptions),
			model,
			thinkingLevel: 'medium',
			tools,
		},
		streamFn: models.streamSimple.bind(models),
		// M4.6：每轮注入工作状态（session_status_block 思想），防止轮次推进丢上下文
		transformContext: async (messages) => {
			const status = renderSessionStatus(notesStore);
			if (!status) return messages;
			return [
				...messages,
				{
					role: 'user',
					content: status,
					timestamp: new Date().toISOString(),
				} as never,
			];
		},
		beforeToolCall: async (context) => {
			await audit.onToolStart(context);
			return gate(context);
		},
		afterToolCall: async (context) => {
			await audit.onToolEnd(context);
			return undefined;
		},
	});

	const factBefore = await store.countFacts(o.seedId);
	const findingBefore = (await findingStore.listFindings({ seedId: o.seedId, limit: 500 })).length;

		// 超时控制：recon_full 攻击面遍历需穷举 8 类，给 25 分钟；其余意图 10 分钟
		const timeoutMs =
			o.timeoutMs ?? (intent.intentType === 'recon_full' ? 25 * 60 * 1000 : 10 * 60 * 1000);
		let timedOut = false;
		// 硬超时：pi Agent 内置 abort()，超时直接中断当前 run（含进行中的 LLM 调用），
		// 不阻塞整个 batch（runDirectHunt 多目标并发）。无需改 pi。
		const timer = setTimeout(() => {
			timedOut = true;
			agent.abort();
		}, timeoutMs);

		try {
			// ★ worker 循环（AutoHunter「挖到底」）：LLM 不调终态工具就 continue 续跑，
			//   最多 maxTurns 轮，直到意图被置 done/failed 或产出 finding
			const maxTurns = intent.intentType === 'recon_full' ? 8 : 5;
			await agent.prompt(
				`执行意图「${intent.description}」。\n先用 recon 工具吃透目标，需要验证时用 http_req/nuclei_scan/sqlmap_run（受授权范围约束），发现的情报用 graph_store_fact 落图，确认的漏洞用 finding_submit 提交（证据五件套），完成后用 task_result_submit 结束。`,
			);

			for (let turn = 0; turn < maxTurns; turn++) {
				if (timedOut) break;
				// 检查是否已终态（LLM 调了 task_result_submit / finding_submit 后 intent 被置 done）
				const cur = await store.getIntent(intent.id);
				if (cur?.status === 'done' || cur?.status === 'failed') break;
				// 检查是否已产出 finding（确认漏洞已提交）——只算本意图新增（用 before/after 增量，避免 seed 全量误判）
				const fAfter = await findingStore.listFindings({ seedId: o.seedId, limit: 500 });
				const newFindings = fAfter.length - findingBefore;
				// 若本 turn 已产出 finding 但仍未调终态 → 继续一轮让其收尾；否则引导继续挖
				if (newFindings > 0 && turn > 0) {
					// 已有产出，引导收尾提交 task_result_submit
					agent.steer({
						role: 'user',
						content: '已提交漏洞。若还有未测攻击面继续测；否则调用 task_result_submit 结束本轮。',
						timestamp: new Date().toISOString(),
					} as never);
				} else {
					agent.steer({
						role: 'user',
						content:
							'你还没有完成：要么继续测试未覆盖的攻击面并 finding_submit 确认的漏洞，要么明确记录 coverage（无入口）后 task_result_submit。不要直接结束。',
						timestamp: new Date().toISOString(),
					} as never);
				}
				await agent.continue();
			}
		} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		if (timedOut) {
			await store.updateIntentStatus(intent.id, 'failed', `timeout: ${msg}`);
			await store.logActivity(o.seedId, 'intent_done', '意图超时', { intentId: intent.id });
			return { intentId: intent.id, status: 'timeout', factCount: 0, summary: 'timeout' };
		}
		await store.updateIntentStatus(intent.id, 'failed', msg);
		await store.logActivity(o.seedId, 'intent_done', `意图失败: ${msg.slice(0, 150)}`, {
			intentId: intent.id,
		});
		return { intentId: intent.id, status: 'failed', factCount: 0, summary: msg };
		} finally {
			if (timer) clearTimeout(timer);
		}

	const factAfter = await store.countFacts(o.seedId);
	const factCount = factAfter - factBefore;
	// 超时：意图必须标 failed（不能标 done），避免「超时但被当作完成」导致不再重挖
	if (timedOut) {
		await store.updateIntentStatus(intent.id, 'failed', 'worker timeout');
		await store.logActivity(o.seedId, 'intent_done', '意图超时', { intentId: intent.id });
		return { intentId: intent.id, status: 'timeout', factCount, summary: 'timeout' };
	}
	const current = await store.getIntent(intent.id);
	// task_result_submit 已把意图置 done；若 worker 没调终态工具则强制置 done
	if (current?.status === 'running') {
		await store.updateIntentStatus(intent.id, 'done', 'worker finished without terminate tool');
	}

	return {
		intentId: intent.id,
		status: 'done',
		factCount,
		summary: current?.resultSummary ?? '',
	};
}
