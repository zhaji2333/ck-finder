/**
 * Planner 角色（M2/M4）：唯一意图生成者
 *
 * 每轮独立 Agent 会话（无隐藏历史）：
 *   - 输入：AGENTS 方法论总纲 + 探索图态势（高价值资产 + 已有意图/事实）
 *   - 决策：**双通道候选**（AutoHunter「可达即挖」）——评分≥60 的高价值资产
 *     + 低分但强信号（cve_hints/已知组件/API/登录页）的目标，都进候选；
 *     playbook 路线（component_exposure/spa_js_api/...）指导意图类型
 *   - 收敛：planner 不派新意图 → 空轮收敛
 *
 * 预算控制由 Controller 执行（轮数上限）；planner 每轮只产意图，不做执行。
 */
import { Agent } from '@earendil-works/pi-agent-core';
import type { ExplorationStore } from '../graph/store.js';
import type { ExplorationIntent } from '../graph/store.js';
import { createDeepSeekModels, resolveDeepSeekModel } from '../llm/provider.js';
import { type WebappQueryRow, queryWebapps } from '../recon/storage/models/query.js';
import { createExplorationSubmit } from './graph_tools.js';
import {
	type PlannerTarget,
	buildAttackSurfaceIntent,
	buildPlannerTargets,
	routeIntentTemplate,
} from './playbook.js';
import {
	AGENT_IDENTITY,
	HIGH_VALUE_ENTRY,
	OUTPUT_FORMAT,
	SKILL_ROUTING_TABLE,
	TEST_DISCIPLINE,
} from './prompts.js';

export interface PlannerOptions {
	seedId: string;
	scope: string[];
	modelId?: string;
	store: ExplorationStore;
	round: number;
	maxRounds: number;
	/** 是否启用 LLM（未配 key 时跳过 planner） */
	enabled: boolean;
	/** 确定性必挖目标数（top-N 按 pri 排序，默认 5） */
	maxTargets?: number;
	/** 初始引导提示词（如「重点挖掘 SQL 注入/SSRF，不要挖 XSS」） */
	goal?: string;
}

/** 构建 planner 系统提示词：方法论 + 当前态势（含信号与路线） */
function buildPlannerPrompt(
	o: PlannerOptions,
	targets: PlannerTarget[],
	existingIntents: ExplorationIntent[],
	facts: Array<{ factType: string; summary: string; assetId: string | null }>,
): string {
	const targetText = targets
		.slice(0, 50)
		.map((t) => {
			const routeMark = `[打法:${t.routeId}]`;
			const signalMark =
				t.signals.cveHints > 0
					? ` ⚠cve×${t.signals.cveHints}(${t.signals.cveSeverities.join('/')})`
					: '';
			const stage = String((t.meta as Record<string, unknown>).score_stage ?? '?');
			const sigDetail =
				t.signals.detail.length > 0 ? `（${t.signals.detail.slice(0, 2).join('; ')}）` : '';
			return `- [pri=${t.priorityScore} score=${t.score}] role=${t.role} stage=${stage} ${routeMark}${signalMark} ${t.url}${sigDetail} (assetId=${t.assetId})`;
		})
		.join('\n');
	const intentText =
		existingIntents.length > 0
			? existingIntents
					.map(
						(i) => `- [${i.status}] #${i.intentType} ${i.description.slice(0, 100)} (id=${i.id})`,
					)
					.join('\n')
			: '（暂无）';
	const factText =
		facts.length > 0
			? facts.map((f) => `- (${f.factType}) ${f.summary.slice(0, 120)}`).join('\n')
			: '（暂无）';

	return `${AGENT_IDENTITY}

你是规划者（Planner）：负责把侦察目标分解为可执行的意图，派发给 worker。
${TEST_DISCIPLINE}

${SKILL_ROUTING_TABLE}

${OUTPUT_FORMAT}

高价值入口参考：
${HIGH_VALUE_ENTRY}

===== 当前作战态势（第 ${o.round}/${o.maxRounds} 轮）=====

【本次任务 seedId】${o.seedId}
（exploration_submit 的 seedId 参数必须用这个值）
${o.goal ? `\n【任务引导 GOAL】\n${o.goal}\n（此为本次任务的重点/回避方向：优先派发「重点」覆盖的意图，避开「不要挖」的类型）` : ''}

【目标候选（按综合优先级分排序，含评分 + 信号加成）】
${targetText || '（无候选目标）'}

说明：
- pri = 综合优先级分（评分 + 信号加成）；score = ck-recon 评分
- ⚠cve×N = 已知组件漏洞线索 N 条（即使评分低也高优先——低分高信号目标必须挖）
- 打法：component_exposure=验证已知组件CVE / spa_js_api=扒JS找接口 / api_authorization=接口越权 / auth_gateway=认证弱口令 / generic_admin=通用验证 / static_low_value=快速收敛

【已有意图】
${intentText}

【已收集事实】
${factText}

===== 规划指令 =====
1. 从目标候选中挑选最值得挖的目标（优先：⚠cve critical/high > 高评分 > API/登录页；**低分但有 cve_hints/已知组件的目标必须派意图**，这是挖洞重点）
2. 按目标打法（routeId）确定意图类型：component_exposure → 验证已知组件 CVE；spa_js_api → recon_js；api_authorization → recon_api；auth_gateway → recon_auth
3. 参考「已有意图/事实」避免重复派发
4. 产出 1-2 条新的侦察意图，描述要具体到目标 URL、组件、关注的 CVE/PoC 面
5. 用 exploration_submit 提交意图（seedId 用上文【本次任务 seedId】，assetId 用候选里的 assetId，终态提交后本轮结束）
6. 若所有候选都已被意图覆盖（含低分信号目标），直接输出「本轮无新意图」并结束——不要凑数`;
}

export interface PlannerRunResult {
	/** 本轮是否派发了新意图 */
	submitted: boolean;
	newIntentCount: number;
	summary: string;
}

/**
 * 执行一轮 planner。
 * AutoHunter「可达即挖」：目标选中是**确定性**的（top-N 按 pri 排序，低分高信号必挖），
 * LLM 只做意图增强（对已选目标细化打法，只增不减，不挑目标）。
 * 返回 submitted=false 表示无新意图（收敛）。
 */
export async function runPlannerRound(o: PlannerOptions): Promise<PlannerRunResult> {
	let summaryText = '';
	if (!o.enabled) {
		// 无 LLM 时也做确定性意图生成（AutoHunter「确定性流程不走 LLM」）
		await o.store.logActivity(
			o.seedId,
			'budget',
			'planner 降级：确定性生成必挖意图（未配置 DEEPSEEK_API_KEY）',
		);
	}

	// 态势：三通道候选（AutoHunter「可达即挖」），全部限定当前 seed 资产（防跨 seed 串扰）+ 排除域名
	//   ① 高评分（≥60）  ② 全量（limit 200）  ③ ★ 有 cve_hints 的低分目标（已知组件漏洞，独立查询防截断）
	const { getConfig } = await import('../recon/config.js');
	const exclude = [...getConfig().agent.huntExclude];
	const [hi, all, cve] = await Promise.all([
		queryWebapps({ scoreGt: 60, seedId: o.seedId, excludeDomains: exclude, limit: 50 }),
		queryWebapps({ scoreGt: 0, seedId: o.seedId, excludeDomains: exclude, limit: 200 }),
		queryWebapps({
			scoreGt: 0,
			hasCveHints: true,
			seedId: o.seedId,
			excludeDomains: exclude,
			limit: 100,
		}),
	]);
	// 去重（按 assetId）+ 合并
	const byId = new Map<string, WebappQueryRow>();
	for (const w of [...hi.webapps, ...all.webapps, ...cve.webapps]) {
		if (w.assetId) byId.set(w.assetId, w);
	}
	const targets = buildPlannerTargets([...byId.values()]);
	const existingIntents = await o.store.listIntents(o.seedId);
	const beforeCount = existingIntents.length;

	// ★ 确定性选中 top-N 必挖目标（AutoHunter「可达即挖」：低分高信号也必挖）
	const maxTargets = o.maxTargets ?? 5;
	const topTargets = targets.slice(0, maxTargets);
	// 已有意图只统计「有效」的（pending/running/done），canceled/failed 不算已覆盖（否则失败/清理后无法重派）
	const existingByAsset = new Set(
		existingIntents
			.filter((i) => i.assetId && i.status !== 'canceled' && i.status !== 'failed')
			.map((i) => i.assetId),
	);

	// ★ 兜底规则（AutoHunter「每目标挖到底」）：**所有 seed 内 webapp 都值得系统性攻击面遍历**
	//   攻击面遍历意图（recon_full）无视浅意图（recon_js/verify 等），只被同类型 recon_full 挡住——
	//   保证 sqli/ssrf/upload/xxe 等各类攻击面都被穷举（通用方法论，非靶场清单）
	const fullCovered = new Set(
		existingIntents
			.filter(
				(i) => i.intentType === 'recon_full' && i.status !== 'canceled' && i.status !== 'failed',
			)
			.map((i) => i.assetId),
	);
	const allSeedWebapps = (
		await queryWebapps({
			scoreGt: 0,
			seedId: o.seedId,
			excludeDomains: exclude,
			limit: 100,
		})
	).webapps;
	const fallbackTargets = allSeedWebapps
		.filter((w) => w.assetId && !fullCovered.has(w.assetId))
		.slice(0, 3); // 兜底最多 3 个（防大量历史资产涌入）

	// 为未覆盖的 top 目标生成确定性意图（route 模板）+ 兜底目标（generic）
	let created = 0;
	for (const t of topTargets) {
		if (!t.assetId || existingByAsset.has(t.assetId)) continue;
		const tmpl = routeIntentTemplate(t);
		await o.store.createIntent({
			seedId: o.seedId,
			intentType: tmpl.intentType,
			description: tmpl.description,
			priority: 1,
			assetId: t.assetId,
			scopeAnchor: o.scope.join(',') || o.seedId,
		});
		existingByAsset.add(t.assetId); // 本轮内去重
		created++;
	}
	// 强信号 top 目标也补攻击面遍历（AutoHunter「挖到底」：专项验证完继续穷举全攻击面）
	for (const t of topTargets) {
		if (!t.assetId || fullCovered.has(t.assetId)) continue;
		const tmpl = buildAttackSurfaceIntent(t.url);
		await o.store.createIntent({
			seedId: o.seedId,
			intentType: tmpl.intentType,
			description: tmpl.description,
			priority: 1,
			assetId: t.assetId,
			scopeAnchor: o.scope.join(',') || o.seedId,
		});
		fullCovered.add(t.assetId); // 本轮内去重（防与 fallbackTargets 重复派 recon_full）
		created++;
	}
	for (const t of fallbackTargets) {
		// 通用攻击面遍历意图（AutoHunter「每目标挖到底」：穷举全部攻击面，不写死靶场）
		if (fullCovered.has(t.assetId!)) continue; // top 目标已补过 recon_full，跳过
		const tmpl = buildAttackSurfaceIntent(t.url);
		await o.store.createIntent({
			seedId: o.seedId,
			intentType: tmpl.intentType,
			description: tmpl.description,
			priority: 2,
			assetId: t.assetId,
			scopeAnchor: o.scope.join(',') || o.seedId,
		});
		fullCovered.add(t.assetId!);
		created++;
	}
	if (created > 0) {
		await o.store.logActivity(
			o.seedId,
			'intent_created',
			`确定性派发 ${created} 条必挖意图（top${maxTargets}${fallbackTargets.length > 0 ? ` + 兜底${fallbackTargets.length}` : ''}）`,
			{
				round: o.round,
				targets: [...topTargets.map((t) => t.url), ...fallbackTargets.map((t) => t.url)],
			},
		);
	}

	// ★ coverage 缺口补派（AutoHunter report_coverage → deepen 机制，确定性）
	//   读 coverage facts：确认有入口的攻击面（sqli/ssrf/xxe/upload/...）但该 seed 无对应 finding
	//   → 补派专项验证意图（聚焦单类深挖到提交），不靠 LLM 自觉
	created += await fillCoverageGaps(o, o.store, existingIntents);

	// LLM 增强：对已选目标细化打法（只增不减；无 LLM 时跳过增强，确定性意图已够）
	if (o.enabled) {
		const facts = await o.store.listFacts(o.seedId);
		const refreshed = await o.store.listIntents(o.seedId);
		const models = createDeepSeekModels();
		const model = resolveDeepSeekModel(models, o.modelId ?? 'deepseek-v4-flash');
		const agent = new Agent({
			initialState: {
				systemPrompt: buildPlannerPrompt(o, targets, refreshed, facts),
				model,
				thinkingLevel: 'high',
				tools: [createExplorationSubmit(o.store, o.scope)],
			},
			streamFn: models.streamSimple.bind(models),
			beforeToolCall: async () => undefined,
		});
		const goal = `你是规划者。以下 top${maxTargets} 目标已确定必挖（已派意图）:\n${topTargets.map((t) => `- ${t.url} (${t.assetId})`).join('\n')}\n\n请检查是否有值得**追加**的意图（如某目标还有第二打法、或 top 之外有明显高价值未覆盖）。只增不减，不要重复派已覆盖目标。无追加则输出「无需追加」。`;
		agent.subscribe((event) => {
			if (event.type === 'agent_end') summaryText = 'planner enhance finished';
		});
		await agent.prompt(goal);
	}

	const afterCount = (await o.store.listIntents(o.seedId)).length;
	const newIntentCount = afterCount - beforeCount;
	const submitted = newIntentCount > 0;

	await o.store.logActivity(
		o.seedId,
		submitted ? 'intent_created' : 'planner_converged',
		submitted
			? `planner 第 ${o.round} 轮派发 ${newIntentCount} 条新意图`
			: 'planner 收敛（无新意图）',
		{ round: o.round, newIntentCount },
	);

	return { submitted, newIntentCount, summary: summaryText };
}

/**
 * coverage 缺口补派（AutoHunter report_coverage → deepen 机制）
 *
 * 读探索图 facts：确认有漏洞入口的攻击面（[sqli]/[ssrf]/[xxe]/[file-handling]/[deserialization]/[rce]/[auth-bypass] 等）
 * 但该 seed 无对应 finding → 补派专项验证意图（聚焦单类深挖到提交，确定性不靠 LLM 自觉）。
 *
 * 攻击面 → 意图类型映射（通用方法论，非靶场清单）。
 */
const COVERAGE_TO_INTENT: Array<{
	tag: string;
	intentType: string;
	keywords: string[];
	/** 该意图可能产出的 canonical vuln_type（用于 finding 级去重） */
	vulnTypes: string[];
}> = [
	{ tag: 'sqli', intentType: 'verify_inject', keywords: ['sql', '注入', 'sqli'], vulnTypes: ['injection'] },
	{ tag: 'ssrf', intentType: 'verify_ssrf', keywords: ['ssrf', 'url'], vulnTypes: ['ssrf'] },
	{ tag: 'xxe', intentType: 'verify_xxe', keywords: ['xxe', 'xml'], vulnTypes: ['xxe'] },
	{
		tag: 'deserialization',
		intentType: 'verify_deser',
		keywords: ['反序列化', 'deserial', 'unser'],
		vulnTypes: ['deserialization'],
	},
	{
		tag: 'file-handling',
		intentType: 'verify_file',
		keywords: ['文件', 'upload', '下载', '下载', 'lfi', '穿越'],
		vulnTypes: ['file_upload', 'path_traversal'],
	},
	{ tag: 'rce', intentType: 'verify_rce', keywords: ['rce', '命令', 'eval', '执行'], vulnTypes: ['injection'] },
	{
		tag: 'auth-bypass',
		intentType: 'verify_auth',
		keywords: ['认证', '暴力', '验证码', 'auth', '越权'],
		vulnTypes: ['auth', 'broken_access', 'idor'],
	},
	{
		tag: 'info-leak',
		intentType: 'verify_info',
		keywords: ['泄露', '信息', 'info', '重定向'],
		vulnTypes: ['info_disclosure', 'redirect'],
	},
];

async function fillCoverageGaps(
	o: PlannerOptions,
	store: ExplorationStore,
	existingIntents: ExplorationIntent[],
): Promise<number> {
	const facts = await store.listFacts(o.seedId);
	if (facts.length === 0) return 0;

	// 已有验证意图类型（pending/running/done，排除 canceled/failed）——防重复补派
	const coveredIntentTypes = new Set(
		existingIntents
			.filter(
				(i) =>
					i.intentType.startsWith('verify_') &&
					i.status !== 'canceled' &&
					i.status !== 'failed',
			)
			.map((i) => i.intentType),
	);

	// 该 seed 已确认的 finding 类型（粗判，用于跳过已有漏洞的攻击面）
	const pool = (await import('../recon/storage/pg.js')).getPg();
	const { rows: findings } = await pool.query(
		'SELECT DISTINCT vuln_type FROM validation_findings WHERE seed_id = $1',
		[o.seedId],
	);
	const foundTypes = new Set(findings.map((r) => String(r.vuln_type).toLowerCase()));

	let created = 0;
	for (const fact of facts) {
		if (fact.factType !== 'endpoint') continue;
		const summary = fact.summary.toLowerCase();
		for (const map of COVERAGE_TO_INTENT) {
			// 该攻击面已确认有入口（fact 含关键词）
			const hasEntry =
				map.keywords.some((k) => summary.includes(k)) && /入口|存在|确认|漏洞/.test(summary);
			if (!hasEntry) continue;
			// 是否已有同类型验证意图（含本轮刚创建的，防重复）
			if (coveredIntentTypes.has(map.intentType)) continue;
			// 是否已有对应 canonical vuln_type 的 finding
			if (map.vulnTypes.some((t) => foundTypes.has(t))) continue;
			// 补派专项验证意图
			await store.createIntent({
				seedId: o.seedId,
				intentType: map.intentType,
				description: `【专项验证-${map.tag}】coverage 确认 ${map.tag} 类有入口（${fact.summary.slice(0, 80)}）。skill_load 对应技能 → http_req 构造 payload 坐实漏洞 → finding_submit 提交（证据五件套）。`,
				priority: 1,
				assetId: fact.assetId ?? undefined,
				scopeAnchor: o.scope.join(',') || o.seedId,
			});
			coveredIntentTypes.add(map.intentType); // 本轮内去重
			created++;
		}
	}
	if (created > 0) {
		await store.logActivity(
			o.seedId,
			'intent_created',
			`coverage 缺口补派 ${created} 条专项验证意图`,
			{
				round: o.round,
				types: COVERAGE_TO_INTENT.filter((m) => m.tag).length,
			},
		);
	}
	return created;
}
