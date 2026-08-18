import { runPlannerRound } from './agents/planner.js';
import { runWorker } from './agents/worker.js';
import { type ExplorationIntent, ExplorationStore } from './graph/store.js';
/**
 * Controller（M2）：任务编排层（TS 代码，不走 LLM）
 *
 * 流程：
 *   1. 触发收集：runRecon（进程内异步）→ 轮询进度（recon_task_info 数据源）
 *   2. planner 循环：每轮派意图（预算内，默认 3 轮）
 *   3. worker 循环：执行所有 pending 意图（每意图独立会话）
 *   4. 收敛：planner 空轮 或 达到预算上限
 *   5. 崩溃恢复：seed 已有未完成意图 → 续跑 worker（不重复 planner）
 *
 * 预算硬上限：maxRounds（默认 3）、maxIntents（默认 20）、单意图超时（10 分钟）。
 */
import { runRecon } from './recon/pipeline/runner.js';
import { querySeedById } from './recon/storage/models/query.js';

export interface CampaignOptions {
	seedId: string;
	scope: string[];
	modelId?: string;
	/** planner 轮数上限 */
	maxRounds?: number;
	/** 每任务意图数上限 */
	maxIntents?: number;
	/** 是否启用 LLM planner（未配 key 自动 false） */
	llmEnabled?: boolean;
	/** 是否已触发过收集（崩溃恢复时为 true，跳过 runRecon） */
	skipCollection?: boolean;
	/** deepen 回炉最大深度（默认 2，防死循环） */
	maxDeepenDepth?: number;
	/** planner 确定性必挖目标数（透传给 runPlannerRound） */
	maxTargets?: number;
	/** 初始引导提示词（如「重点挖掘 SQL 注入/SSRF，不要挖 XSS」）——注入 planner/worker 提示词 */
	goal?: string;
	onLog?: (msg: string) => void;
}

export interface CampaignResult {
	seedId: string;
	intentsCreated: number;
	intentsDone: number;
	factsCollected: number;
	rounds: number;
	converged: boolean;
}

function log(o: CampaignOptions, msg: string): void {
	o.onLog?.(msg);
	console.log(`[controller] ${msg}`);
}

/** 从 activity 里提取某意图的 deepen_lead（worker 交棒给下一轮的方向） */
async function extractDeepenLead(
	store: ExplorationStore,
	seedId: string,
	intentId: string,
): Promise<string | null> {
	const activities = await store.listActivities(seedId, 10);
	for (const a of activities) {
		if (a.activityType === 'intent_done' && a.meta.intentId === intentId) {
			const lead = a.meta.deepen_lead;
			if (typeof lead === 'string' && lead.trim()) return lead.trim();
		}
	}
	return null;
}

/**
 * 触发/确认收集任务（runRecon 进程内异步 + 轮询）。
 * 返回 true = 收集已就绪（done 或已有足够数据）。
 */
async function ensureCollection(o: CampaignOptions, seedValue: string): Promise<void> {
	if (o.skipCollection) return;

	// 触发收集（fire-and-forget，runRecon 内部 upsertSeed + 更新进度）
	log(o, `触发收集: ${seedValue}`);
	runRecon(seedValue, {
		mode: 'auto',
		useFofa: true,
	}).catch((err) => {
		log(
			o,
			`收集任务启动失败（不阻塞，等待已有数据）: ${err instanceof Error ? err.message : String(err)}`,
		);
	});

	// 轮询等待：done 或超时（单站 1-5 分钟；全量可能更长，这里最多等 10 分钟做首次覆盖）
	const deadline = Date.now() + 10 * 60 * 1000;
	let lastStatus = 'pending';
	while (Date.now() < deadline) {
		const seed = await querySeedById(o.seedId);
		const status = seed?.status ?? 'pending';
		const stage = (seed?.progress as { stage?: string } | null)?.stage;
		if (status !== lastStatus) {
			log(o, `收集进度: ${status}${stage ? `（阶段 ${stage}）` : ''}`);
			lastStatus = status;
		}
		if (status === 'done' || status === 'partial') return;
		if (status === 'failed') {
			log(o, '收集任务 failed，继续用已有资产数据');
			return;
		}
		await new Promise((r) => setTimeout(r, 10_000));
	}
	log(o, '收集等待超时（10 分钟），继续用当前已有数据');
}

/**
 * 主编排循环。
 */
export async function runCampaign(o: CampaignOptions): Promise<CampaignResult> {
	const store = new ExplorationStore();
	const maxRounds = o.maxRounds ?? 3;
	const maxIntents = o.maxIntents ?? 20;

	const seed = await querySeedById(o.seedId);
	if (!seed) throw new Error(`任务不存在: ${o.seedId}`);
	log(o, `目标: ${seed.seedType} ${seed.value}`);

	// 1) 收集
	await ensureCollection(o, seed.value);

	// 2) 崩溃恢复：已有未完成意图 → 续跑 worker（跳过 planner 新轮）
	const unfinished = await store.countUnfinished(o.seedId);
	if (unfinished > 0) {
		log(o, `检测到 ${unfinished} 条未完成意图（崩溃恢复），直接续跑 worker`);
	}

	// 3) planner + worker 循环
	let rounds = 0;
	let converged = false;
	let _totalFacts = 0;
	const llmEnabled = o.llmEnabled ?? false;

	while (rounds < maxRounds) {
		const pending = await store.countByStatus(o.seedId);
		// 意图上限只统计「活跃」意图（pending/running）；done 是历史已完成，不计入预算
		// （否则 done 意图永久累积，一旦 ≥ maxIntents 就再也无法规划——破坏 7×24 重复挖）
		const totalIntents = (pending.pending ?? 0) + (pending.running ?? 0);
		if (totalIntents >= maxIntents) {
			log(o, `达到意图数上限 ${maxIntents}，停止规划`);
			converged = true;
			break;
		}

		rounds++;
		// planner 一轮（未配 LLM 时 disabled 直接返回 submitted=false → 收敛）
		const planResult = await runPlannerRound({
			seedId: o.seedId,
			scope: o.scope,
			modelId: o.modelId,
			store,
			round: rounds,
			maxRounds,
			maxTargets: o.maxTargets,
			enabled: llmEnabled,
			goal: o.goal,
		});

		if (!planResult.submitted && rounds > 1) {
			// planner 收敛（无新意图）且已执行过 → 结束
			converged = true;
			log(o, `planner 第 ${rounds} 轮收敛，结束`);
			break;
		}

		// 执行当前全部 pending 意图（worker 循环）
		let executed = 0;
		for (;;) {
			const intent = await store.claimNext(o.seedId);
			if (!intent) break;
			log(o, `worker 执行: [${intent.intentType}] ${intent.description.slice(0, 80)}`);
			const result = await runWorker({
				seedId: o.seedId,
				scope: o.scope,
				modelId: o.modelId,
				store,
				intent,
				goal: o.goal,
			});
			_totalFacts += result.factCount;
			executed++;
			log(o, `  → ${result.status}（新增事实 ${result.factCount}）`);

			// M4.9 确定性验证兜底：verify_ 专项意图 worker 未产出 finding → 用确定性例程实际验证
			if (result.factCount === 0 && intent.intentType.startsWith('verify_')) {
				await runDeterministicVerify(o, store, intent);
			}

			// M4.2 deepen 回炉：worker 带 deepen_lead（突破口没打穿）→ 自动重派定向意图（最多 2 次）
			const deepenLead = await extractDeepenLead(store, o.seedId, intent.id);
			if (deepenLead && intent.depth < (o.maxDeepenDepth ?? 2)) {
				const deepened = await store.createIntent({
					seedId: o.seedId,
					intentType: 'deepen',
					description: `【深挖】${deepenLead}`,
					priority: 1, // 提到队首
					scopeAnchor: intent.scopeAnchor,
					assetId: intent.assetId,
					depth: intent.depth + 1,
				});
				await store.logActivity(
					o.seedId,
					'intent_created',
					`深挖回炉: ${deepenLead.slice(0, 120)}`,
					{
						intentId: deepened.id,
						parentIntentId: intent.id,
					},
				);
				log(o, `  → 深挖回炉（深度 ${intent.depth + 1}）: ${deepenLead.slice(0, 80)}`);
			}
		}

		if (executed === 0 && !planResult.submitted) {
			// 第一轮 planner 就没派意图且无待执行 → 收敛
			converged = true;
			log(o, 'planner 无意图且无待执行，收敛');
			break;
		}
	}

	if (rounds >= maxRounds && !converged) {
		log(o, `达到 planner 轮数上限 ${maxRounds}`);
	}

	// 4) 汇总
	const finalCounts = await store.countByStatus(o.seedId);
	const facts = await store.listFacts(o.seedId);
	await store.logActivity(o.seedId, 'campaign_end', 'campaign finished', {
		rounds,
		intentsCreated: Object.values(finalCounts).reduce((a, b) => a + b, 0),
		intentsDone: finalCounts.done ?? 0,
		factsCollected: facts.length,
		converged,
	});

	log(
		o,
		`campaign 完成: 意图 ${Object.values(finalCounts).reduce((a, b) => a + b, 0)}（done=${finalCounts.done ?? 0} failed=${finalCounts.failed ?? 0}），事实 ${facts.length}，轮次 ${rounds}`,
	);

	return {
		seedId: o.seedId,
		intentsCreated: Object.values(finalCounts).reduce((a, b) => a + b, 0),
		intentsDone: finalCounts.done ?? 0,
		factsCollected: facts.length,
		rounds,
		converged,
	};
}

/**
 * M4.9 确定性验证兜底：verify_ 专项意图 worker 未产出 finding 时，
 * 用确定性例程（http_req 实际验证）补验，命中则入库 pending finding（AI 初审复核）。
 * 通用方法论，非靶场硬编码。
 */
async function runDeterministicVerify(
	o: CampaignOptions,
	store: ExplorationStore,
	intent: ExplorationIntent,
): Promise<void> {
	try {
		const { verifyUpload, verifySsrf, verifyDeserialization } = await import(
			'./agents/verify_routines.js'
		);
		const { queryWebapps } = await import('./recon/storage/models/query.js');
		const { FindingStore } = await import('./validation/finding_store.js');
		const findStore = new FindingStore();
		// 已有 finding 数（避免重复）
		const before = (await findStore.listFindings({ seedId: o.seedId })).length;

		// 目标 URL：意图 assetId 对应 webapp（限定当前 seed + 排除域名，防跨 seed 串扰）
		let targetUrl = '';
		let tech: string[] = [];
		if (intent.assetId) {
			const { getConfig } = await import('./recon/config.js');
			const exclude = [...getConfig().agent.huntExclude];
			const { webapps } = await queryWebapps({
				scoreGt: 0,
				seedId: o.seedId,
				excludeDomains: exclude,
				limit: 200,
			});
			const w = webapps.find((x) => x.assetId === intent.assetId);
			if (w) {
				targetUrl = w.url;
				tech = (w.tech ?? []).map(String);
			}
		}
		if (!targetUrl) return;

		// 从 facts 提取具体入口路径（coverage facts 记录了「入口 xxx.php」相对路径）
		const facts = await store.listFacts(o.seedId);
		const origin = (() => {
			try {
				return new URL(targetUrl).origin;
			} catch {
				return targetUrl;
			}
		})();

		let finding = null;
		if (intent.intentType === 'verify_file') {
			const uploadPath = extractEntryPath(facts, ['upload', 'unsafeupload', 'file']);
			const uploadUrl = uploadPath ? joinUrl(origin, uploadPath) : `${targetUrl}/upload.php`;
			finding = await verifyUpload(uploadUrl, tech, o.seedId);
		} else if (intent.intentType === 'verify_ssrf') {
			const ssrfPath = extractEntryPath(facts, ['ssrf']);
			const ssrfUrl = ssrfPath ? joinUrl(origin, ssrfPath) : targetUrl;
			finding = await verifySsrf(ssrfUrl, o.seedId);
		} else if (intent.intentType === 'verify_deser') {
			const deserPath = extractEntryPath(facts, ['unser', 'deserial', '反序列化']);
			const deserUrl = deserPath ? joinUrl(origin, deserPath) : `${targetUrl}/unser.php`;
			finding = await verifyDeserialization(deserUrl, o.seedId);
		}

		if (finding) {
			const after = (await findStore.listFindings({ seedId: o.seedId })).length;
			if (after > before) {
				log(o, `  → 确定性验证命中: ${finding.vulnName} @ ${finding.url.slice(0, 60)}`);
				await store.logActivity(
					o.seedId,
					'finding_deterministic',
					`确定性验证补挖: ${finding.vulnName}`,
					{
						intentId: intent.id,
						url: finding.url,
					},
				);
			}
		}
	} catch (err) {
		log(o, `  → 确定性验证异常: ${err instanceof Error ? err.message : String(err).slice(0, 80)}`);
	}
}

/** 从 coverage facts 提取具体入口相对路径（如 unsafeupload/clientcheck.php） */
function extractEntryPath(
	facts: Array<{ factType: string; summary: string }>,
	keywords: string[],
): string | null {
	for (const f of facts) {
		if (f.factType !== 'endpoint') continue;
		// facts summary 形如「[file-handling] ... 入口：unsafeupload/clientcheck.php(前端...)」
		const entryMatch = f.summary.match(
			/入口[：:]\s*([^\s(，,]+(?:\.php|\.jsp|\.aspx|\.action|\.do)[^\s(，,]*)/i,
		);
		if (entryMatch) {
			const path = entryMatch[1]!.replace(/[)）].*$/, '');
			if (keywords.some((k) => path.toLowerCase().includes(k))) return path;
		}
	}
	// 兜底：找含关键词的路径
	for (const f of facts) {
		const m = f.summary.match(/([a-z0-9/_.-]+\.(?:php|jsp|aspx|action|do))/i);
		if (m && keywords.some((k) => m[1]!.toLowerCase().includes(k))) return m[1];
	}
	return null;
}

/** 相对路径拼 origin */
function joinUrl(origin: string, path: string): string {
	if (/^https?:\/\//i.test(path)) return path;
	const p = path.startsWith('/') ? path : `/${path}`;
	return `${origin}${p}`;
}
