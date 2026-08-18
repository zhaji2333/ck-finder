#!/usr/bin/env node
/**
 * ck-finder 统一 CLI 入口（合并后）
 *
 * 用法:
 *   ck-finder run --target <域名|URL> --scope "example.com,*.example.com" [--goal "自然语言目标"]
 *   ck-finder doctor                        # 环境自检（Node / Key / PG / Redis / 工具链）
 *   ck-finder server [--mcp]                # 启动 REST(8787) + Web 控制台（可选 --mcp :8788）
 *   ck-finder recon                         # 收集引擎自检（PG/Redis + 数据概览）
 *   ck-finder migrate [--status]            # 数据库迁移
 *   ck-finder scan/score/deep-scan/...      # 收集引擎 CLI（原 ck-recon 命令，转发 src/recon/cli）
 *   ck-finder verify --target <ip:port> --scope <范围> [--auth-brute] [--login-url <url>]
 *                                            # M3 确定性漏洞验证（http_req+nuclei+dir_brute+可选弱口令）
 *   ck-finder findings [seedId]             # 查看漏洞 finding
 *   ck-finder health                        # 健康检查
 */
import { checkToolchain } from './doctor.js';
import { runReconCli } from './recon/cli.js';
import { closePg } from './recon/storage/pg.js';
import { closeRedis } from './recon/storage/redis.js';

interface ParsedArgs {
	command: string;
	target: string | undefined;
	scope: string | undefined;
	goal: string | undefined;
	model: string | undefined;
	argv: string[];
}

function parseArgs(argv: string[]): ParsedArgs {
	// 首个非 flag 参数是主命令（query 等带子命令的命令原样转发给 runReconCli）
	const args: ParsedArgs = {
		command: argv[0] ?? '',
		target: undefined,
		scope: undefined,
		goal: undefined,
		model: undefined,
		argv,
	};
	for (let i = 1; i < argv.length; i++) {
		const a = argv[i]!;
		if (a === '--target') args.target = argv[++i];
		else if (a === '--scope') args.scope = argv[++i];
		else if (a === '--goal') args.goal = argv[++i];
		else if (a === '--model') args.model = argv[++i];
	}
	return args;
}

/** 收集引擎自检：PG/Redis 连通 + 数据概览（doctor 的子集，供快速排查） */
async function reconCheck(): Promise<void> {
	const { getConfig } = await import('./recon/config.js');
	const { pgHealthCheck } = await import('./recon/storage/pg.js');
	const { redisHealthCheck } = await import('./recon/storage/redis.js');
	const { querySeeds, queryWebapps } = await import('./recon/storage/models/query.js');
	console.log('[recon] 收集引擎自检');
	try {
		const config = getConfig();
		console.log(`[recon] PG: ${config.db.host}:${config.db.port}/${config.db.database}`);
		console.log(`[recon] Redis: ${config.redis.host}:${config.redis.port}/${config.redis.db}`);
	} catch (err) {
		console.log(`[recon] 配置不可用: ${err instanceof Error ? err.message : String(err)}`);
	}
	try {
		const v = await pgHealthCheck();
		console.log(`[recon] PostgreSQL: OK (${v})`);
	} catch (err) {
		console.log(`[recon] PostgreSQL: MISS (${err instanceof Error ? err.message : String(err)})`);
	}
	try {
		const pong = await redisHealthCheck();
		console.log(`[recon] Redis: OK (${pong})`);
	} catch (err) {
		console.log(`[recon] Redis: MISS (${err instanceof Error ? err.message : String(err)})`);
	}
	// 数据概览
	try {
		const seeds = await querySeeds(5);
		const { total } = await queryWebapps({ scoreGt: 60, limit: 1 });
		console.log(`[recon] 数据: webapps(score>60)>=${total} · 最近任务 ${seeds.length} 个`);
		for (const s of seeds.slice(0, 3)) {
			console.log(
				`  - ${s.seedType} ${s.value} status=${s.status} assets=${s.assetCount} webapps=${s.webappCount}`,
			);
		}
	} catch (err) {
		console.log(`[recon] 数据概览不可用: ${err instanceof Error ? err.message : String(err)}`);
	}
	await Promise.all([closePg(), closeRedis()]);
}

async function main(): Promise<void> {
	const argv = process.argv.slice(2);
	if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
		console.log(`ck-finder - 基于 pi 的渗透 / SRC 挖掘 Agent（含收集引擎，混合架构）

用法:
  ck-finder run --target <域名|URL> --scope "example.com,*.example.com" [--goal "..."]
  ck-finder doctor
  ck-finder server [--mcp]
  ck-finder recon
  ck-finder migrate [--status]
  ck-finder scan|score|deep-scan|metadata|query|fofa|health ...   (收集引擎命令)

选项:
  --target <t>   目标域名或 URL
  --scope <s>    授权范围（逗号分隔：domain / *.domain / ip / cidr）
  --goal <g>     自然语言目标描述（缺省按 target 自动生成）
  --model <id>   模型 id（缺省 deepseek-chat）
`);
		return;
	}

	const args = parseArgs(argv);
	const command = args.command;

	// 收集引擎命令转发（scan/score/deep-scan/sources/metadata/query/fofa/health）
	const reconCommands = new Set([
		'scan',
		'score',
		'deep-scan',
		'source-collect',
		'sources',
		'metadata',
		'query',
		'fofa',
		'health',
	]);
	if (reconCommands.has(command)) {
		try {
			await runReconCli(argv);
		} finally {
			// 转发收集命令后必须关闭连接，否则 ioredis/PG 连接保持导致进程不退出
			await Promise.all([closePg(), closeRedis()]);
		}
		return;
	}

	if (command === 'doctor') {
		await checkToolchain();
		return;
	}

	if (command === 'recon') {
		await reconCheck();
		return;
	}

	if (command === 'migrate') {
		const { runMigrateCli } = await import('./recon/migrate.js');
		await runMigrateCli(argv.slice(1));
		return;
	}

	if (command === 'server') {
		const { startServer } = await import('./recon/api/server.js');
		const enableMcp = argv.includes('--mcp');
		await startServer({ enableMcp });
		return;
	}

	if (command === 'graph') {
		await runGraphCmd(argv.slice(1));
		return;
	}

	if (command === 'verify') {
		await runVerifyCmd(argv.slice(1));
		return;
	}

	if (command === 'findings') {
		await runFindingsCmd(argv.slice(1));
		return;
	}

	if (command === 'review') {
		await runReviewCmd(argv.slice(1));
		return;
	}

	if (command === 'hunt') {
		await runHuntCmd(argv.slice(1));
		return;
	}

	if (command === 'report') {
		await runReportCmd(argv.slice(1));
		return;
	}

	if (command === 'queue') {
		await runQueueCmd(argv.slice(1));
		return;
	}

	if (command === 'killsweep') {
		await runKillsweepCmd();
		return;
	}

	if (command !== 'run') {
		throw new Error(
			`未知命令: ${command}（支持 run / doctor / server / recon / migrate / graph / verify / findings / scan 等）`,
		);
	}

	// ---- M2 run：目标 → 收集 → planner → worker → 探索图 ----
	const { getConfig } = await import('./recon/config.js');
	const config = getConfig();
	const scope = args.scope
		? args.scope
				.split(',')
				.map((s) => s.trim())
				.filter((s) => s.length > 0)
		: [...config.agent.scope];
	const target = args.target;
	if (!target) {
		throw new Error('缺少 --target（M2 编排需要目标种子）');
	}

	// 进程内提交种子 → seedId
	const { normalizeSeed } = await import('./recon/seeds/normalizer.js');
	const { upsertSeed } = await import('./recon/storage/models/asset.js');
	const normalized = normalizeSeed(target);
	const seedId = await upsertSeed(normalized);

	console.log(`[ck-finder] 目标: ${target}`);
	console.log(`[ck-finder] 种子: ${seedId} (${normalized.seedType})`);
	console.log(
		`[ck-finder] 范围: ${scope.length > 0 ? scope.join(', ') : '(未设置，web_fetch 将被拒绝)'}`,
	);
	console.log(`[ck-finder] 模型: ${args.model ?? config.agent.model}`);
	console.log(
		`[ck-finder] LLM: ${config.llm.apiKey ? 'enabled' : 'disabled（未配 key，planner 跳过，worker 不派发）'}`,
	);

	const { runCampaign } = await import('./controller.js');
	try {
		const result = await runCampaign({
			seedId,
			scope,
			modelId: args.model ?? config.agent.model,
			llmEnabled: Boolean(config.llm.apiKey),
		});
		// 输出最终图摘要
		const { ExplorationStore } = await import('./graph/store.js');
		const store = new ExplorationStore();
		const intents = await store.listIntents(seedId);
		const facts = await store.listFacts(seedId);
		console.log('\n[ck-finder] ═══ 探索图摘要 ═══');
		for (const i of intents) {
			console.log(`  [${i.status}] #${i.intentType} ${i.description.slice(0, 90)}`);
		}
		console.log(`\n  事实 ${facts.length} 条:`);
		for (const f of facts.slice(0, 20)) {
			console.log(`    (${f.factType}) ${f.summary.slice(0, 90)}`);
		}
		console.log(
			`\n  campaign: 意图 ${result.intentsCreated} / done ${result.intentsDone} / 事实 ${result.factsCollected} / 轮次 ${result.rounds}${result.converged ? '（收敛）' : ''}`,
		);
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/** graph 命令：查看探索图（intents / facts） */
async function runGraphCmd(args: string[]): Promise<void> {
	const { ExplorationStore } = await import('./graph/store.js');
	const store = new ExplorationStore();
	try {
		if (args[0]) {
			// 指定 seedId
			const seedId = args[0];
			const intents = await store.listIntents(seedId);
			const facts = await store.listFacts(seedId);
			const activities = await store.listActivities(seedId);
			console.log(`[graph] seed ${seedId}`);
			console.log(`意图 ${intents.length} 条:`);
			for (const i of intents) {
				console.log(
					`  [${i.status}] #${i.intentType} ${i.description.slice(0, 80)}${i.assetId ? ` (asset=${i.assetId.slice(0, 8)})` : ''}`,
				);
			}
			console.log(`事实 ${facts.length} 条:`);
			for (const f of facts) {
				console.log(`  (${f.factType}) ${f.summary.slice(0, 80)}`);
			}
			console.log(`活动（最近 ${activities.length}）:`);
			for (const a of activities.slice(0, 10)) {
				console.log(`  [${a.activityType}] ${a.message.slice(0, 80)}`);
			}
		} else {
			// 列出最近 seed
			const { querySeeds } = await import('./recon/storage/models/query.js');
			const seeds = await querySeeds(10);
			console.log('[graph] 最近任务（ck-finder graph <seedId> 查看详情）:');
			for (const s of seeds) {
				const unfinished = await store.countUnfinished(s.id);
				console.log(
					`  ${s.id}  ${s.seedType} ${s.value}  status=${s.status}  未完成意图=${unfinished}`,
				);
			}
		}
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/**
 * verify 命令：确定性漏洞验证（M3，不走 LLM）
 * ck-finder verify --target <ip[:port][,ip:port...]> --scope <范围> [--auth-brute] [--login-url <url>]
 */
async function runVerifyCmd(args: string[]): Promise<void> {
	let targets: string[] = [];
	let scope: string[] = [];
	let authBrute = false;
	let loginUrl: string | undefined;

	for (let i = 0; i < args.length; i++) {
		const a = args[i]!;
		if (a === '--target') {
			const v = args[++i];
			if (v)
				targets = v
					.split(',')
					.map((s) => s.trim())
					.filter(Boolean);
		} else if (a === '--scope') {
			const v = args[++i];
			if (v)
				scope = v
					.split(',')
					.map((s) => s.trim())
					.filter(Boolean);
		} else if (a === '--auth-brute') {
			authBrute = true;
		} else if (a === '--login-url') {
			loginUrl = args[++i];
		}
	}

	if (targets.length === 0) {
		throw new Error(
			'缺少 --target（逗号分隔的 ip[:port] 列表，如 192.0.2.10:8080,192.0.2.10:8082）',
		);
	}
	const { getConfig } = await import('./recon/config.js');
	const config = getConfig();
	if (scope.length === 0) scope = [...config.agent.scope];
	if (scope.length === 0) {
		console.warn('[verify] 警告: 未设置授权范围，所有网络工具将被拒绝');
	}

	// 创建种子记录（复用收集引擎 seeds 表）
	const { normalizeSeed } = await import('./recon/seeds/normalizer.js');
	const { upsertSeed } = await import('./recon/storage/models/asset.js');
	const seedInput = targets[0]?.includes(':') ? targets[0]! : targets[0]!;
	const normalized = normalizeSeed(seedInput);
	const seedId = await upsertSeed(normalized);

	console.log(`[verify] 种子: ${seedId} (${normalized.seedType})`);
	console.log(`[verify] 范围: ${scope.join(', ')}`);
	console.log(`[verify] 目标: ${targets.join(', ')}`);
	console.log(
		`[verify] 弱口令: ${authBrute ? 'ON' : 'off'}${loginUrl ? ` (登录接口 ${loginUrl})` : ''}`,
	);

	const { runVerify } = await import('./verify.js');
	try {
		await runVerify({ targets, scope, authBrute, loginUrl, seedId });
		console.log(`\n[verify] 完成。查看结果: ck-finder findings ${seedId}`);
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/** findings 命令：查看漏洞 finding */
async function runFindingsCmd(args: string[]): Promise<void> {
	const { FindingStore } = await import('./validation/finding_store.js');
	const store = new FindingStore();
	try {
		const seedId = args[0];
		const { querySeeds } = await import('./recon/storage/models/query.js');
		if (!seedId) {
			// 列出有 finding 的种子
			const seeds = await querySeeds(20);
			console.log('[findings] 最近任务:');
			for (const s of seeds) {
				const counts = await store.countByStatus(s.id);
				const total = Object.values(counts).reduce((a, b) => a + b, 0);
				if (total > 0) {
					console.log(`  ${s.id}  ${s.value}  findings=${total} ${JSON.stringify(counts)}`);
				}
			}
			return;
		}
		const findings = await store.listFindings({ seedId });
		console.log(`[findings] seed ${seedId} 共 ${findings.length} 条:`);
		for (const f of findings) {
			console.log(`  [${f.severity}/${f.status}] ${f.vulnName} @ ${f.url}`);
			console.log(`      ${f.summary.slice(0, 120)}`);
		}
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/**
 * review 命令：M4 复审（AI 初审 / 人工裁决）
 * ck-finder review                      # 待审队列 + AI 初审
 * ck-finder review pending|reviewed|confirmed|dismissed   # 查看各状态
 * ck-finder review --id <findingId>     # 单条详情
 * ck-finder review --approve <id>       # 人工通过
 * ck-finder review --decline <id>       # 人工驳回
 * ck-finder review --deepen <id> --directive "指令"
 */
async function runReviewCmd(args: string[]): Promise<void> {
	const { FindingStore } = await import('./validation/finding_store.js');
	const { ReviewStore } = await import('./validation/review_store.js');
	const { listPendingReviews } = await import('./agents/reviewer.js');

	let action = 'list';
	let findingId: string | undefined;
	let directive = '';
	for (let i = 0; i < args.length; i++) {
		const a = args[i]!;
		if (a === '--id') findingId = args[++i];
		else if (a === '--approve') {
			action = 'approve';
			findingId = args[++i];
		} else if (a === '--decline') {
			action = 'decline';
			findingId = args[++i];
		} else if (a === '--deepen') {
			action = 'deepen';
			findingId = args[++i];
		} else if (a === '--directive') directive = args[++i];
		else if (['pending', 'reviewed', 'confirmed', 'dismissed'].includes(a)) action = a;
	}

	const store = new FindingStore();
	try {
		// 前缀解析辅助：uuid 前缀 → 完整 id
		const resolveId = async (prefix: string): Promise<string> => {
			if (prefix.includes('-') && prefix.length === 36) return prefix;
			const f = await store.getFindingByPrefix(prefix);
			if (!f) throw new Error(`finding 不存在: ${prefix}`);
			return f.id;
		};

		// 人工裁决
		if (action === 'approve' && findingId) {
			const full = await resolveId(findingId);
			await store.updateReviewStatus(full, 'confirmed');
			console.log(`[review] finding ${full} 已通过（confirmed）`);
			return;
		}
		if (action === 'decline' && findingId) {
			const full = await resolveId(findingId);
			await store.updateReviewStatus(full, 'dismissed');
			console.log(`[review] finding ${full} 已驳回（dismissed）`);
			return;
		}
		if (action === 'deepen' && findingId) {
			if (!directive) throw new Error('--deepen 需要 --directive');
			const full = await resolveId(findingId);
			const count = await store.setDeepen(full, directive);
			await store.updateReviewStatus(full, 'reviewed');
			console.log(`[review] finding ${full} 打回深挖（第 ${count} 次）: ${directive}`);
			return;
		}

		// 详情
		if (findingId) {
			const full = await resolveId(findingId);
			const f = await store.getFinding(full);
			if (!f) throw new Error('finding not found');
			const reviewStore = new ReviewStore();
			const reviews = await reviewStore.listReviewsByFinding(full);
			console.log(`[review] ${f.vulnName} [${f.severity}/${f.reviewStatus}] @ ${f.url}`);
			console.log(`  summary: ${f.summary}`);
			console.log(`  poc: ${f.evidence.poc.slice(0, 300)}`);
			if (reviews.length > 0) {
				console.log('  复审记录:');
				for (const r of reviews) {
					console.log(
						`    [${r.verdict}]${r.reproduced ? ' 系统复现✓' : ''} ${r.score}分 ${r.reasoning.slice(0, 200)}`,
					);
				}
			}
			return;
		}

		// 队列列表
		const findings =
			action === 'list'
				? await listPendingReviews()
				: await store.listFindings({ reviewStatus: action as never, limit: 50 });
		console.log(`[review] 队列 ${action === 'list' ? '待审' : action}（${findings.length} 条）:`);
		for (const f of findings) {
			console.log(
				`  [${f.severity}] ${f.reviewStatus} ${f.vulnName} @ ${f.url} (${f.id.slice(0, 8)})`,
			);
		}
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/**
 * hunt 命令：直接打目标挖洞（AutoHunter 模式：免收集 + 并发 + 凭据注入）
 * ck-finder hunt --targets "http://192.0.2.10:8080,http://192.0.2.10:8082/login.html" [--concurrency 4]
 */
async function runHuntCmd(args: string[]): Promise<void> {
	let targetsStr = '';
	let concurrency = 4;
	let queue = false;
	for (let i = 0; i < args.length; i++) {
		const a = args[i]!;
		if (a === '--targets') targetsStr = args[++i] ?? '';
		else if (a === '--concurrency') concurrency = Number.parseInt(args[++i] ?? '4', 10);
		else if (a === '--queue') queue = true;
	}
	if (!targetsStr) {
		throw new Error('缺少 --targets（逗号分隔的目标 URL 列表）');
	}
	const targets = targetsStr
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean)
		.map((url) => ({ url }));

	console.log(
		`[hunt] 目标 ${targets.length} 个 · 并发 ${concurrency} · 凭据来自 CKFINDER_HUNT_CREDENTIALS`,
	);
	try {
		if (queue) {
			// M5：入队 + 调度（7×24 挂机，持久化 + 崩溃恢复）
			const { HuntQueue, runQueue } = await import('./queue.js');
			const q = new HuntQueue();
			const ids = await q.enqueue(targets, { maxIntents: 20, maxRounds: 3 });
			console.log(`[hunt] 已入队 ${ids.length} 个任务，启动调度循环`);
			await runQueue(concurrency);
		} else {
			// 直接并发（一次性，不入队）
			const startAt = Date.now();
			const { runDirectHunt } = await import('./hunt.js');
			await runDirectHunt({ targets, concurrency });
			const duration = Math.round((Date.now() - startAt) / 1000);
			console.log(`\n[hunt] 完成，耗时 ${Math.floor(duration / 60)}分${duration % 60}秒`);
			console.log('[hunt] 查看结果: ck-finder findings <seedId> 或 ck-finder review');
		}
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/** 队列状态查看 + worker 循环（7×24 挂机入口） */
async function runQueueCmd(args: string[]): Promise<void> {
	const { HuntQueue, runQueue } = await import('./queue.js');
	const q = new HuntQueue();
	try {
		if (args[0] === 'status' || args[0] === 'list') {
			const stats = await q.stats();
			console.log('[queue] 任务状态:', JSON.stringify(stats));
			const tasks = await q.list(20);
			for (const t of tasks) {
				console.log(
					`  [${t.status}] ${t.id.slice(0, 8)} ${t.targetUrl.slice(0, 50)} retry=${t.retryCount}`,
				);
			}
			return;
		}
		// 默认：启动 worker 循环（7×24 长驻轮询）
		const concurrency = Number.parseInt(args[1] ?? '4', 10);
		await runQueue(concurrency, true);
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/**
 * killsweep 命令：对 confirmed 漏洞分析同款产品 + fofa 圈定同款站点
 */
async function runKillsweepCmd(): Promise<void> {
	const { runKillsweepBatch } = await import('./agents/killsweep.js');
	try {
		const results = await runKillsweepBatch(20);
		console.log(`[killsweep] 分析 ${results.length} 条 confirmed 漏洞:`);
		for (const r of results) {
			console.log(`  [${r.isGenericProduct ? '通杀' : '单品'}] ${r.productName}`);
			console.log(`    fofa: ${r.fofaQuery}`);
			if (r.verifiedUrls.length > 0) {
				console.log(
					`    同款站点 ${r.verifiedUrls.length} 个: ${r.verifiedUrls.slice(0, 5).join(', ')}`,
				);
			} else {
				console.log(`    （无 FOFA 或未发现同款站点）`);
			}
		}
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

/**
 * report 命令：导出 Markdown 漏洞报告（含复现 POC）
 * ck-finder report [seedId] [--out path.md] [--all]
 */
async function runReportCmd(args: string[]): Promise<void> {
	const { FindingStore } = await import('./validation/finding_store.js');
	const { exportReport } = await import('./validation/report.js');
	const { querySeeds } = await import('./recon/storage/models/query.js');

	let seedId: string | undefined;
	let outPath = 'reports/ck-finder-report.md';
	let all = false;
	for (let i = 0; i < args.length; i++) {
		const a = args[i]!;
		if (a === '--out') outPath = args[++i] ?? outPath;
		else if (a === '--all') all = true;
		else if (!a.startsWith('--')) seedId = a;
	}

	const store = new FindingStore();
	try {
		let findings;
		if (all) {
			// 全部 confirmed + reviewed 的 finding
			findings = [
				...(await store.listFindings({ reviewStatus: 'confirmed' })),
				...(await store.listFindings({ reviewStatus: 'reviewed' })),
			];
		} else if (seedId) {
			findings = await store.listFindings({ seedId });
		} else {
			// 默认：最近 seed 的全部 finding
			const seeds = await querySeeds(1);
			findings = seeds.length > 0 ? await store.listFindings({ seedId: seeds[0]!.id }) : [];
		}
		// 去重（按 id）
		const byId = new Map(findings.map((f) => [f.id, f]));
		const deduped = [...byId.values()];

		if (deduped.length === 0) {
			console.log('[report] 无 finding 可导出');
			return;
		}
		await exportReport(deduped, outPath);
		console.log(`[report] 已导出 ${deduped.length} 条 finding → ${outPath}`);
	} finally {
		await Promise.all([closePg(), closeRedis()]);
	}
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error);
	console.error(`[ck-finder] 失败: ${message}`);
	process.exitCode = 1;
});
