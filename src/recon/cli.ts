/**
 * ck-recon CLI 入口（合并后：作为 ck-finder 的收集命令子集，由 src/index.ts 转发）
 *
 * 用法：
 *   ck-finder scan <seed>            # 执行完整扫描管道（含评分）
 *   ck-finder score <seedId>         # 给已扫描的 webapp 重跑评分
 *   ck-finder deep-scan <webappId>   # 对单个 webapp 跑 M3 深度扫描
 *   ck-finder metadata <webappId>    # 输出 webapp metadata 快照
 *   ck-finder query assets <seedId>  # 查询资产图
 *   ck-finder query webapps          # 查询 webapps（含评分）
 *   ck-finder query endpoints <webappId>  # 查询端点
 *   ck-finder query findings <webappId>   # 查询发现
 *   ck-finder query audit <action>   # 查询审计日志
 *   ck-finder health                 # 健康检查
 */

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { queryAuditLog } from './gate/audit_log.js';
import { runRecon } from './pipeline/runner.js';
import { closePg, pgHealthCheck } from './storage/pg.js';
import { getPg } from './storage/pg.js';
import { closeRedis, redisHealthCheck } from './storage/redis.js';

/** 判断是否为直接运行入口（tsx 下 argv[1] 可能是 symlink，需归一化比较） */
function isMainEntry(): boolean {
	const entry = process.argv[1];
	if (!entry) return false;
	try {
		return import.meta.url === pathToFileURL(resolve(entry)).href;
	} catch {
		return false;
	}
}

export async function runReconCli(argv: string[]): Promise<void> {
	const [cmd, ...rest] = argv;

	switch (cmd) {
		case 'scan':
			return await cmdScan(rest);
		case 'score':
			return await cmdScore(rest);
		case 'deep-scan':
			return await cmdDeepScan(rest);
		case 'source-collect':
			return await cmdSourceCollect(rest);
		case 'sources':
			return await cmdSources(rest);
		case 'metadata':
			return await cmdMetadata(rest);
		case 'query':
			return await cmdQuery(rest);
		case 'fofa':
			return await cmdFofa(rest);
		case 'health':
			return await cmdHealth();
		default:
			printHelp();
			process.exit(1);
	}
}

async function cmdScan(args: string[]): Promise<void> {
	if (args.length === 0) {
		console.error(
			'Usage: cli scan <seed> [--mode auto|site|full] [--skip-nmap] [--skip-httpx] [--max-subdomains N]',
		);
		process.exit(1);
	}
	const seed = args[0];
	const flags = parseFlags(args.slice(1));

	// 模式：auto（默认，URL→单站）/ site（强制单站）/ full（强制全量）
	const mode = flags.mode;
	if (mode && !['auto', 'site', 'full'].includes(mode)) {
		console.error(`[cli] invalid --mode "${mode}": must be auto|site|full`);
		process.exit(1);
	}

	console.log(`[cli] starting recon for: ${seed}${mode ? ` (mode=${mode})` : ' (mode=auto)'}`);
	const result = await runRecon(seed, {
		mode: (mode as 'auto' | 'site' | 'full') ?? 'auto',
		skipNmap: flags['skip-nmap'] === 'true',
		skipHttpx: flags['skip-httpx'] === 'true',
		skipSubfinder: flags['skip-subfinder'] === 'true',
		skipOneForAll: flags['skip-oneforall'] === 'true',
		oneforallBrute: flags['oneforall-brute'] ? flags['oneforall-brute'] !== 'false' : undefined,
		skipScoring: flags['skip-scoring'] === 'true',
		skipLlm: flags['skip-llm'] === 'true',
		maxSubdomains: flags['max-subdomains'] ? Number.parseInt(flags['max-subdomains'], 10) : 1000,
		maxCompanyDomains: flags['max-company-domains']
			? Number.parseInt(flags['max-company-domains'], 10)
			: 50,
		companyDomainConcurrency: flags.concurrency ? Number.parseInt(flags.concurrency, 10) : 3,
		nmapPorts: flags.ports,
		portScanner: flags['port-scanner'] === 'masscan' ? 'masscan' : 'nmap',
		masscanRate: flags['masscan-rate'] ? Number.parseInt(flags['masscan-rate'], 10) : 5000,
		useFofa: flags['use-fofa'] === 'true',
		// site 模式专属
		skipCrawl: flags['skip-crawl'] === 'true',
		skipDirscan: flags['skip-dirscan'] === 'true',
		skipSourceCollect: flags['skip-source-collect'] === 'true',
		maxJsFiles: flags['max-js-files'] ? Number.parseInt(flags['max-js-files'], 10) : 50,
		maxMapFiles: flags['max-map-files'] ? Number.parseInt(flags['max-map-files'], 10) : 50,
	});

	console.log('\n[cli] recon completed:');
	const { site: _site, ...resultSummary } = result;
	console.log(JSON.stringify(resultSummary, null, 2));
	console.log(`\n[cli] seed_id: ${result.seedId}`);
	console.log(`[cli] query with: cli query assets ${result.seedId}`);
	console.log(`[cli] score with: cli score ${result.seedId}`);
	console.log(`[cli] deep-scan with: cli deep-scan ${result.seedId}`);

	// 单站模式：打印站点元数据摘要 + 完整 snapshot
	if (result.site) {
		const s = result.site;
		console.log('\n[cli] === 单站元数据 (site mode) ===');
		console.log(`  url: ${s.url}`);
		if (s.finalUrl && s.finalUrl !== s.url) console.log(`  final_url: ${s.finalUrl}`);
		console.log(`  title: ${s.title ?? '-'}`);
		console.log(`  status: ${s.statusCode ?? '-'}  webserver: ${s.webserver ?? '-'}`);
		console.log(`  tech: [${s.tech.join(', ')}]  fingerprints: [${s.fingerprints.join(', ')}]`);
		console.log(`  框架 framework: [${s.framework.join(', ') || '-'}]`);
		console.log(`  语言 language: [${s.language.join(', ') || '-'}]`);
		console.log(`  构建工具 build_tool: [${s.buildTool.join(', ') || '-'}]`);
		console.log(`  架构 architecture: ${s.architecture ?? '-'}`);
		console.log(
			`  webpack: ${s.webpackDetected}  sourcemap: ${s.sourceAvailable}  restored: ${s.restoredFiles}`,
		);
		console.log(`  JS 文件: ${s.jsFiles.length} (downloaded=${s.jsDownloaded})`);
		console.log(
			`  js_apis: ${s.jsApiCount}  endpoints: ${s.endpointCount}  params: ${s.paramCount}  secrets: ${s.secretCount}`,
		);
		console.log(`  score: ${s.score ?? '-'}  role: ${s.role ?? '-'}`);
		if (s.webappId) {
			console.log(`\n[cli] webapp_id: ${s.webappId}`);
			console.log(`[cli] 完整元数据快照: cli metadata ${s.webappId}`);
			console.log(`[cli] REST: GET /api/v1/assets/${s.webappId}/metadata`);
			console.log(`[cli] MCP: get_asset_metadata asset_id=${s.webappId}`);
		}
		if (s.snapshot) {
			console.log('\n[cli] metadata snapshot:');
			console.log(JSON.stringify(s.snapshot, null, 2));
		}
	}

	// 可选：扫描完成后立即跑深度扫描
	if (flags['deep-scan'] === 'true' && result.webappCount > 0) {
		console.log(`\n[cli] starting deep scan for seed ${result.seedId}...`);
		const { deepScanBySeed } = await import('./pipeline/deep_scan.js');
		const dsResults = await deepScanBySeed(result.seedId, {
			maxJsFiles: flags['max-js-files'] ? Number.parseInt(flags['max-js-files'], 10) : 50,
			maxHistoryUrls: flags['max-history-urls']
				? Number.parseInt(flags['max-history-urls'], 10)
				: 2000,
		});
		console.log(`[cli] deep scan: ${dsResults.length} webapps processed`);
	}
}

async function cmdScore(args: string[]): Promise<void> {
	if (args.length === 0) {
		console.error('Usage: cli score <seedId> [--skip-llm]');
		process.exit(1);
	}
	const seedId = args[0];
	const flags = parseFlags(args.slice(1));
	const { scoreBySeed } = await import('./scoring/pipeline.js');
	const results = await scoreBySeed(seedId, { skipLlm: flags['skip-llm'] === 'true' });
	console.log(`\n[score] ${results.length} webapps scored:`);
	for (const r of results) {
		const cveList =
			r.vulnHints.length > 0 ? ` cve=[${r.vulnHints.map((h) => h.cve).join(',')}]` : '';
		console.log(
			`  [${r.level}] score=${r.score}  role=${r.role}(${r.roleSource},${r.roleConfidence.toFixed(2)})  ${r.url}${cveList}`,
		);
	}
}

async function cmdMetadata(args: string[]): Promise<void> {
	if (args.length === 0) {
		console.error('Usage: cli metadata <webappId> [--save]');
		process.exit(1);
	}
	const webappId = args[0];
	const flags = parseFlags(args.slice(1));
	const { generateSnapshot, generateAndSaveSnapshot } = await import('./scoring/snapshot.js');
	const snapshot =
		flags.save === 'true'
			? await generateAndSaveSnapshot(webappId)
			: await generateSnapshot(webappId);
	console.log(JSON.stringify(snapshot, null, 2));
}

async function cmdDeepScan(args: string[]): Promise<void> {
	if (args.length === 0) {
		console.error(
			'Usage: cli deep-scan <webappId|seedId> [--force] [--skip-task <name>] [--max-js-files N] [--max-history-urls N]',
		);
		console.error(
			'  如果传入 seedId（UUID 格式但不是 webapp），会对该 seed 下所有 webapp 跑深度扫描',
		);
		process.exit(1);
	}
	const target = args[0];
	const flags = parseFlags(args.slice(1));

	const { deepScanWebapp, deepScanBySeed } = await import('./pipeline/deep_scan.js');

	// 先尝试当 webappId 处理
	const pool = getPg();
	const { rows } = await pool.query('SELECT asset_id FROM webapps WHERE asset_id = $1', [target]);

	if (rows.length > 0) {
		// 单个 webapp 深度扫描
		console.log(`[deep-scan] starting for webapp: ${target}`);
		const skipTasks = flags['skip-task'] ? [flags['skip-task']] : [];
		const result = await deepScanWebapp(target, {
			force: flags.force === 'true',
			skipTasks: skipTasks as never[],
			maxJsFiles: flags['max-js-files'] ? Number.parseInt(flags['max-js-files'], 10) : 50,
			maxHistoryUrls: flags['max-history-urls']
				? Number.parseInt(flags['max-history-urls'], 10)
				: 2000,
		});
		console.log('\n[deep-scan] completed:');
		console.log(
			JSON.stringify(
				{
					webappId: result.webappId,
					url: result.url,
					ranTasks: result.ranTasks,
					skippedTasks: result.skippedTasks,
					failedTasks: result.failedTasks,
					summaries: result.summaries,
				},
				null,
				2,
			),
		);
	} else {
		// 当 seedId 处理
		console.log(`[deep-scan] starting for seed: ${target} (batch mode)`);
		const results = await deepScanBySeed(target, {
			force: flags.force === 'true',
			maxJsFiles: flags['max-js-files'] ? Number.parseInt(flags['max-js-files'], 10) : 50,
			maxHistoryUrls: flags['max-history-urls']
				? Number.parseInt(flags['max-history-urls'], 10)
				: 2000,
		});
		console.log(`\n[deep-scan] ${results.length} webapps processed:`);
		for (const r of results) {
			console.log(
				`  ${r.url}  ran=${r.ranTasks.length}  skipped=${r.skippedTasks.length}  failed=${r.failedTasks.length}`,
			);
		}
	}
}

async function cmdQuery(args: string[]): Promise<void> {
	const [subCmd, ...rest] = args;
	const pool = getPg();

	switch (subCmd) {
		case 'assets': {
			const seedId = rest[0];
			if (!seedId) {
				console.error('Usage: cli query assets <seedId>');
				process.exit(1);
			}
			const { rows } = await pool.query(
				`SELECT id, type, value, value_norm, parent_id, discovered_by, first_seen, last_seen, alive
         FROM assets WHERE seed_id = $1 ORDER BY type, first_seen`,
				[seedId],
			);
			console.log(`[query] ${rows.length} assets for seed ${seedId}:`);
			for (const r of rows) {
				console.log(
					`  [${r.type}] ${r.value_norm}  by=${r.discovered_by}  alive=${r.alive ?? '-'}  parent=${r.parent_id ?? '-'}`,
				);
			}
			break;
		}
		case 'webapps': {
			const { rows } = await pool.query(
				`SELECT w.url, w.title, w.status_code, w.tech, w.host, w.port, w.webserver, w.cdn, w.waf, w.role, w.score, w.meta, w.fingerprints
         FROM webapps w
         ORDER BY w.score DESC, w.last_seen DESC LIMIT 100`,
			);
			console.log(`[query] ${rows.length} webapps (sorted by score desc):`);
			for (const r of rows) {
				const meta = r.meta ?? {};
				const cdnTag = r.cdn ? `cdn=${meta.cdn_name ?? 'yes'}` : '';
				const wafTag = r.waf ? `waf=${r.waf}` : '';
				const fpTag =
					(r.fingerprints?.length ?? 0) > 0 ? `fp={${r.fingerprints.slice(0, 3).join(',')}}` : '';
				const levelTag = meta.task_level ? `[${meta.task_level}]` : '';
				console.log(
					`  ${levelTag} score=${r.score ?? 0}  role=${r.role ?? 'unknown'}  [${r.status_code ?? '?'}] ${r.url}  title="${r.title ?? ''}"  tech={${(r.tech ?? []).join(',')}}  ${fpTag}  ${cdnTag}  ${wafTag}`
						.replace(/\s+/g, ' ')
						.trim(),
				);
			}
			break;
		}
		case 'audit': {
			const action = rest[0];
			const rows = await queryAuditLog({ action, limit: 50 });
			console.log(`[query] ${rows.length} audit log entries:`);
			for (const r of rows) {
				console.log(
					`  ${r.ts.toISOString()} [${r.decision}] ${r.actor} ${r.action} ${r.target ?? ''} ${r.reason ?? ''}`,
				);
			}
			break;
		}
		case 'seeds': {
			const { rows } = await pool.query(
				'SELECT id, seed_type, value, status, created_at FROM seeds ORDER BY created_at DESC LIMIT 20',
			);
			console.log(`[query] ${rows.length} seeds:`);
			for (const r of rows) {
				console.log(`  ${r.id}  [${r.seed_type}] ${r.value}  status=${r.status}`);
			}
			break;
		}
		case 'endpoints': {
			const webappId = rest[0];
			if (!webappId) {
				console.error('Usage: cli query endpoints <webappId>');
				process.exit(1);
			}
			const { rows } = await pool.query(
				`SELECT url, path, method, source, status_code, discovered_at
         FROM endpoints WHERE webapp_id = $1
         ORDER BY discovered_at DESC LIMIT 200`,
				[webappId],
			);
			console.log(`[query] ${rows.length} endpoints for webapp ${webappId}:`);
			for (const r of rows) {
				console.log(
					`  [${r.source}] [${r.method}] [${r.status_code ?? '?'}] ${r.path}  url=${r.url}`,
				);
			}
			break;
		}
		case 'jsapis': {
			const webappId = rest[0];
			if (!webappId) {
				console.error('Usage: cli query jsapis <webappId>');
				process.exit(1);
			}
			const { rows } = await pool.query(
				`SELECT api_path, method, params, source_js, found_at
         FROM js_apis WHERE webapp_id = $1
         ORDER BY found_at DESC LIMIT 200`,
				[webappId],
			);
			console.log(`[query] ${rows.length} js_apis for webapp ${webappId}:`);
			for (const r of rows) {
				const paramsTag = (r.params?.length ?? 0) > 0 ? `params={${r.params.join(',')}}` : '';
				const srcTag = r.source_js ? `src=${r.source_js.split('/').pop()}` : '';
				console.log(`  [${r.method}] ${r.api_path}  ${paramsTag}  ${srcTag}`);
			}
			break;
		}
		case 'params': {
			const webappId = rest[0];
			if (!webappId) {
				console.error('Usage: cli query params <webappId>');
				process.exit(1);
			}
			const { rows } = await pool.query(
				`SELECT param, source, context, discovered_at
         FROM params WHERE webapp_id = $1
         ORDER BY discovered_at DESC LIMIT 200`,
				[webappId],
			);
			console.log(`[query] ${rows.length} params for webapp ${webappId}:`);
			for (const r of rows) {
				console.log(`  [${r.source}] ${r.param}  ctx=${r.context ?? '-'}`);
			}
			break;
		}
		case 'findings': {
			const target = rest[0];
			const severityFilter = rest[1];
			const whereParts: string[] = [];
			const values: unknown[] = [];
			let idx = 1;
			if (target) {
				// target 可以是 webappId 或 assetId
				whereParts.push(`(webapp_id = $${idx} OR asset_id = $${idx})`);
				values.push(target);
				idx++;
			}
			if (severityFilter) {
				whereParts.push(`severity = $${idx++}`);
				values.push(severityFilter);
			}
			const where = whereParts.length > 0 ? `WHERE ${whereParts.join(' AND ')}` : '';
			values.push(200);
			const { rows } = await pool.query(
				`SELECT id, asset_id, webapp_id, type, severity, detail, evidence, source_tool, created_at, meta
         FROM findings ${where}
         ORDER BY created_at DESC LIMIT $${idx}`,
				values,
			);
			console.log(`[query] ${rows.length} findings:`);
			for (const r of rows) {
				console.log(
					`  [${r.severity}] [${r.type}] ${r.detail.slice(0, 100)}  src=${r.source_tool}  at=${r.created_at?.toISOString()}`,
				);
			}
			break;
		}
		default:
			console.error(
				'Usage: cli query <assets|webapps|endpoints|jsapis|params|findings|audit|seeds> [args]',
			);
			process.exit(1);
	}
}

async function cmdSourceCollect(args: string[]): Promise<void> {
	if (args.length === 0) {
		console.error('Usage: cli source-collect <webappId> [--force] [--max-js-files N]');
		process.exit(1);
	}
	const webappId = args[0];
	const flags = parseFlags(args.slice(1));

	// 查 webapp 信息
	const pool = getPg();
	const { rows } = await pool.query('SELECT asset_id, url FROM webapps WHERE asset_id = $1', [
		webappId,
	]);
	if (rows.length === 0) {
		console.error(`[source-collect] webapp not found: ${webappId}`);
		process.exit(1);
	}

	const url = rows[0].url;
	console.log(`[source-collect] starting for ${url} (${webappId})`);

	const { collectSources } = await import('./pipeline/source_collect.js');
	const result = await collectSources({
		webappId,
		url,
		maxJsFiles: flags['max-js-files'] ? Number.parseInt(flags['max-js-files'], 10) : 100,
		force: flags.force === 'true',
	});

	console.log('\n[source-collect] completed:');
	console.log(
		JSON.stringify(
			{
				webappId: result.webappId,
				url: result.url,
				sourceDir: result.sourceDir,
				sourceAvailable: result.sourceAvailable,
				webpackDetected: result.info.webpackDetected,
				frameworks: result.info.frameworks,
				jsDownloaded: result.jsDownloaded,
				mapDownloaded: result.mapDownloaded,
				restoredFiles: result.restore?.restoredCount ?? 0,
				endpoints: result.endpoints.length,
				secrets: result.secrets.length,
				totalBytes: result.totalBytes,
				durationMs: result.durationMs,
				error: result.error,
			},
			null,
			2,
		),
	);

	if (result.endpoints.length > 0) {
		console.log('\n[source-collect] endpoints extracted:');
		for (const ep of result.endpoints.slice(0, 20)) {
			console.log(`  [${ep.method}] ${ep.path}  src=${ep.sourceJs}`);
		}
		if (result.endpoints.length > 20) {
			console.log(`  ... 还有 ${result.endpoints.length - 20} 条`);
		}
	}

	if (result.secrets.length > 0) {
		console.log('\n[source-collect] secrets extracted:');
		for (const sec of result.secrets.slice(0, 20)) {
			console.log(`  [${sec.type}] ${sec.value}  src=${sec.sourceJs}`);
		}
		if (result.secrets.length > 20) {
			console.log(`  ... 还有 ${result.secrets.length - 20} 条`);
		}
	}
}

async function cmdSources(args: string[]): Promise<void> {
	const [subCmd, ...rest] = args;

	switch (subCmd) {
		case 'list': {
			const { listSourceDumps } = await import('./storage/models/source_dump.js');
			const { records, total } = await listSourceDumps({ limit: 50 });
			console.log(`[sources] ${records.length}/${total} source dumps:`);
			for (const r of records) {
				const sizeMb = (r.sizeBytes / 1024 / 1024).toFixed(2);
				const restoreTag = r.restored ? 'restored' : 'raw';
				const completeTag = r.complete ? 'complete' : 'partial';
				console.log(
					`  ${r.id}  files=${r.fileCount}  size=${sizeMb}MB  ${restoreTag}/${completeTag}  dir=${r.sourceDir}`,
				);
			}
			break;
		}
		case 'show': {
			const webappId = rest[0];
			if (!webappId) {
				console.error('Usage: cli sources show <webappId>');
				process.exit(1);
			}
			const { querySourceDumpsByWebapp } = await import('./storage/models/source_dump.js');
			const records = await querySourceDumpsByWebapp(webappId);
			if (records.length === 0) {
				console.log(`[sources] no source dumps for webapp ${webappId}`);
				process.exit(0);
			}
			console.log(`[sources] ${records.length} source dumps for ${webappId}:`);
			for (const r of records) {
				const sizeMb = (r.sizeBytes / 1024 / 1024).toFixed(2);
				console.log(`  id=${r.id}`);
				console.log(`    dir=${r.sourceDir}`);
				console.log(
					`    files=${r.fileCount}  size=${sizeMb}MB  restored=${r.restored}  complete=${r.complete}`,
				);
				console.log(`    entryPoints=[${r.entryPoints.join(', ')}]`);
				console.log(`    createdAt=${r.createdAt.toISOString()}`);
			}
			break;
		}
		case 'index': {
			const webappId = rest[0];
			if (!webappId) {
				console.error('Usage: cli sources index <webappId>');
				process.exit(1);
			}
			const { querySourceDumpsByWebapp } = await import('./storage/models/source_dump.js');
			const { readFile } = await import('node:fs/promises');
			const { join } = await import('node:path');
			const records = await querySourceDumpsByWebapp(webappId);
			if (records.length === 0) {
				console.log(`[sources] no source dumps for ${webappId}`);
				process.exit(0);
			}
			const indexPath = join(records[0].sourceDir, records[0].indexPath ?? 'INDEX.json');
			try {
				const content = await readFile(indexPath, 'utf8');
				const index = JSON.parse(content);
				console.log(`[sources] INDEX.json for ${webappId}:`);
				console.log(JSON.stringify(index, null, 2));
			} catch (err) {
				console.error(
					`[sources] read INDEX.json failed: ${err instanceof Error ? err.message : err}`,
				);
				process.exit(1);
			}
			break;
		}
		default:
			console.error('Usage: cli sources <list|show|index> [args]');
			console.error('  cli sources list                   List all source dumps');
			console.error('  cli sources show <webappId>        Show source dumps for webapp');
			console.error('  cli sources index <webappId>       Read INDEX.json for webapp');
			process.exit(1);
	}
}

async function cmdHealth(): Promise<void> {
	console.log('[health] PostgreSQL:', await pgHealthCheck());
	console.log('[health] Redis:', await redisHealthCheck());
	const pool = getPg();
	const { rows } = await pool.query('SELECT COUNT(*) AS n FROM assets');
	console.log(`[health] assets in DB: ${rows[0].n}`);
}

async function cmdFofa(args: string[]): Promise<void> {
	const { searchFofaAssets, isFofaEnabled, searchByIconHash } = await import(
		'./adapters/fofa_adapter.js'
	);

	if (!isFofaEnabled()) {
		console.error('[fofa] 未启用：请在 .env 配置 FOFA_EMAIL + FOFA_KEY');
		process.exit(1);
	}

	const [subCmd, ...rest] = args;
	const flags = parseFlags(rest);

	switch (subCmd) {
		case 'search': {
			const query = rest[0];
			if (!query) {
				console.error('Usage: cli fofa search "<fofa-query>" [--max N]');
				console.error('  例: cli fofa search \'domain="baidu.com"\'');
				console.error('  例: cli fofa search \'icon_hash="-247388890"\'');
				process.exit(1);
			}
			const result = await searchFofaAssets({
				query,
				maxResults: flags.max ? Number.parseInt(flags.max, 10) : 100,
			});
			console.log(
				`[fofa] enabled=${result.enabled} total=${result.total} returned=${result.assets.length} fpoint=${result.consumedFpoint ?? 0}`,
			);
			if (result.message) console.log(`[fofa] message: ${result.message}`);
			for (const a of result.assets.slice(0, 50)) {
				const portTag = a.port ? `:${a.port}` : '';
				const protoTag = a.protocol ? `${a.protocol}://` : '';
				const titleTag = a.title ? ` title="${a.title.slice(0, 40)}"` : '';
				const serverTag = a.server ? ` server=${a.server}` : '';
				const iconTag = a.iconHash ? ` icon=${a.iconHash}` : '';
				console.log(`  ${protoTag}${a.host}${portTag}${titleTag}${serverTag}${iconTag}`);
			}
			if (result.assets.length > 50)
				console.log(`  ... 还有 ${result.assets.length - 50} 条未显示`);
			break;
		}
		case 'icon': {
			const hash = rest[0];
			if (!hash) {
				console.error('Usage: cli fofa icon <icon_hash> [--max N]');
				process.exit(1);
			}
			const result = await searchByIconHash(hash, {
				maxResults: flags.max ? Number.parseInt(flags.max, 10) : 100,
			});
			console.log(
				`[fofa] icon_hash="${hash}" total=${result.total} returned=${result.assets.length}`,
			);
			for (const a of result.assets.slice(0, 50)) {
				const portTag = a.port ? `:${a.port}` : '';
				const titleTag = a.title ? ` title="${a.title.slice(0, 40)}"` : '';
				console.log(`  ${a.host}${portTag}${titleTag}`);
			}
			break;
		}
		default:
			console.error('Usage: cli fofa <search|icon> <args> [--max N]');
			console.error('  cli fofa search \'domain="baidu.com"\'  --max 50');
			console.error('  cli fofa icon "-247388890"  --max 100');
			process.exit(1);
	}
}

function parseFlags(args: string[]): Record<string, string> {
	const out: Record<string, string> = {};
	for (let i = 0; i < args.length; i++) {
		const a = args[i];
		if (a.startsWith('--')) {
			const key = a.slice(2);
			const next = args[i + 1];
			if (next && !next.startsWith('--')) {
				out[key] = next;
				i++;
			} else {
				out[key] = 'true';
			}
		}
	}
	return out;
}

function printHelp(): void {
	console.log(`ck-recon CLI

Usage:
  cli scan <seed> [options]            Run recon pipeline (含 M2 评分)
    --mode auto|site|full              auto（默认）: URL→单站，其余→全量
                                       site: 只收集该站信息（框架/语言/接口/JS/webpack），不枚举子域/端口
                                       full: 强制全量资产发现（URL 也走 domain 流程）
    --skip-crawl                       Site mode: 跳过 katana 同域爬取
    --skip-dirscan                     Site mode: 跳过 dirsearch 小字典目录探测
    --skip-source-collect              Site mode: 跳过 M4 webpack 源码收集
    --skip-nmap                         Skip nmap port scan
    --skip-httpx                        Skip httpx webapp probe
    --skip-subfinder                    Skip subfinder (passive source)
    --skip-oneforall                    Skip OneForAll (passive + brute)
    --oneforall-brute false             Disable OneForAll brute module
    --skip-scoring                      Skip M2 scoring pipeline
    --skip-llm                          Skip LLM fallback classification
    --deep-scan                         Also run M3 deep scan after M1+M2
    --max-subdomains N                  Cap subdomains (default 1000)
    --max-company-domains N             Cap ICP reverse-lookup domains (default 50, for company_name seed)
    --concurrency N                     Company multi-domain parallel concurrency (default 3)
    --ports "80,443,8080"               nmap port range

  cli score <seedId> [--skip-llm]       Re-run scoring for all webapps of a seed
  cli deep-scan <webappId|seedId>       Run M3 deep scan (history_url/jsmining/dirscan/source_collect)
    --force                             Force re-run (ignore recent scan history)
    --skip-task <name>                  Skip specific task (history_url/jsmining/dirscan/source_collect)
    --max-js-files N                    Cap JS files to scan (default 50)
    --max-history-urls N                Cap history URLs (default 2000)
  cli metadata <webappId> [--save]      Output webapp metadata snapshot (JSON)

  cli query assets <seedId>             List assets for a seed
  cli query webapps                     List all webapps (sorted by score)
  cli query endpoints <webappId>        List endpoints (history_url/jsmining/dirscan)
  cli query jsapis <webappId>           List JS-extracted APIs
  cli query params <webappId>           List params (historical/js/dirscan)
  cli query findings [webappId] [sev]   List findings (sensitive info / github leak)
  cli query audit [action]              Show audit log
  cli query seeds                       List recent seeds

  cli fofa search "<query>" [--max N]   Search FOFA assets (REST API)
  cli fofa icon <icon_hash> [--max N]   Search FOFA by favicon hash

  cli source-collect <webappId>         M4: collect webpack sources + restore sourcemap
  cli sources list                      List all source dumps
  cli sources show <webappId>           Show source dumps for webapp
  cli sources index <webappId>          Read INDEX.json for webapp

  cli health                            Check PG/Redis connection

Examples:
  cli scan https://example.com          # URL → 单站元数据（框架/语言/接口/JS/webpack），不扩大范围
  cli scan https://example.com --mode full   # URL → 全量资产发现（子域/端口）
  cli scan baidu.com --skip-nmap --deep-scan
  cli scan '北京百度网讯科技有限公司' --skip-nmap --max-company-domains 5
  cli score <seed-id> --skip-llm
  cli deep-scan <webapp-id> --force
  cli deep-scan <seed-id>               # batch deep scan for all webapps of a seed
  cli metadata <webapp-id> --save
  cli query webapps
  cli query endpoints <webapp-id>
  cli query findings <webapp-id> high
  cli fofa search 'domain="baidu.com"' --max 50
  cli fofa icon "-247388890"
  cli source-collect <webapp-id> --force
  cli sources index <webapp-id>
  cli health
`);
}

export async function main(): Promise<void> {
	await runReconCli(process.argv.slice(2));
}

// 直接运行（node/tsx src/recon/cli.ts）时执行
if (isMainEntry()) {
	main()
		.catch((err) => {
			console.error('[cli] fatal:', err);
			process.exit(1);
		})
		.finally(async () => {
			await Promise.all([closePg(), closeRedis()]);
		});
}
