/**
 * 确定性扫描管道
 *
 * 6 种入口路由（架构文档 §四 4.1/4.2）：
 *   domain       → 直接跑 domain 流程
 *   url          → 提取根域名后跑 domain 流程
 *   ip           → 直接跑 ip 流程（nmap + httpx）
 *   cidr         → 枚举 IP 后跑 ip 流程
 *   ip_port      → 跑 ip + port 流程（nmap 单端口 + httpx）
 *   company_name → ICP 反查域名后跑 domain 流程（M3.9 提前实现）
 *
 * domain 流程：
 *   subfinder（子域）→ dnsx（A 记录，IP 发现）→ nmap（端口扫描）→ httpx（webapp 指纹）→ 入库
 *
 * 全程不走 LLM，工具出数据直接入库。
 */

import { type FofaAsset, isFofaEnabled, searchFofaAssets } from '../adapters/fofa_adapter.js';
import { queryDomainsByCompany } from '../adapters/icp_adapter.js';
import { getConfig } from '../config.js';
import { normalizeSeed } from '../seeds/normalizer.js';
import type { Seed } from '../seeds/types.js';
import {
	createScanRun,
	finishScanRun,
	updateSeedProgress,
	updateSeedStatus,
	upsertAsset,
	upsertAssetsBatch,
	upsertIpAsset,
	upsertIpAssetsBatch,
	upsertSeed,
	upsertService,
	upsertServicesBatch,
	upsertSubdomains,
} from '../storage/models/asset.js';
import type { AssetType } from '../storage/models/asset.js';
import { type DnsxRecord, runDnsx } from '../tools/dnsx.js';
import { runHttpx } from '../tools/httpx.js';
import { runMasscan } from '../tools/masscan.js';
import { type NmapServiceRecord, runNmap } from '../tools/nmap.js';
import { type OneForAllRecord, runOneForAll } from '../tools/oneforall.js';
import { type SubfinderRecord, runSubfinder } from '../tools/subfinder.js';
import { type SingleSiteResult, runSingleSitePipeline } from './single_site.js';
import { upsertWebappRecords } from './webapp_upsert.js';

export type ReconMode = 'auto' | 'site' | 'full';

export interface ReconOptions {
	/** 收集模式：'auto'（默认，URL→单站，其余→全量）| 'site'（单站，不扩大范围）| 'full'（全量资产发现） */
	mode?: ReconMode;
	/** 是否跳过 nmap */
	skipNmap?: boolean;
	/** 是否跳过 httpx */
	skipHttpx?: boolean;
	/** 是否跳过 OneForAll（默认 false，subfinder + oneforall 双源聚合） */
	skipOneForAll?: boolean;
	/** 是否跳过 subfinder（默认 false） */
	skipSubfinder?: boolean;
	/** 子域数量上限（防止超大目标的子域爆炸） */
	maxSubdomains?: number;
	/** 公司名反查域名数量上限 */
	maxCompanyDomains?: number;
	/** 公司多域名并行扫描并发数（默认 3） */
	companyDomainConcurrency?: number;
	/** nmap 端口范围（"80,443" / "1-1000" / "top100" / "top1000"，不传=nmap 默认 top1000） */
	nmapPorts?: string;
	/** 端口扫描器选择：'nmap'（默认，准但慢） / 'masscan'（快但需 sudo，无版本探测） */
	portScanner?: 'nmap' | 'masscan';
	/** masscan 发包速率（仅 portScanner='masscan' 时生效，默认 5000） */
	masscanRate?: number;
	/** 是否启用 FOFA 资产补充（默认 false，需配置 FOFA_EMAIL/FOFA_KEY） */
	useFofa?: boolean;
	/** 子域超时 */
	subfinderTimeoutMs?: number;
	/** OneForAll 超时 */
	oneforallTimeoutMs?: number;
	/** OneForAll 是否启用爆破（默认 true） */
	oneforallBrute?: boolean;
	/** 全局单种子超时上限 */
	totalTimeoutMs?: number;
	/** 跳过 M2 评分流水线（默认 false，scan 后自动跑评分） */
	skipScoring?: boolean;
	/** 跳过 LLM 兜底分类（默认 false，confidence<0.7 才调） */
	skipLlm?: boolean;
	/** site 模式：跳过 katana 同域爬取（默认 false） */
	skipCrawl?: boolean;
	/** site 模式：跳过 dirsearch 小字典目录探测（默认 false） */
	skipDirscan?: boolean;
	/** site 模式：跳过 M4 webpack 源码收集（默认 false） */
	skipSourceCollect?: boolean;
	/** site 模式：JS 扫描/下载文件数上限（默认 50） */
	maxJsFiles?: number;
	/** site 模式：sourcemap 还原文件数上限（默认 50） */
	maxMapFiles?: number;
}

export interface ReconResult {
	seedId: string;
	seedType: string;
	value: string;
	subdomainCount: number;
	ipCount: number;
	portCount: number;
	webappCount: number;
	durationMs: number;
	/** 单站模式（site）时的完整站点元数据结果 */
	site?: SingleSiteResult;
	/** 决策点1：LLM planner 建议的深挖级别（none/l1/l2/l3，未启用时无此字段） */
	plannerDeepScan?: string;
}

/**
 * 执行单个种子的完整扫描管道
 */
export async function runRecon(input: string, opts: ReconOptions = {}): Promise<ReconResult> {
	const startAt = Date.now();
	const seed: Seed = normalizeSeed(input);
	console.log(`[recon] seed=${seed.seedType} value=${seed.valueNorm}`);

	const seedId = await upsertSeed(seed);

	// 状态：pending → running
	await updateSeedStatus(seedId, 'running');
	const progress = (
		stage: string,
		stageLabel: string,
		stageIndex: number,
		extra: Record<string, unknown> = {},
	) =>
		updateSeedProgress(seedId, {
			stage,
			stageLabel,
			stageIndex,
			totalStages: 7,
			...extra,
			updatedAt: new Date().toISOString(),
		});

	// ===========================================================================
	// 决策点 1：LLM 侦察策略规划（mode 未显式指定或为 auto 时；用户显式参数优先）
	// ===========================================================================
	const userMode = opts.mode;
	let effectiveOpts = { ...opts };
	let plannerDeepScan: string | null = null;
	if ((userMode === undefined || userMode === 'auto') && getConfig().llm.plannerEnabled) {
		try {
			const { planRecon } = await import('../agents/llm_planner.js');
			const planner = await planRecon({
				seed,
				defaults: {
					maxSubdomains: opts.maxSubdomains ?? 1000,
					maxCompanyDomains: opts.maxCompanyDomains ?? 50,
					skipNmap: opts.skipNmap ?? false,
					skipHttpx: opts.skipHttpx ?? false,
				},
				hasHistory: false,
			});
			if (planner) {
				// 用户显式传了某个参数 → LLM 建议不覆盖；否则采纳（护栏已在 planner 内完成）
				effectiveOpts = {
					...effectiveOpts,
					mode: planner.mode ?? 'auto',
					...(opts.skipNmap === undefined && planner.options.skipNmap !== undefined
						? { skipNmap: planner.options.skipNmap }
						: {}),
					...(opts.skipOneForAll === undefined && planner.options.skipOneForAll !== undefined
						? { skipOneForAll: planner.options.skipOneForAll }
						: {}),
					...(opts.maxSubdomains === undefined && planner.options.maxSubdomains !== undefined
						? { maxSubdomains: planner.options.maxSubdomains }
						: {}),
					...(opts.nmapPorts === undefined && planner.options.ports !== undefined
						? { nmapPorts: planner.options.ports }
						: {}),
				};
				plannerDeepScan = planner.deepScanLevel;
				console.log(
					`[recon] LLM planner: mode=${planner.mode ?? 'auto'} deep=${planner.deepScanLevel} ` +
						`options=${JSON.stringify(planner.options)}${planner.guardNotes.length > 0 ? ` guard=[${planner.guardNotes.join(';')}]` : ''}`,
				);
			}
		} catch (err) {
			console.warn('[recon] LLM planner failed (non-blocking, use defaults):', err);
		}
	}
	opts = effectiveOpts;

	// 模式判定：auto 时 URL → site（单站），其余 → 全量
	const mode: ReconMode = opts.mode ?? 'auto';
	let usedSiteMode = false;
	let siteResult: SingleSiteResult | null = null;

	let result: PipelineStats;
	// 单站模式进度：阶段 1=探测收集；全量模式阶段由子管道内部更新
	await progress('collect', '收集执行中', usedSiteMode ? 1 : 1, {
		...(usedSiteMode ? { webappCount: 0 } : {}),
	});
	switch (seed.seedType) {
		case 'domain':
			if (mode === 'site') {
				usedSiteMode = true;
				// 单站模式：只探测 http(s)://根域，不枚举子域
				siteResult = await runSingleSitePipeline(
					seedId,
					[`http://${seed.valueNorm}`, `https://${seed.valueNorm}`],
					siteModeOpts(opts),
				);
				result = siteStats(siteResult);
			} else {
				result = await runDomainPipeline(seedId, seed.valueNorm, opts);
			}
			break;
		case 'url':
			if (mode === 'full') {
				if (seed.parsed.kind !== 'url') throw new Error('seed parsed mismatch');
				result = await runDomainPipeline(seedId, seed.parsed.domain, opts);
			} else {
				usedSiteMode = true;
				if (seed.parsed.kind !== 'url') throw new Error('seed parsed mismatch');
				// 单站模式：只探测给定 URL（含路径），不提取根域名扩大
				siteResult = await runSingleSitePipeline(seedId, [seed.parsed.url], siteModeOpts(opts));
				result = siteStats(siteResult);
			}
			break;
		case 'company_name':
			if (seed.parsed.kind !== 'company_name') throw new Error('seed parsed mismatch');
			result = await runCompanyPipeline(seedId, seed.valueNorm, opts);
			break;
		case 'ip':
			if (seed.parsed.kind !== 'ip') throw new Error('seed parsed mismatch');
			result = await runIpPipeline(seedId, seed.parsed.ip, null, opts);
			break;
		case 'ip_port':
			if (seed.parsed.kind !== 'ip_port') throw new Error('seed parsed mismatch');
			result = await runIpPipeline(seedId, seed.parsed.ip, seed.parsed.port, opts);
			break;
		case 'cidr':
			if (seed.parsed.kind !== 'cidr') throw new Error('seed parsed mismatch');
			result = await runCidrPipeline(seedId, seed.parsed.cidr, opts);
			break;
		default:
			console.warn(`[recon] unknown seed type: ${seed.seedType as string}`);
			result = { subdomainCount: 0, ipCount: 0, portCount: 0, webappCount: 0 };
	}

	const durationMs = Date.now() - startAt;
	console.log(
		`[recon] done in ${(durationMs / 1000).toFixed(1)}s | ` +
			`subs=${result.subdomainCount} ips=${result.ipCount} ports=${result.portCount} webapps=${result.webappCount}`,
	);
	// 进度：收集完成
	await progress('scoring', '评分中', 5, {
		subdomainCount: result.subdomainCount,
		webappCount: result.webappCount,
	});

	// M2：扫描完成后自动跑评分流水线（指纹→角色→LLM兜底→评分→CVE→门控→快照）
	// 单站模式已在管道内完成评分，这里跳过避免重复
	if (result.webappCount > 0 && !opts.skipScoring && !usedSiteMode) {
		try {
			console.log(`[recon] running scoring pipeline for seed ${seedId}...`);
			const { scoreBySeed } = await import('../scoring/pipeline.js');
			const scoringResults = await scoreBySeed(seedId, { skipLlm: opts.skipLlm });
			console.log(`[scoring] ${scoringResults.length} webapps scored`);
			for (const r of scoringResults) {
				console.log(
					`  ${r.url}  role=${r.role}(${r.roleSource})  score=${r.score}  level=${r.level}  cve_hints=${r.vulnHints.length}`,
				);
			}
		} catch (err) {
			console.error('[scoring] pipeline failed (non-blocking):', err);
		}
	}

	// 进度 + 状态：完成
	await progress('done', '完成', 7, {
		subdomainCount: result.subdomainCount,
		webappCount: result.webappCount,
	});
	await updateSeedStatus(seedId, 'done');

	return {
		seedId,
		seedType: seed.seedType,
		value: seed.valueNorm,
		...result,
		durationMs,
		...(siteResult ? { site: siteResult } : {}),
		...(plannerDeepScan ? { plannerDeepScan } : {}),
	};
}

/** 单站结果 → PipelineStats（单站模式不产生子域/IP/端口） */
function siteStats(s: SingleSiteResult): PipelineStats {
	return {
		subdomainCount: 0,
		ipCount: 0,
		portCount: 0,
		webappCount: s.webappId ? 1 : 0,
	};
}

/** 从 ReconOptions 提取单站模式专属参数 */
function siteModeOpts(opts: ReconOptions) {
	return {
		skipCrawl: opts.skipCrawl,
		skipDirscan: opts.skipDirscan,
		skipSourceCollect: opts.skipSourceCollect,
		maxJsFiles: opts.maxJsFiles,
		maxMapFiles: opts.maxMapFiles,
		skipScoring: opts.skipScoring,
		skipLlm: opts.skipLlm,
	};
}

interface PipelineStats {
	subdomainCount: number;
	ipCount: number;
	portCount: number;
	webappCount: number;
}

// =============================================================================
// company_name 流程：ICP 反查域名 → 逐个跑 domain 流程
// =============================================================================

async function runCompanyPipeline(
	seedId: string,
	company: string,
	opts: ReconOptions,
): Promise<PipelineStats> {
	console.log(`[recon] company → ICP reverse query: ${company}`);

	// 1. ICP 反查
	const icpScanId = await createScanRun({ seedId, tool: 'icp_query', params: { company } });
	let domains: string[] = [];
	try {
		const records = await queryDomainsByCompany(company, {
			maxDomains: opts.maxCompanyDomains ?? 50,
			timeoutMs: 60_000,
		});
		domains = records.map((r) => r.domain);
		await finishScanRun(icpScanId, {
			status: 'done',
			resultSummary: { count: domains.length, total: records.length },
		});
		console.log(`[recon] ICP: ${domains.length} domains for company "${company}"`);
	} catch (err) {
		await finishScanRun(icpScanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] ICP reverse query failed:', err);
		return { subdomainCount: 0, ipCount: 0, portCount: 0, webappCount: 0 };
	}

	// 2. 创建公司资产
	const companyAssetId = await upsertAsset({
		type: 'company',
		value: company,
		valueNorm: company,
		seedId,
		discoveredBy: 'seed',
	});

	// 3. 域名资产入库（parent 指向 company）
	for (const d of domains) {
		await upsertAsset({
			type: 'domain',
			value: d,
			valueNorm: d,
			seedId,
			parentId: companyAssetId,
			discoveredBy: 'icp_query',
		});
	}

	// 4. 对每个域名并行跑 domain 流程（限制并发，避免被动源 API 限流）
	const concurrency = opts.companyDomainConcurrency ?? 3;
	const stats: PipelineStats = { subdomainCount: 0, ipCount: 0, portCount: 0, webappCount: 0 };
	const queue = [...domains];
	const workers: Promise<void>[] = [];
	for (let w = 0; w < Math.min(concurrency, domains.length); w++) {
		workers.push(
			(async () => {
				while (queue.length > 0) {
					const domain = queue.shift();
					if (!domain) break;
					console.log(`[recon] → domain pipeline: ${domain}`);
					try {
						const sub = await runDomainPipeline(seedId, domain, opts, companyAssetId);
						stats.subdomainCount += sub.subdomainCount;
						stats.ipCount += sub.ipCount;
						stats.portCount += sub.portCount;
						stats.webappCount += sub.webappCount;
					} catch (err) {
						console.error(`[recon] domain pipeline failed for ${domain}:`, err);
					}
				}
			})(),
		);
	}
	await Promise.all(workers);
	return stats;
}

// =============================================================================
// domain 流程：subfinder → dnsx → nmap → httpx → 入库
// =============================================================================

async function runDomainPipeline(
	seedId: string,
	rootDomain: string,
	opts: ReconOptions,
	parentAssetId?: string,
): Promise<PipelineStats> {
	// 1. 根域名资产
	const domainAssetId = await upsertAsset({
		type: 'domain',
		value: rootDomain,
		valueNorm: rootDomain,
		seedId,
		parentId: parentAssetId,
		discoveredBy: parentAssetId ? 'icp_query' : 'seed',
	});

	// 2. 子域发现：subfinder + oneforall 并行（双源聚合）
	const tasks: Promise<{ subfinder: SubfinderRecord[]; oneforall: OneForAllRecord[] }>[] = [];
	if (!opts.skipSubfinder) {
		tasks.push(
			(async () => ({
				subfinder: await runSubfinderStep(seedId, domainAssetId, rootDomain, opts),
				oneforall: [] as OneForAllRecord[],
			}))(),
		);
	}
	if (!opts.skipOneForAll) {
		tasks.push(
			(async () => ({
				subfinder: [] as SubfinderRecord[],
				oneforall: await runOneForAllStep(seedId, domainAssetId, rootDomain, opts),
			}))(),
		);
	}
	const results = await Promise.all(tasks);
	const subfinderRecords = results.flatMap((r) => r.subfinder);
	const oneforallRecords = results.flatMap((r) => r.oneforall);

	// 聚合 + 去重（按子域 host）
	const allSubs = new Map<string, { host: string; source: string }>();
	for (const r of subfinderRecords) {
		if (!allSubs.has(r.host))
			allSubs.set(r.host, { host: r.host, source: `subfinder:${r.source ?? '?'}` });
	}
	for (const r of oneforallRecords) {
		if (!allSubs.has(r.subdomain)) {
			allSubs.set(r.subdomain, { host: r.subdomain, source: `oneforall:${r.source ?? '?'}` });
		}
	}
	const allHosts = [rootDomain, ...Array.from(allSubs.keys())];

	// 入库子域（标记发现工具）
	if (subfinderRecords.length > 0) {
		await upsertSubdomains(
			seedId,
			domainAssetId,
			subfinderRecords.map((r) => r.host),
			'subfinder',
		);
	}
	if (oneforallRecords.length > 0) {
		await upsertSubdomains(
			seedId,
			domainAssetId,
			oneforallRecords.map((r) => r.subdomain),
			'oneforall',
		);
	}
	console.log(
		`[recon] subdomain sources: subfinder=${subfinderRecords.length} oneforall=${oneforallRecords.length} merged=${allSubs.size}`,
	);
	// 进度：子域完成
	await updateSeedProgress(seedId, {
		stage: 'dns_resolve',
		stageLabel: 'DNS 解析',
		stageIndex: 2,
		totalStages: 7,
		subdomainCount: allSubs.size,
		updatedAt: new Date().toISOString(),
	});

	// 3. dnsx
	const dnsRecords = await runDnsxStep(seedId, domainAssetId, allHosts);
	const ipSet = new Set<string>();
	const resolvedHosts = new Set<string>();
	for (const r of dnsRecords) {
		if ((r.a ?? []).length > 0) {
			resolvedHosts.add(r.host);
			for (const ip of r.a ?? []) ipSet.add(ip);
		}
	}
	for (const ip of ipSet) {
		await upsertIpAsset(ip, { seedId, parentId: domainAssetId, discoveredBy: 'dnsx' });
	}
	// 进度：DNS 完成
	await updateSeedProgress(seedId, {
		stage: 'port_scan',
		stageLabel: '端口扫描',
		stageIndex: 3,
		totalStages: 7,
		subdomainCount: allSubs.size,
		webappCount: 0,
		updatedAt: new Date().toISOString(),
	});

	// 4. FOFA 资产补充（默认开启；FOFA_ENABLED=false 或未配置 email/key 时跳过）
	let fofaAssets: FofaAsset[] = [];
	const fofaOn = opts.useFofa ?? getConfig().fofa.enabled;
	if (fofaOn && isFofaEnabled()) {
		fofaAssets = await runFofaStep(seedId, domainAssetId, rootDomain);
		// FOFA 发现的资产补充进 ipSet 和 resolvedHosts
		for (const a of fofaAssets) {
			if (a.ip) ipSet.add(a.ip);
			if (a.host && !allSubs.has(a.host)) {
				resolvedHosts.add(a.host);
			}
		}
	}

	// 5. 端口扫描（nmap 或 masscan）
	let portCount = 0;
	let portServices: Array<{ ip: string; port: number; service?: string; protocol: 'tcp' | 'udp' }> =
		[];
	if (!opts.skipNmap && ipSet.size > 0) {
		const r = await runPortScanStep(seedId, domainAssetId, Array.from(ipSet), opts);
		portCount = r.count;
		portServices = r.services;
	}

	// 6. httpx（探测所有有 A 记录的子域 + nmap 发现的 http 端口）
	let webappCount = 0;
	if (!opts.skipHttpx) {
		const hostsToProbe = resolvedHosts.size > 0 ? Array.from(resolvedHosts) : [rootDomain];
		webappCount = await runHttpxStep(seedId, domainAssetId, hostsToProbe, portServices, fofaAssets);
		// 进度：httpx 完成
		await updateSeedProgress(seedId, {
			stage: 'scoring',
			stageLabel: '评分',
			stageIndex: 5,
			totalStages: 7,
			subdomainCount: allSubs.size,
			webappCount,
			updatedAt: new Date().toISOString(),
		});
	}

	return {
		subdomainCount: allSubs.size,
		ipCount: ipSet.size,
		portCount,
		webappCount,
	};
}

// =============================================================================
// ip 流程：nmap + httpx
// =============================================================================

async function runIpPipeline(
	seedId: string,
	ip: string,
	fixedPort: number | null,
	opts: ReconOptions,
): Promise<PipelineStats> {
	console.log(`[recon] ip pipeline: ${ip}${fixedPort ? `:${fixedPort}` : ''}`);

	const ipAssetId = await upsertIpAsset(ip, { seedId, discoveredBy: 'seed' });

	// FOFA 资产补充（IP 种子：ip="1.2.3.4" 查 FOFA，关联 host/端口/服务入库）
	const fofaOn = opts.useFofa ?? getConfig().fofa.enabled;
	let fofaAssets: FofaAsset[] = [];
	if (fofaOn && isFofaEnabled()) {
		fofaAssets = await runFofaIpStep(seedId, ipAssetId, ip);
	}

	let portCount = 0;
	let ports: NmapServiceRecord[] = [];
	if (!opts.skipNmap) {
		ports = await runNmapForIp(
			seedId,
			ipAssetId,
			ip,
			fixedPort ? String(fixedPort) : opts.nmapPorts,
		);
		portCount = ports.length;
	}

	let webappCount = 0;
	if (!opts.skipHttpx) {
		// 构造 URL：固定端口 → nmap 发现的 http 端口 → FOFA 发现的 host:port
		const fofaUrls = fofaAssets
			.filter((a) => a.host && a.port)
			.map((a) => `${a.protocol === 'https' ? 'https' : 'http'}://${a.host}:${a.port}`);
		const urls = fixedPort
			? [`http://${ip}:${fixedPort}`, `https://${ip}:${fixedPort}`]
			: [
					...ports
						.filter(
							(p) =>
								p.port === 80 || p.port === 443 || p.service === 'http' || p.service === 'https',
						)
						.flatMap((p) => [`http://${ip}:${p.port}`, `https://${ip}:${p.port}`]),
					...fofaUrls,
				];
		if (urls.length > 0) {
			const records = await runHttpxForUrls(seedId, ipAssetId, [...new Set(urls)]);
			webappCount = records;
		}
	}

	return { subdomainCount: 0, ipCount: 1, portCount, webappCount };
}

// =============================================================================
// cidr 流程：枚举 IP → 逐个跑 ip 流程（M1 简化：只扫前 N 个 IP）
// =============================================================================

async function runCidrPipeline(
	seedId: string,
	cidr: string,
	opts: ReconOptions,
): Promise<PipelineStats> {
	console.log(`[recon] cidr pipeline: ${cidr} (M1: limited to /28 max)`);

	// 解析 CIDR 枚举 IP（最多 16 个，避免 /8 这种巨型 CIDR）
	const ips = enumerateCidr(cidr, 16);
	if (ips.length === 0) {
		console.warn(`[recon] cidr ${cidr} yielded 0 IPs`);
		return { subdomainCount: 0, ipCount: 0, portCount: 0, webappCount: 0 };
	}

	// CIDR 资产入库
	const cidrAssetId = await upsertAsset({
		type: 'ip',
		value: cidr,
		valueNorm: cidr,
		seedId,
		discoveredBy: 'seed',
		meta: { cidr: true },
	});

	const stats: PipelineStats = { subdomainCount: 0, ipCount: 0, portCount: 0, webappCount: 0 };
	for (const ip of ips) {
		const sub = await runIpPipeline(seedId, ip, null, opts);
		stats.ipCount += sub.ipCount;
		stats.portCount += sub.portCount;
		stats.webappCount += sub.webappCount;
	}
	void cidrAssetId;
	return stats;
}

// =============================================================================
// 工具步骤封装
// =============================================================================

async function runSubfinderStep(
	seedId: string,
	domainAssetId: string,
	domain: string,
	opts: ReconOptions,
): Promise<SubfinderRecord[]> {
	const scanId = await createScanRun({ seedId, assetId: domainAssetId, tool: 'subfinder' });
	try {
		let records = await runSubfinder({
			domain,
			timeoutMs: opts.subfinderTimeoutMs ?? 5 * 60 * 1000,
			useCache: true,
		});
		const maxSubs = opts.maxSubdomains ?? 1000;
		if (records.length > maxSubs) {
			console.log(`[recon] subdomain cap: ${records.length} → ${maxSubs}`);
			records = records.slice(0, maxSubs);
		}
		await finishScanRun(scanId, { status: 'done', resultSummary: { count: records.length } });
		console.log(`[recon] subfinder: ${records.length} subdomains`);
		return records;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] subfinder failed:', err);
		return [];
	}
}

async function runOneForAllStep(
	seedId: string,
	domainAssetId: string,
	domain: string,
	opts: ReconOptions,
): Promise<OneForAllRecord[]> {
	const scanId = await createScanRun({ seedId, assetId: domainAssetId, tool: 'oneforall' });
	try {
		let records = await runOneForAll({
			domain,
			timeoutMs: opts.oneforallTimeoutMs ?? 10 * 60 * 1000,
			useCache: true,
			// OneForAll 自带 HTTP/CDN/接管，关掉这些（交给 httpx -cdn 单独做）
			httpProbe: false,
			cdnCheck: false,
			takeover: false,
			brute: opts.oneforallBrute ?? true,
		});
		const maxSubs = opts.maxSubdomains ?? 1000;
		if (records.length > maxSubs) {
			console.log(`[recon] oneforall cap: ${records.length} → ${maxSubs}`);
			records = records.slice(0, maxSubs);
		}
		await finishScanRun(scanId, { status: 'done', resultSummary: { count: records.length } });
		console.log(`[recon] oneforall: ${records.length} subdomains`);
		return records;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] oneforall failed:', err);
		return [];
	}
}

async function runDnsxStep(
	seedId: string,
	domainAssetId: string,
	hosts: string[],
): Promise<DnsxRecord[]> {
	const scanId = await createScanRun({ seedId, assetId: domainAssetId, tool: 'dnsx' });
	try {
		const records = await runDnsx({
			domains: hosts,
			recordTypes: ['a'],
			timeoutMs: 3 * 60 * 1000,
		});
		await finishScanRun(scanId, { status: 'done', resultSummary: { count: records.length } });
		console.log(`[recon] dnsx: ${records.length} records`);
		return records;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] dnsx failed:', err);
		return [];
	}
}

async function runPortScanStep(
	seedId: string,
	domainAssetId: string,
	ips: string[],
	opts: ReconOptions,
): Promise<{
	count: number;
	services: Array<{ ip: string; port: number; service?: string; protocol: 'tcp' | 'udp' }>;
}> {
	if (ips.length === 0) return { count: 0, services: [] };
	const scanner = opts.portScanner ?? 'nmap';
	const scanId = await createScanRun({
		seedId,
		tool: scanner,
		params: { ips, ports: opts.nmapPorts },
	});
	const allServices: Array<{
		ip: string;
		port: number;
		service?: string;
		protocol: 'tcp' | 'udp';
	}> = [];
	let total = 0;
	try {
		if (scanner === 'masscan') {
			// masscan 批量扫描（速度快，无版本探测）
			const records = await runMasscan({
				ips: ips.slice(0, 200), // masscan 适合批量
				ports: opts.nmapPorts,
				rate: opts.masscanRate ?? 5000,
				timeoutMs: 10 * 60 * 1000,
			});
			// 批量 upsert IP + 服务（消除 N+1 串行往返）
			const ipMap = await upsertIpAssetsBatch(
				records.map((r) => ({
					ip: r.ip,
					opts: { seedId, parentId: domainAssetId, discoveredBy: 'dnsx' },
				})),
			);
			await upsertServicesBatch(
				records
					.map((r) => {
						const ipAssetId = ipMap.get(r.ip);
						return ipAssetId
							? {
									ipAssetId,
									ip: r.ip,
									port: r.port,
									protocol: r.protocol,
									opts: {
										isHttp: r.port === 80 || r.port === 443 || r.port === 8080 || r.port === 8443,
										discoveredBy: 'masscan',
									},
								}
							: null;
					})
					.filter((e): e is NonNullable<typeof e> => e !== null),
			);
			for (const r of records) {
				allServices.push({ ip: r.ip, port: r.port, protocol: r.protocol });
				total++;
			}
		} else {
			// nmap 逐个扫描（准但慢，有版本探测）——先批量 upsert IP，再批量 upsert 服务
			const ipList = ips.slice(0, 50);
			const ipMap = await upsertIpAssetsBatch(
				ipList.map((ip) => ({
					ip,
					opts: { seedId, parentId: domainAssetId, discoveredBy: 'dnsx' },
				})),
			);
			const svcEntries: Parameters<typeof upsertServicesBatch>[0] = [];
			for (const ip of ipList) {
				const records = await runNmap({
					target: ip,
					...(opts.nmapPorts?.startsWith('top')
						? { topPorts: Number.parseInt(opts.nmapPorts.slice(3), 10) }
						: opts.nmapPorts
							? { ports: opts.nmapPorts }
							: {}), // 都不传 = nmap 默认 top 1000
					timing: 'T4',
					serviceVersion: true,
					timeoutMs: 5 * 60 * 1000,
				});
				const ipAssetId = ipMap.get(ip);
				if (!ipAssetId) continue;
				for (const r of records) {
					svcEntries.push({
						ipAssetId,
						ip: r.ip,
						port: r.port,
						protocol: r.protocol,
						opts: {
							service: r.service,
							version: r.version,
							banner: r.banner,
							isHttp:
								r.service === 'http' || r.service === 'https' || r.port === 80 || r.port === 443,
							discoveredBy: 'nmap',
						},
					});
					allServices.push({ ip: r.ip, port: r.port, service: r.service, protocol: r.protocol });
					total++;
				}
			}
			await upsertServicesBatch(svcEntries);
		}
		await finishScanRun(scanId, { status: 'done', resultSummary: { count: total } });
		console.log(`[recon] ${scanner}: ${total} open ports`);
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error(`[recon] ${scanner} failed:`, err);
	}
	return { count: total, services: allServices };
}

/**
 * FOFA 资产补充：用 domain="xxx" 查询，把 FOFA 发现的 host/ip 入库
 */
async function runFofaStep(
	seedId: string,
	domainAssetId: string,
	rootDomain: string,
): Promise<FofaAsset[]> {
	const scanId = await createScanRun({
		seedId,
		tool: 'fofa',
		params: { query: `domain="${rootDomain}"` },
	});
	try {
		const result = await searchFofaAssets({
			query: `domain="${rootDomain}"`,
			maxResults: 500,
			timeoutMs: 30_000,
		});
		if (!result.enabled) {
			await finishScanRun(scanId, {
				status: 'done',
				resultSummary: { count: 0, message: result.message },
			});
			console.log(`[recon] fofa: disabled (${result.message})`);
			return [];
		}
		// FOFA 资产入库（host → subdomain，ip → ip 资产）——批量 upsert，消除 N+1
		await upsertAssetsBatch(
			result.assets
				.filter((a) => a.host)
				.map((a) => ({
					type: 'subdomain' as const,
					value: a.host,
					valueNorm: a.host.toLowerCase(),
					seedId,
					parentId: domainAssetId,
					discoveredBy: 'fofa',
					alive: true,
					meta: { title: a.title, server: a.server, port: a.port, protocol: a.protocol },
				})),
		);
		await upsertIpAssetsBatch(
			result.assets
				.filter((a) => a.ip)
				.map((a) => ({ ip: a.ip!, opts: { seedId, parentId: domainAssetId, discoveredBy: 'fofa' } })),
		);
		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { count: result.assets.length, total: result.total },
		});
		console.log(`[recon] fofa: ${result.assets.length} assets (total=${result.total})`);
		return result.assets;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] fofa failed:', err);
		return [];
	}
}

/**
 * FOFA 资产补充（IP 种子）：用 ip="1.2.3.4" 查询，关联 host/端口入库
 * 返回值供 httpx 探测 FOFA 已知的 host:port
 */
async function runFofaIpStep(seedId: string, ipAssetId: string, ip: string): Promise<FofaAsset[]> {
	const scanId = await createScanRun({
		seedId,
		tool: 'fofa',
		params: { query: `ip="${ip}"` },
	});
	try {
		const result = await searchFofaAssets({
			query: `ip="${ip}"`,
			maxResults: 300,
			timeoutMs: 30_000,
		});
		if (!result.enabled) {
			await finishScanRun(scanId, {
				status: 'done',
				resultSummary: { count: 0, message: result.message },
			});
			return [];
		}
		// FOFA 发现的 host/port 入库（subdomain 资产，parent 指向该 IP）——批量 upsert，消除 N+1
		await upsertAssetsBatch(
			result.assets
				.filter((a) => a.host && a.port)
				.map((a) => ({
					type: 'subdomain' as const,
					value: a.host,
					valueNorm: a.host.toLowerCase(),
					seedId,
					parentId: ipAssetId,
					discoveredBy: 'fofa',
					alive: true,
					meta: { title: a.title, server: a.server, port: a.port, protocol: a.protocol, ip },
				})),
		);
		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { count: result.assets.length, total: result.total },
		});
		console.log(
			`[recon] fofa(ip): ${result.assets.length} assets for ${ip} (total=${result.total})`,
		);
		return result.assets;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] fofa(ip) failed:', err);
		return [];
	}
}

async function runNmapForIp(
	seedId: string,
	ipAssetId: string,
	ip: string,
	ports: string | undefined,
): Promise<NmapServiceRecord[]> {
	const scanId = await createScanRun({
		seedId,
		assetId: ipAssetId,
		tool: 'nmap',
		params: { ip, ports },
	});
	try {
		const records = await runNmap({
			target: ip,
			// ports 可能是 "80,443" / "1-1000" / "top100" / "top1000" / undefined
			...(ports?.startsWith('top')
				? { topPorts: Number.parseInt(ports.slice(3), 10) }
				: ports
					? { ports }
					: {}), // 都不传 = nmap 默认 top 1000
			timing: 'T4',
			serviceVersion: true,
			timeoutMs: 5 * 60 * 1000,
		});
		for (const r of records) {
			await upsertService(ipAssetId, r.ip, r.port, r.protocol, {
				seedId,
				service: r.service,
				version: r.version,
				banner: r.banner,
				isHttp: r.service === 'http' || r.service === 'https' || r.port === 80 || r.port === 443,
				discoveredBy: 'nmap',
			});
		}
		await finishScanRun(scanId, { status: 'done', resultSummary: { count: records.length } });
		console.log(`[recon] nmap: ${records.length} open ports for ${ip}`);
		return records;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] nmap failed:', err);
		return [];
	}
}

/**
 * httpx 探测步骤
 *
 * 合并三个来源构造待探测 URL：
 * 1. 有 A 记录的子域 → http://h + https://h（默认 80/443）
 * 2. nmap/masscan 发现的端口服务 → http(s)://ip:port（覆盖 8080/8443 等非标端口）
 * 3. FOFA 资产 → 已知 protocol://host:port
 */
async function runHttpxStep(
	seedId: string,
	domainAssetId: string,
	hosts: string[],
	portServices: Array<{ ip: string; port: number; service?: string; protocol: 'tcp' | 'udp' }> = [],
	fofaAssets: FofaAsset[] = [],
): Promise<number> {
	const scanId = await createScanRun({ seedId, tool: 'httpx' });
	try {
		const urlSet = new Set<string>();

		// 1. 子域默认 80/443
		for (const h of hosts) {
			urlSet.add(`http://${h}`);
			urlSet.add(`https://${h}`);
		}

		// 2. nmap 发现的所有端口服务（http/https 服务 + 常见 web 端口）
		const WEB_PORTS = new Set([
			80, 443, 8080, 8443, 8000, 8008, 8081, 8888, 9000, 3000, 3001, 5000, 5601, 9200,
		]);
		for (const s of portServices) {
			if (
				s.service === 'http' ||
				s.service === 'https' ||
				s.service === 'http-proxy' ||
				WEB_PORTS.has(s.port)
			) {
				urlSet.add(`http://${s.ip}:${s.port}`);
				urlSet.add(`https://${s.ip}:${s.port}`);
			}
		}

		// 3. FOFA 资产（已知 protocol+host+port，直接用）
		for (const a of fofaAssets) {
			if (a.host && a.port) {
				const proto = a.protocol === 'https' ? 'https' : 'http';
				urlSet.add(`${proto}://${a.host}:${a.port}`);
			}
		}

		const urls = Array.from(urlSet).slice(0, 2000); // 上限提升到 2000
		console.log(
			`[recon] httpx: probing ${urls.length} urls (hosts=${hosts.length} ports=${portServices.length} fofa=${fofaAssets.length})`,
		);
		const records = await runHttpx({ urls, timeoutMs: 15 * 60 * 1000 });
		const inserted = await upsertWebappRecords(seedId, records, domainAssetId);
		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { count: records.length, inserted, urlsProbed: urls.length },
		});
		console.log(`[recon] httpx: ${records.length} live webapps (inserted=${inserted})`);
		return inserted;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] httpx failed:', err);
		return 0;
	}
}

async function runHttpxForUrls(
	seedId: string,
	parentAssetId: string,
	urls: string[],
): Promise<number> {
	const scanId = await createScanRun({ seedId, tool: 'httpx', params: { urls } });
	try {
		const records = await runHttpx({ urls, timeoutMs: 10 * 60 * 1000 });
		const inserted = await upsertWebappRecords(seedId, records, parentAssetId);
		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { count: records.length, inserted },
		});
		console.log(`[recon] httpx: ${records.length} live webapps (inserted=${inserted})`);
		return inserted;
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[recon] httpx failed:', err);
		return 0;
	}
}

// =============================================================================
// 工具函数
// =============================================================================

/** 枚举 CIDR 内的 IP（带上限防止爆炸） */
function enumerateCidr(cidr: string, maxIps: number): string[] {
	const [ipPart, prefixPart] = cidr.split('/');
	const prefix = Number.parseInt(prefixPart, 10);
	const parts = ipPart.split('.').map((p) => Number.parseInt(p, 10));
	if (parts.length !== 4 || prefix < 0 || prefix > 32) return [];
	const ipNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
	const count = prefix === 0 ? Math.min(2 ** 32, maxIps) : Math.min(2 ** (32 - prefix), maxIps);
	const out: string[] = [];
	for (let i = 0; i < count; i++) {
		const n = (ipNum + i) >>> 0;
		out.push([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.'));
	}
	return out;
}

// 导出 asset type 供 cli 使用
export type { AssetType };
