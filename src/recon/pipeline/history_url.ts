/**
 * M3 历史 URL 收集任务
 *
 * 整合 waybackurls + gau + paramspider 三源，去重后：
 * - 提取 path → endpoints(source=historical)
 * - 提取 query 参数 → params(source=historical)
 * - 提取 JS 文件 URL → 后续 JS 挖掘的输入
 *
 * 注意：历史 URL 是被动源，不会触发目标，所以可以放心跑。
 */

import { auditLog } from '../gate/audit_log.js';
import { createScanRun, finishScanRun } from '../storage/models/asset.js';
import { upsertEndpoints, upsertParams } from '../storage/models/recon.js';
import { type GauRecord, runGau } from '../tools/gau.js';
import { type ParamSpiderRecord, runParamSpider } from '../tools/paramspider.js';
import { type WaybackurlsRecord, runWaybackurls } from '../tools/waybackurls.js';

export interface HistoryUrlOptions {
	/** 目标域名（不带协议，如 example.com） */
	domain: string;
	/** webapp 资产 ID（endpoints/params 入库时关联） */
	webappId: string;
	/** 资产 ID（findings 入库时关联，可选） */
	assetId?: string;
	/** seed ID（scan_run 记录） */
	seedId?: string;
	/** 跳过 waybackurls */
	skipWaybackurls?: boolean;
	/** 跳过 gau */
	skipGau?: boolean;
	/** 跳过 paramspider */
	skipParamSpider?: boolean;
	/** URL 数量上限（防止大站点返回数万条） */
	maxUrls?: number;
	/** 单工具超时 */
	timeoutMs?: number;
}

export interface HistoryUrlResult {
	/** 去重后的历史 URL 总数 */
	urlCount: number;
	/** 入库 endpoint 数 */
	endpointCount: number;
	/** 入库 param 数 */
	paramCount: number;
	/** 提取到的 JS 文件 URL（去重，用于后续 JS 挖掘） */
	jsUrls: string[];
}

/**
 * 跑历史 URL 收集
 *
 * 工作流：
 *   1. 并行跑 waybackurls + gau + paramspider
 *   2. 合并去重
 *   3. 解析每条 URL 的 path 和 query 参数
 *   4. 入库 endpoints（source=historical）+ params（source=historical）
 *   5. 单独抽出 .js 文件 URL，返回给调用方做 JS 挖掘
 */
export async function collectHistoryUrls(opts: HistoryUrlOptions): Promise<HistoryUrlResult> {
	const maxUrls = opts.maxUrls ?? 2000;
	console.log(`[history_url] collecting for ${opts.domain} (cap=${maxUrls})`);

	const sources: string[] = [];
	if (!opts.skipWaybackurls) sources.push('waybackurls');
	if (!opts.skipGau) sources.push('gau');
	if (!opts.skipParamSpider) sources.push('paramspider');

	const scanId = await createScanRun({
		seedId: opts.seedId,
		assetId: opts.assetId,
		tool: 'history_url',
		params: { domain: opts.domain, sources },
	});

	try {
		// 1. 并行跑三源
		const tasks: Promise<{ source: string; records: Array<{ url: string }> }>[] = [];
		if (!opts.skipWaybackurls) {
			tasks.push(
				(async () => ({
					source: 'waybackurls',
					records: (await runWaybackurls({ domain: opts.domain, timeoutMs: opts.timeoutMs })).map(
						(r: WaybackurlsRecord) => ({ url: r.url }),
					),
				}))(),
			);
		}
		if (!opts.skipGau) {
			tasks.push(
				(async () => ({
					source: 'gau',
					records: (await runGau({ domain: opts.domain, timeoutMs: opts.timeoutMs })).map(
						(r: GauRecord) => ({ url: r.url }),
					),
				}))(),
			);
		}
		if (!opts.skipParamSpider) {
			tasks.push(
				(async () => ({
					source: 'paramspider',
					records: (await runParamSpider({ domain: opts.domain, timeoutMs: opts.timeoutMs })).map(
						(r: ParamSpiderRecord) => ({ url: r.url }),
					),
				}))(),
			);
		}
		// 用 allSettled 容错：单源失败（如 web.archive.org 不可达）不影响其他源
		const settled = await Promise.allSettled(tasks);
		const results: { source: string; records: Array<{ url: string }> }[] = [];
		for (let i = 0; i < settled.length; i++) {
			const s = settled[i];
			if (s.status === 'fulfilled') {
				results.push(s.value);
			} else {
				console.warn(
					`[history_url] source #${i} failed:`,
					s.reason instanceof Error ? s.reason.message : s.reason,
				);
			}
		}

		// 2. 合并 + 去重 + 过滤（只保留同域名 URL，避免历史数据中混入第三方）
		const seen = new Set<string>();
		const allUrls: string[] = [];
		const jsUrls = new Set<string>();
		const sourceCounts: Record<string, number> = {};
		for (const r of results) {
			sourceCounts[r.source] = r.records.length;
			for (const item of r.records) {
				const url = item.url.trim();
				if (!url || seen.has(url)) continue;
				seen.add(url);
				// 只保留目标域名的 URL（包括子域）
				if (!isSameSite(url, opts.domain)) continue;
				allUrls.push(url);
				// 抽出 JS 文件 URL
				if (/\.(js|mjs)(\?|$)/i.test(url)) {
					jsUrls.add(url);
				}
				if (allUrls.length >= maxUrls) break;
			}
			if (allUrls.length >= maxUrls) break;
		}

		const waybackCount = sourceCounts.waybackurls ?? 0;
		const gauCount = sourceCounts.gau ?? 0;
		const paramspiderCount = sourceCounts.paramspider ?? 0;
		console.log(
			`[history_url] waybackurls=${waybackCount} gau=${gauCount} paramspider=${paramspiderCount} merged=${allUrls.length} js=${jsUrls.size}`,
		);

		// 3. 解析 path + query 参数
		const endpointItems: Array<{
			url: string;
			path: string;
			method: string;
			source: 'historical';
			statusCode?: number;
		}> = [];
		const paramItems: Array<{ param: string; source: 'historical'; context?: string }> = [];
		const paramSeen = new Set<string>();

		for (const url of allUrls) {
			try {
				const parsed = new URL(url);
				const path = parsed.pathname || '/';
				endpointItems.push({ url, path, method: 'GET', source: 'historical' });

				// 提取 query 参数
				const params = parsed.searchParams;
				for (const key of params.keys()) {
					const pk = `${key}|historical`;
					if (paramSeen.has(pk)) continue;
					paramSeen.add(pk);
					paramItems.push({ param: key, source: 'historical', context: path });
				}
			} catch {
				// URL 解析失败跳过
			}
		}

		// 4. 入库
		const endpointCount = await upsertEndpoints(opts.webappId, endpointItems);
		const paramCount = await upsertParams(opts.webappId, paramItems);

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: {
				urlCount: allUrls.length,
				endpointCount,
				paramCount,
				jsCount: jsUrls.size,
				waybackurlsCount: waybackCount,
				gauCount,
				paramspiderCount,
			},
		});

		await auditLog({
			actor: 'tool:history_url',
			action: 'scan_finish',
			target: opts.webappId,
			decision: 'pass',
			reason: `urls=${allUrls.length} endpoints=${endpointCount} params=${paramCount} js=${jsUrls.size}`,
			meta: {
				domain: opts.domain,
				waybackurls: waybackCount,
				gau: gauCount,
				paramspider: paramspiderCount,
			},
		});

		return {
			urlCount: allUrls.length,
			endpointCount,
			paramCount,
			jsUrls: Array.from(jsUrls),
		};
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[history_url] failed:', err);
		return { urlCount: 0, endpointCount: 0, paramCount: 0, jsUrls: [] };
	}
}

/**
 * 判断 URL 是否属于目标站点（同根域或子域）
 *
 * 例：domain=example.com
 *   - https://example.com/...  ✅
 *   - https://www.example.com/... ✅
 *   - https://api.example.com/... ✅
 *   - https://other.com/...  ❌
 */
function isSameSite(url: string, rootDomain: string): boolean {
	try {
		const parsed = new URL(url);
		const host = parsed.hostname.toLowerCase();
		const root = rootDomain.toLowerCase().replace(/^\./, '');
		return host === root || host.endsWith(`.${root}`);
	} catch {
		return false;
	}
}
