/**
 * 单站元数据管道（site mode）
 *
 * 对给定 URL（或域名的 http+https）只收集「这一个站」的信息，**不扩大范围**：
 *   ❌ 不跑 subfinder / oneforall（子域枚举）
 *   ❌ 不跑 dnsx / nmap / masscan（IP、端口扫描）
 *   ❌ 不调 FOFA / ICP（关联资产反查）
 *
 * 收集内容（全部限定在同一 host）：
 *   1. httpx 单 URL 探测 → webapp 入库 + 指纹匹配
 *   2. HTML 深度分析（纯 TS，无 LLM）→ 框架 / 开发语言 / 构建工具 / 架构（SPA/MPA/SSR/静态）
 *   3. packer_infofinder → webpack 指纹 + sourcemap 可达性 + JS 清单
 *   4. katana 同域爬取（-fs fqdn，不跨主机）→ 页面 URL / 更多 JS
 *   5. dirsearch 小字典 → 目录端点 + 敏感路径
 *   6. JS 下载 + 接口/参数/密钥提取 → js_apis / params / findings
 *   7. source_collect（M4）→ 下载 JS + .map + 还原源码 + INDEX.json
 *   8. 评分 + metadata 快照 → 输出给渗透 Agent 消费
 *
 * 设计原则：与 deep_scan 一致——每个步骤独立 try/catch，失败不阻塞后续。
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { scoreWebappById } from '../scoring/pipeline.js';
import { type WebappSnapshot, generateSnapshot } from '../scoring/snapshot.js';
import { createScanRun, finishScanRun, upsertAsset } from '../storage/models/asset.js';
import {
	insertFinding,
	upsertEndpoints,
	upsertJsApis,
	upsertParams,
} from '../storage/models/recon.js';
import { getPg } from '../storage/pg.js';
import { type DirsearchRecord, runDirsearch } from '../tools/dirsearch.js';
import { runHttpx } from '../tools/httpx.js';
import { type KatanaRecord, runKatana } from '../tools/katana.js';
import { type PackerInfoResult, detectSourcemap } from '../tools/packer_infofinder.js';
import { isSensitivePath, severityForSecret } from './deep_scan.js';
import { scanJsFiles } from './js_scan.js';
import { collectSources } from './source_collect.js';
import { upsertWebappRecords } from './webapp_upsert.js';

// =============================================================================
// 类型定义
// =============================================================================

export type SiteArchitecture = 'spa' | 'mpa' | 'ssr' | 'static' | null;

export interface SingleSiteOptions {
	/** 跳过 katana 同域爬取（默认 false） */
	skipCrawl?: boolean;
	/** 跳过 dirsearch 小字典目录探测（默认 false） */
	skipDirscan?: boolean;
	/** 跳过 M4 source_collect 源码收集（默认 false） */
	skipSourceCollect?: boolean;
	/** JS 扫描/下载文件数上限（默认 50） */
	maxJsFiles?: number;
	/** sourcemap 还原文件数上限（默认 50） */
	maxMapFiles?: number;
	/** 跳过评分（默认 false，单站模式自动评分） */
	skipScoring?: boolean;
	/** 跳过 LLM 兜底分类（默认 false） */
	skipLlm?: boolean;
}

export interface SingleSiteResult {
	seedId: string;
	webappId: string | null;
	url: string;
	finalUrl?: string | null;
	title?: string | null;
	statusCode?: number | null;
	webserver?: string | null;
	tech: string[];
	fingerprints: string[];
	// —— 站信息（元数据）——
	framework: string[];
	language: string[];
	buildTool: string[];
	architecture: string | null;
	webpackDetected: boolean;
	sourceAvailable: boolean;
	jsFiles: string[];
	jsDownloaded: number;
	mapDownloaded: number;
	restoredFiles: number;
	jsApiCount: number;
	endpointCount: number;
	paramCount: number;
	secretCount: number;
	findingCount: number;
	score: number | null;
	role: string | null;
	snapshot: WebappSnapshot | null;
	durationMs: number;
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 对单个站点跑完整「单站元数据」收集
 *
 * @param seedId 种子 ID
 * @param targets 待探测 URL 列表（URL 种子 1 个；domain 种子 site 模式传 http+https 两个）
 */
export async function runSingleSitePipeline(
	seedId: string,
	targets: string[],
	opts: SingleSiteOptions = {},
): Promise<SingleSiteResult> {
	const startAt = Date.now();
	const maxJsFiles = opts.maxJsFiles ?? 50;
	const maxMapFiles = opts.maxMapFiles ?? 50;

	const result: SingleSiteResult = {
		seedId,
		webappId: null,
		url: targets[0] ?? '',
		tech: [],
		fingerprints: [],
		framework: [],
		language: [],
		buildTool: [],
		architecture: null,
		webpackDetected: false,
		sourceAvailable: false,
		jsFiles: [],
		jsDownloaded: 0,
		mapDownloaded: 0,
		restoredFiles: 0,
		jsApiCount: 0,
		endpointCount: 0,
		paramCount: 0,
		secretCount: 0,
		findingCount: 0,
		score: null,
		role: null,
		snapshot: null,
		durationMs: 0,
	};

	// 1. 探测目标 URL（只探测给定 URL，跟随重定向）
	const probeScanId = await createScanRun({ seedId, tool: 'httpx', params: { urls: targets } });
	let primaryWebappId: string | null = null;
	try {
		const records = await runHttpx({ urls: targets, timeoutMs: 10 * 60 * 1000 });
		if (records.length > 0) {
			// 父资产：host 对应的 domain 资产（单站模式只建这一条，不做子域）
			const parentHost = hostOf(records[0].url ?? targets[0]);
			const domainAssetId = await upsertAsset({
				type: 'domain',
				value: parentHost,
				valueNorm: parentHost,
				seedId,
				discoveredBy: 'seed',
			});
			await upsertWebappRecords(seedId, records, domainAssetId);
			// 主 webapp：优先取 200 的，否则取第一条；id 按归一化 url_norm 反查
			const live = records.find((r) => r.status_code === 200) ?? records[0];
			primaryWebappId = await findWebappIdByUrl(seedId, live?.url);
			result.url = live?.url ?? targets[0];
			result.finalUrl = live?.location ?? null;
			result.title = live?.title ?? null;
			result.statusCode = live?.status_code ?? null;
			result.webserver = live?.webserver ?? null;
			result.tech = Array.isArray(live?.tech) ? live.tech : live?.tech ? [live.tech] : [];
			result.fingerprints = [];
		}
		await finishScanRun(probeScanId, {
			status: 'done',
			resultSummary: { probed: targets.length, live: records.length },
		});
		console.log(`[single_site] httpx: ${records.length} live webapps (${targets.join(', ')})`);
	} catch (err) {
		await finishScanRun(probeScanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] httpx failed:', err);
	}

	// 探测失败（无存活 webapp）→ 直接返回
	if (!primaryWebappId) {
		result.durationMs = Date.now() - startAt;
		return result;
	}
	result.webappId = primaryWebappId;

	// 2. HTML 深度分析（框架/语言/构建工具/架构）——用主 webapp 的 URL
	const analysisUrl = result.finalUrl ?? result.url;
	const { analysis, page } = await analyzeSiteStep(primaryWebappId, analysisUrl, seedId);
	result.framework = analysis.framework;
	result.language = analysis.language;
	result.buildTool = analysis.buildTool;
	result.architecture = analysis.architecture;

	// 2.5 LLM 分析③：技术栈架构级分析（渲染方式/API 风格/认证机制/第三方集成）
	if (getConfig().llm.analysisEnabled) {
		await runArchAnalysisStep(primaryWebappId, analysisUrl, seedId, page?.html, analysis);
	}

	// 3. packer_infofinder：webpack 指纹 + sourcemap + JS 清单
	const packer = await runPackerStep(primaryWebappId, analysisUrl, seedId, maxJsFiles);
	result.webpackDetected = packer.info.webpackDetected;
	result.sourceAvailable = packer.info.sourceAvailable;
	result.jsFiles = packer.jsUrls;

	// 4. katana 同域爬取（-fs fqdn，只在本 host 内）
	let crawledUrls: string[] = [];
	if (!opts.skipCrawl) {
		const crawl = await runCrawlStep(primaryWebappId, analysisUrl, seedId);
		result.endpointCount += crawl.endpointCount;
		crawledUrls = crawl.jsUrls;
	}

	// 5. dirsearch 小字典
	if (!opts.skipDirscan) {
		const dirscan = await runDirscanStep(primaryWebappId, analysisUrl, seedId);
		result.endpointCount += dirscan.endpointCount;
		result.findingCount += dirscan.findingCount;
	}

	// 5.5 LLM 分析①：页面语义分类（高价值入口定位）
	if (getConfig().llm.analysisEnabled) {
		await runPageClassifyStep(primaryWebappId, analysisUrl, seedId);
	}

	// 6. JS 下载 + 接口/参数/密钥提取
	const mergedJs = mergeJsUrls(result.jsFiles, crawledUrls);
	result.jsFiles = mergedJs;
	if (mergedJs.length > 0) {
		const jsScan = await runJsScanStep(primaryWebappId, analysisUrl, mergedJs, seedId, maxJsFiles);
		result.jsApiCount += jsScan.jsApiCount;
		result.paramCount += jsScan.paramCount;
		result.secretCount += jsScan.secretCount;
		result.findingCount += jsScan.findingCount;
		result.jsDownloaded = jsScan.jsDownloaded;
	}

	// 6.5 LLM 分析②：接口聚类攻击面地图
	if (getConfig().llm.analysisEnabled) {
		await runAttackSurfaceStep(primaryWebappId, analysisUrl);
	}

	// 7. source_collect（M4）：下载 JS + .map + 还原 + INDEX.json
	if (!opts.skipSourceCollect) {
		const src = await runSourceCollectStep(
			primaryWebappId,
			analysisUrl,
			seedId,
			maxJsFiles,
			maxMapFiles,
		);
		result.sourceAvailable = result.sourceAvailable || src.sourceAvailable;
		result.jsDownloaded = Math.max(result.jsDownloaded, src.jsDownloaded);
		result.mapDownloaded = src.mapDownloaded;
		result.restoredFiles = src.restoredFiles;
		result.jsApiCount += src.jsApiCount;
		result.secretCount += src.secretCount;
		result.findingCount += src.findingCount;
		if (src.frameworks.length > 0) {
			for (const f of src.frameworks) {
				if (!result.framework.includes(f)) result.framework.push(f);
			}
		}
	}

	// 8. 评分 + metadata 快照
	if (!opts.skipScoring) {
		try {
			const scored = await scoreWebappById(primaryWebappId, { skipLlm: opts.skipLlm });
			result.score = scored.score;
			result.role = scored.role;
		} catch (err) {
			console.error('[single_site] scoring failed (non-blocking):', err);
		}
	}

	// 8.5 决策点 4：LLM 停止/继续判断（每 webapp 最多追加 1 轮）
	if (getConfig().llm.stopJudgeEnabled) {
		await runStopJudgeStep(
			primaryWebappId,
			analysisUrl,
			seedId,
			result,
			opts,
			maxJsFiles,
			maxMapFiles,
		);
	}

	try {
		result.snapshot = await generateSnapshot(primaryWebappId);
	} catch (err) {
		console.warn('[single_site] snapshot generation failed:', err);
	}

	result.durationMs = Date.now() - startAt;

	await auditLog({
		actor: 'pipeline:single_site',
		action: 'scan_finish',
		target: result.url,
		decision: 'pass',
		reason:
			`framework=[${result.framework.join(',')}] lang=[${result.language.join(',')}] ` +
			`arch=${result.architecture ?? '-'} webpack=${result.webpackDetected} sourcemap=${result.sourceAvailable} ` +
			`js=${result.jsFiles.length} apis=${result.jsApiCount} endpoints=${result.endpointCount} secrets=${result.secretCount}`,
		meta: {
			seedId,
			webappId: primaryWebappId,
			framework: result.framework,
			language: result.language,
			buildTool: result.buildTool,
			architecture: result.architecture,
			webpackDetected: result.webpackDetected,
			sourceAvailable: result.sourceAvailable,
			jsFileCount: result.jsFiles.length,
			durationMs: result.durationMs,
		},
	});

	console.log(
		`[single_site] done in ${(result.durationMs / 1000).toFixed(1)}s | ` +
			`framework=[${result.framework.join(',')}] lang=[${result.language.join(',')}] build=[${result.buildTool.join(',')}] ` +
			`arch=${result.architecture ?? '-'} webpack=${result.webpackDetected} sourcemap=${result.sourceAvailable} ` +
			`js=${result.jsFiles.length} apis=${result.jsApiCount} secrets=${result.secretCount} score=${result.score ?? '-'}`,
	);

	return result;
}

// =============================================================================
// 步骤实现
// =============================================================================

// ---------- 步骤 2：HTML 深度分析 ----------

export async function analyzeSiteStep(
	webappId: string,
	url: string,
	seedId: string,
): Promise<{ analysis: SiteAnalysis; page: SitePage | null }> {
	const scanId = await createScanRun({
		seedId,
		assetId: webappId,
		tool: 'site_analysis',
		params: { url },
	});
	try {
		const page = await fetchSiteHtml(url);
		if (!page) {
			await finishScanRun(scanId, { status: 'done', resultSummary: { htmlFetched: false } });
			return { analysis: emptyAnalysis(), page: null };
		}
		const analysis = analyzeSiteHtml(page.html, page.headers, page.finalUrl);

		// LLM 兜底：正则识别不到框架/语言时，把 HTML 头 + 响应头 + JS 文件名喂给 flash
		// （规则库覆盖不到的冷门框架/私有架构；触发条件严格：framework 和 language 都为空）
		if (
			getConfig().llm.techDetectEnabled &&
			analysis.framework.length === 0 &&
			analysis.language.length === 0
		) {
			try {
				const { detectTechByLlm } = await import('../scoring/llm_tech_detect.js');
				const headSnippet = page.html.slice(0, 3000).replace(/\s+/g, ' ').trim();
				const llmResult = await detectTechByLlm({
					webappId,
					url: page.finalUrl,
					headers: page.headers,
					htmlSnippet: headSnippet,
					jsFiles: analysis.jsUrls,
				});
				// 任一字段有值即合并（framework/language/buildTool/architecture 都可能单独补上）
				if (
					llmResult &&
					(llmResult.framework.length > 0 ||
						llmResult.language.length > 0 ||
						llmResult.buildTool.length > 0 ||
						llmResult.architecture !== null)
				) {
					for (const f of llmResult.framework) {
						if (!analysis.framework.includes(f)) analysis.framework.push(f);
					}
					for (const l of llmResult.language) {
						if (!analysis.language.includes(l)) analysis.language.push(l);
					}
					for (const b of llmResult.buildTool) {
						if (!analysis.buildTool.includes(b)) analysis.buildTool.push(b);
					}
					if (!analysis.architecture) analysis.architecture = llmResult.architecture;
					console.log(
						`[single_site] tech_detect LLM fallback: framework=[${analysis.framework.join(',')}] lang=[${analysis.language.join(',')}] arch=${analysis.architecture ?? '-'}`,
					);
				}
			} catch (err) {
				console.warn('[single_site] tech_detect LLM fallback failed (non-blocking):', err);
			}
		}

		// 写入 webapp.meta
		const pool = getPg();
		await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
			JSON.stringify({
				site_framework: analysis.framework,
				site_language: analysis.language,
				site_build_tool: analysis.buildTool,
				site_architecture: analysis.architecture,
				site_generator: analysis.generator ?? null,
				site_js_file_count: analysis.jsUrls.length,
				site_analyzed_at: new Date().toISOString(),
			}),
			webappId,
		]);
		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: {
				framework: analysis.framework,
				language: analysis.language,
				buildTool: analysis.buildTool,
				architecture: analysis.architecture,
			},
		});
		console.log(
			`[single_site] analysis: framework=[${analysis.framework.join(',')}] lang=[${analysis.language.join(',')}] ` +
				`build=[${analysis.buildTool.join(',')}] arch=${analysis.architecture ?? '-'}`,
		);
		return { analysis, page };
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] site analysis failed:', err);
		return { analysis: emptyAnalysis(), page: null };
	}
}

// ---------- 步骤 3：packer_infofinder ----------

async function runPackerStep(
	webappId: string,
	url: string,
	seedId: string,
	maxJsFiles: number,
): Promise<{ info: PackerInfoResult; jsUrls: string[] }> {
	const scanId = await createScanRun({
		seedId,
		assetId: webappId,
		tool: 'packer_infofinder',
		params: { url },
	});
	try {
		const info = await detectSourcemap({
			url,
			timeoutMs: 15_000,
			maxJsFiles,
			probeMapPaths: true,
		});
		// 写入 webapp.meta（供 snapshot site.webpack_detected 读取）
		try {
			const pool = getPg();
			await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
				JSON.stringify({
					site_webpack_detected: info.webpackDetected,
					site_packer_frameworks: info.frameworks,
				}),
				webappId,
			]);
		} catch {
			// meta 写失败不阻塞
		}
		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: {
				webpackDetected: info.webpackDetected,
				frameworks: info.frameworks,
				js: info.jsFiles.length,
				maps: info.mapFiles.length,
				sourceAvailable: info.sourceAvailable,
			},
		});
		console.log(
			`[single_site] packer: webpack=${info.webpackDetected} frameworks=[${info.frameworks.join(',')}] ` +
				`js=${info.jsFiles.length} maps=${info.mapFiles.length} sourceAvailable=${info.sourceAvailable}`,
		);
		return { info, jsUrls: info.jsFiles };
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] packer_infofinder failed:', err);
		return { info: emptyPackerInfo(), jsUrls: [] };
	}
}

// ---------- 步骤 4：katana 同域爬取 ----------

async function runCrawlStep(
	webappId: string,
	url: string,
	seedId: string,
): Promise<{ jsUrls: string[]; endpointCount: number }> {
	const scanId = await createScanRun({
		seedId,
		assetId: webappId,
		tool: 'katana',
		params: { url, depth: 2 },
	});
	try {
		const records = await runKatana({
			url,
			depth: 2,
			sameDomain: true, // -fs fqdn：严格限定同一 host
			timeoutMs: 3 * 60 * 1000,
		});
		const jsUrls = records
			.filter((r: KatanaRecord) => /\.(js|mjs)(\?|$)/i.test(r.url))
			.map((r: KatanaRecord) => r.url);

		// 所有爬到的 URL 入 endpoints（source=js，与 deep_scan 一致）
		const endpoints = records
			.filter((r) => r.url)
			.map((r) => {
				try {
					const parsed = new URL(r.url);
					return {
						url: r.url,
						path: parsed.pathname || '/',
						method: r.method ?? 'GET',
						source: 'js' as const,
					};
				} catch {
					return null;
				}
			})
			.filter((x): x is { url: string; path: string; method: string; source: 'js' } => x !== null);
		const endpointCount = await upsertEndpoints(webappId, endpoints);

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { crawled: records.length, js: jsUrls.length },
		});
		console.log(`[single_site] katana: ${records.length} urls crawled, ${jsUrls.length} js files`);
		return { jsUrls, endpointCount };
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] katana failed:', err);
		return { jsUrls: [], endpointCount: 0 };
	}
}

// ---------- 步骤 5：dirsearch 小字典 ----------

async function runDirscanStep(
	webappId: string,
	url: string,
	seedId: string,
): Promise<{ endpointCount: number; findingCount: number }> {
	// dirsearch 目标用站点根（scheme://host[:port]），不做子路径爆破
	const baseUrl = originOf(url);
	const scanId = await createScanRun({
		seedId,
		assetId: webappId,
		tool: 'dirscan',
		params: { url: baseUrl },
	});
	try {
		const records: DirsearchRecord[] = await runDirsearch({
			url: baseUrl,
			timeoutMs: 5 * 60 * 1000,
			excludeStatus: [404],
			// 小字典：dirsearch 内置默认字典（不传 wordlist）
		});

		const endpointItems = records.map((r) => ({
			url: r.url,
			path: r.path,
			method: 'GET',
			source: 'dirscan' as const,
			statusCode: r.status,
		}));
		const endpointCount = await upsertEndpoints(webappId, endpointItems);

		// 敏感路径入 findings
		let findingCount = 0;
		for (const r of records) {
			if (isSensitivePath(r.path)) {
				await insertFinding({
					assetId: webappId,
					webappId,
					type: 'sensitive_path',
					severity: r.status === 200 ? 'medium' : 'low',
					detail: `目录探测发现敏感路径：${r.path}（${r.status}）`,
					evidence: `HTTP ${r.status}`,
					sourceTool: 'dirsearch',
					meta: { path: r.path, status: r.status },
				});
				findingCount++;
			}
		}

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { found: records.length, sensitive: findingCount },
		});
		console.log(
			`[single_site] dirsearch: ${records.length} paths found (sensitive=${findingCount})`,
		);
		return { endpointCount, findingCount };
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] dirsearch failed:', err);
		return { endpointCount: 0, findingCount: 0 };
	}
}

// ---------- 步骤 6：JS 扫描 ----------

async function runJsScanStep(
	webappId: string,
	url: string,
	jsUrls: string[],
	seedId: string,
	maxJsFiles: number,
): Promise<{
	jsDownloaded: number;
	jsApiCount: number;
	paramCount: number;
	secretCount: number;
	findingCount: number;
}> {
	const scanId = await createScanRun({
		seedId,
		assetId: webappId,
		tool: 'jsmining',
		params: { url, jsFiles: jsUrls.length },
	});

	try {
		// 限制 JS 文件数
		const capped = jsUrls.slice(0, maxJsFiles);
		if (capped.length < jsUrls.length) {
			console.log(`[single_site] js cap: ${jsUrls.length} → ${maxJsFiles}`);
		}

		const jsScan = await scanJsFiles({ urls: capped, useLlm: true, webappId });

		// JS 接口入库
		const jsApiItems = jsScan.endpoints.map((ep) => ({
			apiPath: ep.path,
			method: ep.method,
			params: ep.params ?? [],
			sourceJs: ep.sourceJs,
		}));
		const jsApiCount = await upsertJsApis(webappId, jsApiItems);

		// 参数入库
		const jsParamItems = jsScan.endpoints
			.filter((ep) => ep.params && ep.params.length > 0)
			.flatMap((ep) =>
				(ep.params ?? []).map((p) => ({ param: p, source: 'js' as const, context: ep.sourceJs })),
			);
		const paramCount = await upsertParams(webappId, jsParamItems);

		// 敏感信息 findings
		let secretCount = 0;
		let findingCount = 0;
		for (const s of jsScan.secrets) {
			await insertFinding({
				assetId: webappId,
				webappId,
				type: 'secret',
				severity: severityForSecret(s.type),
				detail: `JS 中发现 ${s.type}（来源：${s.sourceJs}）`,
				evidence: s.value,
				sourceTool: 'js_scan',
				meta: { type: s.type, sourceJs: s.sourceJs, context: s.context?.slice(0, 200) },
			});
			secretCount++;
			findingCount++;
		}

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: {
				jsFiles: jsScan.fetchedCount,
				jsFailed: jsScan.failedCount,
				endpoints: jsApiCount,
				params: paramCount,
				secrets: secretCount,
			},
		});
		console.log(
			`[single_site] js_scan: fetched=${jsScan.fetchedCount} failed=${jsScan.failedCount} ` +
				`apis=${jsApiCount} params=${paramCount} secrets=${secretCount}`,
		);
		return { jsDownloaded: jsScan.fetchedCount, jsApiCount, paramCount, secretCount, findingCount };
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] js_scan failed:', err);
		return { jsDownloaded: 0, jsApiCount: 0, paramCount: 0, secretCount: 0, findingCount: 0 };
	}
}

// ---------- 步骤 7：source_collect（M4）----------

async function runSourceCollectStep(
	webappId: string,
	url: string,
	seedId: string,
	maxJsFiles: number,
	maxMapFiles: number,
): Promise<{
	sourceAvailable: boolean;
	jsDownloaded: number;
	mapDownloaded: number;
	restoredFiles: number;
	jsApiCount: number;
	secretCount: number;
	findingCount: number;
	frameworks: string[];
}> {
	const scanId = await createScanRun({
		seedId,
		assetId: webappId,
		tool: 'source_collect',
		params: { url },
	});
	try {
		const result = await collectSources({
			webappId,
			url,
			maxJsFiles,
			maxMapFiles,
			force: false,
		});

		// sourcemap 泄露 → finding
		let findingCount = 0;
		if (result.sourceAvailable) {
			try {
				await insertFinding({
					assetId: webappId,
					webappId,
					type: 'sourcemap',
					severity: 'high',
					detail: `Sourcemap exposed at ${url}`,
					evidence: result.info.mapFiles.slice(0, 5).join('\n'),
					sourceTool: 'packer_infofinder',
					meta: {
						url,
						mapFiles: result.info.mapFiles,
						frameworks: result.info.frameworks,
						sourceDir: result.sourceDir,
					},
				});
				findingCount++;
			} catch {
				// ignore
			}
		}

		// 提取的接口入 js_apis
		let jsApiCount = 0;
		if (result.endpoints.length > 0) {
			try {
				jsApiCount = await upsertJsApis(
					webappId,
					result.endpoints.map((ep) => ({
						apiPath: ep.path,
						method: ep.method,
						params: ep.params ?? [],
						sourceJs: ep.sourceJs,
					})),
				);
			} catch {
				// ignore
			}
		}

		// 密钥入 findings
		let secretCount = 0;
		for (const sec of result.secrets) {
			try {
				await insertFinding({
					assetId: webappId,
					webappId,
					type: 'secret',
					severity: severityForSecret(sec.type),
					detail: `${sec.type} leaked in JS: ${sec.value}`,
					evidence: sec.context ?? '',
					sourceTool: 'source_collect',
					meta: {
						secretType: sec.type,
						sourceJs: sec.sourceJs,
						maskedValue: sec.value,
					},
				});
				secretCount++;
				findingCount++;
			} catch {
				// ignore
			}
		}

		// 源码审计（source-auditor）：还原出源码时，LLM 审 INDEX.json + 关键文件提渗透线索
		let auditFindingCount = 0;
		if (result.sourceAvailable || (result.restore?.restoredCount ?? 0) > 0) {
			try {
				const { auditSourceDump } = await import('./source_audit.js');
				const audit = await auditSourceDump({
					webappId,
					url,
					sourceDir: result.sourceDir,
				});
				if (audit) {
					auditFindingCount = audit.findings.length;
					console.log(
						`[single_site] source_audit: ${audit.findings.length} findings (fromCache=${audit.fromCache})`,
					);
				}
			} catch (err) {
				console.warn('[single_site] source_audit failed (non-blocking):', err);
			}
		}

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: {
				sourceAvailable: result.sourceAvailable,
				jsDownloaded: result.jsDownloaded,
				mapDownloaded: result.mapDownloaded,
				restoredCount: result.restore?.restoredCount ?? 0,
				endpoints: result.endpoints.length,
				secrets: result.secrets.length,
				sourceAuditFindings: auditFindingCount,
			},
		});
		console.log(
			`[single_site] source_collect: sourcemap=${result.sourceAvailable} js=${result.jsDownloaded} ` +
				`map=${result.mapDownloaded} restored=${result.restore?.restoredCount ?? 0} ` +
				`endpoints=${result.endpoints.length} secrets=${result.secrets.length} audit=${auditFindingCount}`,
		);
		return {
			sourceAvailable: result.sourceAvailable,
			jsDownloaded: result.jsDownloaded,
			mapDownloaded: result.mapDownloaded,
			restoredFiles: result.restore?.restoredCount ?? 0,
			jsApiCount,
			secretCount,
			findingCount: findingCount + auditFindingCount,
			frameworks: result.info.frameworks,
		};
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		console.error('[single_site] source_collect failed:', err);
		return {
			sourceAvailable: false,
			jsDownloaded: 0,
			mapDownloaded: 0,
			restoredFiles: 0,
			jsApiCount: 0,
			secretCount: 0,
			findingCount: 0,
			frameworks: [],
		};
	}
}

// =============================================================================
// HTML 站信息分析（纯 TS，无 LLM）
// =============================================================================

export interface SiteAnalysis {
	/** 前端/后端框架（react/vue/next/thinkphp...） */
	framework: string[];
	/** 开发语言（php/java/csharp/nodejs/python...） */
	language: string[];
	/** 构建工具（webpack/vite...） */
	buildTool: string[];
	/** 架构形态（spa/mpa/ssr/static） */
	architecture: SiteArchitecture;
	/** HTML 中引用的 JS 文件 URL（未截断） */
	jsUrls: string[];
	/** meta generator 内容（如有） */
	generator?: string;
}

export function analyzeSiteHtml(
	html: string,
	headers: Record<string, string> | undefined,
	baseUrl: string,
): SiteAnalysis {
	const framework = detectFrameworks(html);
	const language = detectLanguages(html, headers);
	const buildTool = detectBuildTools(html, framework);
	const architecture = detectArchitecture(html, framework, buildTool);
	const jsUrls = extractScriptSrcs(html, baseUrl);
	const generator = extractGenerator(html);

	return { framework, language, buildTool, architecture, jsUrls, generator };
}

function emptyAnalysis(): SiteAnalysis {
	return { framework: [], language: [], buildTool: [], architecture: null, jsUrls: [] };
}

// ---------- 框架检测 ----------

const FRAMEWORK_RULES: Array<[string, RegExp]> = [
	['next', /__NEXT_DATA__/],
	['nuxt', /__NUXT__/],
	['react', /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react(\.production)?\.min\.js|ReactDOM/],
	['vue', /data-v-[a-f0-9]{6,}|__VUE__|vue(\.production)?\.min\.js|createApp\(/],
	['angular', /ng-version=|ng-app=|angular\.min\.js|@angular/],
	['jquery', /jquery(\.min)?\.js|jQuery/],
	['bootstrap', /bootstrap(\.min)?\.(css|js)|data-bs-(toggle|target|theme|ride)/],
	['layui', /layui(\.js)?|laytpl/],
	['element-ui', /element-ui|element-plus|el-icon-|el-upload|el-button/],
	['ant-design', /ant-design|antd\.min|@antv|ant-btn|ant-input/],
	['wordpress', /wp-content|wp-includes|wp-json|wordpress/],
	['thinkphp', /thinkphp|think\.php|__token__|think-app/],
	['laravel', /laravel|csrf-token|laravel_session/],
	['drupal', /drupal|Drupal\.settings/],
	['struts', /struts|Struts/],
	['spring', /springframework|org\.springframework|__spring/],
	['gatsby', /___gatsby/],
	['docusaurus', /docusaurus/],
	['ckeditor', /ckeditor/],
	['umeditor', /umeditor/],
	['swiper', /swiper(\.min)?\.js/],
	['echarts', /echarts(\.min)?\.js/],
	['highcharts', /highcharts(\.min)?\.js/],
];

function detectFrameworks(html: string): string[] {
	const out: string[] = [];
	for (const [name, re] of FRAMEWORK_RULES) {
		re.lastIndex = 0;
		if (re.test(html) && !out.includes(name)) out.push(name);
	}
	return out;
}

// ---------- 语言检测（响应头 + HTML 线索）----------

function detectLanguages(html: string, headers: Record<string, string> | undefined): string[] {
	const out: string[] = [];
	const h = Object.fromEntries(Object.entries(headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
	const xPowered = h['x-powered-by'] ?? '';

	// 响应头
	if (/ASP\.NET/i.test(xPowered) || h['x-aspnet-version']) out.push('csharp');
	if (/PHP/i.test(xPowered)) out.push('php');
	if (/Express/i.test(xPowered)) out.push('nodejs');
	if (/java|Servlet/i.test(xPowered)) out.push('java');

	// HTML 线索
	if (/JSESSIONID/i.test(html)) out.push('java');
	if (/\.jsp(\?|")|\.do(\?|")|\.action(\?|")/i.test(html)) out.push('java');
	if (/\.aspx|\.ashx/i.test(html)) out.push('csharp');
	if (/\.php(\?|")/i.test(html)) out.push('php');
	if (/\.py(\?|")/i.test(html)) out.push('python');
	if (/\.go(\?|")/i.test(html)) out.push('golang');
	if (/\.rb(\?|")/i.test(html)) out.push('ruby');

	// meta generator
	const generator = extractGenerator(html);
	if (generator) {
		if (/WordPress|Typecho|ThinkPHP|Laravel/i.test(generator)) out.push('php');
		if (/Drupal/i.test(generator)) out.push('php');
		if (/Jekyll/i.test(generator)) out.push('ruby');
		if (/Hugo/i.test(generator)) out.push('golang');
		if (/Hexo|Ghost/i.test(generator)) out.push('nodejs');
	}

	return [...new Set(out)];
}

function extractGenerator(html: string): string | undefined {
	const m = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
	return m?.[1]?.trim() || undefined;
}

// ---------- 构建工具检测 ----------

function detectBuildTools(html: string, framework: string[]): string[] {
	const out: string[] = [];
	if (/webpackJsonp|webpackChunk|__webpack_require__|webpack-/i.test(html)) out.push('webpack');
	if (/\/@vite|vite\/client|__VITE__|import\.meta\.env/i.test(html)) out.push('vite');
	// SSR 框架自带构建体系
	if (
		framework.includes('next') ||
		framework.includes('nuxt') ||
		framework.includes('gatsby') ||
		framework.includes('docusaurus')
	) {
		if (!out.includes('webpack')) out.push('webpack');
	}
	return out;
}

// ---------- 架构形态检测 ----------

function detectArchitecture(
	html: string,
	framework: string[],
	buildTool: string[],
): SiteArchitecture {
	// SSR：服务端渲染框架带页面数据
	if (framework.some((f) => ['next', 'nuxt', 'gatsby', 'docusaurus'].includes(f))) {
		return 'ssr';
	}
	// SPA：挂载点 + noscript 提示
	const hasRoot = /<div[^>]+id=["'](root|app|app-root|app-root|mount|__nuxt|__next)["']/.test(html);
	const hasNoscript =
		/<noscript[^>]*>[\s\S]{0,200}?javascript/i.test(html) || /<noscript>/.test(html);
	if (hasRoot || hasNoscript) {
		return 'spa';
	}
	// 静态站：Hugo/Jekyll/Hexo 生成器，且 JS 极少
	const generator = extractGenerator(html);
	if (generator && /Hugo|Jekyll|Hexo/i.test(generator)) {
		return 'static';
	}
	// MPA：多个 .html 页面链接
	const staticLinks = (html.match(/href=["'][^"']*\.html?(?:["'?#]|$)/gi) ?? []).length;
	if (staticLinks > 3) {
		return 'mpa';
	}
	void buildTool;
	return null;
}

// ---------- HTML 脚本提取 ----------

/**
 * 从 HTML 中提取 <script src> 的 JS URL（与 packer_infofinder 同规则）
 */
function extractScriptSrcs(html: string, baseUrl: string): string[] {
	const urls: string[] = [];
	const scriptRegex = /<script[^>]+src=(?:"([^"]+)"|'([^']+)'|([^\s>]+))[^>]*>/gi;
	for (const match of html.matchAll(scriptRegex)) {
		const src = match[1] ?? match[2] ?? match[3];
		if (!src) continue;
		const abs = resolveUrl(src, baseUrl);
		if (abs && /\.(js|mjs)(\?|$)/i.test(abs)) {
			urls.push(abs);
		}
	}
	return [...new Set(urls)];
}

function resolveUrl(src: string, baseUrl: string): string | null {
	try {
		if (src.startsWith('//')) {
			const proto = baseUrl.startsWith('https://') ? 'https:' : 'http:';
			return proto + src;
		}
		return new URL(src, baseUrl).toString();
	} catch {
		return null;
	}
}

// =============================================================================
// 内部工具
// =============================================================================

interface SitePage {
	html: string;
	headers: Record<string, string>;
	finalUrl: string;
	status: number;
}

/** 抓取页面 HTML + 响应头（跟随重定向） */
async function fetchSiteHtml(url: string, timeoutMs = 20_000): Promise<SitePage | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await fetch(url, {
			method: 'GET',
			signal: controller.signal,
			redirect: 'follow',
			headers: {
				'User-Agent': 'Mozilla/5.0 (compatible; ck-recon/0.1; site-analysis)',
				Accept: 'text/html,application/xhtml+xml,*/*',
			},
		});
		clearTimeout(timer);
		if (!resp.ok) return null;
		const html = await resp.text();
		const headers: Record<string, string> = {};
		resp.headers.forEach((v, k) => {
			headers[k] = v;
		});
		return { html, headers, finalUrl: resp.url, status: resp.status };
	} catch {
		clearTimeout(timer);
		return null;
	}
}

/** 从 httpx 记录 URL 反查已入库 webapp 的 asset_id */
async function findWebappIdByUrl(seedId: string, url: string | undefined): Promise<string | null> {
	if (!url) return null;
	let parsedUrl: URL;
	try {
		parsedUrl = new URL(url);
	} catch {
		return null;
	}
	const scheme = parsedUrl.protocol.replace(':', '');
	const host = parsedUrl.hostname.toLowerCase();
	const defaultPort = scheme === 'https' ? 443 : 80;
	const port = parsedUrl.port ? Number.parseInt(parsedUrl.port, 10) : defaultPort;
	const urlNorm = `${scheme}://${host}${port !== defaultPort ? `:${port}` : ''}${parsedUrl.pathname.replace(/\/+$/, '') || '/'}`;
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT asset_id FROM webapps WHERE url_norm = $1 AND asset_id IN (
       SELECT id FROM assets WHERE seed_id = $2
     ) LIMIT 1`,
		[urlNorm, seedId],
	);
	return rows[0]?.asset_id ?? null;
}

function hostOf(url: string): string {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return url;
	}
}

function originOf(url: string): string {
	try {
		const u = new URL(url);
		return `${u.protocol}//${u.host}`;
	} catch {
		return url;
	}
}

/** 合并 JS URL 清单（去重保序） */
function mergeJsUrls(...lists: string[][]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const list of lists) {
		for (const u of list) {
			if (!seen.has(u)) {
				seen.add(u);
				out.push(u);
			}
		}
	}
	return out;
}

function emptyPackerInfo(): PackerInfoResult {
	return {
		sourceAvailable: false,
		webpackDetected: false,
		frameworks: [],
		jsFiles: [],
		mapFiles: [],
		durationMs: 0,
	};
}

// =============================================================================
// 决策点 4：停止/继续判断（LLM Stop-Judge）
// =============================================================================

/**
 * LLM 判断是否追加深挖一轮；每 webapp 最多追加 1 次（meta.deep_judge_at 防重复）
 */
async function runStopJudgeStep(
	webappId: string,
	url: string,
	seedId: string,
	result: SingleSiteResult,
	opts: SingleSiteOptions,
	maxJsFiles: number,
	maxMapFiles: number,
): Promise<void> {
	try {
		// 1. 防重复：已判断过则跳过
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT meta->>'deep_judge_at' AS judged_at FROM webapps WHERE asset_id = $1`,
			[webappId],
		);
		if (rows[0]?.judged_at) {
			console.log('[single_site] stop_judge: already judged, skip');
			return;
		}

		// 2. 调 LLM 判断
		const { judgeContinueDeep } = await import('../agents/llm_stop_judge.js');
		const judge = await judgeContinueDeep({
			webappId,
			url,
			summary: {
				framework: result.framework,
				language: result.language,
				jsFileCount: result.jsFiles.length,
				jsApiCount: result.jsApiCount,
				endpointCount: result.endpointCount,
				secretCount: result.secretCount,
				sourceAvailable: result.sourceAvailable,
				restoredFiles: result.restoredFiles,
			},
			score: result.score,
			role: result.role,
			level: null,
		});

		// 3. 标记已判断（无论结果，防止重复问）
		await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
			JSON.stringify({ deep_judge_at: new Date().toISOString() }),
			webappId,
		]);

		if (!judge || !judge.continueDeep || !judge.suggestedNext) {
			console.log(`[single_site] stop_judge: continue=${judge?.continueDeep ?? false}，正常收尾`);
			return;
		}

		// 4. 追加执行（限定现有任务，同 host 约束不变）
		console.log(
			`[single_site] stop_judge: 追加深挖任务 ${judge.suggestedNext} (${judge.reasoning})`,
		);
		switch (judge.suggestedNext) {
			case 'jsmining': {
				const jsScan = await runJsScanStep(webappId, url, result.jsFiles, seedId, maxJsFiles);
				result.jsApiCount = Math.max(result.jsApiCount, jsScan.jsApiCount);
				result.paramCount += jsScan.paramCount;
				result.secretCount += jsScan.secretCount;
				result.findingCount += jsScan.findingCount;
				result.jsDownloaded = Math.max(result.jsDownloaded, jsScan.jsDownloaded);
				break;
			}
			case 'source_collect': {
				if (!opts.skipSourceCollect) {
					const src = await runSourceCollectStep(webappId, url, seedId, maxJsFiles, maxMapFiles);
					result.sourceAvailable = result.sourceAvailable || src.sourceAvailable;
					result.mapDownloaded = src.mapDownloaded;
					result.restoredFiles = src.restoredFiles;
					result.jsApiCount += src.jsApiCount;
					result.secretCount += src.secretCount;
					result.findingCount += src.findingCount;
				}
				break;
			}
			case 'dirscan': {
				if (!opts.skipDirscan) {
					const dirscan = await runDirscanStep(webappId, url, seedId);
					result.endpointCount += dirscan.endpointCount;
					result.findingCount += dirscan.findingCount;
				}
				break;
			}
			case 'history_url':
				// single_site 无历史 URL 步骤，提示走 deep-scan
				console.log('[single_site] stop_judge: history_url 建议请用 cli deep-scan <webappId> 执行');
				break;
		}

		// 5. 追加后重新评分 + 快照
		if (!opts.skipScoring) {
			try {
				const scored = await scoreWebappById(webappId, { skipLlm: opts.skipLlm });
				result.score = scored.score;
				result.role = scored.role;
			} catch (err) {
				console.error('[single_site] re-scoring failed (non-blocking):', err);
			}
		}
	} catch (err) {
		console.warn('[single_site] stop_judge failed (non-blocking):', err);
	}
}

// =============================================================================
// LLM 分析驱动 Phase 1（页面分类 / 攻击面地图 / 架构级分析）
// =============================================================================

/**
 * LLM 分析③：技术栈架构级分析
 */
export async function runArchAnalysisStep(
	webappId: string,
	url: string,
	seedId: string,
	html: string | undefined,
	analysis: SiteAnalysis,
): Promise<void> {
	try {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT meta->>'site_arch_analyzed_at' AS at FROM webapps WHERE asset_id = $1`,
			[webappId],
		);
		if (rows[0]?.at) return; // 防重复
		if (!html) return;

		const { analyzeArchitecture } = await import('../scoring/llm_arch_analysis.js');
		await analyzeArchitecture({
			webappId,
			url,
			htmlSnippet: html.slice(0, 3000).replace(/\s+/g, ' ').trim(),
			jsFiles: analysis.jsUrls,
			framework: analysis.framework,
			architecture: analysis.architecture,
		});
		void seedId;
	} catch (err) {
		console.warn('[single_site] arch_analysis failed (non-blocking):', err);
	}
}

/**
 * LLM 分析①：页面语义分类（高价值入口定位）
 */
export async function runPageClassifyStep(
	webappId: string,
	url: string,
	seedId: string,
): Promise<void> {
	try {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT meta->>'page_classified_at' AS at FROM webapps WHERE asset_id = $1`,
			[webappId],
		);
		if (rows[0]?.at) return; // 防重复

		// 取已收集的 endpoints
		const { rows: eps } = await pool.query(
			'SELECT path, method, source FROM endpoints WHERE webapp_id = $1 LIMIT 100',
			[webappId],
		);
		if (eps.length === 0) return;

		const { classifyPagesByLlm } = await import('../scoring/llm_page_classify.js');
		await classifyPagesByLlm({
			webappId,
			url,
			endpoints: eps.map((e: { path: string; method: string; source: string }) => ({
				path: e.path,
				method: e.method,
				source: e.source,
			})),
		});
		void seedId;
	} catch (err) {
		console.warn('[single_site] page_classify failed (non-blocking):', err);
	}
}

/**
 * LLM 分析②：接口聚类攻击面地图
 */
async function runAttackSurfaceStep(webappId: string, url: string): Promise<void> {
	try {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT meta->>'attack_surface_at' AS at FROM webapps WHERE asset_id = $1`,
			[webappId],
		);
		if (rows[0]?.at) return; // 防重复

		// 取 js_apis
		const { rows: apis } = await pool.query(
			'SELECT api_path, method, params FROM js_apis WHERE webapp_id = $1 LIMIT 150',
			[webappId],
		);
		if (apis.length === 0) return;

		const { analyzeAttackSurface } = await import('../scoring/llm_attack_surface.js');
		await analyzeAttackSurface({
			webappId,
			url,
			jsApis: apis.map((a: { api_path: string; method: string; params: string[] }) => ({
				apiPath: a.api_path,
				method: a.method,
				params: a.params ?? [],
			})),
		});
	} catch (err) {
		console.warn('[single_site] attack_surface failed (non-blocking):', err);
	}
}
