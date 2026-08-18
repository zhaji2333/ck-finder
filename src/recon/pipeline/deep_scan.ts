/**
 * M3/M4 深度扫描管道
 *
 * 对单个 webapp 按 suggested_next 跑深度扫描任务：
 *   - history_url   → waybackurls + gau + endpoints/params 入库（M3）
 *   - jsmining      → katana 抓 JS 文件 + JS 接口/敏感信息提取 + 入库（M3）
 *   - dirscan       → dirsearch 目录爆破 + endpoints 入库（仅 L1+）（M3）
 *   - （github_search 已移除：GitHub 匿名 API 限流 + 零产出，纯亏损）
 *   - source_collect→ webpack 源码完整收集 + sourcemap 还原 + INDEX.json（M4）
 *
 * 调用入口：
 *   1. pipeline.runner 在 M2 评分完成后调 deepScanWebapp(webappId)
 *   2. CLI 单独调 cli deep-scan <webappId>
 *
 * 设计要点：
 * - 按 suggested_next 顺序跑（被动任务在前，主动任务在后）
 * - 每个任务独立 try/catch，失败不阻塞下一个
 * - 每个任务前先查 scan_runs，最近跑过的跳过（避免重扫）
 * - 跑完后更新 webapp.meta.deep_scan_done = true
 */

import { auditLog } from '../gate/audit_log.js';
import type { SuggestedNext } from '../gate/task_gate.js';
import { createScanRun, finishScanRun } from '../storage/models/asset.js';
import {
	type UpsertFindingInput,
	insertFinding,
	isWebappScannedRecently,
	upsertEndpoints,
	upsertJsApis,
	upsertParams,
} from '../storage/models/recon.js';
import { getPg } from '../storage/pg.js';
import { type DirsearchRecord, runDirsearch } from '../tools/dirsearch.js';
import { type KatanaRecord, runKatana } from '../tools/katana.js';
import { runWafw00f } from '../tools/wafw00f.js';
import { collectHistoryUrls } from './history_url.js';
import { scanJsFiles } from './js_scan.js';
import { collectSources } from './source_collect.js';

export interface DeepScanOptions {
	/** 跳过最近已扫的任务（默认 7 天内跳过） */
	skipRecent?: boolean;
	/** 强制重跑（忽略 skipRecent） */
	force?: boolean;
	/** 跳过指定任务 */
	skipTasks?: SuggestedNext[];
	/** JS 扫描的文件数上限（默认 50） */
	maxJsFiles?: number;
	/** 历史 URL 数量上限（默认 2000） */
	maxHistoryUrls?: number;
	/** dirsearch 超时（毫秒，默认 5 分钟） */
	dirscanTimeoutMs?: number;
	/** 是否跑 wafw00f 补全 WAF 信息（默认 true） */
	detectWaf?: boolean;
}

export interface DeepScanResult {
	webappId: string;
	url: string;
	/** 实际跑的任务列表 */
	ranTasks: string[];
	/** 跳过的任务（已扫过） */
	skippedTasks: string[];
	/** 失败的任务 */
	failedTasks: string[];
	/** 各任务的结果摘要 */
	summaries: Record<
		string,
		{
			status: 'ok' | 'skipped' | 'failed';
			durationMs: number;
			summary?: Record<string, unknown>;
			error?: string;
		}
	>;
}

/**
 * 对单个 webapp 跑 M3 深度扫描
 *
 * @param webappId webapp 资产 ID（= assets.id）
 */
export async function deepScanWebapp(
	webappId: string,
	opts: DeepScanOptions = {},
): Promise<DeepScanResult> {
	const pool = getPg();

	// 1. 加载 webapp 信息
	const { rows } = await pool.query(
		`SELECT w.asset_id, w.url, w.host, w.scheme, w.path, w.score, w.role, w.suggested_next,
            w.cdn, w.waf, a.seed_id, a.parent_id
     FROM webapps w JOIN assets a ON w.asset_id = a.id
     WHERE w.asset_id = $1`,
		[webappId],
	);
	if (rows.length === 0) {
		throw new Error(`webapp not found: ${webappId}`);
	}
	const w = rows[0];
	const suggested: SuggestedNext[] = w.suggested_next ?? [];
	const seedId: string | null = w.seed_id;
	const assetId: string | null = w.parent_id;

	console.log(`[deep_scan] webapp=${webappId} url=${w.url} suggested=[${suggested.join(',')}]`);

	const result: DeepScanResult = {
		webappId,
		url: w.url,
		ranTasks: [],
		skippedTasks: [],
		failedTasks: [],
		summaries: {},
	};

	// 2. 可选：先跑 wafw00f 补全 WAF（不影响 suggested_next）
	if (opts.detectWaf !== false && !w.waf) {
		await tryDetectWaf(webappId, w.url);
	}

	// 2.5 技术栈画像前置：HTML 分析（正则 + LLM 兜底）+ 架构级分析
	//     补齐全量模式扫出的 webapp 缺少技术栈画像的问题
	if (seedId) {
		try {
			const { analyzeSiteStep, runArchAnalysisStep } = await import('./single_site.js');
			const { analysis, page } = await analyzeSiteStep(webappId, w.url, seedId);
			// 架构级分析（HTML + 已识别技术栈）
			const pool = getPg();
			const { rows: metaRows } = await pool.query('SELECT meta FROM webapps WHERE asset_id = $1', [
				webappId,
			]);
			const meta = metaRows[0]?.meta ?? {};
			const hasArch = meta.site_rendering || meta.site_api_style;
			if (!hasArch && page?.html) {
				await runArchAnalysisStep(webappId, w.url, seedId, page.html, analysis);
			}
			console.log(
				`[deep_scan] 技术栈画像: framework=[${analysis.framework.join(',')}] arch=${analysis.architecture ?? '-'}`,
			);
		} catch (err) {
			console.warn('[deep_scan] 技术栈画像失败 (non-blocking):', err);
		}
	}

	// 3. 按 suggested_next 顺序跑任务
	const skipTasks = new Set(opts.skipTasks ?? []);

	for (const task of suggested) {
		if (skipTasks.has(task)) {
			result.skippedTasks.push(task);
			result.summaries[task] = {
				status: 'skipped',
				durationMs: 0,
				summary: { reason: 'manually skipped' },
			};
			continue;
		}

		// 检查最近是否已扫
		if (!opts.force && opts.skipRecent !== false) {
			const recentlyScanned = await isWebappScannedRecently(webappId, task);
			if (recentlyScanned) {
				console.log(`[deep_scan] ${task}: skipped (recently scanned)`);
				result.skippedTasks.push(task);
				result.summaries[task] = {
					status: 'skipped',
					durationMs: 0,
					summary: { reason: 'recently scanned' },
				};
				continue;
			}
		}

		const startAt = Date.now();
		try {
			let summary: Record<string, unknown> = {};
			switch (task) {
				case 'history_url':
					summary = await runHistoryUrlTask({
						webappId,
						seedId: seedId ?? undefined,
						assetId: assetId ?? undefined,
						domain: w.host,
						maxUrls: opts.maxHistoryUrls,
					});
					break;
				case 'jsmining':
					summary = await runJsminingTask({
						webappId,
						seedId: seedId ?? undefined,
						assetId: assetId ?? undefined,
						url: w.url,
						maxJsFiles: opts.maxJsFiles,
					});
					break;
				case 'dirscan':
					summary = await runDirscanTask({
						webappId,
						seedId: seedId ?? undefined,
						url: w.url,
						timeoutMs: opts.dirscanTimeoutMs,
					});
					break;
				case 'source_collect':
					summary = await runSourceCollectTask({
						webappId,
						seedId: seedId ?? undefined,
						assetId: assetId ?? webappId,
						url: w.url,
						maxJsFiles: opts.maxJsFiles,
					});
					break;
			}
			const durationMs = Date.now() - startAt;
			result.ranTasks.push(task);
			result.summaries[task] = { status: 'ok', durationMs, summary };
			console.log(`[deep_scan] ${task}: done in ${(durationMs / 1000).toFixed(1)}s`);
		} catch (err) {
			const durationMs = Date.now() - startAt;
			const error = err instanceof Error ? err.message : String(err);
			result.failedTasks.push(task);
			result.summaries[task] = { status: 'failed', durationMs, error };
			console.error(`[deep_scan] ${task} failed:`, err);
		}
	}

	// 3.5 页面语义分类（endpoints 角色标注，高价值入口定位）
	if (seedId) {
		try {
			const { runPageClassifyStep } = await import('./single_site.js');
			await runPageClassifyStep(webappId, w.url, seedId);
		} catch (err) {
			console.warn('[deep_scan] 页面分类失败 (non-blocking):', err);
		}
	}

	// 4. 更新 webapp.meta.deep_scan_done
	await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
		JSON.stringify({ deep_scan_done: true, deep_scan_at: new Date().toISOString() }),
		webappId,
	]);

	await auditLog({
		actor: 'system',
		action: 'scan_finish',
		target: webappId,
		decision: result.failedTasks.length === 0 ? 'pass' : 'fail',
		reason: `deep_scan: ran=${result.ranTasks.length} skipped=${result.skippedTasks.length} failed=${result.failedTasks.length}`,
		meta: {
			ran: result.ranTasks,
			skipped: result.skippedTasks,
			failed: result.failedTasks,
		},
	});

	console.log(
		`[deep_scan] done: ran=${result.ranTasks.length} skipped=${result.skippedTasks.length} failed=${result.failedTasks.length}`,
	);

	return result;
}

/**
 * 批量深度扫描：对 seed 下的所有 webapp 跑深度扫描
 */
export async function deepScanBySeed(
	seedId: string,
	opts: DeepScanOptions = {},
): Promise<DeepScanResult[]> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT w.asset_id
     FROM webapps w JOIN assets a ON w.asset_id = a.id
     WHERE a.seed_id = $1
     ORDER BY w.score DESC, w.last_seen DESC`,
		[seedId],
	);
	console.log(`[deep_scan] ${rows.length} webapps to deep scan for seed ${seedId}`);
	const results: DeepScanResult[] = [];
	for (const row of rows) {
		try {
			const r = await deepScanWebapp(row.asset_id, opts);
			results.push(r);
		} catch (err) {
			console.error(`[deep_scan] failed for webapp ${row.asset_id}:`, err);
		}
	}
	return results;
}

// =============================================================================
// 任务实现
// =============================================================================

async function runHistoryUrlTask(opts: {
	webappId: string;
	seedId?: string;
	assetId?: string;
	domain: string;
	maxUrls?: number;
}): Promise<Record<string, unknown>> {
	const r = await collectHistoryUrls({
		domain: opts.domain,
		webappId: opts.webappId,
		seedId: opts.seedId,
		assetId: opts.assetId,
		maxUrls: opts.maxUrls ?? 2000,
	});
	return {
		urlCount: r.urlCount,
		endpointCount: r.endpointCount,
		paramCount: r.paramCount,
		jsCount: r.jsUrls.length,
	};
}

async function runJsminingTask(opts: {
	webappId: string;
	seedId?: string;
	assetId?: string;
	url: string;
	maxJsFiles?: number;
}): Promise<Record<string, unknown>> {
	const scanId = await createScanRun({
		seedId: opts.seedId,
		assetId: opts.assetId,
		tool: 'jsmining',
		params: { url: opts.url },
	});

	try {
		// 1. 用 katana 抓 JS 文件 URL
		let jsUrls: string[] = [];
		try {
			const katanaRecords = await runKatana({
				url: opts.url,
				depth: 2,
				sameDomain: true,
				timeoutMs: 3 * 60 * 1000,
			});
			jsUrls = katanaRecords
				.filter((r: KatanaRecord) => /\.(js|mjs)(\?|$)/i.test(r.url))
				.map((r: KatanaRecord) => r.url);
			// 也把 katana 抓到的所有 URL 入 endpoints
			const endpoints = katanaRecords
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
				.filter(
					(x): x is { url: string; path: string; method: string; source: 'js' } => x !== null,
				);
			await upsertEndpoints(opts.webappId, endpoints);
		} catch (err) {
			console.warn('[jsmining] katana failed:', err);
		}

		// 2. 限制 JS 文件数（防止大站点抓数千 JS）
		const maxJs = opts.maxJsFiles ?? 50;
		if (jsUrls.length > maxJs) {
			console.log(`[jsmining] JS URL cap: ${jsUrls.length} → ${maxJs}`);
			jsUrls = jsUrls.slice(0, maxJs);
		}

		// 3. 下载 + 扫描 JS 文件
		const jsScanResult = await scanJsFiles({ urls: jsUrls, useLlm: true, webappId: opts.webappId });

		// 4. 入库 JS 接口
		const jsApiItems = jsScanResult.endpoints.map((ep) => ({
			apiPath: ep.path,
			method: ep.method,
			params: ep.params ?? [],
			sourceJs: ep.sourceJs,
		}));
		const jsApiCount = await upsertJsApis(opts.webappId, jsApiItems);

		// 5. 入库 JS 提取的参数
		const jsParamItems = jsScanResult.endpoints
			.filter((ep) => ep.params && ep.params.length > 0)
			.flatMap((ep) =>
				(ep.params ?? []).map((p) => ({ param: p, source: 'js' as const, context: ep.sourceJs })),
			);
		const jsParamCount = await upsertParams(opts.webappId, jsParamItems);

		// 6. 入库敏感信息 findings
		let secretCount = 0;
		for (const s of jsScanResult.secrets) {
			await insertFinding({
				assetId: opts.assetId ?? opts.webappId,
				webappId: opts.webappId,
				type: 'secret',
				severity: severityForSecret(s.type),
				detail: `JS 中发现 ${s.type}（来源：${s.sourceJs}）`,
				evidence: s.value,
				sourceTool: 'js_scan',
				meta: { type: s.type, sourceJs: s.sourceJs, context: s.context?.slice(0, 200) },
			});
			secretCount++;
		}

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: {
				jsFiles: jsScanResult.fetchedCount,
				jsFailed: jsScanResult.failedCount,
				endpoints: jsApiCount,
				params: jsParamCount,
				secrets: secretCount,
			},
		});

		return {
			jsFiles: jsScanResult.fetchedCount,
			jsFailed: jsScanResult.failedCount,
			endpoints: jsApiCount,
			params: jsParamCount,
			secrets: secretCount,
		};
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		throw err;
	}
}

async function runDirscanTask(opts: {
	webappId: string;
	seedId?: string;
	url: string;
	timeoutMs?: number;
}): Promise<Record<string, unknown>> {
	const scanId = await createScanRun({
		seedId: opts.seedId,
		assetId: opts.webappId,
		tool: 'dirscan',
		params: { url: opts.url },
	});

	try {
		const records: DirsearchRecord[] = await runDirsearch({
			url: opts.url,
			timeoutMs: opts.timeoutMs ?? 5 * 60 * 1000,
			excludeStatus: [404],
		});

		// 入库 endpoints（source=dirscan）
		const endpointItems = records.map((r) => ({
			url: new URL(r.path, opts.url).toString(),
			path: r.path,
			method: 'GET',
			source: 'dirscan' as const,
			statusCode: r.status,
		}));
		const endpointCount = await upsertEndpoints(opts.webappId, endpointItems);

		// 敏感路径入 findings
		let sensitiveCount = 0;
		for (const r of records) {
			if (isSensitivePath(r.path)) {
				await insertFinding({
					assetId: opts.webappId,
					webappId: opts.webappId,
					type: 'sensitive_path',
					severity: r.status === 200 ? 'medium' : 'low',
					detail: `目录爆破发现敏感路径：${r.path}（${r.status}）`,
					evidence: `HTTP ${r.status}`,
					sourceTool: 'dirsearch',
					meta: { path: r.path, status: r.status },
				});
				sensitiveCount++;
			}
		}

		await finishScanRun(scanId, {
			status: 'done',
			resultSummary: { found: records.length, endpoints: endpointCount, sensitive: sensitiveCount },
		});

		return {
			found: records.length,
			endpoints: endpointCount,
			sensitive: sensitiveCount,
		};
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		throw err;
	}
}

async function tryDetectWaf(webappId: string, url: string): Promise<void> {
	try {
		const wafName = await runWafw00f({ url }).then((records) => {
			const hit = records.find((r) => r.hasWaf && r.wafName);
			return hit?.wafName ?? null;
		});
		if (wafName) {
			const pool = getPg();
			await pool.query(
				'UPDATE webapps SET waf = $1, meta = meta || $2::jsonb WHERE asset_id = $3',
				[wafName, JSON.stringify({ waf_name: wafName, waf_source: 'wafw00f' }), webappId],
			);
			console.log(`[deep_scan] wafw00f detected: ${wafName}`);
		}
	} catch (err) {
		console.warn('[deep_scan] wafw00f failed:', err);
	}
}

/**
 * 敏感路径判断（用于 dirsearch 结果标记 findings）
 */
export function isSensitivePath(path: string): boolean {
	const lower = path.toLowerCase();
	const patterns = [
		/\/admin/i,
		/\/manage/i,
		/\/console/i,
		/\/dashboard/i,
		/\/backup/i,
		/\/\.git/i,
		/\/\.svn/i,
		/\/\.env/i,
		/\/config/i,
		/\/test/i,
		/\/debug/i,
		/\/phpinfo/i,
		/\/swagger/i,
		/\/api-docs/i,
		/\/\.well-known/i,
		/\/server-status/i,
		/\/wp-admin/i,
		/\/phpmyadmin/i,
	];
	return patterns.some((p) => p.test(lower));
}

/**
 * 根据敏感信息类型决定严重级别
 */
export function severityForSecret(type: string): UpsertFindingInput['severity'] {
	switch (type) {
		case 'private_key':
		case 'aws_secret_key':
		case 'db_connection_string':
			return 'critical';
		case 'aws_access_key':
		case 'aliyun_access_key_id':
		case 'tencent_secret_id':
		case 'api_key':
		case 'jwt':
		case 'slack_token':
		case 'github_token':
		case 'token':
		case 'password':
		case 'secret':
			return 'high';
		case 'webhook_url':
			return 'medium';
		case 'internal_ip':
			return 'low';
		default:
			return 'medium';
	}
}

// =============================================================================
// M4: source_collect 任务
// =============================================================================

async function runSourceCollectTask(opts: {
	webappId: string;
	seedId?: string;
	assetId?: string;
	url: string;
	maxJsFiles?: number;
}): Promise<Record<string, unknown>> {
	const scanId = await createScanRun({
		seedId: opts.seedId,
		assetId: opts.assetId,
		tool: 'source_collect',
		params: { url: opts.url },
	});

	try {
		const result = await collectSources({
			webappId: opts.webappId,
			url: opts.url,
			maxJsFiles: opts.maxJsFiles ?? 100,
			maxMapFiles: 50,
			force: false,
		});

		// 如果发现 sourcemap 泄露，写一条 finding
		if (result.sourceAvailable) {
			try {
				await insertFinding({
					assetId: opts.assetId ?? opts.webappId,
					webappId: opts.webappId,
					type: 'sourcemap',
					severity: 'high',
					detail: `Sourcemap exposed at ${opts.url}`,
					evidence: result.info.mapFiles.slice(0, 5).join('\n'),
					sourceTool: 'packer_infofinder',
					meta: {
						url: opts.url,
						mapFiles: result.info.mapFiles,
						frameworks: result.info.frameworks,
						sourceDir: result.sourceDir,
					},
				});
			} catch {
				// ignore finding insert error
			}
		}

		// 把提取到的接口入 js_apis（M4.6 的轻量版：直接入 source_collect 提取的）
		if (result.endpoints.length > 0) {
			try {
				await upsertJsApis(
					opts.webappId,
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

		// 把密钥入 findings
		for (const sec of result.secrets) {
			try {
				await insertFinding({
					assetId: opts.assetId ?? opts.webappId,
					webappId: opts.webappId,
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
			} catch {
				// ignore
			}
		}

		// 源码审计（source-auditor）：还原出源码时，LLM 审 INDEX.json + 关键文件提渗透线索
		let auditFindings = 0;
		if (result.sourceAvailable || (result.restore?.restoredCount ?? 0) > 0) {
			try {
				const { auditSourceDump } = await import('./source_audit.js');
				const audit = await auditSourceDump({
					webappId: opts.webappId,
					url: opts.url,
					sourceDir: result.sourceDir,
				});
				auditFindings = audit?.findings.length ?? 0;
			} catch (err) {
				console.warn('[deep_scan] source_audit failed (non-blocking):', err);
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
				totalBytes: result.totalBytes,
				sourceAuditFindings: auditFindings,
			},
		});

		return {
			sourceAvailable: result.sourceAvailable,
			webpackDetected: result.info.webpackDetected,
			frameworks: result.info.frameworks,
			jsDownloaded: result.jsDownloaded,
			mapDownloaded: result.mapDownloaded,
			restoredFiles: result.restore?.restoredCount ?? 0,
			endpoints: result.endpoints.length,
			secrets: result.secrets.length,
			totalBytes: result.totalBytes,
			sourceDir: result.sourceDir,
			sourceAuditFindings: auditFindings,
		};
	} catch (err) {
		await finishScanRun(scanId, {
			status: 'failed',
			error: err instanceof Error ? err.message : String(err),
		});
		throw err;
	}
}
