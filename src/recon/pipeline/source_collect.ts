/**
 * M4 源码完整收集管道（M4.2 + M4.3 + M4.4）
 *
 * 流程：
 *   1. detectSourcemap() 探测 webpack/sourcemap（M4.1 packer_infofinder）
 *   2. 全量下载 JS + .map 文件 → sources/<domain>/raw/（M4.2）
 *   3. restoreSourceMap() 还原 .map → sources/<domain>/src/（M4.3）
 *   4. 生成 INDEX.json（M4.4）：文件清单/入口/接口/密钥
 *   5. 写 source_dumps 表（M4.5 model 在 source_dump.ts）
 *   6. 更新 webapp.meta.source_available
 *
 * 目录结构：
 *   sources/
 *     <domain>/
 *       raw/                  # 原始下载的 JS + .map
 *         main.js
 *         main.js.map
 *       src/                  # 还原后的源码（按 .map 中的 sources 路径）
 *         src/
 *           main.tsx
 *         node_modules/
 *           react/index.js
 *       INDEX.json            # 索引文件（M4.4）
 *
 * 设计原则（架构文档 §4.3）：
 *   "全量落地 + LLM 审计"——不以工具抽取结果为准，宁可多下载，不漏。
 */

import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { type PackerInfoResult, detectSourcemap } from '../tools/packer_infofinder.js';
import { type RestoreResult, restoreSourceMap } from '../tools/source_map_restore.js';
import {
	type JsApiEndpoint,
	type JsSecret,
	extractApiEndpoints,
	extractSecrets,
} from './js_scan.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface SourceCollectOptions {
	/** webapp ID */
	webappId: string;
	/** 目标 URL（含协议） */
	url: string;
	/** 单文件下载超时（毫秒，默认 15s） */
	fetchTimeoutMs?: number;
	/** 最大 JS 文件数（默认 100，避免超大站点） */
	maxJsFiles?: number;
	/** 最大 .map 文件数（默认 50） */
	maxMapFiles?: number;
	/** 单文件大小上限（字节，默认 5MB） */
	maxFileBytes?: number;
	/** 下载并发数（默认 5） */
	concurrency?: number;
	/** User-Agent */
	userAgent?: string;
	/** 是否强制重新下载（忽略已存在的 sources 目录） */
	force?: boolean;
}

export interface SourceCollectResult {
	webappId: string;
	url: string;
	/** 源码落地目录（绝对路径） */
	sourceDir: string;
	/** sourcemap 探测结果 */
	info: PackerInfoResult;
	/** 下载的 JS 文件数 */
	jsDownloaded: number;
	/** 下载的 .map 文件数 */
	mapDownloaded: number;
	/** 还原结果（如有 .map） */
	restore?: RestoreResult;
	/** INDEX.json 路径（相对 sourceDir） */
	indexPath: string;
	/** 总字节数 */
	totalBytes: number;
	/** 是否发现 sourcemap */
	sourceAvailable: boolean;
	/** 提取的接口 */
	endpoints: JsApiEndpoint[];
	/** 提取的密钥 */
	secrets: JsSecret[];
	/** 耗时（ms） */
	durationMs: number;
	/** 错误信息（如有） */
	error?: string;
}

// =============================================================================
// 主入口
// =============================================================================

export async function collectSources(opts: SourceCollectOptions): Promise<SourceCollectResult> {
	const startTs = Date.now();
	const cfg = getConfig();
	const fetchTimeoutMs = opts.fetchTimeoutMs ?? 15_000;
	const maxJsFiles = opts.maxJsFiles ?? 100;
	const maxMapFiles = opts.maxMapFiles ?? 50;
	const maxFileBytes = opts.maxFileBytes ?? 5 * 1024 * 1024;
	const concurrency = opts.concurrency ?? 5;
	const ua = opts.userAgent ?? 'Mozilla/5.0 (compatible; ck-recon/0.1; source-collector)';

	// 计算域名和源码目录
	const domain = safeHostname(opts.url);
	const sourceDir = resolve(cfg.sources.dir, domain);
	const rawDir = join(sourceDir, 'raw');
	const srcDir = join(sourceDir, 'src');

	const result: SourceCollectResult = {
		webappId: opts.webappId,
		url: opts.url,
		sourceDir,
		info: {} as PackerInfoResult,
		jsDownloaded: 0,
		mapDownloaded: 0,
		indexPath: 'INDEX.json',
		totalBytes: 0,
		sourceAvailable: false,
		endpoints: [],
		secrets: [],
		durationMs: 0,
	};

	try {
		// 0. 准备目录（force 模式先清空）
		if (opts.force && existsSync(sourceDir)) {
			await rm(sourceDir, { recursive: true, force: true });
		}
		await mkdir(rawDir, { recursive: true });
		await mkdir(srcDir, { recursive: true });

		// 1. M4.1 探测 sourcemap
		console.log(`[source-collect] probing sourcemap for ${opts.url}...`);
		const info = await detectSourcemap({
			url: opts.url,
			timeoutMs: fetchTimeoutMs,
			maxJsFiles,
			userAgent: ua,
			probeMapPaths: true,
		});
		result.info = info;
		result.sourceAvailable = info.sourceAvailable;
		console.log(
			`[source-collect] webpack=${info.webpackDetected} frameworks=[${info.frameworks.join(',')}] js=${info.jsFiles.length} maps=${info.mapFiles.length} sourceAvailable=${info.sourceAvailable}`,
		);

		// 即使没有发现 sourcemap，也下载所有 JS 文件（压缩 JS 也有审计价值）
		const jsUrlsToDownload = info.jsFiles.slice(0, maxJsFiles);
		const mapUrlsToDownload = info.mapFiles.slice(0, maxMapFiles);

		// 2. M4.2 下载 JS 文件
		console.log(`[source-collect] downloading ${jsUrlsToDownload.length} JS files...`);
		const jsFiles = await downloadFiles(jsUrlsToDownload, rawDir, {
			timeoutMs: fetchTimeoutMs,
			maxFileBytes,
			concurrency,
			userAgent: ua,
			extension: '.js',
		});
		result.jsDownloaded = jsFiles.downloaded;
		result.totalBytes += jsFiles.totalBytes;

		// 3. M4.2 下载 .map 文件
		if (mapUrlsToDownload.length > 0) {
			console.log(`[source-collect] downloading ${mapUrlsToDownload.length} .map files...`);
			const mapFiles = await downloadFiles(mapUrlsToDownload, rawDir, {
				timeoutMs: fetchTimeoutMs,
				maxFileBytes,
				concurrency,
				userAgent: ua,
				extension: '.map',
			});
			result.mapDownloaded = mapFiles.downloaded;
			result.totalBytes += mapFiles.totalBytes;

			// 4. M4.3 还原 .map 文件
			if (mapFiles.files.length > 0) {
				console.log(`[source-collect] restoring ${mapFiles.files.length} source maps...`);
				const allRestored: RestoreResult = {
					restoredCount: 0,
					failedCount: 0,
					restoredFiles: [],
					failedFiles: [],
					entryPoints: [],
					totalBytes: 0,
					durationMs: 0,
				};
				for (const mapFile of mapFiles.files) {
					try {
						const r = await restoreSourceMap({
							mapFilePath: mapFile.localPath,
							outputDir: srcDir,
							keepWebpackPrefix: false,
						});
						allRestored.restoredCount += r.restoredCount;
						allRestored.failedCount += r.failedCount;
						allRestored.restoredFiles.push(...r.restoredFiles);
						allRestored.failedFiles.push(...r.failedFiles);
						allRestored.entryPoints.push(...r.entryPoints);
						allRestored.totalBytes += r.totalBytes;
						allRestored.durationMs += r.durationMs;
					} catch (err) {
						console.warn(
							`[source-collect] restore failed for ${mapFile.localPath}: ${err instanceof Error ? err.message : err}`,
						);
					}
				}
				result.restore = allRestored;
				console.log(
					`[source-collect] restored ${allRestored.restoredCount} files (${allRestored.totalBytes} bytes), failed ${allRestored.failedCount}`,
				);
			}
		} else {
			console.log('[source-collect] no .map files to download');
		}

		// 5. M4.4 提取接口和密钥（从下载的 JS + 还原的源码）
		console.log('[source-collect] extracting APIs and secrets...');
		const { endpoints, secrets } = await extractFromAllFiles(rawDir, srcDir);
		result.endpoints = endpoints;
		result.secrets = secrets;
		console.log(
			`[source-collect] extracted ${endpoints.length} endpoints, ${secrets.length} secrets`,
		);

		// 6. M4.4 生成 INDEX.json
		console.log('[source-collect] generating INDEX.json...');
		await generateIndex(sourceDir, {
			webappId: opts.webappId,
			url: opts.url,
			info,
			jsDownloaded: result.jsDownloaded,
			mapDownloaded: result.mapDownloaded,
			restore: result.restore,
			endpoints,
			secrets,
			totalBytes: result.totalBytes,
		});

		// 7. M4.5 更新 source_dumps 表 + webapp.meta
		await upsertSourceDumpRecord(opts.webappId, sourceDir, result);

		// 8. 更新 webapp.meta.source_available
		await updateWebappMeta(opts.webappId, {
			source_available: result.sourceAvailable,
			source_dir: sourceDir,
			frameworks: info.frameworks,
		});

		result.durationMs = Date.now() - startTs;
		console.log(
			`[source-collect] done in ${result.durationMs}ms: js=${result.jsDownloaded} map=${result.mapDownloaded} restored=${result.restore?.restoredCount ?? 0} bytes=${result.totalBytes}`,
		);

		await auditLog({
			actor: 'pipeline:source_collect',
			action: 'scan_finish',
			target: opts.url,
			decision: 'pass',
			reason: `js=${result.jsDownloaded} map=${result.mapDownloaded} restored=${result.restore?.restoredCount ?? 0} endpoints=${endpoints.length} secrets=${secrets.length}`,
			meta: {
				webappId: opts.webappId,
				sourceDir,
				sourceAvailable: result.sourceAvailable,
				jsDownloaded: result.jsDownloaded,
				mapDownloaded: result.mapDownloaded,
				restoredCount: result.restore?.restoredCount ?? 0,
				totalBytes: result.totalBytes,
				durationMs: result.durationMs,
			},
		});

		return result;
	} catch (err) {
		result.durationMs = Date.now() - startTs;
		result.error = err instanceof Error ? err.message : String(err);
		await auditLog({
			actor: 'pipeline:source_collect',
			action: 'scan_finish',
			target: opts.url,
			decision: 'deny',
			reason: `error: ${result.error}`,
			meta: { webappId: opts.webappId, durationMs: result.durationMs },
		});
		return result;
	}
}

// =============================================================================
// 内部：文件下载
// =============================================================================

interface DownloadResult {
	downloaded: number;
	failed: number;
	totalBytes: number;
	files: { url: string; localPath: string; bytes: number }[];
}

async function downloadFiles(
	urls: string[],
	outputDir: string,
	opts: {
		timeoutMs: number;
		maxFileBytes: number;
		concurrency: number;
		userAgent: string;
		extension: string;
	},
): Promise<DownloadResult> {
	const result: DownloadResult = {
		downloaded: 0,
		failed: 0,
		totalBytes: 0,
		files: [],
	};

	if (urls.length === 0) return result;

	// 并发下载池
	const queue = [...urls];
	const seen = new Set<string>();
	const workers: Promise<void>[] = [];

	for (let w = 0; w < Math.min(opts.concurrency, urls.length); w++) {
		workers.push(
			(async () => {
				while (queue.length > 0) {
					const url = queue.shift();
					if (!url) break;
					if (seen.has(url)) continue;
					seen.add(url);

					const localPath = await downloadOne(url, outputDir, opts);
					if (localPath) {
						result.downloaded++;
						try {
							const s = await stat(localPath);
							result.totalBytes += s.size;
							result.files.push({ url, localPath, bytes: s.size });
						} catch {
							// ignore
						}
					} else {
						result.failed++;
					}
				}
			})(),
		);
	}
	await Promise.all(workers);
	return result;
}

/**
 * 下载单个文件
 *
 * @returns 本地路径，失败返回 null
 */
async function downloadOne(
	url: string,
	outputDir: string,
	opts: { timeoutMs: number; maxFileBytes: number; userAgent: string; extension: string },
): Promise<string | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), opts.timeoutMs);

	try {
		const resp = await fetch(url, {
			method: 'GET',
			signal: controller.signal,
			headers: {
				'User-Agent': opts.userAgent,
				Accept: '*/*',
			},
			redirect: 'follow',
		});
		clearTimeout(timer);

		if (!resp.ok) return null;

		// 大小检查
		const contentLength = Number.parseInt(resp.headers.get('content-length') ?? '0', 10);
		if (contentLength > opts.maxFileBytes) return null;

		const content = await resp.text();
		if (content.length > opts.maxFileBytes) return null;

		// 内容类型校验：.map 文件必须是 JSON（SPA 服务器可能对所有路径返回 HTML）
		if (opts.extension === '.map') {
			const trimmed = content.trimStart();
			if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
				return null; // 不是 JSON，跳过（可能是 404 HTML fallback）
			}
		} else if (opts.extension === '.js') {
			// JS 文件不能是 HTML（SPA fallback）
			const trimmed = content.trimStart();
			if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<html')) {
				return null;
			}
		}

		// 生成本地文件名
		const localName = makeLocalFilename(url, opts.extension);
		const localPath = join(outputDir, localName);
		await mkdir(dirname(localPath), { recursive: true });
		await writeFile(localPath, content, 'utf8');
		return localPath;
	} catch {
		clearTimeout(timer);
		return null;
	}
}

/**
 * 从 URL 生成本地文件名（去 query，加扩展名，hash 防重）
 *
 * 例：
 *   https://cdn.com/static/js/main.js?v=1 → main.js
 *   https://cdn.com/static/js/chunk-abc123.js → chunk-abc123.js
 *   https://cdn.com/ → index.js
 */
function makeLocalFilename(url: string, extension: string): string {
	try {
		const u = new URL(url);
		let name = basename(u.pathname);
		if (!name || name === '/') {
			name = 'index';
		}
		// 去掉已有的 .map/.js 后缀（统一加）
		name = name.replace(/\.(js|mjs|map)$/i, '');
		// 加扩展名
		if (extension === '.map' && !name.endsWith('.js')) {
			name = `${name}.js${extension}`;
		} else {
			name = `${name}${extension}`;
		}
		// URL hash 防重（取 path + query 的短 hash）
		const hashInput = u.pathname + u.search;
		const hash = shortHash(hashInput);
		return `${hash}_${name}`;
	} catch {
		return `${shortHash(url)}_file${extension}`;
	}
}

/**
 * 简单的短 hash（FNV-1a 32-bit，返回 8 位 hex）
 */
function shortHash(input: string): string {
	let h = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		h ^= input.charCodeAt(i);
		h = (h * 0x01000193) >>> 0;
	}
	return h.toString(16).padStart(8, '0');
}

// =============================================================================
// 内部：从所有 JS/源码文件提取接口和密钥
// =============================================================================

async function extractFromAllFiles(
	rawDir: string,
	srcDir: string,
): Promise<{ endpoints: JsApiEndpoint[]; secrets: JsSecret[] }> {
	const endpoints: JsApiEndpoint[] = [];
	const secrets: JsSecret[] = [];

	// 扫描 raw/ 和 src/ 两个目录
	const allFiles: { path: string; isSource: boolean }[] = [];
	await collectFiles(rawDir, rawDir, allFiles, false);
	if (existsSync(srcDir)) {
		await collectFiles(srcDir, srcDir, allFiles, true);
	}

	// 限制文件数（避免超大项目拖慢）
	const filesToScan = allFiles.slice(0, 500);

	for (const file of filesToScan) {
		try {
			const content = await readFile(file.path, 'utf8');
			if (content.length === 0 || content.length > 2 * 1024 * 1024) continue;

			const sourceLabel = file.isSource
				? relative(srcDir, file.path)
				: `raw/${relative(rawDir, file.path)}`;
			const eps = extractApiEndpoints(content, sourceLabel);
			const secs = extractSecrets(content, sourceLabel);
			endpoints.push(...eps);
			secrets.push(...secs);
		} catch {
			// ignore
		}
	}

	// 去重
	const seenEp = new Set<string>();
	const dedupEndpoints: JsApiEndpoint[] = [];
	for (const ep of endpoints) {
		const key = `${ep.method}|${ep.path}|${ep.sourceJs}`;
		if (seenEp.has(key)) continue;
		seenEp.add(key);
		dedupEndpoints.push(ep);
	}

	return { endpoints: dedupEndpoints, secrets };
}

async function collectFiles(
	baseDir: string,
	currentDir: string,
	out: { path: string; isSource: boolean }[],
	isSource: boolean,
): Promise<void> {
	let entries: string[];
	try {
		entries = await readdir(currentDir);
	} catch {
		return;
	}
	for (const entry of entries) {
		const fullPath = join(currentDir, entry);
		let s;
		try {
			s = await stat(fullPath);
		} catch {
			continue;
		}
		if (s.isDirectory()) {
			// 跳过 node_modules（太深）
			if (entry === 'node_modules' && !isSource) continue;
			await collectFiles(baseDir, fullPath, out, isSource);
		} else if (s.isFile()) {
			// 只扫描 .js/.mjs/.ts/.tsx/.jsx/.map（.map 是 JSON，提取无意义，跳过）
			if (/\.(js|mjs|ts|tsx|jsx)$/i.test(entry)) {
				out.push({ path: fullPath, isSource });
			}
		}
	}
}

// =============================================================================
// 内部：生成 INDEX.json
// =============================================================================

interface IndexData {
	generatedAt: string;
	webappId: string;
	url: string;
	domain: string;
	sourceAvailable: boolean;
	webpackDetected: boolean;
	frameworks: string[];
	stats: {
		jsDownloaded: number;
		mapDownloaded: number;
		restoredFiles: number;
		failedFiles: number;
		totalBytes: number;
	};
	entryPoints: string[];
	endpoints: JsApiEndpoint[];
	secrets: JsSecret[];
	files: string[]; // 所有文件相对路径
}

async function generateIndex(
	sourceDir: string,
	data: {
		webappId: string;
		url: string;
		info: PackerInfoResult;
		jsDownloaded: number;
		mapDownloaded: number;
		restore?: RestoreResult;
		endpoints: JsApiEndpoint[];
		secrets: JsSecret[];
		totalBytes: number;
	},
): Promise<void> {
	// 列出所有文件
	const allFiles: string[] = [];
	const rawDir = join(sourceDir, 'raw');
	const srcDir = join(sourceDir, 'src');
	if (existsSync(rawDir)) await listAllFiles(rawDir, sourceDir, allFiles);
	if (existsSync(srcDir)) await listAllFiles(srcDir, sourceDir, allFiles);

	const index: IndexData = {
		generatedAt: new Date().toISOString(),
		webappId: data.webappId,
		url: data.url,
		domain: safeHostname(data.url),
		sourceAvailable: data.info.sourceAvailable,
		webpackDetected: data.info.webpackDetected,
		frameworks: data.info.frameworks,
		stats: {
			jsDownloaded: data.jsDownloaded,
			mapDownloaded: data.mapDownloaded,
			restoredFiles: data.restore?.restoredCount ?? 0,
			failedFiles: data.restore?.failedCount ?? 0,
			totalBytes: data.totalBytes,
		},
		entryPoints: data.restore?.entryPoints ?? [],
		endpoints: data.endpoints,
		secrets: data.secrets,
		files: allFiles,
	};

	const indexPath = join(sourceDir, 'INDEX.json');
	await writeFile(indexPath, JSON.stringify(index, null, 2), 'utf8');
}

async function listAllFiles(currentDir: string, baseDir: string, out: string[]): Promise<void> {
	let entries: string[];
	try {
		entries = await readdir(currentDir);
	} catch {
		return;
	}
	for (const entry of entries) {
		const fullPath = join(currentDir, entry);
		let s;
		try {
			s = await stat(fullPath);
		} catch {
			continue;
		}
		if (s.isDirectory()) {
			await listAllFiles(fullPath, baseDir, out);
		} else if (s.isFile()) {
			out.push(relative(baseDir, fullPath));
		}
	}
}

// =============================================================================
// 内部：source_dumps 表 + webapp.meta 更新
// =============================================================================

async function upsertSourceDumpRecord(
	webappId: string,
	sourceDir: string,
	result: SourceCollectResult,
): Promise<void> {
	const pool = getPg();
	const entryPoints = result.restore?.entryPoints ?? [];
	const fileCount = (result.jsDownloaded ?? 0) + (result.restore?.restoredCount ?? 0);
	const restored = (result.restore?.restoredCount ?? 0) > 0;

	await pool.query(
		`INSERT INTO source_dumps (webapp_id, source_dir, file_count, size_bytes, index_path, restored, complete, entry_points)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[])
     ON CONFLICT (webapp_id, source_dir) DO UPDATE
       SET file_count = EXCLUDED.file_count,
           size_bytes = EXCLUDED.size_bytes,
           index_path = EXCLUDED.index_path,
           restored = EXCLUDED.restored,
           complete = EXCLUDED.complete,
           entry_points = EXCLUDED.entry_points,
           updated_at = now()`,
		[
			webappId,
			sourceDir,
			fileCount,
			result.totalBytes,
			'INDEX.json',
			restored,
			result.mapDownloaded > 0 && (result.restore?.failedCount ?? 0) === 0,
			entryPoints,
		],
	);
}

async function updateWebappMeta(
	webappId: string,
	meta: {
		source_available: boolean;
		source_dir: string;
		frameworks: string[];
	},
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`UPDATE webapps
     SET meta = COALESCE(meta, '{}'::jsonb) || jsonb_build_object(
       'source_available', $2::boolean,
       'source_dir', $3::text,
       'source_frameworks', $4::jsonb,
       'source_collected_at', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
     )
     WHERE asset_id = $1`,
		[webappId, meta.source_available, meta.source_dir, JSON.stringify(meta.frameworks)],
	);
}

// =============================================================================
// 内部工具
// =============================================================================

function safeHostname(url: string): string {
	try {
		return new URL(url).hostname;
	} catch {
		// 不是合法 URL，把非字母数字字符换成 -
		return url.replace(/[^a-zA-Z0-9.-]/g, '_').slice(0, 100);
	}
}
