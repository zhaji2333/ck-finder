/**
 * Packer-InfoFinder 适配器（纯 TS 实现）
 *
 * M4.1：探测 webpack/sourcemap 是否暴露
 *
 * 原工具：https://github.com/rtcatc/Packer-InfoFinder
 *   - 检测 HTML 中的 webpack 指纹（webpackJsonp、__NEXT_DATA__ 等）
 *   - 检测 JS 文件末尾的 //# sourceMappingURL=xxx.map 注释
 *   - 探测常见 .map 路径（/static/js/*.map、/dist/*.map 等）
 *
 * 本实现为纯 TS，不依赖外部工具，直接用 fetch 探测。
 *
 * 输出：
 *   - sourceAvailable: 是否发现 sourcemap
 *   - webpackDetected: 是否检测到 webpack 指纹
 *   - jsFiles: 发现的 JS 文件 URL
 *   - mapFiles: 发现的 .map 文件 URL
 */

import { auditLog } from '../gate/audit_log.js';

export interface PackerInfoResult {
	/** 是否发现 sourcemap（任一 .map 可达即为 true） */
	sourceAvailable: boolean;
	/** 是否检测到 webpack 指纹 */
	webpackDetected: boolean;
	/** 检测到的 webpack 框架（webpack/next/vue/react） */
	frameworks: string[];
	/** 发现的 JS 文件 URL（来自 HTML 解析） */
	jsFiles: string[];
	/** 发现的 .map 文件 URL（来自 sourceMappingURL 注释 + 路径探测） */
	mapFiles: string[];
	/** HTML 标题 */
	title?: string;
	/** 探测耗时（ms） */
	durationMs: number;
}

export interface PackerInfoOptions {
	/** 目标 URL（含协议） */
	url: string;
	/** 单文件超时（毫秒，默认 10s） */
	timeoutMs?: number;
	/** 最大 JS 文件探测数（默认 30，避免超大站点拖慢） */
	maxJsFiles?: number;
	/** User-Agent */
	userAgent?: string;
	/** 是否启用 .map 路径爆破（默认 true） */
	probeMapPaths?: boolean;
}

/**
 * 探测目标的 webpack/sourcemap 暴露情况
 *
 * 流程：
 *   1. fetch HTML → 解析 <script src> 提取 JS URL
 *   2. 检测 HTML 中的 webpack 指纹关键字
 *   3. 并发下载前 N 个 JS → 检查末尾 //# sourceMappingURL= 注释
 *   4. 对 .map URL 发 HEAD 请求确认可达
 *   5. （可选）探测常见 .map 路径（/static/js/main.js.map 等）
 */
export async function detectSourcemap(opts: PackerInfoOptions): Promise<PackerInfoResult> {
	const startTs = Date.now();
	const timeoutMs = opts.timeoutMs ?? 10_000;
	const maxJsFiles = opts.maxJsFiles ?? 30;
	const ua = opts.userAgent ?? 'Mozilla/5.0 (compatible; ck-recon/0.1; Packer-InfoFinder)';
	const probeMapPaths = opts.probeMapPaths !== false;

	const result: PackerInfoResult = {
		sourceAvailable: false,
		webpackDetected: false,
		frameworks: [],
		jsFiles: [],
		mapFiles: [],
		durationMs: 0,
	};

	// 1. fetch HTML
	const htmlResult = await fetchUrl(opts.url, { timeoutMs, userAgent: ua });
	if (!htmlResult.ok || !htmlResult.content) {
		await auditLog({
			actor: 'tool:packer_infofinder',
			action: 'tool_call',
			target: opts.url,
			decision: 'deny',
			reason: `HTML fetch failed: ${htmlResult.error ?? `status ${htmlResult.status}`}`,
			meta: { url: opts.url },
		});
		result.durationMs = Date.now() - startTs;
		return result;
	}

	const html = htmlResult.content;
	result.title = extractTitle(html);

	// 2. 检测 webpack 指纹
	const frameworks = detectWebpackFrameworks(html);
	if (frameworks.length > 0) {
		result.webpackDetected = true;
		result.frameworks = frameworks;
	}

	// 3. 解析 <script src> 提取 JS URL
	const jsUrls = extractScriptSrcs(html, opts.url);
	result.jsFiles = jsUrls.slice(0, maxJsFiles);

	// 4. 并发下载 JS，检查 sourceMappingURL 注释
	const mapUrls: string[] = [];
	const jsToProbe = jsUrls.slice(0, maxJsFiles);
	const concurrency = 5;
	const queue = [...jsToProbe];
	const workers: Promise<void>[] = [];

	for (let w = 0; w < Math.min(concurrency, jsToProbe.length); w++) {
		workers.push(
			(async () => {
				while (queue.length > 0) {
					const jsUrl = queue.shift();
					if (!jsUrl) break;
					const jsResult = await fetchUrl(jsUrl, { timeoutMs, userAgent: ua });
					if (!jsResult.ok || !jsResult.content) continue;

					// 检查末尾的 //# sourceMappingURL= 注释
					const mapUrl = extractSourceMappingURL(jsResult.content, jsUrl);
					if (mapUrl) {
						mapUrls.push(mapUrl);
					}

					// 也检测 JS 内容中的 webpack 指纹（更准）
					if (!result.webpackDetected && hasWebpackFingerprint(jsResult.content)) {
						result.webpackDetected = true;
						result.frameworks.push('webpack');
					}
				}
			})(),
		);
	}
	await Promise.all(workers);

	// 5. 可选：探测常见 .map 路径（当 HTML 没找到 JS 或 JS 无 sourceMappingURL 时）
	if (probeMapPaths && mapUrls.length === 0) {
		const probedMaps = await probeCommonMapPaths(opts.url, { timeoutMs, userAgent: ua });
		mapUrls.push(...probedMaps);
	}

	// 6. 去重 .map URL
	const seenMap = new Set<string>();
	const dedupedMaps: string[] = [];
	for (const u of mapUrls) {
		if (seenMap.has(u)) continue;
		seenMap.add(u);
		dedupedMaps.push(u);
	}
	result.mapFiles = dedupedMaps;
	result.sourceAvailable = dedupedMaps.length > 0;
	result.durationMs = Date.now() - startTs;

	await auditLog({
		actor: 'tool:packer_infofinder',
		action: 'tool_call',
		target: opts.url,
		decision: 'pass',
		reason: `webpack=${result.webpackDetected} frameworks=[${result.frameworks.join(',')}] js=${result.jsFiles.length} maps=${result.mapFiles.length} sourceAvailable=${result.sourceAvailable}`,
		meta: {
			url: opts.url,
			webpackDetected: result.webpackDetected,
			frameworks: result.frameworks,
			jsFileCount: result.jsFiles.length,
			mapFileCount: result.mapFiles.length,
			sourceAvailable: result.sourceAvailable,
			durationMs: result.durationMs,
		},
	});

	return result;
}

// =============================================================================
// 内部工具函数
// =============================================================================

interface FetchResult {
	ok: boolean;
	status?: number;
	content?: string;
	error?: string;
}

async function fetchUrl(
	url: string,
	opts: { timeoutMs: number; userAgent: string },
): Promise<FetchResult> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
	try {
		const resp = await fetch(url, {
			method: 'GET',
			signal: controller.signal,
			headers: {
				'User-Agent': opts.userAgent,
				Accept: 'text/html,application/javascript,*/*',
			},
			redirect: 'follow',
		});
		clearTimeout(timer);
		if (!resp.ok) {
			return { ok: false, status: resp.status, error: `HTTP ${resp.status}` };
		}
		const content = await resp.text();
		return { ok: true, status: resp.status, content };
	} catch (err) {
		clearTimeout(timer);
		return { ok: false, error: err instanceof Error ? err.message : String(err) };
	}
}

/**
 * 从 HTML 中提取 <title>
 */
function extractTitle(html: string): string | undefined {
	const m = html.match(/<title[^>]*>([^<]*)<\/title>/i);
	return m?.[1]?.trim() || undefined;
}

/**
 * 检测 HTML 中的 webpack 框架指纹
 *
 * 检测规则：
 *   - webpackJsonp / webpackChunk：经典 webpack
 *   - __NEXT_DATA__：Next.js
 *   - __NUXT__：Nuxt.js
 *   - data-reactroot / __REACT_DEVTOOLS：React
 *   - data-v-：Vue
 *   - Gatsby：Gatsby
 *   - Docusaurus：Docusaurus
 */
function detectWebpackFrameworks(html: string): string[] {
	const frameworks: string[] = [];
	if (/webpackJsonp|webpackChunk|webpack-/i.test(html)) frameworks.push('webpack');
	if (/__NEXT_DATA__/i.test(html)) frameworks.push('next');
	if (/__NUXT__/i.test(html)) frameworks.push('nuxt');
	if (/data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__/i.test(html)) frameworks.push('react');
	if (/data-v-[a-f0-9]{8}/i.test(html)) frameworks.push('vue');
	if (/___gatsby/i.test(html)) frameworks.push('gatsby');
	if (/docusaurus/i.test(html)) frameworks.push('docusaurus');
	return frameworks;
}

/**
 * 检测 JS 内容中的 webpack 指纹
 */
function hasWebpackFingerprint(jsContent: string): boolean {
	return /webpackJsonp|webpackChunk|__webpack_require__|webpack-/i.test(jsContent);
}

/**
 * 从 HTML 中提取 <script src> 的 JS URL
 *
 * 处理：
 *   - 绝对路径 https://...
 *   - 相对路径 /static/js/main.js
 *   - 协议相对路径 //cdn.example.com/main.js
 *   - 同目录相对路径 ./main.js 或 main.js
 */
function extractScriptSrcs(html: string, baseUrl: string): string[] {
	const urls: string[] = [];
	// 兼容三种写法：
	//   <script src="main.js">
	//   <script src='main.js'>
	//   <script src=main.js>   （HTML5 无引号，如 Vue CLI 默认输出）
	const scriptRegex = /<script[^>]+src=(?:"([^"]+)"|'([^']+)'|([^\s>]+))[^>]*>/gi;
	for (const match of html.matchAll(scriptRegex)) {
		const src = match[1] ?? match[2] ?? match[3];
		if (!src) continue;
		const abs = resolveUrl(src, baseUrl);
		if (abs && /\.(js|mjs)(\?|$)/i.test(abs)) {
			urls.push(abs);
		}
	}
	// 去重
	return [...new Set(urls)];
}

/**
 * 解析 URL（相对/绝对）为完整 URL
 */
function resolveUrl(src: string, baseUrl: string): string | null {
	try {
		if (src.startsWith('//')) {
			// 协议相对：//cdn.example.com/main.js → https://cdn.example.com/main.js
			const proto = baseUrl.startsWith('https://') ? 'https:' : 'http:';
			return proto + src;
		}
		return new URL(src, baseUrl).toString();
	} catch {
		return null;
	}
}

/**
 * 从 JS 内容末尾提取 //# sourceMappingURL= 注释
 *
 * 格式：
 *   //# sourceMappingURL=main.js.map
 *   //# sourceMappingURL=/static/js/main.js.map
 *   //# sourceMappingURL=https://cdn.example.com/main.js.map
 *
 * @returns 完整的 .map URL，或 null
 */
function extractSourceMappingURL(jsContent: string, jsUrl: string): string | null {
	// 只看最后 2000 字符（sourceMappingURL 在末尾）
	const tail = jsContent.slice(-2000);
	const m = tail.match(/\/\/[#@]\s*sourceMappingURL=(\S+)/);
	if (!m) return null;
	const mapPath = m[1];
	return resolveUrl(mapPath, jsUrl);
}

/**
 * 探测常见 .map 路径
 *
 * 当 HTML 解析不到 sourceMappingURL 时，尝试常见路径：
 *   - /static/js/main.js.map
 *   - /static/js/bundle.js.map
 *   - /dist/main.js.map
 *   - /assets/index.js.map
 *   - /build/main.js.map
 *   - 直接在已知 JS URL 后加 .map
 */
async function probeCommonMapPaths(
	baseUrl: string,
	opts: { timeoutMs: number; userAgent: string },
): Promise<string[]> {
	const candidates: string[] = [];

	// 1. 常见固定路径
	const commonPaths = [
		'/static/js/main.js.map',
		'/static/js/bundle.js.map',
		'/static/js/main.chunk.js.map',
		'/dist/main.js.map',
		'/dist/bundle.js.map',
		'/assets/index.js.map',
		'/assets/main.js.map',
		'/build/main.js.map',
		'/js/main.js.map',
		'/js/bundle.js.map',
		'/main.js.map',
		'/app.js.map',
		'/bundle.js.map',
	];
	for (const p of commonPaths) {
		const u = resolveUrl(p, baseUrl);
		if (u) candidates.push(u);
	}

	// 2. HEAD 请求确认可达（并发 5）
	const found: string[] = [];
	const concurrency = 5;
	const queue = [...candidates];
	const workers: Promise<void>[] = [];
	for (let w = 0; w < Math.min(concurrency, candidates.length); w++) {
		workers.push(
			(async () => {
				while (queue.length > 0) {
					const url = queue.shift();
					if (!url) break;
					const ok = await headExists(url, opts);
					if (ok) found.push(url);
				}
			})(),
		);
	}
	await Promise.all(workers);
	return found;
}

/**
 * HEAD 请求确认 URL 可达
 */
async function headExists(
	url: string,
	opts: { timeoutMs: number; userAgent: string },
): Promise<boolean> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
	try {
		const resp = await fetch(url, {
			method: 'GET', // 用 GET 而非 HEAD，因为很多服务器对 .map 只配 GET
			signal: controller.signal,
			headers: {
				'User-Agent': opts.userAgent,
				Accept: 'application/json,*/*',
			},
			redirect: 'follow',
		});
		clearTimeout(timer);
		if (!resp.ok) return false;

		// 关键：检查内容是否是 JSON（.map 文件是 JSON）
		// SPA 服务器会对所有路径返回 index.html（200 + HTML），不能只看状态码
		const text = await resp.text();
		const trimmed = text.trimStart();
		if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
			return true;
		}
		// sourcemap JSON 至少含 version/sources 等字段
		if (trimmed.includes('"version"') && trimmed.includes('"sources"')) {
			return true;
		}
		return false;
	} catch {
		clearTimeout(timer);
		return false;
	}
}
