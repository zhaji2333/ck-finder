/**
 * JS 文件下载器 + 接口提取器（纯 TS 实现）
 *
 * 职责：
 * 1. 下载给定的 JS 文件 URL（HTTP GET，带超时和大小上限）
 * 2. 从 JS 内容中提取：
 *    - API 路径（/api/xxx, /v1/xxx, fetch('xxx'), axios.get('xxx')）
 *    - 字符串字面量中的 URL 路径
 *    - 敏感信息（key/token/secret/AKID/access_key 等）
 *
 * 这是 M3.2 + M3.3 的纯 TS 实现，不依赖外部工具。
 * katana 提供发现 JS 文件的能力，本模块负责"读 JS 内容"。
 */

import { auditLog } from '../gate/audit_log.js';

export interface JsFetchResult {
	url: string;
	ok: boolean;
	status?: number;
	content?: string;
	contentLength?: number;
	error?: string;
}

export interface JsApiEndpoint {
	/** API 路径，如 /api/v1/login */
	path: string;
	/** 推断的 HTTP 方法（无法推断时为 GET） */
	method: string;
	/** 命中的源 JS URL */
	sourceJs: string;
	/** 命中的上下文（前后各 80 字符） */
	context?: string;
	/** 推断的参数名（从 query/path 中提取） */
	params?: string[];
}

export interface JsSecret {
	/** 敏感信息类型（access_key/token/secret/password/private_key/jwt/webhook_url 等） */
	type: string;
	/** 命中的值（脱敏后） */
	value: string;
	/** 命中的源 JS URL */
	sourceJs: string;
	/** 上下文 */
	context?: string;
}

export interface JsScanResult {
	/** 下载的 JS 文件数 */
	fetchedCount: number;
	/** 失败数 */
	failedCount: number;
	/** 提取的 API 端点 */
	endpoints: JsApiEndpoint[];
	/** 提取的敏感信息 */
	secrets: JsSecret[];
}

export interface JsScanOptions {
	/** JS 文件 URL 列表 */
	urls: string[];
	/** 单文件超时（毫秒，默认 15s） */
	timeoutMs?: number;
	/** 最大文件大小（字节，默认 2MB，超出跳过） */
	maxSizeBytes?: number;
	/** 并发数（默认 5） */
	concurrency?: number;
	/** User-Agent */
	userAgent?: string;
	/** 启用 LLM 补充提取：正则命中少时用 flash 模型补充（预算由 llm_js_extract 控制） */
	useLlm?: boolean;
	/** webapp 资产 ID（LLM 预算与审计用，useLlm 时必填） */
	webappId?: string;
}

/**
 * 下载并扫描多个 JS 文件
 */
export async function scanJsFiles(opts: JsScanOptions): Promise<JsScanResult> {
	const timeoutMs = opts.timeoutMs ?? 15_000;
	const maxSize = opts.maxSizeBytes ?? 2 * 1024 * 1024;
	const concurrency = opts.concurrency ?? 5;
	const ua =
		opts.userAgent ?? 'Mozilla/5.0 (compatible; ck-recon/0.1; +https://github.com/ck-recon)';

	const endpoints: JsApiEndpoint[] = [];
	const secrets: JsSecret[] = [];
	let fetchedCount = 0;
	let failedCount = 0;

	// 简单的并发池
	const queue = [...opts.urls];
	const workers: Promise<void>[] = [];
	for (let w = 0; w < Math.min(concurrency, opts.urls.length); w++) {
		workers.push(
			(async () => {
				while (queue.length > 0) {
					const url = queue.shift();
					if (!url) break;
					const result = await fetchJs(url, { timeoutMs, maxSizeBytes: maxSize, userAgent: ua });
					if (!result.ok || !result.content) {
						failedCount++;
						continue;
					}
					fetchedCount++;
					const eps = extractApiEndpoints(result.content, url);
					const secs = extractSecrets(result.content, url);

					// LLM 补充提取：正则命中少时用 flash 补接口（触发/预算/去重由 llm_js_extract 控制）
					if (opts.useLlm && opts.webappId) {
						try {
							const { getConfig } = await import('../config.js');
							if (getConfig().llm.jsExtractEnabled) {
								const { extractApisByLlm } = await import('../scoring/llm_js_extract.js');
								const llmResult = await extractApisByLlm({
									webappId: opts.webappId,
									url,
									content: result.content,
									sourceJs: url,
									ruleHits: eps.map((e) => ({ path: e.path, method: e.method })),
								});
								if (llmResult.endpoints.length > 0) {
									for (const ep of llmResult.endpoints) {
										const dup = eps.some((e) => e.path === ep.path && e.method === ep.method);
										if (!dup) {
											eps.push({
												path: ep.path,
												method: ep.method,
												params: ep.params,
												sourceJs: url,
											});
										}
									}
								}
							}
						} catch {
							// LLM 失败不影响正则结果
						}
					}

					endpoints.push(...eps);
					secrets.push(...secs);
				}
			})(),
		);
	}
	await Promise.all(workers);

	// 去重 endpoints（按 path+method）
	const seenEp = new Set<string>();
	const dedupEndpoints: JsApiEndpoint[] = [];
	for (const ep of endpoints) {
		const key = `${ep.method}|${ep.path}|${ep.sourceJs}`;
		if (seenEp.has(key)) continue;
		seenEp.add(key);
		dedupEndpoints.push(ep);
	}

	await auditLog({
		actor: 'tool:js_scan',
		action: 'scan_finish',
		target: `${opts.urls.length} js files`,
		decision: 'pass',
		reason: `fetched=${fetchedCount} failed=${failedCount} endpoints=${dedupEndpoints.length} secrets=${secrets.length}`,
		meta: {
			fetchedCount,
			failedCount,
			endpointCount: dedupEndpoints.length,
			secretCount: secrets.length,
		},
	});

	return {
		fetchedCount,
		failedCount,
		endpoints: dedupEndpoints,
		secrets,
	};
}

// =============================================================================
// 内部：JS 文件下载
// =============================================================================

async function fetchJs(
	url: string,
	opts: { timeoutMs: number; maxSizeBytes: number; userAgent: string },
): Promise<JsFetchResult> {
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

		if (!resp.ok) {
			return { url, ok: false, status: resp.status, error: `HTTP ${resp.status}` };
		}

		const contentLength = Number.parseInt(resp.headers.get('content-length') ?? '0', 10);
		if (contentLength > opts.maxSizeBytes) {
			return { url, ok: false, status: resp.status, error: `too large (${contentLength} bytes)` };
		}

		const text = await resp.text();
		if (text.length > opts.maxSizeBytes) {
			return { url, ok: false, status: resp.status, error: `too large (${text.length} bytes)` };
		}

		return {
			url,
			ok: true,
			status: resp.status,
			content: text,
			contentLength: text.length,
		};
	} catch (err) {
		clearTimeout(timer);
		return {
			url,
			ok: false,
			error: err instanceof Error ? err.message : String(err),
		};
	}
}

// =============================================================================
// 内部：API 端点提取
// =============================================================================

/**
 * 从 JS 内容中提取 API 端点
 *
 * 匹配模式：
 * 1. 字符串字面量中的路径：'/api/...', '/v1/...', '/v2/...'
 * 2. fetch('...'), axios.get('...'), $.ajax({url:'...'}), XMLHttpRequest.open('GET', '...')
 * 3. 路径模板：`/users/${id}` 中的 /users 部分
 */
export function extractApiEndpoints(content: string, sourceJs: string): JsApiEndpoint[] {
	const out: JsApiEndpoint[] = [];

	// 模式 1：字符串字面量中的 API 路径（双引号/单引号/反引号）
	// 匹配 '/api/...', '/v1/...', '/v2/...'，路径至少 2 段
	const apiPathRegex =
		/['"`](\/(?:api|v\d|graphql|rest|service|admin|manage|backend|internal)\/[A-Za-z0-9_\-./{}$]+)['"`]/g;
	for (const match of content.matchAll(apiPathRegex)) {
		const path = match[1];
		if (!path || path.length > 500) continue;
		const context = extractContext(content, match.index ?? 0, 80);
		out.push({
			path: normalizePath(path),
			method: inferMethod(content, match.index ?? 0),
			sourceJs,
			context,
		});
	}

	// 模式 2：fetch('url'), axios.get('url'), $.ajax({url:'...'})
	const fetchRegex =
		/(?:fetch|axios\.(?:get|post|put|delete|patch|head|options)|axios\(\s*\{[^}]*url:\s*|XMLHttpRequest[^)]*open\(\s*['"](\w+)['"]\s*,\s*)['"`]([^'"`]+)['"`]/gi;
	for (const match of content.matchAll(fetchRegex)) {
		const method = match[1]?.toUpperCase() || 'GET';
		const url = match[2];
		if (!url) continue;
		// 提取路径部分（去掉 query string 和 hash）
		let path: string;
		try {
			if (/^https?:\/\//i.test(url)) {
				const parsed = new URL(url);
				path = parsed.pathname || '/';
			} else if (url.startsWith('/')) {
				path = url.split('?')[0].split('#')[0];
			} else {
				// 相对路径，跳过
				continue;
			}
		} catch {
			continue;
		}
		if (path === '/' || path.length < 2 || path.length > 500) continue;
		const context = extractContext(content, match.index ?? 0, 80);
		const params = extractParamsFromUrl(url);
		out.push({ path: normalizePath(path), method, sourceJs, context, params });
	}

	return out;
}

/**
 * 从 URL/path 中提取 query 参数名
 */
function extractParamsFromUrl(url: string): string[] {
	try {
		const queryStart = url.indexOf('?');
		if (queryStart < 0) return [];
		const queryStr = url.slice(queryStart + 1).split('#')[0];
		const params: string[] = [];
		for (const pair of queryStr.split('&')) {
			const key = pair.split('=')[0];
			if (key) params.push(key);
		}
		return params;
	} catch {
		return [];
	}
}

/**
 * 标准化路径：去 query/hash，替换模板变量
 *
 * 例：/api/users/123  →  /api/users/{id}
 *     /api/v1/posts/abc/comments  →  /api/v1/posts/{id}/comments
 */
function normalizePath(path: string): string {
	let p = path.split('?')[0].split('#')[0];
	// 把纯数字段替换为 {id}
	p = p.replace(/\/(\d+)(?=\/|$)/g, '/{id}');
	// 把 UUID 段替换为 {id}
	p = p.replace(
		/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi,
		'/{id}',
	);
	// 去掉末尾斜杠
	if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1);
	return p;
}

/**
 * 从上下文推断 HTTP 方法
 */
function inferMethod(content: string, matchIndex: number): string {
	// 向前看 50 字符，找 method 提示
	const before = content.slice(Math.max(0, matchIndex - 50), matchIndex).toLowerCase();
	if (before.includes('post') || before.includes('create') || before.includes('add')) return 'POST';
	if (before.includes('put') || before.includes('update')) return 'PUT';
	if (before.includes('delete') || before.includes('remove')) return 'DELETE';
	if (before.includes('patch')) return 'PATCH';
	return 'GET';
}

/**
 * 提取匹配位置的上下文（前后各 n 字符）
 */
function extractContext(content: string, index: number, n: number): string {
	const start = Math.max(0, index - n);
	const end = Math.min(content.length, index + n);
	return content.slice(start, end).replace(/\s+/g, ' ').trim();
}

// =============================================================================
// 内部：敏感信息提取
// =============================================================================

/**
 * 敏感信息正则规则
 *
 * 设计原则：
 * - 高置信度规则（精确格式，如 AWS Access Key）：直接命中
 * - 通用规则（如 password=xxx）：要求 key=value 形式，避免误报
 * - 值长度合理：3-200 字符
 */
interface SecretRule {
	type: string;
	pattern: RegExp;
	/** 是否对值做脱敏（默认 true，仅保留首尾 4 字符） */
	mask?: boolean;
}

const SECRET_RULES: SecretRule[] = [
	// AWS Access Key ID（20 个大写字母数字，以 AKIA/ASIA/AGPA 等开头）
	{
		type: 'aws_access_key',
		pattern: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16})\b/g,
	},
	// AWS Secret Access Key（40 个 base64 字符，前缀常伴 secret）
	{
		type: 'aws_secret_key',
		pattern:
			/\b(?:aws_secret|secret_access_key|SecretAccessKey)['"\s:=]+['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
	},
	// 阿里云 AccessKey ID（24 个字符，以 LTAI 开头）
	{
		type: 'aliyun_access_key_id',
		pattern: /\b(LTAI[A-Za-z0-9]{17,20})\b/g,
	},
	// 腾讯云 SecretId（36 字符）
	{
		type: 'tencent_secret_id',
		pattern: /\b(AKID[A-Za-z0-9]{32,40})\b/g,
	},
	// 通用 API Key / Token
	{
		type: 'api_key',
		pattern:
			/\b(?:api[_-]?key|apikey|api[_-]?secret)['"\s:=]+['"]?([A-Za-z0-9_\-./+]{16,128})['"]?/gi,
	},
	// JWT（三段式，eyJ 开头）
	{
		type: 'jwt',
		pattern: /\b(eyJ[A-Za-z0-9_-]{10,200}\.eyJ[A-Za-z0-9_-]{10,200}\.[A-Za-z0-9_-]{10,200})\b/g,
	},
	// Slack Token
	{
		type: 'slack_token',
		pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b/g,
	},
	// GitHub Token
	{
		type: 'github_token',
		pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
	},
	// 通用 token/password/secret 赋值
	{
		type: 'token',
		pattern:
			/\b(?:token|access[_-]?token|auth[_-]?token|bearer)['"\s:=]+['"]?([A-Za-z0-9_\-./+=]{16,200})['"]?/gi,
	},
	{
		type: 'password',
		pattern: /\b(?:password|passwd|pwd)['"\s:=]+['"]?([^\s'"<>]{4,128})['"]?/gi,
	},
	{
		type: 'secret',
		pattern:
			/\b(?:secret|client[_-]?secret|app[_-]?secret)['"\s:=]+['"]?([A-Za-z0-9_\-./+=]{8,200})['"]?/gi,
	},
	// Private Key（PEM 格式）
	{
		type: 'private_key',
		pattern:
			/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
		mask: false,
	},
	// 内网 IP（10./172.16-31./192.168.）
	{
		type: 'internal_ip',
		pattern: /\b((?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b/g,
		mask: false,
	},
	// 数据库连接字符串（mongodb/mysql/postgres://user:pass@host）
	{
		type: 'db_connection_string',
		pattern: /\b((?:mongodb|mysql|postgres|postgresql|redis|amqp):\/\/[^\s\'"<>]{4,200})\b/gi,
	},
	// Webhook URL（常见服务）
	{
		type: 'webhook_url',
		pattern:
			/\b(https:\/\/(?:hooks\.slack\.com|oapi\.dingtalk\.com|qyapi\.weixin\.qq\.com)\/[A-Za-z0-9_\-./]+)\b/g,
		mask: false,
	},
];

export function extractSecrets(content: string, sourceJs: string): JsSecret[] {
	const out: JsSecret[] = [];
	for (const rule of SECRET_RULES) {
		rule.pattern.lastIndex = 0;
		for (const match of content.matchAll(rule.pattern)) {
			const value = match[1] ?? match[0];
			if (!value || value.length < 3 || value.length > 500) continue;
			const context = extractContext(content, match.index ?? 0, 80);
			out.push({
				type: rule.type,
				value: rule.mask === false ? value : maskValue(value),
				sourceJs,
				context,
			});
		}
	}
	return out;
}

/**
 * 值脱敏：保留首尾 4 字符，中间用 *** 代替
 *
 * 例：AKIAIOSFODNN7EXAMPLE → AKIA***MPLE
 *     sk-abc1234567890   → sk-a***7890
 */
function maskValue(value: string): string {
	if (value.length <= 8) return `${value.slice(0, 2)}***`;
	if (value.length <= 16) return `${value.slice(0, 4)}***${value.slice(-4)}`;
	return `${value.slice(0, 4)}***${value.slice(-4)}`;
}
