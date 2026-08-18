/**
 * GitHub 代码搜索适配器
 *
 * 使用 GitHub REST API 的 /search/code 端点搜索代码泄露
 * - 按域名/公司名/关键字搜索
 * - 内置 github-dorks 规则集（常见敏感路径/配置文件泄露）
 * - 命中结果入 findings 表（type=github_leak）
 *
 * API 文档：https://docs.github.com/en/rest/search/search#search-code
 *
 * 限速：
 *   - 无 token：10 req/min（搜索 API 更严格，10 秒/次）
 *   - 有 token：30 req/min
 *
 * 设计：单次调用搜索一个 query，调用方按需多次调用。
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { buildCacheKey, cacheGet, cacheSet } from '../storage/cache.js';

export interface GithubSearchResult {
	/** 命中的 GitHub 仓库全名（owner/repo） */
	repo: string;
	/** 命中文件路径 */
	path: string;
	/** 文件在仓库中的 URL */
	htmlUrl: string;
	/** 命中的代码片段（GitHub 返回的 text_matches，可能为空） */
	snippet?: string;
	/** 仓库最近 push 时间 */
	repoPushedAt?: string;
	/** 仓库 star 数 */
	repoStars?: number;
}

export interface GithubSearchOptions {
	/** 搜索查询（GitHub search syntax） */
	query: string;
	/** 单页结果数（1-100，默认 30） */
	perPage?: number;
	/** 最大结果数（默认从 config.github.maxResults） */
	maxResults?: number;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 启用 L2 缓存（默认 true） */
	useCache?: boolean;
}

export interface GithubSearchResponse {
	total: number;
	incomplete: boolean;
	results: GithubSearchResult[];
}

const GITHUB_API_BASE = 'https://api.github.com';

/**
 * 执行 GitHub 代码搜索
 *
 * @returns 命中结果列表；失败返回空数组
 */
export async function searchGithubCode(opts: GithubSearchOptions): Promise<GithubSearchResponse> {
	const cfg = getConfig().github;
	const maxResults = opts.maxResults ?? cfg.maxResults;
	const perPage = Math.min(opts.perPage ?? 30, 100);

	const cacheKey =
		opts.useCache !== false
			? buildCacheKey('github', 'search', opts.query, `max${maxResults}`)
			: undefined;

	if (cacheKey) {
		const cached = await cacheGet<GithubSearchResponse>(cacheKey);
		if (cached) {
			await auditLog({
				actor: 'tool:github',
				action: 'tool_call',
				target: opts.query,
				decision: 'pass',
				reason: 'L2 cache hit',
				meta: { cached: true, count: cached.results.length },
			});
			return cached;
		}
	}

	const url = new URL(`${GITHUB_API_BASE}/search/code`);
	url.searchParams.set('q', opts.query);
	url.searchParams.set('per_page', String(perPage));

	const headers: Record<string, string> = {
		Accept: 'application/vnd.github+json',
		'X-GitHub-Api-Version': '2022-11-28',
		'User-Agent': 'ck-recon/0.1',
	};
	if (cfg.token) {
		headers.Authorization = `Bearer ${cfg.token}`;
	}

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30_000);

	let resp: Response;
	try {
		resp = await fetch(url, { method: 'GET', headers, signal: controller.signal });
	} catch (err) {
		clearTimeout(timer);
		await auditLog({
			actor: 'tool:github',
			action: 'tool_call',
			target: opts.query,
			decision: 'fail',
			reason: `fetch error: ${err instanceof Error ? err.message : String(err)}`,
		});
		return { total: 0, incomplete: true, results: [] };
	}
	clearTimeout(timer);

	if (resp.status === 403) {
		// 限速
		const rateLimitRemaining = resp.headers.get('x-ratelimit-remaining');
		const rateLimitReset = resp.headers.get('x-ratelimit-reset');
		await auditLog({
			actor: 'tool:github',
			action: 'tool_call',
			target: opts.query,
			decision: 'fail',
			reason: 'rate limited (403)',
			meta: { remaining: rateLimitRemaining, reset: rateLimitReset },
		});
		console.warn(`[github] rate limited; reset at ${rateLimitReset ?? '?'}`);
		return { total: 0, incomplete: true, results: [] };
	}

	if (!resp.ok) {
		await auditLog({
			actor: 'tool:github',
			action: 'tool_call',
			target: opts.query,
			decision: 'fail',
			reason: `HTTP ${resp.status}`,
		});
		return { total: 0, incomplete: true, results: [] };
	}

	const data = (await resp.json()) as {
		total_count: number;
		incomplete_results: boolean;
		items: Array<{
			name: string;
			path: string;
			html_url: string;
			repository?: { full_name: string; pushed_at?: string; stargazers_count?: number };
			text_matches?: Array<{ fragment?: string }>;
		}>;
	};

	const results: GithubSearchResult[] = (data.items ?? []).slice(0, maxResults).map((item) => ({
		repo: item.repository?.full_name ?? '',
		path: item.path,
		htmlUrl: item.html_url,
		snippet: item.text_matches?.[0]?.fragment,
		repoPushedAt: item.repository?.pushed_at,
		repoStars: item.repository?.stargazers_count,
	}));

	const response: GithubSearchResponse = {
		total: data.total_count,
		incomplete: data.incomplete_results,
		results,
	};

	if (cacheKey) {
		// GitHub 搜索结果缓存 6 小时（结果变化不快，且有限速）
		await cacheSet(cacheKey, response, { ttlSec: 6 * 3600 });
	}

	await auditLog({
		actor: 'tool:github',
		action: 'tool_call',
		target: opts.query,
		decision: 'allow',
		reason: `fetched ${results.length}/${data.total_count}`,
		meta: { total: data.total_count, returned: results.length },
	});

	return response;
}

// =============================================================================
// GitHub Dorks：常用敏感文件/关键字搜索规则
// =============================================================================

export interface GithubDorkRule {
	/** 规则 ID */
	id: string;
	/** 搜索查询模板（用 {target} 占位） */
	query: string;
	/** 期望命中的文件类型/路径（用于结果筛选） */
	expectedPath?: string;
	/** 严重级别 */
	severity: 'low' | 'medium' | 'high';
	/** 描述 */
	description: string;
}

/**
 * GitHub Dorks 规则集
 *
 * 按域名搜索时，这些查询会找出可能泄露的：
 * - 配置文件（含数据库密码/密钥）
 * - 源码备份
 * - .env 文件
 * - 硬编码的域名/接口
 */
export const GITHUB_DORKS: GithubDorkRule[] = [
	// 配置文件泄露
	{
		id: 'config-yaml',
		query: '{target} filename:config.yml',
		expectedPath: 'config.yml',
		severity: 'medium',
		description: '配置文件（可能含密钥/数据库连接）',
	},
	{
		id: 'config-json',
		query: '{target} filename:config.json',
		expectedPath: 'config.json',
		severity: 'medium',
		description: '配置文件（可能含密钥）',
	},
	{
		id: 'env-file',
		query: '{target} filename:.env',
		expectedPath: '.env',
		severity: 'high',
		description: '.env 文件（含敏感环境变量）',
	},
	{
		id: 'config-php',
		query: '{target} filename:config.php',
		expectedPath: 'config.php',
		severity: 'medium',
		description: 'PHP 配置文件',
	},
	// 源码备份
	{
		id: 'backup-sql',
		query: '{target} extension:sql',
		expectedPath: '.sql',
		severity: 'high',
		description: 'SQL 备份文件',
	},
	{
		id: 'backup-tar',
		query: '{target} extension:tar.gz',
		expectedPath: '.tar.gz',
		severity: 'high',
		description: 'tar.gz 备份文件',
	},
	{
		id: 'backup-zip',
		query: '{target} extension:zip',
		expectedPath: '.zip',
		severity: 'medium',
		description: 'zip 备份文件',
	},
	// 硬编码密钥
	{
		id: 'api-key',
		query: '"{target}" "api_key" OR "apikey" OR "api-key"',
		severity: 'high',
		description: '硬编码 API Key',
	},
	{
		id: 'secret-key',
		query: '"{target}" "secret_key" OR "secretKey" OR "SECRET"',
		severity: 'high',
		description: '硬编码 Secret',
	},
	{
		id: 'access-token',
		query: '"{target}" "access_token" OR "accessToken"',
		severity: 'high',
		description: '硬编码 Access Token',
	},
	// 内部接口
	{
		id: 'internal-api',
		query: '"{target}" "/api/" path:src',
		severity: 'medium',
		description: '源码中引用的内部 API 路径',
	},
	// Dockerfile / 部署配置
	{
		id: 'dockerfile',
		query: '{target} filename:Dockerfile',
		expectedPath: 'Dockerfile',
		severity: 'low',
		description: 'Dockerfile（可能泄露部署细节）',
	},
	{
		id: 'docker-compose',
		query: '{target} filename:docker-compose.yml',
		expectedPath: 'docker-compose.yml',
		severity: 'medium',
		description: 'docker-compose 配置',
	},
];

/**
 * 批量执行 GitHub Dorks 搜索
 *
 * @param target 搜索目标（域名/公司名）
 * @param opts.maxResultsPerDork 每条 dork 最大结果数（默认 20）
 * @param opts.skipDorks 跳过的 dork ID 列表
 * @returns 所有 dork 命中的结果（已合并去重）
 */
export async function runGithubDorks(
	target: string,
	opts: { maxResultsPerDork?: number; skipDorks?: string[] } = {},
): Promise<Array<GithubSearchResult & { dorkId: string; severity: string; description: string }>> {
	const skip = new Set(opts.skipDorks ?? []);
	const maxPerDork = opts.maxResultsPerDork ?? 20;

	const allResults: Array<
		GithubSearchResult & { dorkId: string; severity: string; description: string }
	> = [];
	const seenUrls = new Set<string>();

	for (const dork of GITHUB_DORKS) {
		if (skip.has(dork.id)) continue;
		const query = dork.query.replace('{target}', target);
		try {
			const resp = await searchGithubCode({
				query,
				maxResults: maxPerDork,
				useCache: true,
			});
			for (const r of resp.results) {
				if (seenUrls.has(r.htmlUrl)) continue;
				seenUrls.add(r.htmlUrl);
				allResults.push({
					...r,
					dorkId: dork.id,
					severity: dork.severity,
					description: dork.description,
				});
			}
			// GitHub 搜索 API 限速：有 token 30/min，无 token 10/min
			// 每次搜索间隔 2 秒，避免触发限速
			await new Promise((resolve) => setTimeout(resolve, 2000));
		} catch (err) {
			console.warn(`[github] dork ${dork.id} failed:`, err);
		}
	}

	return allResults;
}
