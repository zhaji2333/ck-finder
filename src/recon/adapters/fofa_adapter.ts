/**
 * FOFA REST API 适配器
 *
 * 官方 API：https://fofa.info/api/v1/search/all
 *   - 认证：email + key（query string）
 *   - 查询：qbase64 = base64(query)
 *   - 字段：通过 fields 参数指定，默认 host,ip,port,title,server
 *
 * 启用条件：.env 中同时配置 FOFA_EMAIL + FOFA_KEY
 *
 * 安全约束：
 *   - 仅允许只读 search 接口
 *   - 不缓存（避免敏感资产数据落盘）
 *   - 全量 audit log
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';

export interface FofaAsset {
	host: string;
	ip?: string;
	port?: number;
	title?: string;
	server?: string;
	/** favicon mmh3 hash */
	iconHash?: string;
	/** HTTP/HTTPS */
	protocol?: string;
	/** 响应 body 前 N 字节 */
	banner?: string;
}

export interface FofaSearchOptions {
	/** FOFA 查询语法（如 icon_hash="123456" 或 domain="baidu.com"） */
	query: string;
	/** 返回数量上限（默认 100，FOFA 单次上限 10000，免费账户通常 100-500） */
	maxResults?: number;
	/** 超时（毫秒，默认 30s） */
	timeoutMs?: number;
	/** 返回字段（默认 host,ip,port,title,server,protocol,banner,icon_hash） */
	fields?: string;
}

export interface FofaSearchResult {
	enabled: boolean;
	total: number;
	assets: FofaAsset[];
	/** 未启用或失败时的提示信息 */
	message?: string;
	/** 消耗的 F 点（FOFA 计费） */
	consumedFpoint?: number;
}

const FOFA_API_BASE = 'https://fofa.info/api/v1';
/**
 * 默认返回字段（不含 icon_hash，普通会员可能无权限查询 icon_hash 字段，
 * 需要时调用方显式传 fields='host,ip,port,title,icon_hash'）
 */
const DEFAULT_FIELDS = 'host,ip,port,title,server,protocol,banner';

/**
 * FOFA 是否已启用（配置了 email + key）
 */
export function isFofaEnabled(): boolean {
	const cfg = getConfig().fofa;
	return !!(cfg.email && cfg.key);
}

/**
 * 搜索 FOFA 资产
 *
 * 调用 FOFA REST API: GET /search/all?email=...&key=...&qbase64=...&size=...&fields=...
 */
export async function searchFofaAssets(opts: FofaSearchOptions): Promise<FofaSearchResult> {
	const cfg = getConfig().fofa;

	if (!isFofaEnabled()) {
		await auditLog({
			actor: 'tool:fofa',
			action: 'tool_call',
			target: opts.query,
			decision: 'deny',
			reason: 'FOFA disabled (no email/key configured)',
			meta: { query: opts.query },
		});
		return {
			enabled: false,
			total: 0,
			assets: [],
			message: 'FOFA 未启用（缺 FOFA_EMAIL/FOFA_KEY）。配置后自动启用。',
		};
	}

	const size = Math.min(opts.maxResults ?? 100, 10_000);
	const fields = opts.fields ?? DEFAULT_FIELDS;
	const timeoutMs = opts.timeoutMs ?? 30_000;

	// FOFA 要求 query 必须用 base64 编码
	const qbase64 = Buffer.from(opts.query, 'utf8').toString('base64');
	const url = new URL(`${FOFA_API_BASE}/search/all`);
	url.searchParams.set('email', cfg.email);
	url.searchParams.set('key', cfg.key);
	url.searchParams.set('qbase64', qbase64);
	url.searchParams.set('size', String(size));
	url.searchParams.set('fields', fields);

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);

	const startTs = Date.now();
	try {
		const resp = await fetch(url.toString(), {
			method: 'GET',
			signal: controller.signal,
			headers: {
				Accept: 'application/json',
				'User-Agent': 'ck-recon/0.1 (+https://github.com/ck-recon)',
			},
		});
		clearTimeout(timer);
		const durationMs = Date.now() - startTs;

		if (!resp.ok) {
			const errText = await resp.text().catch(() => '');
			await auditLog({
				actor: 'tool:fofa',
				action: 'tool_call',
				target: opts.query,
				decision: 'deny',
				reason: `FOFA HTTP ${resp.status}`,
				meta: {
					query: opts.query,
					status: resp.status,
					durationMs,
					errSnippet: errText.slice(0, 200),
				},
			});
			return {
				enabled: true,
				total: 0,
				assets: [],
				message: `FOFA HTTP ${resp.status}: ${errText.slice(0, 200)}`,
			};
		}

		const data = (await resp.json()) as FofaApiResponse;

		if (data.error) {
			await auditLog({
				actor: 'tool:fofa',
				action: 'tool_call',
				target: opts.query,
				decision: 'deny',
				reason: `FOFA API error: ${data.errmsg ?? 'unknown'}`,
				meta: { query: opts.query, durationMs, errmsg: data.errmsg },
			});
			return {
				enabled: true,
				total: 0,
				assets: [],
				message: `FOFA API 错误: ${data.errmsg ?? 'unknown'}`,
			};
		}

		// 解析 results，第一行为字段名，后续为数据行
		const assets = parseFofaResults(data, fields);

		await auditLog({
			actor: 'tool:fofa',
			action: 'tool_call',
			target: opts.query,
			decision: 'pass',
			reason: `FOFA ok: total=${data.size} returned=${assets.length} fpoint=${data.consumed_fpoint ?? 0}`,
			meta: {
				query: opts.query,
				total: data.size,
				returned: assets.length,
				consumedFpoint: data.consumed_fpoint,
				durationMs,
			},
		});

		return {
			enabled: true,
			total: data.size,
			assets,
			consumedFpoint: data.consumed_fpoint,
		};
	} catch (err) {
		clearTimeout(timer);
		const durationMs = Date.now() - startTs;
		const errMsg = err instanceof Error ? err.message : String(err);
		await auditLog({
			actor: 'tool:fofa',
			action: 'tool_call',
			target: opts.query,
			decision: 'deny',
			reason: `FOFA fetch failed: ${errMsg}`,
			meta: { query: opts.query, durationMs, err: errMsg },
		});
		return {
			enabled: true,
			total: 0,
			assets: [],
			message: `FOFA 请求失败: ${errMsg}`,
		};
	}
}

/**
 * 用 icon_hash 反查资产（关联资产发现）
 *
 * 用例：拿到一个 webapp 的 favicon hash，用 FOFA 找出同 hash 的其他资产
 *
 * @param iconHash favicon mmh3 hash（数字或字符串）
 */
export async function searchByIconHash(
	iconHash: string | number,
	opts: { maxResults?: number } = {},
): Promise<FofaSearchResult> {
	return searchFofaAssets({
		query: `icon_hash="${iconHash}"`,
		maxResults: opts.maxResults ?? 100,
	});
}

// =============================================================================
// 内部：FOFA API 响应解析
// =============================================================================

interface FofaApiResponse {
	error: boolean;
	errmsg?: string;
	consumed_fpoint?: number;
	required_fpoints?: number;
	size: number;
	page?: number;
	mode?: string;
	/** 第一行字段名，后续为数据 */
	results: string[][];
}

/**
 * 解析 FOFA 返回的二维数组为 FofaAsset[]
 *
 * FOFA 返回格式：
 *   results: [
 *     ["host","ip","port","title","server","protocol","banner","icon_hash"],
 *     ["example.com","1.2.3.4","443","首页","nginx","https","...","123"],
 *     ...
 *   ]
 *
 * 但实际生产环境观察：results 不含表头，直接是数据行，字段顺序按 fields 参数。
 * 这里两种格式都兼容。
 */
function parseFofaResults(data: FofaApiResponse, requestedFields: string): FofaAsset[] {
	if (!data.results || data.results.length === 0) return [];

	const fieldList = requestedFields.split(',').map((s) => s.trim());
	const assets: FofaAsset[] = [];

	// 检测第一行是否为表头：如果第一行的所有值都匹配字段名，则视为表头
	let startIdx = 0;
	if (data.results[0]) {
		const firstRow = data.results[0];
		const isHeader =
			firstRow.length === fieldList.length && firstRow.every((v, i) => v === fieldList[i]);
		if (isHeader) startIdx = 1;
	}

	for (let i = startIdx; i < data.results.length; i++) {
		const row = data.results[i];
		if (!row || row.length === 0) continue;

		const asset: Partial<FofaAsset> = {};
		for (let j = 0; j < fieldList.length && j < row.length; j++) {
			const field = fieldList[j];
			const val = row[j];
			if (val === undefined || val === null || val === '') continue;

			switch (field) {
				case 'host':
					asset.host = val;
					break;
				case 'ip':
					asset.ip = val;
					break;
				case 'port':
					asset.port = Number.parseInt(val, 10) || undefined;
					break;
				case 'title':
					asset.title = val;
					break;
				case 'server':
					asset.server = val;
					break;
				case 'protocol':
					asset.protocol = val;
					break;
				case 'banner':
					asset.banner = val;
					break;
				case 'icon_hash':
					asset.iconHash = val;
					break;
			}
		}
		if (asset.host) assets.push(asset as FofaAsset);
	}

	return assets;
}
