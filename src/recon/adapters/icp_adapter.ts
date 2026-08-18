/**
 * ICP_Query 适配器
 *
 * 工信部 ICP 备案查询服务（架构文档 §4.2）
 * 服务：yiminger/ymicp docker 镜像，监听 :16181
 * 接口：GET /query/web?search=<keyword>&pageNum=<n>&pageSize=<n>
 *
 * 用法：
 *   1. 按域名查备案信息（拿公司名）：queryIcpByDomain('baidu.com')
 *   2. 按公司名反查域名（资产发现）：queryDomainsByCompany('北京百度网讯科技有限公司')
 *
 * 返回字段（params.list[]）：
 *   domain, unitName, mainLicence, serviceLicence, natureName,
 *   contentTypeName, serviceName, updateRecordTime, leaderName, limitAccess
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { buildCacheKey, cacheGet, cacheSet } from '../storage/cache.js';

/** ICP 备案记录 */
export interface IcpRecord {
	/** 域名 */
	domain: string;
	/** 主办单位名称（公司名） */
	unitName: string;
	/** 主许可证号（如 京ICP证030173号） */
	mainLicence: string;
	/** 服务许可证号 */
	serviceLicence?: string;
	/** 单位性质（企业/个人/政府等） */
	natureName?: string;
	/** 网站服务内容类型 */
	contentTypeName?: string;
	/** 网站服务名称 */
	serviceName?: string;
	/** 更新时间 */
	updateRecordTime?: string;
	/** 负责人 */
	leaderName?: string;
	/** 限制接入 */
	limitAccess?: string;
}

/** ICP 查询响应 */
interface IcpResponse {
	code: number;
	msg: string;
	success: boolean;
	params: {
		total: number;
		pageNum: number;
		pageSize: number;
		pages: number;
		list: Array<{
			domain: string;
			domainId?: number;
			unitName: string;
			mainId?: number;
			mainLicence: string;
			serviceId?: number;
			serviceLicence?: string;
			natureName?: string;
			contentTypeName?: string;
			serviceName?: string;
			updateRecordTime?: string;
			leaderName?: string;
			limitAccess?: string;
		}>;
	};
}

export interface IcpQueryOptions {
	/** 搜索关键词（域名或公司名都行） */
	search: string;
	/** 页码，默认 1 */
	pageNum?: number;
	/** 每页数量，默认 50 */
	pageSize?: number;
	/** 超时（毫秒），默认 30 秒（ICP 接口可能触发验证码，需要时间） */
	timeoutMs?: number;
	/** 是否启用 L2 缓存（默认 true，备案信息变化慢） */
	useCache?: boolean;
}

/**
 * 查询 ICP 备案
 *
 * 内部统一调用 /query/web 接口，无论是按域名还是按公司名查都走同一接口。
 * 调用方根据需求决定如何使用结果。
 */
export async function queryIcp(opts: IcpQueryOptions): Promise<{
	records: IcpRecord[];
	total: number;
	pageNum: number;
	pageSize: number;
}> {
	const cfg = getConfig().icp;
	const pageNum = opts.pageNum ?? 1;
	const pageSize = opts.pageSize ?? 50;

	const cacheKey =
		opts.useCache !== false
			? buildCacheKey('icp', 'search', opts.search, `p${pageNum}s${pageSize}`)
			: undefined;

	// 缓存命中
	if (cacheKey) {
		const cached = await cacheGet<{
			records: IcpRecord[];
			total: number;
			pageNum: number;
			pageSize: number;
		}>(cacheKey);
		if (cached) {
			await auditLog({
				actor: 'tool:icp',
				action: 'tool_call',
				target: opts.search,
				decision: 'pass',
				reason: 'L2 cache hit',
				meta: { cached: true, count: cached.records.length },
			});
			return cached;
		}
	}

	const url = new URL(`${cfg.url}/query/web`);
	url.searchParams.set('search', opts.search);
	url.searchParams.set('pageNum', String(pageNum));
	url.searchParams.set('pageSize', String(pageSize));

	const startAt = Date.now();
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30_000);

	let resp: Response;
	try {
		resp = await fetch(url, {
			method: 'GET',
			signal: controller.signal,
			headers: { Accept: 'application/json' },
		});
	} catch (err) {
		clearTimeout(timer);
		await auditLog({
			actor: 'tool:icp',
			action: 'tool_call',
			target: opts.search,
			decision: 'fail',
			reason: `fetch error: ${err instanceof Error ? err.message : String(err)}`,
		});
		return { records: [], total: 0, pageNum, pageSize };
	}
	clearTimeout(timer);
	const durationMs = Date.now() - startAt;

	if (!resp.ok) {
		await auditLog({
			actor: 'tool:icp',
			action: 'tool_call',
			target: opts.search,
			decision: 'fail',
			reason: `HTTP ${resp.status}`,
			meta: { durationMs },
		});
		return { records: [], total: 0, pageNum, pageSize };
	}

	let data: IcpResponse;
	try {
		data = (await resp.json()) as IcpResponse;
	} catch (err) {
		await auditLog({
			actor: 'tool:icp',
			action: 'tool_call',
			target: opts.search,
			decision: 'fail',
			reason: `json parse error: ${err instanceof Error ? err.message : String(err)}`,
			meta: { durationMs },
		});
		return { records: [], total: 0, pageNum, pageSize };
	}

	// 转换为标准化记录
	const records: IcpRecord[] = (data.params?.list ?? [])
		.map((item) => ({
			domain: (item.domain ?? '').toLowerCase().trim(),
			unitName: item.unitName ?? '',
			mainLicence: item.mainLicence ?? '',
			serviceLicence: item.serviceLicence,
			natureName: item.natureName,
			contentTypeName: item.contentTypeName,
			serviceName: item.serviceName,
			updateRecordTime: item.updateRecordTime,
			leaderName: item.leaderName,
			limitAccess: item.limitAccess,
		}))
		.filter((r) => r.domain && r.unitName);

	const result = {
		records,
		total: data.params?.total ?? 0,
		pageNum,
		pageSize,
	};

	// 写缓存（24 小时，备案信息变化慢）
	if (cacheKey) {
		await cacheSet(cacheKey, result, { ttlSec: 24 * 3600 });
	}

	await auditLog({
		actor: 'tool:icp',
		action: 'tool_call',
		target: opts.search,
		decision: 'allow',
		reason: `fetched ${records.length}/${result.total}`,
		meta: { durationMs, count: records.length, total: result.total },
	});

	return result;
}

/**
 * 按域名查备案（拿公司名）
 *
 * 用例：拿到一个域名，想确认它属于哪个公司
 */
export async function queryIcpByDomain(
	domain: string,
	opts: { timeoutMs?: number } = {},
): Promise<IcpRecord | null> {
	const { records } = await queryIcp({
		search: domain,
		pageSize: 5,
		timeoutMs: opts.timeoutMs,
	});
	// 优先返回完全匹配的记录
	const exact = records.find((r) => r.domain === domain.toLowerCase());
	return exact ?? records[0] ?? null;
}

/**
 * 按公司名反查域名（资产发现核心）
 *
 * 用例：从公司名出发，找出该公司备案的所有域名
 *
 * @param company 公司全名（如「北京百度网讯科技有限公司」）
 * @param opts.maxDomains 最大返回域名数（防止大公司返回上千条，默认 200）
 * @param opts.timeoutMs 单次请求超时
 */
export async function queryDomainsByCompany(
	company: string,
	opts: { maxDomains?: number; timeoutMs?: number; pageSize?: number } = {},
): Promise<IcpRecord[]> {
	const maxDomains = opts.maxDomains ?? 200;
	const pageSize = opts.pageSize ?? 50;
	const allRecords: IcpRecord[] = [];
	let pageNum = 1;
	let total = Number.POSITIVE_INFINITY;

	while (allRecords.length < maxDomains && pageNum <= Math.ceil(total / pageSize)) {
		const result = await queryIcp({
			search: company,
			pageNum,
			pageSize,
			timeoutMs: opts.timeoutMs,
		});
		if (pageNum === 1) total = result.total;
		allRecords.push(...result.records);
		if (result.records.length < pageSize) break; // 已到末页
		pageNum++;
		// 安全上限：最多翻 20 页
		if (pageNum > 20) break;
	}

	// 去重（按 domain）
	const seen = new Set<string>();
	const deduped: IcpRecord[] = [];
	for (const r of allRecords) {
		if (seen.has(r.domain)) continue;
		seen.add(r.domain);
		deduped.push(r);
	}

	return deduped.slice(0, maxDomains);
}
