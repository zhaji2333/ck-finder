/**
 * finding 查重（M3.9，借鉴 AutoHunter dedup.py）
 *
 * 核心：dedup_key = sha256(host | endpoint | method | vuln_type)
 *   - 不含 seed_id / task_id → 跨任务可复用查重
 *   - endpoint 只取 path + query 参数名集合（参数值不进键）
 *
 * 两层查重：
 *   1. 全局 exact key：dedup_key 完全一致（跨任务/跨 seed）
 *   2. 同 host 软匹配：同 host + 同 vuln_type + 同 endpoint 路径
 */
import { createHash } from 'node:crypto';

/** 漏洞类型归一化（借鉴 AutoHunter normalize_vuln_type：折叠同义词） */
const VULN_TYPE_ALIASES: Record<string, string> = {
	未授权访问: 'unauthorized_access',
	unauthorizedaccess: 'unauthorized_access',
	authbypass: 'auth_bypass',
	认证绕过: 'auth_bypass',
	弱口令: 'weak_password',
	sql注入: 'sql_injection',
	注入: 'sql_injection',
	xss: 'xss',
	'cross-site': 'xss',
	文件上传: 'file_upload',
	目录遍历: 'path_traversal',
	任意文件读取: 'path_traversal',
	信息泄露: 'info_disclosure',
	敏感信息: 'info_disclosure',
};

export function normalizeVulnType(vulnType: string): string {
	const lower = vulnType.toLowerCase().trim();
	return VULN_TYPE_ALIASES[lower] ?? lower.replace(/[^a-z0-9_]+/g, '_');
}

/** endpoint 归一化：host + path + query 参数名集合（参数值不进键） */
export function normalizeEndpoint(url: string): { host: string; path: string } {
	try {
		const u = new URL(url);
		const host = u.hostname.toLowerCase().replace(/^www\./, '');
		const path = u.pathname;
		return { host, path };
	} catch {
		// 非 URL：按 host/path 拆分兜底
		const clean = url.replace(/^https?:\/\//i, '');
		const slash = clean.indexOf('/');
		if (slash === -1) return { host: clean.toLowerCase(), path: '/' };
		return { host: clean.slice(0, slash).toLowerCase(), path: clean.slice(slash) };
	}
}

/** 计算 dedup_key */
export function computeDedupKey(url: string, vulnType: string, method = 'GET'): string {
	const { host, path } = normalizeEndpoint(url);
	const normMethod = method.toUpperCase();
	return createHash('sha256')
		.update(`${host}|${path}|${normMethod}|${normalizeVulnType(vulnType)}`)
		.digest('hex');
}

/** 同一 dedup_key 是否已存在（全局 exact 查重） */
export async function isDuplicateByKey(
	queryFn: (dedupKey: string) => Promise<boolean>,
	url: string,
	vulnType: string,
	method = 'GET',
): Promise<boolean> {
	return queryFn(computeDedupKey(url, vulnType, method));
}
