/**
 * M3 入库模型：endpoints / js_apis / params / findings
 *
 * 对应 001_init.sql §7-§11 表结构。
 * 所有 upsert 都按业务唯一键去重，已存在则更新 last_seen/discovered_at。
 */

import { auditLog } from '../../gate/audit_log.js';
import { getPg } from '../pg.js';

// =============================================================================
// endpoints：端点（URL/接口路径）
// =============================================================================

export type EndpointSource = 'js' | 'historical' | 'dirscan' | 'fofa' | 'icp' | 'manual';

export interface UpsertEndpointInput {
	webappId: string;
	url: string;
	path: string;
	method?: string;
	source: EndpointSource;
	statusCode?: number;
}

/** upsert endpoint（按 webapp_id+path+method+source 去重） */
export async function upsertEndpoint(input: UpsertEndpointInput): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO endpoints (webapp_id, url, path, method, source, status_code)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (webapp_id, path, method, source) DO UPDATE
       SET url = COALESCE(EXCLUDED.url, endpoints.url),
           status_code = COALESCE(EXCLUDED.status_code, endpoints.status_code),
           discovered_at = now()`,
		[
			input.webappId,
			input.url,
			input.path,
			input.method ?? 'GET',
			input.source,
			input.statusCode ?? null,
		],
	);
}

/** 批量 upsert endpoints（按 path+method+source 去重，避免重复请求 DB） */
export async function upsertEndpoints(
	webappId: string,
	items: Array<Omit<UpsertEndpointInput, 'webappId'>>,
): Promise<number> {
	if (items.length === 0) return 0;
	const seen = new Set<string>();
	let inserted = 0;
	for (const item of items) {
		const key = `${item.path}|${item.method ?? 'GET'}|${item.source}`;
		if (seen.has(key)) continue;
		seen.add(key);
		await upsertEndpoint({ ...item, webappId });
		inserted++;
	}
	return inserted;
}

// =============================================================================
// js_apis：JS 内提取的接口
// =============================================================================

export interface UpsertJsApiInput {
	webappId: string;
	apiPath: string;
	method?: string;
	params?: string[];
	sourceJs?: string;
}

/** upsert js_api（按 webapp_id+api_path+method 去重） */
export async function upsertJsApi(input: UpsertJsApiInput): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO js_apis (webapp_id, api_path, method, params, source_js)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (webapp_id, api_path, method) DO UPDATE
       SET params = CASE WHEN EXCLUDED.params = '{}' THEN js_apis.params
                         ELSE ARRAY(SELECT DISTINCT unnest(js_apis.params || EXCLUDED.params)) END,
           source_js = COALESCE(EXCLUDED.source_js, js_apis.source_js),
           found_at = now()`,
		[
			input.webappId,
			input.apiPath,
			input.method ?? 'GET',
			input.params ?? [],
			input.sourceJs ?? null,
		],
	);
}

/** 批量 upsert js_apis */
export async function upsertJsApis(
	webappId: string,
	items: Array<Omit<UpsertJsApiInput, 'webappId'>>,
): Promise<number> {
	if (items.length === 0) return 0;
	const seen = new Set<string>();
	let inserted = 0;
	for (const item of items) {
		const key = `${item.apiPath}|${item.method ?? 'GET'}`;
		if (seen.has(key)) continue;
		seen.add(key);
		await upsertJsApi({ ...item, webappId });
		inserted++;
	}
	return inserted;
}

// =============================================================================
// params：参数（历史/JS/dirscan）
// =============================================================================

export type ParamSource = 'historical' | 'js' | 'dirscan';

export interface UpsertParamInput {
	webappId: string;
	param: string;
	source: ParamSource;
	context?: string;
}

/** upsert param（按 webapp_id+param+source 去重） */
export async function upsertParam(input: UpsertParamInput): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO params (webapp_id, param, source, context)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (webapp_id, param, source) DO UPDATE
       SET context = COALESCE(EXCLUDED.context, params.context),
           discovered_at = now()`,
		[input.webappId, input.param, input.source, input.context ?? null],
	);
}

/** 批量 upsert params */
export async function upsertParams(
	webappId: string,
	items: Array<Omit<UpsertParamInput, 'webappId'>>,
): Promise<number> {
	if (items.length === 0) return 0;
	const seen = new Set<string>();
	let inserted = 0;
	for (const item of items) {
		const key = `${item.param}|${item.source}`;
		if (seen.has(key)) continue;
		seen.add(key);
		await upsertParam({ ...item, webappId });
		inserted++;
	}
	return inserted;
}

// =============================================================================
// findings：发现（敏感信息/源码泄露/CVE hint/内网 IP/敏感路径/GitHub 泄露）
// =============================================================================

export type FindingType =
	| 'sourcemap'
	| 'secret'
	| 'cve_hint'
	| 'internal_ip'
	| 'sensitive_path'
	| 'github_leak'
	| 'sensitive_file'
	| 'info_leak'
	| 'source_audit';

export type FindingSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface UpsertFindingInput {
	/** 资产 ID（assets.id），必填 */
	assetId: string;
	/** webapp 资产 ID，可空 */
	webappId?: string;
	type: FindingType;
	severity: FindingSeverity;
	detail: string;
	evidence?: string;
	sourceTool: string;
	meta?: Record<string, unknown>;
}

/** 写入 finding（每次新发现都写一条，不去重；调用方自行控制是否重复扫描） */
export async function insertFinding(input: UpsertFindingInput): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO findings (asset_id, webapp_id, type, severity, detail, evidence, source_tool, meta)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		[
			input.assetId,
			input.webappId ?? null,
			input.type,
			input.severity,
			input.detail,
			input.evidence ?? null,
			input.sourceTool,
			JSON.stringify(input.meta ?? {}),
		],
	);
	await auditLog({
		actor: `tool:${input.sourceTool}`,
		action: 'data_write',
		target: input.webappId ?? input.assetId,
		decision: 'pass',
		reason: `finding:${input.type}/${input.severity}`,
		meta: { detail: input.detail.slice(0, 200), type: input.type, severity: input.severity },
	});
}

/** 批量写入 findings */
export async function insertFindings(items: UpsertFindingInput[]): Promise<number> {
	if (items.length === 0) return 0;
	for (const item of items) {
		await insertFinding(item);
	}
	return items.length;
}

/** 查询某 webapp 的所有 findings */
export async function queryFindingsByWebapp(
	webappId: string,
	opts: { type?: FindingType; severity?: FindingSeverity; limit?: number } = {},
): Promise<UpsertFindingInput[]> {
	const pool = getPg();
	const conditions = ['webapp_id = $1'];
	const values: unknown[] = [webappId];
	let idx = 2;
	if (opts.type) {
		conditions.push(`type = $${idx++}`);
		values.push(opts.type);
	}
	if (opts.severity) {
		conditions.push(`severity = $${idx++}`);
		values.push(opts.severity);
	}
	values.push(opts.limit ?? 100);
	const { rows } = await pool.query(
		`SELECT asset_id, webapp_id, type, severity, detail, evidence, source_tool, meta, created_at
     FROM findings
     WHERE ${conditions.join(' AND ')}
     ORDER BY created_at DESC
     LIMIT $${idx}`,
		values,
	);
	return rows as unknown as UpsertFindingInput[];
}

// =============================================================================
// scan_runs 辅助：判断某 webapp 是否已跑过某工具（避免重扫）
// =============================================================================

/**
 * 判断 webapp 最近是否已成功跑过某工具
 *
 * @param webappId webapp 资产 ID（= assets.id）
 * @param tool 工具名（如 'dirsearch'、'waybackurls'、'gau'）
 * @param maxAgeMs 最大可接受的历史记录时长（默认 7 天，超时则重跑）
 * @returns true 表示已跑过且未过期，可跳过
 */
export async function isWebappScannedRecently(
	webappId: string,
	tool: string,
	maxAgeMs: number = 7 * 24 * 3600 * 1000,
): Promise<boolean> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT 1 FROM scan_runs
     WHERE asset_id = $1 AND tool = $2 AND status = 'done'
       AND finished_at IS NOT NULL
       AND finished_at > now() - ($3 || ' milliseconds')::interval
     LIMIT 1`,
		[webappId, tool, String(maxAgeMs)],
	);
	return rows.length > 0;
}

// =============================================================================
// 页面语义分类（LLM 分析 Phase 1：endpoints.page_role）
// =============================================================================

/**
 * 批量更新 endpoints 的页面语义分类（page_role）
 *
 * 由 LLM 页面分类分析写入：login/admin/api_doc/upload/export/payment/debug/auth/business/static/other
 */
export async function updateEndpointPageRoles(
	webappId: string,
	items: Array<{ path: string; role: string; reason?: string }>,
): Promise<number> {
	if (items.length === 0) return 0;
	const pool = getPg();
	let updated = 0;
	for (const item of items) {
		if (!item.path || !item.role) continue;
		const r = await pool.query(
			`UPDATE endpoints SET page_role = $3, meta = COALESCE(meta, '{}'::jsonb) || $4::jsonb
       WHERE webapp_id = $1 AND path = $2 AND page_role IS NULL`,
			[webappId, item.path, item.role, JSON.stringify({ page_role_reason: item.reason ?? '' })],
		);
		updated += r.rowCount ?? 0;
	}
	return updated;
}

/** 查询某 webapp 已分类的页面角色统计 */
export async function queryEndpointRoles(
	webappId: string,
): Promise<Array<{ page_role: string; count: number }>> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT page_role, COUNT(*)::int AS count FROM endpoints
     WHERE webapp_id = $1 AND page_role IS NOT NULL
     GROUP BY page_role ORDER BY count DESC`,
		[webappId],
	);
	return rows;
}
