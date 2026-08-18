/**
 * 查询层（合并后新增）
 *
 * 把原来散落在 REST routes（api/routes/*）与 MCP server 里的裸 SQL 查询统一抽到这里，
 * REST、MCP、以及 ck-finder 的 recon_* 工具共用同一套本地查询。
 *
 * 全部为只读查询（SELECT），写路径仍在 models/asset.ts、models/recon.ts。
 */
import { getPg } from '../pg.js';

// ---------------------------------------------------------------------------
// seeds（任务）
// ---------------------------------------------------------------------------

export interface SeedQueryRow {
	id: string;
	seedType: string;
	value: string;
	status: string;
	assetCount: number;
	webappCount: number;
	createdAt: string;
	progress: unknown;
	meta: Record<string, unknown>;
}

function seedSelect() {
	return `SELECT s.id, s.seed_type, s.value, s.status, s.created_at, s.meta,
		(SELECT COUNT(*) FROM assets a WHERE a.seed_id = s.id) AS asset_count,
		(SELECT COUNT(*) FROM webapps w WHERE w.asset_id IN (SELECT id FROM assets WHERE seed_id = s.id)) AS webapp_count
	FROM seeds s`;
}

function toSeedRow(r: Record<string, unknown>): SeedQueryRow {
	return {
		id: r.id as string,
		seedType: r.seed_type as string,
		value: r.value as string,
		status: r.status as string,
		assetCount: Number.parseInt(String(r.asset_count), 10) || 0,
		webappCount: Number.parseInt(String(r.webapp_count), 10) || 0,
		createdAt: r.created_at as string,
		progress: (r.meta as Record<string, unknown> | null)?.progress ?? null,
		meta: (r.meta as Record<string, unknown> | null) ?? {},
	};
}

export async function querySeedById(id: string): Promise<SeedQueryRow | null> {
	const pool = getPg();
	const { rows } = await pool.query(`${seedSelect()} WHERE s.id = $1`, [id]);
	return rows.length > 0 ? toSeedRow(rows[0]) : null;
}

export async function querySeeds(limit = 20): Promise<SeedQueryRow[]> {
	const pool = getPg();
	const { rows } = await pool.query(`${seedSelect()} ORDER BY s.created_at DESC LIMIT $1`, [limit]);
	return rows.map(toSeedRow);
}

// ---------------------------------------------------------------------------
// assets
// ---------------------------------------------------------------------------

export interface AssetQueryRow {
	id: string;
	seedId: string | null;
	parentId: string | null;
	type: string;
	value: string;
	valueNorm: string;
	discoveredBy: string | null;
	alive: boolean | null;
	firstSeen: string | null;
	lastSeen: string | null;
}

function toAssetRow(r: Record<string, unknown>): AssetQueryRow {
	return {
		id: r.id as string,
		seedId: (r.seed_id as string | null) ?? null,
		parentId: (r.parent_id as string | null) ?? null,
		type: r.type as string,
		value: r.value as string,
		valueNorm: r.value_norm as string,
		discoveredBy: (r.discovered_by as string | null) ?? null,
		alive: r.alive === null ? null : Boolean(r.alive),
		firstSeen: (r.first_seen as string | null) ?? null,
		lastSeen: (r.last_seen as string | null) ?? null,
	};
}

export async function queryAssets(params: {
	seedId?: string;
	type?: string;
	limit?: number;
}): Promise<{ total: number; assets: AssetQueryRow[] }> {
	const whereParts: string[] = [];
	const values: unknown[] = [];
	let idx = 1;
	if (params.seedId) {
		whereParts.push(`seed_id = $${idx++}`);
		values.push(params.seedId);
	}
	if (params.type) {
		whereParts.push(`type = $${idx++}`);
		values.push(params.type);
	}
	const where = whereParts.length > 0 ? `WHERE ${whereParts.join(' AND ')}` : '';
	const limit = params.limit ?? 100;
	values.push(limit);
	const pool = getPg();
	// 独立 COUNT（WHERE 参数去掉末尾的 limit），避免 total 误报为页大小
	const countValues = values.slice(0, -1);
	const { rows: countRows } = await pool.query(
		`SELECT COUNT(*)::int AS n FROM assets ${where}`,
		countValues,
	);
	const { rows } = await pool.query(
		`SELECT id, seed_id, parent_id, type, value, value_norm, discovered_by, alive, first_seen, last_seen
		 FROM assets ${where}
		 ORDER BY type, first_seen DESC
		 LIMIT $${idx}`,
		values,
	);
	return { total: Number(countRows[0]?.n ?? 0), assets: rows.map(toAssetRow) };
}

export async function queryAssetById(id: string): Promise<Record<string, unknown> | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT id, seed_id, parent_id, type, value, value_norm, discovered_by, alive, first_seen, last_seen, meta
		 FROM assets WHERE id = $1`,
		[id],
	);
	return rows.length > 0 ? rows[0] : null;
}

/** ILIKE 模糊资产查询（MCP query_assets 用：按值模糊匹配 + 类型筛选） */
export async function queryAssetsFuzzy(params: {
	pattern: string;
	type?: string;
	limit?: number;
}): Promise<{ total: number; assets: AssetQueryRow[] }> {
	const pattern = `%${params.pattern}%`;
	const limit = params.limit ?? 50;
	const values: unknown[] = [pattern, limit];
	let typeClause = '';
	if (params.type) {
		typeClause = 'AND type = $3';
		values.push(params.type);
	}
	const pool = getPg();
	// 独立 COUNT（去掉 limit）
	const countValues = [pattern];
	if (params.type) countValues.push(params.type);
	const { rows: countRows } = await pool.query(
		`SELECT COUNT(*)::int AS n FROM assets WHERE value ILIKE $1 ${typeClause}`,
		countValues,
	);
	const { rows } = await pool.query(
		`SELECT id, seed_id, parent_id, type, value, value_norm, discovered_by, alive, first_seen, last_seen
		 FROM assets
		 WHERE value ILIKE $1 ${typeClause}
		 ORDER BY type, last_seen DESC
		 LIMIT $2`,
		values,
	);
	return { total: Number(countRows[0]?.n ?? 0), assets: rows.map(toAssetRow) };
}

// ---------------------------------------------------------------------------
// webapps（含评分 + findings 聚合）
// ---------------------------------------------------------------------------

export interface WebappQueryRow {
	assetId: string;
	url: string;
	title: string | null;
	statusCode: number | null;
	tech: unknown[];
	host: string | null;
	port: number | null;
	webserver: string | null;
	cdn: boolean | null;
	waf: string | null;
	role: string | null;
	score: number | null;
	scoreBreakdown: unknown[];
	loginPage: boolean | null;
	hardToAttack: boolean | null;
	fingerprints: unknown[];
	meta: Record<string, unknown>;
	findingCount: number;
	findingTypes: unknown[];
	findingMaxSeverity: string | null;
	/** 当前挖洞中的活跃意图数（running+pending），用于「挖洞中」标记 */
	activeIntents: number;
	firstSeen: string | null;
	lastSeen: string | null;
}

function toWebappRow(r: Record<string, unknown>): WebappQueryRow {
	return {
		assetId: r.asset_id as string,
		url: r.url as string,
		title: (r.title as string | null) ?? null,
		statusCode: r.status_code === null ? null : Number(r.status_code),
		tech: (r.tech as unknown[] | null) ?? [],
		host: (r.host as string | null) ?? null,
		port: r.port === null ? null : Number(r.port),
		webserver: (r.webserver as string | null) ?? null,
		cdn: r.cdn === null ? null : Boolean(r.cdn),
		waf: (r.waf as string | null) ?? null,
		role: (r.role as string | null) ?? null,
		score: r.score === null ? null : Number(r.score),
		scoreBreakdown: (r.score_breakdown as unknown[] | null) ?? [],
		loginPage: r.login_page === null ? null : Boolean(r.login_page),
		hardToAttack: r.hard_to_attack === null ? null : Boolean(r.hard_to_attack),
		fingerprints: (r.fingerprints as unknown[] | null) ?? [],
		meta: (r.meta as Record<string, unknown> | null) ?? {},
		findingCount: Number.parseInt(String(r.finding_count), 10) || 0,
		findingTypes: (r.finding_types as unknown[] | null) ?? [],
		findingMaxSeverity: (r.finding_max_severity as string | null) ?? null,
		activeIntents: Number.parseInt(String(r.active_intents), 10) || 0,
		firstSeen: (r.first_seen as string | null) ?? null,
		lastSeen: (r.last_seen as string | null) ?? null,
	};
}

export async function queryWebapps(params: {
	scoreGt?: number;
	role?: string;
	/** 只查有 cve_hints 信号的目标（低分但已知组件漏洞——AutoHunter 已知组件最高优先） */
	hasCveHints?: boolean;
	/** 按 seed 过滤（JOIN assets，只查当前任务的资产——防 planner 跨 seed 串扰） */
	seedId?: string;
	/** 排除域名（逗号分隔，防误挖历史资产如 lenovomm.com） */
	excludeDomains?: string[];
	limit?: number;
	offset?: number;
}): Promise<{ total: number; webapps: WebappQueryRow[] }> {
	const whereParts: string[] = ['score > $1'];
	const values: unknown[] = [params.scoreGt ?? 0];
	let idx = 2;
	if (params.role) {
		whereParts.push(`role = $${idx++}`);
		values.push(params.role);
	}
	if (params.hasCveHints) {
		// meta 里 cve_hints 非空数组
		whereParts.push(
			`COALESCE(jsonb_array_length(COALESCE(w.meta->'cve_hints','[]'::jsonb)),0) > 0`,
		);
	}
	if (params.seedId) {
		// 关联 assets 过滤到当前 seed（webapp 的 asset_id 即 assets.id）
		whereParts.push(
			`EXISTS (SELECT 1 FROM assets a WHERE a.id = w.asset_id AND a.seed_id = $${idx++})`,
		);
		values.push(params.seedId);
	}
	if (params.excludeDomains && params.excludeDomains.length > 0) {
		// 排除指定域名（host 精确/子域匹配，如 lenovomm.com 及其子域）——防误挖历史资产
		const orParts: string[] = [];
		for (const d of params.excludeDomains) {
			const norm = d.toLowerCase().replace(/^\*\./, '');
			orParts.push(`(w.host = $${idx} OR w.host LIKE $${idx + 1})`);
			values.push(norm, `%.${norm}`);
			idx += 2;
		}
		whereParts.push(`NOT (${orParts.join(' OR ')})`);
	}
	const where = whereParts.join(' AND ');
	const limit = params.limit ?? 50;
	const offset = params.offset ?? 0;
	values.push(limit, offset);
	const pool = getPg();
	// 独立 COUNT（WHERE 参数去掉末尾 limit/offset），避免 total 误报为页大小
	const countValues = values.slice(0, -2);
	const { rows: countRows } = await pool.query(
		`SELECT COUNT(*)::int AS n FROM webapps w WHERE ${where}`,
		countValues,
	);
	const { rows } = await pool.query(
		`SELECT w.asset_id, w.url, w.title, w.status_code, w.tech, w.host, w.port, w.webserver,
		        w.cdn, w.waf, w.role, w.score, w.score_breakdown,
		        w.login_page, w.hard_to_attack, w.fingerprints, w.meta,
		        w.first_seen, w.last_seen,
		        (SELECT COUNT(*) FROM findings f WHERE f.webapp_id = w.asset_id) AS finding_count,
		        (SELECT COALESCE(jsonb_agg(DISTINCT f2.type), '[]'::jsonb)
		         FROM findings f2 WHERE f2.webapp_id = w.asset_id) AS finding_types,
		        (SELECT MAX(f3.severity) FROM findings f3 WHERE f3.webapp_id = w.asset_id) AS finding_max_severity,
		        (SELECT COUNT(*)::int FROM exploration_intents i
		         WHERE i.asset_id = w.asset_id AND i.status IN ('running','pending')) AS active_intents
		 FROM webapps w
		 WHERE ${where}
		 ORDER BY w.score DESC, w.last_seen DESC
		 LIMIT $${idx} OFFSET $${idx + 1}`,
		values,
	);
	return { total: Number(countRows[0]?.n ?? 0), webapps: rows.map(toWebappRow) };
}

export async function queryWebappById(id: string): Promise<Record<string, unknown> | null> {
	const pool = getPg();
	const { rows } = await pool.query('SELECT w.* FROM webapps w WHERE w.asset_id = $1', [id]);
	return rows.length > 0 ? rows[0] : null;
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

export interface FindingQueryRow {
	id: string;
	assetId: string | null;
	webappId: string | null;
	type: string;
	severity: string;
	detail: string;
	evidence: string | null;
	sourceTool: string | null;
	createdAt: string | null;
	meta: Record<string, unknown>;
}

function toFindingRow(r: Record<string, unknown>): FindingQueryRow {
	return {
		id: r.id as string,
		assetId: (r.asset_id as string | null) ?? null,
		webappId: (r.webapp_id as string | null) ?? null,
		type: r.type as string,
		severity: r.severity as string,
		detail: r.detail as string,
		evidence: (r.evidence as string | null) ?? null,
		sourceTool: (r.source_tool as string | null) ?? null,
		createdAt: (r.created_at as string | null) ?? null,
		meta: (r.meta as Record<string, unknown> | null) ?? {},
	};
}

export async function queryFindings(params: {
	type?: string;
	severity?: string;
	webappId?: string;
	assetId?: string;
	limit?: number;
}): Promise<{ total: number; findings: FindingQueryRow[] }> {
	const whereParts: string[] = [];
	const values: unknown[] = [];
	let idx = 1;
	if (params.type) {
		whereParts.push(`type = $${idx++}`);
		values.push(params.type);
	}
	if (params.severity) {
		whereParts.push(`severity = $${idx++}`);
		values.push(params.severity);
	}
	if (params.webappId) {
		whereParts.push(`webapp_id = $${idx++}`);
		values.push(params.webappId);
	}
	if (params.assetId) {
		whereParts.push(`asset_id = $${idx++}`);
		values.push(params.assetId);
	}
	const where = whereParts.length > 0 ? `WHERE ${whereParts.join(' AND ')}` : '';
	const limit = params.limit ?? 100;
	values.push(limit);
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT id, asset_id, webapp_id, type, severity, detail, evidence, source_tool, created_at, meta
		 FROM findings ${where}
		 ORDER BY
		   CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		   created_at DESC
		 LIMIT $${idx}`,
		values,
	);
	return { total: rows.length, findings: rows.map(toFindingRow) };
}

export async function queryFindingById(id: string): Promise<Record<string, unknown> | null> {
	const pool = getPg();
	const { rows } = await pool.query('SELECT * FROM findings WHERE id = $1', [id]);
	return rows.length > 0 ? rows[0] : null;
}

/** ILIKE 发现检索（MCP search_findings 用：detail 模糊匹配 + 严重程度/目标筛选） */
export async function queryFindingsFuzzy(params: {
	keyword: string;
	severity?: string;
	webappId?: string;
	limit?: number;
}): Promise<{ total: number; findings: FindingQueryRow[] }> {
	const keyword = `%${params.keyword}%`;
	const limit = params.limit ?? 50;
	const whereParts: string[] = ['detail ILIKE $1'];
	const values: unknown[] = [keyword];
	let idx = 2;
	if (params.severity) {
		whereParts.push(`severity = $${idx++}`);
		values.push(params.severity);
	}
	if (params.webappId) {
		whereParts.push(`webapp_id = $${idx++}`);
		values.push(params.webappId);
	}
	values.push(limit);
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT id, asset_id, webapp_id, type, severity, detail, evidence, source_tool, created_at, meta
		 FROM findings
		 WHERE ${whereParts.join(' AND ')}
		 ORDER BY
		   CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		   created_at DESC
		 LIMIT $${idx}`,
		values,
	);
	return { total: rows.length, findings: rows.map(toFindingRow) };
}

// ---------------------------------------------------------------------------
// scan_runs
// ---------------------------------------------------------------------------

export interface ScanRunQueryRow {
	id: string;
	seedId: string | null;
	assetId: string | null;
	tool: string;
	status: string;
	params: Record<string, unknown>;
	resultSummary: Record<string, unknown>;
	error: string | null;
	startedAt: string | null;
	finishedAt: string | null;
	durationMs: number | null;
}

function toScanRunRow(r: Record<string, unknown>): ScanRunQueryRow {
	return {
		id: r.id as string,
		seedId: (r.seed_id as string | null) ?? null,
		assetId: (r.asset_id as string | null) ?? null,
		tool: r.tool as string,
		status: r.status as string,
		params: (r.params as Record<string, unknown> | null) ?? {},
		resultSummary: (r.result_summary as Record<string, unknown> | null) ?? {},
		error: (r.error as string | null) ?? null,
		startedAt: (r.started_at as string | null) ?? null,
		finishedAt: (r.finished_at as string | null) ?? null,
		durationMs: r.duration_ms === null ? null : Number(r.duration_ms),
	};
}

export async function queryScanRuns(params: {
	seedId?: string;
	assetId?: string;
	tool?: string;
	status?: string;
	limit?: number;
}): Promise<{ total: number; scanRuns: ScanRunQueryRow[] }> {
	const whereParts: string[] = [];
	const values: unknown[] = [];
	let idx = 1;
	if (params.assetId) {
		whereParts.push(`asset_id = $${idx++}`);
		values.push(params.assetId);
	}
	if (params.seedId) {
		whereParts.push(`seed_id = $${idx++}`);
		values.push(params.seedId);
	}
	if (params.tool) {
		whereParts.push(`tool = $${idx++}`);
		values.push(params.tool);
	}
	if (params.status) {
		whereParts.push(`status = $${idx++}`);
		values.push(params.status);
	}
	const where = whereParts.length > 0 ? `WHERE ${whereParts.join(' AND ')}` : '';
	const limit = params.limit ?? 50;
	values.push(limit);
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT id, seed_id, asset_id, tool, status, params, result_summary, error,
		        started_at, finished_at,
		        EXTRACT(EPOCH FROM (COALESCE(finished_at, now()) - started_at)) * 1000 AS duration_ms
		 FROM scan_runs ${where}
		 ORDER BY started_at DESC
		 LIMIT $${idx}`,
		values,
	);
	return { total: rows.length, scanRuns: rows.map(toScanRunRow) };
}

export async function queryScanRunById(id: string): Promise<Record<string, unknown> | null> {
	const pool = getPg();
	const { rows } = await pool.query('SELECT * FROM scan_runs WHERE id = $1', [id]);
	return rows.length > 0 ? rows[0] : null;
}
