/**
 * 资产图入库模型
 *
 * 核心操作：
 * - upsertSeed: 创建/更新种子
 * - upsertAsset: 创建/更新资产（去重 + 来源链）
 * - upsertIp: IP 资产 + ips 表
 * - upsertService: 端口服务
 * - upsertWebapp: webapp 资产 + webapps 表
 *
 * 设计要点：
 * - 所有 upsert 都返回资产 UUID（已存在则更新 last_seen，不存在则新建）
 * - parent_id 形成来源链（discovered_by + parent_id 可追溯完整发现路径）
 * - value_norm 作为去重键
 */

import { auditLog } from '../../gate/audit_log.js';
import type { Seed } from '../../seeds/types.js';
import { getPg } from '../pg.js';

export type AssetType = 'domain' | 'subdomain' | 'ip' | 'url' | 'webapp' | 'company';

export interface UpsertAssetInput {
	type: AssetType;
	value: string;
	valueNorm: string;
	seedId?: string;
	parentId?: string;
	discoveredBy: string;
	alive?: boolean;
	meta?: Record<string, unknown>;
}

export interface Asset {
	id: string;
	seed_id: string | null;
	parent_id: string | null;
	type: AssetType;
	value: string;
	value_norm: string;
	discovered_by: string;
	discovered_at: Date;
	first_seen: Date;
	last_seen: Date;
	alive: boolean | null;
	meta: Record<string, unknown>;
}

/** 创建/更新种子 */
export async function upsertSeed(seed: Seed): Promise<string> {
	const pool = getPg();
	const { rows } = await pool.query(
		`INSERT INTO seeds (seed_type, value, value_norm, status)
     VALUES ($1, $2, $3, 'pending')
     ON CONFLICT (seed_type, value_norm) DO UPDATE
       SET status = CASE WHEN seeds.status = 'done' THEN 'running' ELSE seeds.status END
     RETURNING id`,
		[seed.seedType, seed.value, seed.valueNorm],
	);
	const seedId = rows[0].id;
	await auditLog({
		actor: 'system',
		action: 'seed_submit',
		target: seed.valueNorm,
		decision: 'info',
		reason: `seed type=${seed.seedType}`,
		meta: { seedId, seedType: seed.seedType },
	});
	return seedId;
}

/** 按 type+valueNorm 查询资产 */
export async function findAsset(type: AssetType, valueNorm: string): Promise<Asset | null> {
	const pool = getPg();
	const { rows } = await pool.query('SELECT * FROM assets WHERE type = $1 AND value_norm = $2', [
		type,
		valueNorm,
	]);
	return rows[0] ?? null;
}

/** 更新种子状态（pending → running → done/failed） */
export async function updateSeedStatus(
	seedId: string,
	status: 'pending' | 'running' | 'done' | 'failed' | 'partial',
): Promise<void> {
	const pool = getPg();
	await pool.query('UPDATE seeds SET status = $2 WHERE id = $1', [seedId, status]);
}

/** 扫描进度（写入 seeds.meta.progress，供 Web UI 展示） */
export interface SeedProgress {
	stage: string;
	stageLabel: string;
	stageIndex: number;
	totalStages: number;
	/** 各阶段产出量 */
	subdomainCount?: number;
	webappCount?: number;
	scoredCount?: number;
	/** 自动深挖进度 */
	deepScan?: { done: number; total: number; current?: string };
	updatedAt: string;
}

export async function updateSeedProgress(seedId: string, progress: SeedProgress): Promise<void> {
	const pool = getPg();
	await pool.query('UPDATE seeds SET meta = meta || $1::jsonb WHERE id = $2', [
		JSON.stringify({ progress }),
		seedId,
	]);
}

/**
 * 删除种子及其全部关联数据（级联：assets → webapps/ips/services/findings → 各子表）
 *
 * 注意：
 * - scan_runs.seed_id 为 SET NULL（扫描记录保留但失去种子关联）
 * - audit_log 无外键（审计日志永不删除）
 * - planner_decisions 按 seed value 同步清理
 * - sources/ 磁盘目录不自动删（可能被其他种子共用），由调用方提示
 *
 * @returns 删除的资产数量
 */
export async function deleteSeed(
	seedId: string,
): Promise<{ assetCount: number; seedType: string; seedValue: string }> {
	const pool = getPg();
	const client = await pool.connect();
	try {
		await client.query('BEGIN');
		// 种子信息（审计用）
		const { rows: seedRows } = await client.query(
			'SELECT seed_type, value_norm FROM seeds WHERE id = $1',
			[seedId],
		);
		if (seedRows.length === 0) throw new Error(`seed not found: ${seedId}`);
		const { seed_type: seedType, value_norm: seedValue } = seedRows[0];

		// 资产计数（审计用）
		const { rows: countRows } = await client.query(
			'SELECT COUNT(*)::int AS n FROM assets WHERE seed_id = $1',
			[seedId],
		);
		const assetCount = countRows[0].n;

		// planner 决策缓存（按 seed value）
		await client.query('DELETE FROM planner_decisions WHERE seed_type = $1 AND seed_value = $2', [
			seedType,
			seedValue,
		]);

		// 主删除（CASCADE 清理全部子表）
		await client.query('DELETE FROM seeds WHERE id = $1', [seedId]);

		await client.query('COMMIT');

		await auditLog({
			actor: 'system',
			action: 'data_write',
			target: seedValue,
			decision: 'pass',
			reason: `delete seed ${seedId}: ${assetCount} assets cascaded`,
			meta: { seedId, seedType, assetCount },
		});
		return { assetCount, seedType, seedValue };
	} catch (err) {
		await client.query('ROLLBACK');
		throw err;
	} finally {
		client.release();
	}
}

/** 创建/更新资产（去重 + 来源链） */
export async function upsertAsset(input: UpsertAssetInput): Promise<string> {
	const pool = getPg();
	const { rows } = await pool.query(
		`INSERT INTO assets (type, value, value_norm, seed_id, parent_id, discovered_by, alive, meta)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (type, value_norm) DO UPDATE
       SET last_seen = now(),
           seed_id = COALESCE(EXCLUDED.seed_id, assets.seed_id),
           parent_id = COALESCE(EXCLUDED.parent_id, assets.parent_id),
           alive = COALESCE(EXCLUDED.alive, assets.alive),
           meta = CASE WHEN EXCLUDED.meta::text = '{}'::text
                       THEN assets.meta
                       ELSE assets.meta || EXCLUDED.meta END
     RETURNING id`,
		[
			input.type,
			input.value,
			input.valueNorm,
			input.seedId ?? null,
			input.parentId ?? null,
			input.discoveredBy,
			input.alive ?? null,
			JSON.stringify(input.meta ?? {}),
		],
	);
	return rows[0].id;
}

/** 批量 upsert 子域（来自 subfinder）——单条多行 INSERT ... ON CONFLICT，消除 N+1 往返 */
export async function upsertSubdomains(
	seedId: string,
	parentDomainAssetId: string,
	hosts: string[],
	discoveredBy: string,
): Promise<string[]> {
	const pool = getPg();
	const cleanHosts = [...new Set(hosts.map((h) => h.toLowerCase().trim()).filter(Boolean))];
	if (cleanHosts.length === 0) return [];

	const values: unknown[] = [];
	const placeholders: string[] = [];
	let idx = 1;
	for (const host of cleanHosts) {
		placeholders.push(
			`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, NULL, '{}')`,
		);
		values.push('subdomain', host, host, seedId, parentDomainAssetId, discoveredBy);
	}

	const { rows } = await pool.query(
		`INSERT INTO assets (type, value, value_norm, seed_id, parent_id, discovered_by, alive, meta)
		 VALUES ${placeholders.join(', ')}
		 ON CONFLICT (type, value_norm) DO UPDATE
		   SET last_seen = now(),
		       seed_id = COALESCE(EXCLUDED.seed_id, assets.seed_id),
		       parent_id = COALESCE(EXCLUDED.parent_id, assets.parent_id),
		       alive = COALESCE(EXCLUDED.alive, assets.alive)
		 RETURNING id`,
		values,
	);
	return rows.map((r) => r.id as string);
}

export interface UpsertIpOptions {
	seedId?: string;
	parentId?: string;
	discoveredBy: string;
	asn?: number;
	org?: string;
	cidr?: string;
	isp?: string;
	cdnFlag?: boolean;
	cdnVendor?: string;
	country?: string;
}

/** upsert IP 资产 + ips 表 */
export async function upsertIpAsset(ip: string, opts: UpsertIpOptions): Promise<string> {
	const assetId = await upsertAsset({
		type: 'ip',
		value: ip,
		valueNorm: ip,
		seedId: opts.seedId,
		parentId: opts.parentId,
		discoveredBy: opts.discoveredBy,
	});

	const pool = getPg();
	await pool.query(
		`INSERT INTO ips (asset_id, ip, asn, org, cidr, isp, cdn_flag, cdn_vendor, country)
     VALUES ($1, $2::inet, $3, $4, $5::cidr, $6, $7, $8, $9)
     ON CONFLICT (asset_id) DO UPDATE
       SET last_seen = now(),
           asn = COALESCE(EXCLUDED.asn, ips.asn),
           org = COALESCE(EXCLUDED.org, ips.org),
           cidr = COALESCE(EXCLUDED.cidr, ips.cidr),
           cdn_flag = EXCLUDED.cdn_flag OR ips.cdn_flag,
           cdn_vendor = COALESCE(EXCLUDED.cdn_vendor, ips.cdn_vendor)`,
		[
			assetId,
			ip,
			opts.asn ?? null,
			opts.org ?? null,
			opts.cidr ?? null,
			opts.isp ?? null,
			opts.cdnFlag ?? false,
			opts.cdnVendor ?? null,
			opts.country ?? null,
		],
	);
	return assetId;
}

/** upsert 端口服务 */
export async function upsertService(
	ipAssetId: string,
	ip: string,
	port: number,
	protocol: 'tcp' | 'udp',
	opts: {
		seedId?: string;
		service?: string;
		version?: string;
		banner?: string;
		isHttp?: boolean;
		discoveredBy: string;
	},
): Promise<string> {
	const pool = getPg();
	const { rows } = await pool.query(
		`INSERT INTO services (asset_id, ip, port, protocol, service, version, banner, is_http, discovered_by)
     VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (ip, port, protocol) DO UPDATE
       SET last_seen = now(),
           service = COALESCE(EXCLUDED.service, services.service),
           version = COALESCE(EXCLUDED.version, services.version),
           banner = COALESCE(EXCLUDED.banner, services.banner),
           is_http = services.is_http OR EXCLUDED.is_http,
           asset_id = services.asset_id
     RETURNING id`,
		[
			ipAssetId,
			ip,
			port,
			protocol,
			opts.service ?? null,
			opts.version ?? null,
			opts.banner ?? null,
			opts.isHttp ?? false,
			opts.discoveredBy,
		],
	);
	return rows[0].id;
}

/** 批量 upsert 资产（单条多行 INSERT ... ON CONFLICT，消除 N+1）。返回 value_norm → id 映射 */
export async function upsertAssetsBatch(
	entries: UpsertAssetInput[],
): Promise<Map<string, string>> {
	const pool = getPg();
	const map = new Map<string, string>();
	if (entries.length === 0) return map;

	const values: unknown[] = [];
	const placeholders: string[] = [];
	let idx = 1;
	for (const e of entries) {
		placeholders.push(
			`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`,
		);
		values.push(
			e.type,
			e.value,
			e.valueNorm,
			e.seedId ?? null,
			e.parentId ?? null,
			e.discoveredBy,
			e.alive ?? null,
			JSON.stringify(e.meta ?? {}),
		);
	}
	const { rows } = await pool.query(
		`INSERT INTO assets (type, value, value_norm, seed_id, parent_id, discovered_by, alive, meta)
		 VALUES ${placeholders.join(', ')}
		 ON CONFLICT (type, value_norm) DO UPDATE
		   SET last_seen = now(),
		       seed_id = COALESCE(EXCLUDED.seed_id, assets.seed_id),
		       parent_id = COALESCE(EXCLUDED.parent_id, assets.parent_id),
		       alive = COALESCE(EXCLUDED.alive, assets.alive),
		       meta = CASE WHEN EXCLUDED.meta::text = '{}'::text THEN assets.meta ELSE assets.meta || EXCLUDED.meta END
		 RETURNING id, value_norm`,
		values,
	);
	for (const r of rows) map.set(r.value_norm as string, r.id as string);
	return map;
}

/** 批量 upsert IP 资产 + ips 表（同 IP 去重 + 单条多行 INSERT）。返回 ip → assetId 映射 */
export async function upsertIpAssetsBatch(
	entries: Array<{ ip: string; opts: UpsertIpOptions }>,
): Promise<Map<string, string>> {
	const pool = getPg();
	if (entries.length === 0) return new Map();

	// 同 IP 去重（多端口共享同一 IP，只 upsert 一次）
	const unique = new Map<string, UpsertIpOptions>();
	for (const e of entries) {
		const ip = e.ip.trim();
		if (!ip) continue;
		if (!unique.has(ip)) unique.set(ip, e.opts);
	}

	const assetMap = await upsertAssetsBatch(
		[...unique.entries()].map(([ip, opts]) => ({
			type: 'ip' as const,
			value: ip,
			valueNorm: ip,
			seedId: opts.seedId,
			parentId: opts.parentId,
			discoveredBy: opts.discoveredBy,
		})),
	);

	const ipValues: unknown[] = [];
	const ipPlaceholders: string[] = [];
	let j = 1;
	for (const [ip, opts] of unique) {
		const assetId = assetMap.get(ip);
		if (!assetId) continue;
		ipPlaceholders.push(
			`($${j++}, $${j++}::inet, $${j++}, $${j++}, $${j++}::cidr, $${j++}, $${j++}, $${j++}, $${j++})`,
		);
		ipValues.push(
			assetId,
			ip,
			opts.asn ?? null,
			opts.org ?? null,
			opts.cidr ?? null,
			opts.isp ?? null,
			opts.cdnFlag ?? false,
			opts.cdnVendor ?? null,
			opts.country ?? null,
		);
	}
	if (ipPlaceholders.length > 0) {
		await pool.query(
			`INSERT INTO ips (asset_id, ip, asn, org, cidr, isp, cdn_flag, cdn_vendor, country)
			 VALUES ${ipPlaceholders.join(', ')}
			 ON CONFLICT (asset_id) DO UPDATE
			   SET last_seen = now(),
			       asn = COALESCE(EXCLUDED.asn, ips.asn),
			       org = COALESCE(EXCLUDED.org, ips.org),
			       cidr = COALESCE(EXCLUDED.cidr, ips.cidr),
			       cdn_flag = EXCLUDED.cdn_flag OR ips.cdn_flag,
			       cdn_vendor = COALESCE(EXCLUDED.cdn_vendor, ips.cdn_vendor)`,
			ipValues,
		);
	}
	return assetMap;
}

/** 批量 upsert 端口服务（单条多行 INSERT ... ON CONFLICT，消除 N+1） */
export async function upsertServicesBatch(
	entries: Array<{
		ipAssetId: string;
		ip: string;
		port: number;
		protocol: 'tcp' | 'udp';
		opts: { service?: string; version?: string; banner?: string; isHttp?: boolean; discoveredBy: string };
	}>,
): Promise<void> {
	const pool = getPg();
	if (entries.length === 0) return;
	const values: unknown[] = [];
	const placeholders: string[] = [];
	let idx = 1;
	for (const e of entries) {
		placeholders.push(
			`($${idx++}, $${idx++}::inet, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`,
		);
		values.push(
			e.ipAssetId,
			e.ip,
			e.port,
			e.protocol,
			e.opts.service ?? null,
			e.opts.version ?? null,
			e.opts.banner ?? null,
			e.opts.isHttp ?? false,
			e.opts.discoveredBy,
		);
	}
	await pool.query(
		`INSERT INTO services (asset_id, ip, port, protocol, service, version, banner, is_http, discovered_by)
		 VALUES ${placeholders.join(', ')}
		 ON CONFLICT (ip, port, protocol) DO UPDATE
		   SET last_seen = now(),
		       service = COALESCE(EXCLUDED.service, services.service),
		       version = COALESCE(EXCLUDED.version, services.version),
		       banner = COALESCE(EXCLUDED.banner, services.banner),
		       is_http = services.is_http OR EXCLUDED.is_http,
		       asset_id = services.asset_id`,
		values,
	);
}

/** upsert webapp 资产 + webapps 表 */
export async function upsertWebapp(
	url: string,
	urlNorm: string,
	opts: {
		seedId?: string;
		parentId?: string;
		discoveredBy: string;
		scheme: string;
		host: string;
		port: number;
		path?: string;
		finalUrl?: string;
		title?: string;
		statusCode?: number;
		tech?: string[];
		webserver?: string;
		waf?: string;
		cdn?: boolean;
		bodyPreview?: string;
		responseHeader?: Record<string, string>;
		faviconHash?: number;
		fingerprints?: string[];
	},
): Promise<string> {
	const assetId = await upsertAsset({
		type: 'webapp',
		value: url,
		valueNorm: urlNorm,
		seedId: opts.seedId,
		parentId: opts.parentId,
		discoveredBy: opts.discoveredBy,
		alive: true,
		meta: { webserver: opts.webserver, finalUrl: opts.finalUrl },
	});

	const pool = getPg();
	await pool.query(
		`INSERT INTO webapps (asset_id, url, url_norm, scheme, host, port, path, final_url, title, status_code, tech, webserver, waf, cdn, body_preview, response_header, favicon_hash, fingerprints)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
     ON CONFLICT (url_norm) DO UPDATE
       SET last_seen = now(),
           title = COALESCE(EXCLUDED.title, webapps.title),
           status_code = COALESCE(EXCLUDED.status_code, webapps.status_code),
           tech = CASE WHEN EXCLUDED.tech = '{}' THEN webapps.tech
                       ELSE ARRAY(SELECT DISTINCT unnest(webapps.tech || EXCLUDED.tech)) END,
           webserver = COALESCE(EXCLUDED.webserver, webapps.webserver),
           waf = COALESCE(EXCLUDED.waf, webapps.waf),
           cdn = webapps.cdn OR EXCLUDED.cdn,
           body_preview = COALESCE(EXCLUDED.body_preview, webapps.body_preview),
           response_header = COALESCE(EXCLUDED.response_header, webapps.response_header),
           favicon_hash = COALESCE(EXCLUDED.favicon_hash, webapps.favicon_hash),
           fingerprints = CASE WHEN EXCLUDED.fingerprints = '{}' THEN webapps.fingerprints
                               ELSE ARRAY(SELECT DISTINCT unnest(webapps.fingerprints || EXCLUDED.fingerprints)) END`,
		[
			assetId,
			url,
			urlNorm,
			opts.scheme,
			opts.host,
			opts.port,
			opts.path ?? '/',
			opts.finalUrl ?? null,
			opts.title ?? null,
			opts.statusCode ?? null,
			opts.tech ?? [],
			opts.webserver ?? null,
			opts.waf ?? null,
			opts.cdn ?? false,
			opts.bodyPreview ?? null,
			opts.responseHeader ? JSON.stringify(opts.responseHeader) : null,
			opts.faviconHash ?? null,
			opts.fingerprints ?? [],
		],
	);
	return assetId;
}

/** 写入指纹命中记录（webapp_fingerprints 表） */
export async function upsertWebappFingerprints(
	webappId: string,
	hits: Array<{
		name: string;
		branchIndex: number;
		evidence: Array<{ field: string; op: string; value: string }>;
	}>,
): Promise<void> {
	if (hits.length === 0) return;
	const pool = getPg();
	for (const h of hits) {
		await pool.query(
			`INSERT INTO webapp_fingerprints (webapp_id, fingerprint, branch_index, evidence)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (webapp_id, fingerprint) DO UPDATE
         SET branch_index = EXCLUDED.branch_index,
             evidence = EXCLUDED.evidence,
             matched_at = now()`,
			[webappId, h.name, h.branchIndex, JSON.stringify(h.evidence)],
		);
	}
}

/** 创建 scan_run 记录 */
export async function createScanRun(opts: {
	seedId?: string;
	assetId?: string;
	tool: string;
	params?: Record<string, unknown>;
}): Promise<string> {
	const pool = getPg();
	const { rows } = await pool.query(
		`INSERT INTO scan_runs (seed_id, asset_id, tool, params)
     VALUES ($1, $2, $3, $4)
     RETURNING id`,
		[opts.seedId ?? null, opts.assetId ?? null, opts.tool, JSON.stringify(opts.params ?? {})],
	);
	await auditLog({
		actor: `tool:${opts.tool}`,
		action: 'scan_start',
		target: opts.assetId ?? opts.seedId ?? '',
		decision: 'info',
		meta: { scanRunId: rows[0].id },
	});
	return rows[0].id;
}

/** 完成 scan_run 记录 */
export async function finishScanRun(
	scanRunId: string,
	opts: {
		status: 'done' | 'failed' | 'timeout' | 'canceled';
		rawOutputPath?: string;
		resultSummary?: Record<string, unknown>;
		error?: string;
	},
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`UPDATE scan_runs
     SET finished_at = now(), status = $1, raw_output_path = $2, result_summary = $3, error = $4
     WHERE id = $5`,
		[
			opts.status,
			opts.rawOutputPath ?? null,
			JSON.stringify(opts.resultSummary ?? {}),
			opts.error ?? null,
			scanRunId,
		],
	);
	await auditLog({
		actor: 'system',
		action: 'scan_finish',
		target: scanRunId,
		decision: opts.status === 'done' ? 'pass' : 'fail',
		reason: opts.error,
		meta: { status: opts.status },
	});
}
