/**
 * 统一指挥台 API（M4 前端支撑）
 *
 * 挂载到 Hono server /api/command：
 *   GET  /api/command/overview    聚合看板（任务/资产/webapp/意图/finding/情报统计）
 *   GET  /api/command/seeds       任务列表（含探索图意图统计）
 *   GET  /api/command/intents     探索图意图（worker 状态源）
 *   GET  /api/command/facts       探索图事实
 *   POST /api/command/run         触发挖洞任务（后台 fire-and-forget runCampaign）
 */
import { Hono } from 'hono';
import { ExplorationStore } from '../graph/store.js';
import {
	addScopeEntry,
	getScopeEntries,
	removeScopeEntry,
	scopeEntryFromValue,
} from '../recon/config.js';
import { querySeeds, queryWebapps } from '../recon/storage/models/query.js';
import { getPg } from '../recon/storage/pg.js';

export const commandApp = new Hono();

/** 聚合看板：全部统计一次返回 */
commandApp.get('/overview', async (c) => {
	const pool = getPg();
	const [seeds, webapps, intents, intel] = await Promise.all([
		querySeeds(50),
		queryWebapps({ scoreGt: 0, limit: 200 }),
		pool.query('SELECT status, COUNT(*)::int AS n FROM exploration_intents GROUP BY status'),
		pool.query('SELECT kind, COUNT(*)::int AS n FROM intel_entries GROUP BY kind'),
	]);

	// finding 统计（review_status + severity 双维度）
	const { rows: findings } = await pool.query(
		'SELECT review_status, severity, COUNT(*)::int AS n FROM validation_findings GROUP BY review_status, severity',
	);
	const findingByStatus: Record<string, number> = {};
	const findingBySeverity: Record<string, number> = {};
	for (const r of findings) {
		const st = r.review_status as string;
		const sev = r.severity as string;
		findingByStatus[st] = (findingByStatus[st] ?? 0) + Number(r.n);
		findingBySeverity[sev] = (findingBySeverity[sev] ?? 0) + Number(r.n);
	}

	const intentCounts: Record<string, number> = {};
	for (const r of intents.rows) intentCounts[r.status as string] = Number(r.n);

	const intelCounts: Record<string, number> = {};
	for (const r of intel.rows) intelCounts[r.kind as string] = Number(r.n);

	return c.json({
		seeds: seeds.length,
		assets: await countAll(pool, 'assets'),
		webapps: webapps.total,
		intents: intentCounts,
		intentsTotal: Object.values(intentCounts).reduce((a, b) => a + b, 0),
		findings: findingByStatus,
		findingsTotal: Object.values(findingByStatus).reduce((a, b) => a + b, 0),
		findingBySeverity,
		intel: intelCounts,
		// 高危热区（confirmed/high+critical 待提交）
		highValueFindings: findings
			.filter(
				(r) =>
					['high', 'critical'].includes(r.severity as string) &&
					['pending', 'reviewed', 'confirmed'].includes(r.review_status as string),
			)
			.map((r) => ({ reviewStatus: r.review_status, severity: r.severity, count: Number(r.n) })),
	});
});

async function countAll(pool: Awaited<ReturnType<typeof getPg>>, table: string): Promise<number> {
	try {
		const { rows } = await pool.query(`SELECT COUNT(*)::int AS n FROM ${table}`);
		return Number(rows[0]?.n ?? 0);
	} catch {
		return 0;
	}
}

/** 任务列表 + 每个任务的意图状态统计 */
commandApp.get('/seeds', async (c) => {
	const seeds = await querySeeds(Number(c.req.query('limit') ?? 30));
	const store = new ExplorationStore();
	const out = [];
	for (const s of seeds) {
		const counts = await store.countByStatus(s.id);
		const total = Object.values(counts).reduce((a, b) => a + b, 0);
		out.push({
			...s,
			intentCounts: counts,
			intentsTotal: total,
		});
	}
	return c.json({ total: out.length, seeds: out });
});

/** 探索图意图（worker 状态源，可按 seed 筛选） */
commandApp.get('/intents', async (c) => {
	const store = new ExplorationStore();
	const seedId = c.req.query('seed_id');
	const limit = Number(c.req.query('limit') ?? 100);
	if (seedId) {
		const intents = await store.listIntents(seedId);
		return c.json({ total: intents.length, intents: intents.slice(-limit) });
	}
	// 无 seed：列出最近有意图的任务（每个取最新意图）
	const seeds = await querySeeds(10);
	const all: Array<{ seedId: string; intents: unknown[] }> = [];
	for (const s of seeds) {
		const intents = await store.listIntents(s.id);
		if (intents.length > 0) all.push({ seedId: s.id, intents: intents.slice(-5) });
	}
	return c.json({ tasks: all });
});

/** 探索图事实 */
commandApp.get('/facts', async (c) => {
	const store = new ExplorationStore();
	const seedId = c.req.query('seed_id');
	const limit = Number(c.req.query('limit') ?? 50);
	if (!seedId) return c.json({ total: 0, facts: [] });
	const facts = await store.listFacts(seedId);
	return c.json({ total: facts.length, facts: facts.slice(-limit) });
});

/**
 * 资产管理统计：资产类型计数 + 站点角色分布 + 端口/IP 总数。
 * 指挥台「资产管理」顶部统计卡数据源。
 */
commandApp.get('/assets/stats', async (c) => {
	const pool = getPg();
	const [byType, services, ips, roles, alive] = await Promise.all([
		pool.query('SELECT type, COUNT(*)::int AS n FROM assets GROUP BY type'),
		pool.query('SELECT COUNT(*)::int AS n FROM services'),
		pool.query('SELECT COUNT(*)::int AS n FROM ips'),
		pool.query(
			'SELECT role, COUNT(*)::int AS n FROM webapps WHERE role IS NOT NULL GROUP BY role',
		),
		pool.query(
			"SELECT COUNT(*)::int AS n FROM assets WHERE alive = true AND type IN ('webapp','ip','subdomain')",
		),
	]);
	const types: Record<string, number> = {};
	for (const r of byType.rows) types[r.type as string] = Number(r.n);
	const roleCounts: Record<string, number> = {};
	for (const r of roles.rows) roleCounts[r.role as string] = Number(r.n);
	return c.json({
		types,
		domain: (types.domain ?? 0) + (types.subdomain ?? 0),
		ip: types.ip ?? 0,
		webapp: types.webapp ?? 0,
		services: Number(services.rows[0]?.n ?? 0),
		ips: Number(ips.rows[0]?.n ?? 0),
		alive: Number(alive.rows[0]?.n ?? 0),
		roles: roleCounts,
	});
});

/**
 * 类型化资产列表（指挥台「资产管理」子视图数据源）
 *   type=webapp|domain|subdomain|ip|service   （默认 webapp）
 *   q=   模糊搜索（domain/ip/service 生效）
 *   limit= 默认 100，上限 500
 */
commandApp.get('/assets', async (c) => {
	const type = c.req.query('type') ?? 'webapp';
	const q = (c.req.query('q') ?? '').trim();
	const limit = Math.min(Number(c.req.query('limit') ?? 100), 500);
	const pool = getPg();
	const like = `%${q}%`;

	if (type === 'domain' || type === 'subdomain') {
		// 「域名」视图：根域 + 子域合并展示（资产测绘视角）；type=subdomain 则只看子域
		const typeFilter =
			type === 'subdomain' ? "a.type = 'subdomain'" : "a.type IN ('domain','subdomain')";
		const { rows } = await pool.query(
			`SELECT a.id, a.type, a.value, a.discovered_by, a.alive, a.first_seen, a.last_seen
			 FROM assets a
			 WHERE ${typeFilter} AND ($1 = '' OR a.value ILIKE $2)
			 ORDER BY a.type DESC, a.value
			 LIMIT $3`,
			[q, like, limit],
		);
		return c.json({ type, total: rows.length, assets: rows });
	}

	if (type === 'ip') {
		const { rows } = await pool.query(
			`SELECT a.id, i.ip, i.asn, i.org, i.isp, i.country, i.region, i.city, i.cdn_flag, i.cdn_vendor,
			        (SELECT COUNT(*)::int FROM services s WHERE s.ip = i.ip) AS svc_count
			 FROM assets a JOIN ips i ON i.asset_id = a.id
			 WHERE ($1 = '' OR i.ip::text ILIKE $2 OR i.org ILIKE $2 OR i.isp ILIKE $2)
			 ORDER BY i.ip
			 LIMIT $3`,
			[q, like, limit],
		);
		return c.json({ type, total: rows.length, assets: rows });
	}

	if (type === 'service') {
		const { rows } = await pool.query(
			`SELECT s.id, s.ip, s.port, s.protocol, s.service, s.version, s.banner, s.is_http, s.last_seen
			 FROM services s
			 WHERE ($1 = '' OR s.ip::text ILIKE $2 OR s.service ILIKE $2)
			 ORDER BY s.ip, s.port
			 LIMIT $3`,
			[q, like, limit],
		);
		return c.json({ type, total: rows.length, assets: rows });
	}

	// 默认 webapp（复用评分排序查询；scoreGt:-1 让 score=0 的站点也返回，前端「全部评分」才完整）
	const { webapps, total } = await queryWebapps({ scoreGt: -1, limit });
	return c.json({ type: 'webapp', total, assets: webapps });
});

/**
 * 授权范围白名单（资产范围 → 自动白名单）
 * GET  /api/command/scope            读当前白名单
 * POST /api/command/scope            { action: add|remove, value } 增删白名单
 */
commandApp.get('/scope', (c) => {
	return c.json({ scope: getScopeEntries() });
});

commandApp.post('/scope', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { action?: string; value?: string };
	if (!body.value || !body.value.trim()) return c.json({ error: 'missing value' }, 400);
	if (body.action === 'remove') {
		return c.json({ scope: removeScopeEntry(body.value) });
	}
	if (body.action === 'add' || !body.action) {
		return c.json({ scope: addScopeEntry(body.value) });
	}
	return c.json({ error: `unknown action: ${body.action}` }, 400);
});

/**
 * 添加资产（域名/IP/URL）→ 创建 seed + 自动加入白名单，可选立即触发信息收集。
 * body: { value, collect?, mode? }
 */
commandApp.post('/assets/add', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as {
		value?: string;
		collect?: boolean;
		mode?: string;
	};
	const value = (body.value ?? '').trim();
	if (!value) return c.json({ error: 'missing value' }, 400);

	// 归一化 seed → seedId
	const { normalizeSeed } = await import('../recon/seeds/normalizer.js');
	const { upsertSeed } = await import('../recon/storage/models/asset.js');
	const normalized = normalizeSeed(value);
	const seedId = await upsertSeed(normalized);

	// 资产范围自动加入白名单（域名/IP 去端口）
	const scopeEntry = scopeEntryFromValue(value);
	let scope = getScopeEntries();
	if (!scope.includes(scopeEntry)) scope = addScopeEntry(value);

	// 可选：立即触发信息收集（fire-and-forget）
	if (body.collect) {
		const { runRecon } = await import('../recon/pipeline/runner.js');
		runRecon(value, { mode: (body.mode as never) ?? 'auto', useFofa: true }).catch((err) => {
			console.error(`[command] 收集 ${value} failed:`, err);
		});
	}

	return c.json({
		seedId,
		seedType: normalized.seedType,
		value,
		scopeEntry,
		scope,
		collectStarted: Boolean(body.collect),
	});
});

/**
 * 恢复滞留任务：把超过阈值（默认 30 分钟）仍 running 的 scan_runs 标记为 failed，
 * 并把「已无 running 子任务」的 running seed 判定为 done（有资产）或 failed（无资产）。
 * 用于服务器重启/进程中断后清理卡在 running 的扫描任务。
 * body: { olderThanMs? }
 */
commandApp.post('/recover', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { olderThanMs?: number };
	const cutoff = new Date(Date.now() - (body.olderThanMs ?? 30 * 60 * 1000)).toISOString();
	const pool = getPg();
	const { rows: stale } = await pool.query(
		`UPDATE scan_runs SET status = 'failed', error = '进程中断（recover）', finished_at = now()
		 WHERE status = 'running' AND started_at < $1 RETURNING seed_id`,
		[cutoff],
	);
	const { rows: seeds } = await pool.query(
		`UPDATE seeds s SET status = CASE
		   WHEN (SELECT COUNT(*)::int FROM assets a WHERE a.seed_id = s.id) > 0 THEN 'done'
		   ELSE 'failed'
		 END
		 WHERE s.status = 'running'
		   AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.seed_id = s.id AND r.status = 'running')
		 RETURNING id, value, status`,
	);
	return c.json({ staleRuns: stale.length, recoveredSeeds: seeds.length, seeds });
});

/**
 * 清空探索图（意图 + 事实 + 活动），用于重新挖某个/全部站点。
 * body: { seedId? }  —— 传 seedId 只清该站点；不传清全部。
 */
commandApp.post('/intents/clear', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { seedId?: string };
	const pool = getPg();
	const where = body.seedId ? 'WHERE seed_id = $1' : '';
	const args = body.seedId ? [body.seedId] : [];
	const act = await pool.query(`DELETE FROM exploration_activities ${where}`, args);
	const fact = await pool.query(`DELETE FROM exploration_facts ${where}`, args);
	const intent = await pool.query(`DELETE FROM exploration_intents ${where}`, args);
	return c.json({
		seedId: body.seedId ?? null,
		intents: intent.rowCount ?? 0,
		facts: fact.rowCount ?? 0,
		activities: act.rowCount ?? 0,
	});
});

/**
 * 清理滞留意图：把 pending/running 超过阈值（默认 10 分钟）未推进的意图标记为 canceled。
 * 用于清掉崩溃/中断残留的意图，避免「大量 pending」堆积（不影响正在进行的 campaign）。
 * body: { seedId?, olderThanMs? }
 */
commandApp.post('/intents/cancel-stuck', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as {
		seedId?: string;
		olderThanMs?: number;
	};
	const cutoff = new Date(Date.now() - (body.olderThanMs ?? 10 * 60 * 1000)).toISOString();
	const pool = getPg();
	const { rows } = await pool.query(
		`UPDATE exploration_intents
		 SET status = 'canceled', result_summary = COALESCE(result_summary, '滞留清理（指挥台手动取消）'), updated_at = now()
		 WHERE status IN ('pending', 'running') AND updated_at < $1
		   AND ($2::uuid IS NULL OR seed_id = $2)
		 RETURNING id`,
		[cutoff, body.seedId ?? null],
	);
	return c.json({ canceled: rows.length, cutoff });
});

/**
 * 触发挖洞任务（后台 fire-and-forget runCampaign）
 * body: { seed, scope: string[], goal?: string, maxRounds?, maxIntents? }
 */
commandApp.post('/run', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as {
		seed?: string;
		scope?: string[] | string;
		/** 初始引导提示词（如「重点挖掘 SQL 注入/SSRF，不要挖 XSS」） */
		goal?: string;
		maxRounds?: number;
		maxIntents?: number;
	};
	if (!body.seed) return c.json({ error: 'missing seed' }, 400);

	// 归一化 seed → seedId
	const { normalizeSeed } = await import('../recon/seeds/normalizer.js');
	const { upsertSeed } = await import('../recon/storage/models/asset.js');
	const normalized = normalizeSeed(body.seed);
	const seedId = await upsertSeed(normalized);

	const scope = Array.isArray(body.scope)
		? body.scope
		: typeof body.scope === 'string'
			? body.scope
					.split(',')
					.map((s) => s.trim())
					.filter(Boolean)
			: [];

	// 后台触发（不阻塞响应），进度由 exploration_intents 状态可见
	const { runCampaign } = await import('../controller.js');
	runCampaign({
		seedId,
		scope,
		goal: body.goal,
		maxRounds: body.maxRounds ?? 3,
		maxIntents: body.maxIntents ?? 20,
		llmEnabled: true,
	}).catch((err) => {
		console.error(`[command] campaign ${seedId} failed:`, err);
	});

	return c.json(
		{
			seedId,
			seed: body.seed,
			seedType: normalized.seedType,
			status: 'campaign_started',
			goal: body.goal ?? null,
			message: '挖洞任务已后台启动。GET /api/command/intents?seed_id= 查看意图进度。',
		},
		202,
	);
});

// ---------------------------------------------------------------------------
// 资产组（资产管理分组）
// ---------------------------------------------------------------------------

/** 资产组列表（含匹配范围命中的站点/域名计数；范围里的 URL 会先提取 hostname 再匹配） */
commandApp.get('/groups', async (c) => {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT id, name, description, scope, created_at, updated_at FROM asset_groups ORDER BY created_at DESC`,
	);
	const out = [];
	for (const g of rows) {
		const rawScope = (g.scope as string[]) ?? [];
		// 归一化 scope（URL → hostname，IP:port → IP，去 *. 前缀）仅用于匹配统计；原始值保留供收集
		const hosts = [
			...new Set(rawScope.map((s) => scopeEntryFromValue(s).replace(/^\*\./, '')).filter(Boolean)),
		];
		const { rows: c } = await pool.query(
			`SELECT
			  (SELECT COUNT(*)::int FROM webapps w WHERE EXISTS (
			     SELECT 1 FROM unnest($1::text[]) AS s WHERE w.host = s OR w.host LIKE ('%.' || s)
			  )) AS webapp_count,
			  (SELECT COUNT(*)::int FROM assets a WHERE a.type IN ('domain','subdomain') AND EXISTS (
			     SELECT 1 FROM unnest($1::text[]) AS s WHERE a.value_norm = s OR a.value_norm LIKE ('%.' || s)
			  )) AS domain_count`,
			[hosts],
		);
		out.push({
			...g,
			webapp_count: Number(c[0]?.webapp_count ?? 0),
			domain_count: Number(c[0]?.domain_count ?? 0),
		});
	}
	return c.json({ total: out.length, groups: out });
});

/** 新建资产组：名称 + 范围（范围自动加入白名单） */
commandApp.post('/groups', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as {
		name?: string;
		scope?: string[] | string;
		description?: string;
	};
	const name = (body.name ?? '').trim();
	if (!name) return c.json({ error: 'missing name' }, 400);
	const scope = Array.isArray(body.scope)
		? body.scope.map((s) => s.trim()).filter(Boolean)
		: typeof body.scope === 'string'
			? body.scope.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean)
			: [];
	const normalizedScope = [
		...new Set(scope.map((s) => s.toLowerCase().replace(/^\*\./, '').replace(/\/+$/, ''))),
	];

	// 组范围自动加入全局白名单（资产范围自带白名单）
	for (const s of normalizedScope) {
		if (!getScopeEntries().includes(s)) addScopeEntry(s);
	}

	const pool = getPg();
	const { rows } = await pool.query(
		`INSERT INTO asset_groups (name, scope, description) VALUES ($1,$2,$3)
		 ON CONFLICT (name) DO UPDATE SET scope = EXCLUDED.scope, description = EXCLUDED.description, updated_at = now()
		 RETURNING *`,
		[name, normalizedScope, body.description ?? ''],
	);
	return c.json({ group: rows[0] });
});

/** 资产组详情（组信息 + 命中范围站点的 webapp 列表） */
commandApp.get('/groups/:id', async (c) => {
	const id = c.req.param('id');
	const pool = getPg();
	const { rows } = await pool.query('SELECT * FROM asset_groups WHERE id = $1', [id]);
	if (rows.length === 0) return c.json({ error: 'group not found' }, 404);
	const g = rows[0];
	const rawScope = (g.scope as string[]) ?? [];
	// 归一化 scope（URL → hostname，IP:port → IP，去 *. 前缀）仅用于匹配；原始值保留供收集
	const hosts = [
		...new Set(rawScope.map((s) => scopeEntryFromValue(s).replace(/^\*\./, '')).filter(Boolean)),
	];
	const { rows: webapps } = await pool.query(
		`SELECT w.asset_id, w.url, w.title, w.host, w.port, w.tech, w.role, w.score, w.status_code, w.last_seen
		 FROM webapps w
		 WHERE EXISTS (
		   SELECT 1 FROM unnest($1::text[]) AS s
		   WHERE w.host = s OR w.host LIKE ('%.' || s)
		 )
		 ORDER BY w.score DESC
		 LIMIT 200`,
		[hosts],
	);
	return c.json({ group: g, webappTotal: webapps.length, webapps });
});

/** 删除资产组（仅删分组，不动资产/白名单） */
commandApp.delete('/groups/:id', async (c) => {
	const id = c.req.param('id');
	const pool = getPg();
	const { rowCount } = await pool.query('DELETE FROM asset_groups WHERE id = $1', [id]);
	return c.json({ deleted: rowCount ?? 0 });
});

/** 对资产组范围触发信息收集（fire-and-forget） */
commandApp.post('/groups/:id/collect', async (c) => {
	const id = c.req.param('id');
	const pool = getPg();
	const { rows } = await pool.query('SELECT * FROM asset_groups WHERE id = $1', [id]);
	if (rows.length === 0) return c.json({ error: 'group not found' }, 404);
	const g = rows[0];
	const scope = g.scope as string[];
	const { runRecon } = await import('../recon/pipeline/runner.js');
	for (const s of scope) {
		runRecon(s, { mode: 'auto', useFofa: true }).catch((err) => {
			console.error(`[command] group ${g.name} collect ${s} failed:`, err);
		});
	}
	return c.json({ groupId: id, name: g.name, collectStarted: scope.length });
});

// ---------------------------------------------------------------------------
// ICP 备案查询（公司名 → 备案域名资产）
// ---------------------------------------------------------------------------

/** 新建 ICP 查询：{ name: 任务名称, company: 公司名称 } → 提交 company_name seed + 触发 ICP 反查 */
commandApp.post('/icp', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { name?: string; company?: string };
	const company = (body.company ?? '').trim();
	if (!company) return c.json({ error: 'missing company' }, 400);
	const taskName = (body.name ?? '').trim() || company;

	const { normalizeSeed } = await import('../recon/seeds/normalizer.js');
	const { upsertSeed } = await import('../recon/storage/models/asset.js');
	const normalized = normalizeSeed(company); // 非域名/IP/URL 自动识别为 company_name
	const seedId = await upsertSeed(normalized);

	// 记录任务名到 meta
	const pool = getPg();
	await pool.query(
		`UPDATE seeds SET meta = meta || jsonb_build_object('task_name', $1) WHERE id = $2`,
		[taskName, seedId],
	);

	// 触发 ICP 反查（fire-and-forget）
	const { runRecon } = await import('../recon/pipeline/runner.js');
	runRecon(company, { mode: 'auto', useFofa: true }).catch((err) => {
		console.error(`[command] ICP 查询 ${company} failed:`, err);
	});

	return c.json({
		seedId,
		seedType: normalized.seedType,
		company,
		name: taskName,
		status: 'icp_started',
	});
});

/** ICP 查询任务列表（company_name seed + 备案域名/子域/站点计数） */
commandApp.get('/icp', async (c) => {
	const pool = getPg();
	const { rows } = await pool.query(`
		SELECT s.id, s.value AS company, s.status, s.created_at,
		       COALESCE(s.meta->>'task_name', s.value) AS name,
		       (SELECT COUNT(*)::int FROM assets a WHERE a.seed_id = s.id AND a.type = 'domain') AS icp_domain_count,
		       (SELECT COUNT(*)::int FROM assets a WHERE a.seed_id = s.id AND a.type = 'subdomain') AS subdomain_count,
		       (SELECT COUNT(*)::int FROM assets a WHERE a.seed_id = s.id AND a.type = 'webapp') AS webapp_count
		FROM seeds s
		WHERE s.seed_type = 'company_name'
		ORDER BY s.created_at DESC
		LIMIT 50`);
	return c.json({ total: rows.length, tasks: rows });
});

// ---------------------------------------------------------------------------
// 删除资产 / 清理数据（级联删除资产及对应数据）
// ---------------------------------------------------------------------------

/** 删除单个资产及其子孙资产（递归 parent_id）+ 关联数据（webapps/ips/services/findings 级联 + 探索图锚点清理） */
commandApp.delete('/assets/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) return c.json({ error: 'invalid asset id' }, 400);
	const pool = getPg();
	// 递归收集子孙资产
	const { rows: desc } = await pool.query(
		`WITH RECURSIVE descendants AS (
		   SELECT id FROM assets WHERE id = $1
		   UNION
		   SELECT a.id FROM assets a JOIN descendants d ON a.parent_id = d.id
		 )
		 SELECT id FROM descendants`,
		[id],
	);
	const ids = desc.map((r) => r.id as string);
	if (ids.length === 0) return c.json({ error: 'asset not found' }, 404);
	// 清理探索图锚点（软引用，无 FK）
	await pool.query(`DELETE FROM exploration_intents WHERE asset_id = ANY($1::uuid[])`, [ids]);
	await pool.query(`DELETE FROM exploration_facts WHERE asset_id = ANY($1::uuid[])`, [ids]);
	// 删除资产（webapps/ips/services/findings 等 FK CASCADE 自动级联）
	const { rowCount } = await pool.query(`DELETE FROM assets WHERE id = ANY($1::uuid[])`, [ids]);
	return c.json({ deleted: rowCount ?? 0, assetIds: ids });
});

/** 删除任务（seed）及其全部资产/意图/事实/漏洞数据（FK CASCADE 级联） */
commandApp.delete('/seeds/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) return c.json({ error: 'invalid seed id' }, 400);
	const pool = getPg();
	const { rowCount } = await pool.query('DELETE FROM seeds WHERE id = $1', [id]);
	return c.json({ deleted: rowCount ?? 0 });
});

/** 批量删除任务（seed）：body { ids: string[] }，级联删除各任务资产/意图/漏洞数据 */
commandApp.post('/seeds/batch-delete', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { ids?: string[] };
	const ids = (body.ids ?? []).filter((id) => /^[0-9a-f-]{36}$/i.test(id));
	if (ids.length === 0) return c.json({ error: 'missing ids' }, 400);
	const pool = getPg();
	const { rowCount } = await pool.query(`DELETE FROM seeds WHERE id = ANY($1::uuid[])`, [ids]);
	return c.json({ deleted: rowCount ?? 0, ids });
});

/**
 * 按域名清理（purge）：删除 value_norm 匹配该域名（含子域）的所有 seed，级联清掉其资产。
 * 用于一键清空历史堆积资产（如 lenovomm.com）。
 * body: { domain: string }
 */
commandApp.post('/purge', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as { domain?: string };
	const domain = (body.domain ?? '').trim().toLowerCase().replace(/^\*\./, '');
	if (!domain) return c.json({ error: 'missing domain' }, 400);
	// 转义 LIKE 通配符（% / _ / \），防止 domain 含通配符时误删无关资产
	const escapedDomain = domain.replace(/[\\%_]/g, '\\$&');
	const pool = getPg();
	// 先统计将删除的资产数
	const { rows: stat } = await pool.query(
		`SELECT COUNT(*)::int AS seeds,
		        (SELECT COUNT(*)::int FROM assets a WHERE a.seed_id IN (
		           SELECT id FROM seeds WHERE value_norm = $1 OR value_norm LIKE '%.' || $2 ESCAPE '\\'
		         )) AS assets
		 FROM seeds WHERE value_norm = $1 OR value_norm LIKE '%.' || $2 ESCAPE '\\'`,
		[domain, escapedDomain],
	);
	const { rows: deleted } = await pool.query(
		`DELETE FROM seeds WHERE value_norm = $1 OR value_norm LIKE '%.' || $2 ESCAPE '\\' RETURNING id, value`,
		[domain, escapedDomain],
	);
	return c.json({
		domain,
		deletedSeeds: deleted.length,
		deletedAssets: Number(stat[0]?.assets ?? 0),
		seeds: deleted,
	});
});

// ---------------------------------------------------------------------------
// 一键挖洞（选中资产批量直打，AutoHunter 多 worker 并发）
// ---------------------------------------------------------------------------

/**
 * 选中资产 → 一键挖洞：直接对目标 URL 列表并发挖（免收集，runDirectHunt）。
 * body: { urls: string[], concurrency?, goal? }
 */
commandApp.post('/hunt', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as {
		urls?: string[];
		concurrency?: number;
		goal?: string;
	};
	const urls = (body.urls ?? []).map((u) => u.trim()).filter(Boolean);
	if (urls.length === 0) return c.json({ error: 'missing urls' }, 400);

	const { runDirectHunt } = await import('../hunt.js');
	runDirectHunt({
		targets: urls.map((url) => ({ url })),
		concurrency: Math.max(1, body.concurrency ?? 4),
		goal: body.goal,
	}).catch((err) => {
		console.error('[command] hunt failed:', err);
	});

	return c.json({ started: urls.length, urls, goal: body.goal ?? null }, 202);
});
