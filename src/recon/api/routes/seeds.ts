/**
 * /api/v1/seeds 路由
 *
 * POST /api/v1/seeds          提交种子（公司名/域名/URL/IP/CIDR/IP:端口）
 * GET  /api/v1/seeds/:id      任务状态/进度
 * GET  /api/v1/seeds          列出最近种子
 */

import { Hono } from 'hono';
import { runRecon } from '../../pipeline/runner.js';
import { normalizeSeed } from '../../seeds/normalizer.js';
import { querySeedById, querySeeds } from '../../storage/models/query.js';

export const seedsApp = new Hono();

/**
 * POST /api/v1/seeds
 * Body: { "seed": "baidu.com", "options": { "skipNmap": true, "mode": "auto|site|full" } }
 */
seedsApp.post('/', async (c) => {
	let body: { seed?: string; options?: Record<string, unknown> };
	try {
		body = await c.req.json();
	} catch {
		return c.json({ error: 'invalid JSON body' }, 400);
	}

	const seed = body.seed?.trim();
	if (!seed) {
		return c.json({ error: 'missing required field: seed' }, 400);
	}

	// 异步触发扫描（不阻塞响应）—— runRecon 内部会 upsertSeed
	const opts = body.options ?? {};
	let seedId: string | undefined;
	try {
		const normalized = normalizeSeed(seed);
		const { upsertSeed } = await import('../../storage/models/asset.js');
		seedId = await upsertSeed(normalized);
	} catch (err) {
		return c.json(
			{ error: `seed normalize failed: ${err instanceof Error ? err.message : err}` },
			400,
		);
	}

	// 模式校验：auto/site/full（site = 单站元数据，不扩大范围）
	const mode = opts.mode;
	if (mode !== undefined && !['auto', 'site', 'full'].includes(String(mode))) {
		return c.json({ error: `invalid mode "${String(mode)}": must be auto|site|full` }, 400);
	}

	runRecon(seed, {
		mode: mode as 'auto' | 'site' | 'full' | undefined,
		skipNmap: opts.skipNmap === true,
		skipHttpx: opts.skipHttpx === true,
		skipSubfinder: opts.skipSubfinder === true,
		skipOneForAll: opts.skipOneForAll === true,
		skipScoring: opts.skipScoring === true,
		skipLlm: opts.skipLlm === true,
		useFofa: typeof opts.useFofa === 'boolean' ? opts.useFofa : undefined,
		maxSubdomains: typeof opts.maxSubdomains === 'number' ? opts.maxSubdomains : 1000,
		maxCompanyDomains: typeof opts.maxCompanyDomains === 'number' ? opts.maxCompanyDomains : 50,
		companyDomainConcurrency: typeof opts.concurrency === 'number' ? opts.concurrency : 3,
	})
		.then((result) => {
			console.log(`[api] seed ${seed} scan completed: ${result.webappCount} webapps`);
		})
		.catch((err) => {
			console.error(`[api] seed ${seed} scan failed:`, err);
		});

	return c.json(
		{
			seedId,
			seed,
			status: 'queued',
			message: 'scan started asynchronously. GET /api/v1/seeds/:id to check progress.',
		},
		202,
	);
});

/**
 * GET /api/v1/seeds/:id
 */
seedsApp.get('/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid seed id' }, 400);
	}

	const seed = await querySeedById(id);
	if (!seed) {
		return c.json({ error: 'seed not found' }, 404);
	}

	return c.json({
		id: seed.id,
		seedType: seed.seedType,
		value: seed.value,
		status: seed.status,
		assetCount: seed.assetCount,
		webappCount: seed.webappCount,
		createdAt: seed.createdAt,
		progress: seed.progress ?? null,
	});
});

/**
 * DELETE /api/v1/seeds/:id
 * 删除种子及其全部关联数据（级联：assets → webapps/ips/services/findings → 各子表）
 * 保留：audit_log（审计）、scan_runs 记录（seed_id 置 NULL）、sources/ 磁盘目录
 */
seedsApp.delete('/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid seed id' }, 400);
	}

	try {
		const { deleteSeed } = await import('../../storage/models/asset.js');
		const r = await deleteSeed(id);
		return c.json({
			deleted: true,
			seedId: id,
			seedType: r.seedType,
			seedValue: r.seedValue,
			assetCount: r.assetCount,
			message: `种子 ${r.seedValue} 及其 ${r.assetCount} 个资产已删除（audit_log 与 sources/ 目录保留）`,
		});
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		if (msg.includes('not found')) {
			return c.json({ error: 'seed not found' }, 404);
		}
		console.error(`[api] delete seed ${id} failed:`, err);
		return c.json({ error: `delete failed: ${msg}` }, 500);
	}
});

/**
 * GET /api/v1/seeds
 * 列出最近的种子
 * Query: ?limit=20
 */
seedsApp.get('/', async (c) => {
	const limit = Math.min(Number.parseInt(c.req.query('limit') ?? '20', 10), 100);

	const seeds = await querySeeds(limit);

	return c.json({
		total: seeds.length,
		seeds: seeds.map((r) => ({
			id: r.id,
			seedType: r.seedType,
			value: r.value,
			status: r.status,
			assetCount: r.assetCount,
			webappCount: r.webappCount,
			createdAt: r.createdAt,
			progress: r.progress ?? null,
		})),
	});
});
