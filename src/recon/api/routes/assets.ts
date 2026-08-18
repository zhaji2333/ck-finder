/**
 * /api/v1/assets 路由
 *
 * GET /api/v1/assets?seed_id=&type=    资产图查询
 * GET /api/v1/assets/:id/metadata      单资产 Metadata 快照（渗透 Agent 主接口）
 */

import { Hono } from 'hono';
import { generateSnapshot } from '../../scoring/snapshot.js';
import { queryAssetById, queryAssets } from '../../storage/models/query.js';

export const assetsApp = new Hono();

/**
 * GET /api/v1/assets?seed_id=&type=
 *
 * Query:
 *   seed_id: 按 seed 筛选
 *   type: domain/subdomain/ip/url/webapp/company
 *   limit: 默认 100，上限 500
 */
assetsApp.get('/', async (c) => {
	const seedId = c.req.query('seed_id');
	const type = c.req.query('type');
	const limit = Math.min(Number.parseInt(c.req.query('limit') ?? '100', 10), 500);

	const { total, assets } = await queryAssets({ seedId, type, limit });

	return c.json({
		total,
		assets: assets.map((r) => ({
			id: r.id,
			seedId: r.seedId,
			parentId: r.parentId,
			type: r.type,
			value: r.value,
			valueNorm: r.valueNorm,
			discoveredBy: r.discoveredBy,
			alive: r.alive,
			firstSeen: r.firstSeen,
			lastSeen: r.lastSeen,
		})),
	});
});

/**
 * GET /api/v1/assets/:id/metadata
 *
 * 返回 webapp 的完整 metadata 快照（含 tech/endpoints/params/sourcemap/suggested_next）
 * 这是渗透 Agent 的主接口。
 *
 * 注：id 是 webapp 的 asset_id（UUID）
 */
assetsApp.get('/:id/metadata', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid asset id' }, 400);
	}

	try {
		const snapshot = await generateSnapshot(id);
		return c.json(snapshot);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		if (msg.includes('not found') || msg.includes('no rows')) {
			return c.json({ error: 'webapp not found' }, 404);
		}
		return c.json({ error: `generate snapshot failed: ${msg}` }, 500);
	}
});

/**
 * GET /api/v1/assets/:id
 * 单资产详情
 */
assetsApp.get('/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid asset id' }, 400);
	}

	const row = await queryAssetById(id);
	if (!row) {
		return c.json({ error: 'asset not found' }, 404);
	}

	return c.json(row);
});
