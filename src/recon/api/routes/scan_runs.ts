/**
 * /api/v1/scan_runs 路由
 *
 * GET /api/v1/scan_runs?asset_id=&tool=&status=  扫描历史
 *
 * 用途：渗透 Agent 查询"谁跑过什么"，避免重复扫描。
 */

import { Hono } from 'hono';
import { queryScanRunById, queryScanRuns } from '../../storage/models/query.js';

export const scanRunsApp = new Hono();

/**
 * GET /api/v1/scan_runs
 *
 * Query:
 *   asset_id:  按 asset 筛选
 *   seed_id:   按 seed 筛选
 *   tool:      按 tool 筛选（subfinder/httpx/dirsearch/source_collect 等）
 *   status:    按 status 筛选（done/failed/timeout/canceled）
 *   limit:     默认 50，上限 200
 */
scanRunsApp.get('/', async (c) => {
	const assetId = c.req.query('asset_id');
	const seedId = c.req.query('seed_id');
	const tool = c.req.query('tool');
	const status = c.req.query('status');
	const limit = Math.min(Number.parseInt(c.req.query('limit') ?? '50', 10), 200);

	const { total, scanRuns } = await queryScanRuns({ assetId, seedId, tool, status, limit });

	return c.json({
		total,
		scanRuns: scanRuns.map((r) => ({
			id: r.id,
			seedId: r.seedId,
			assetId: r.assetId,
			tool: r.tool,
			status: r.status,
			params: r.params,
			resultSummary: r.resultSummary,
			error: r.error,
			startedAt: r.startedAt,
			finishedAt: r.finishedAt,
			durationMs: r.durationMs,
		})),
	});
});

/**
 * GET /api/v1/scan_runs/:id
 * 单 scan_run 详情
 */
scanRunsApp.get('/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid scan_run id' }, 400);
	}

	const row = await queryScanRunById(id);
	if (!row) {
		return c.json({ error: 'scan_run not found' }, 404);
	}

	return c.json(row);
});
