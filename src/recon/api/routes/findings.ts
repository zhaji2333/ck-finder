/**
 * /api/v1/findings 路由
 *
 * GET /api/v1/findings?type=sourcemap&severity=high&webapp_id=xxx
 */

import { Hono } from 'hono';
import { queryFindingById, queryFindings } from '../../storage/models/query.js';

export const findingsApp = new Hono();

/**
 * GET /api/v1/findings
 *
 * Query:
 *   type:       sourcemap/secret/cve_hint/internal_ip/sensitive_path/github_leak/sensitive_file/info_leak
 *   severity:   info/low/medium/high/critical
 *   webapp_id:  按 webapp 筛选
 *   asset_id:   按 asset 筛选
 *   limit:      默认 100，上限 500
 */
findingsApp.get('/', async (c) => {
	const type = c.req.query('type');
	const severity = c.req.query('severity');
	const webappId = c.req.query('webapp_id');
	const assetId = c.req.query('asset_id');
	const limit = Math.min(Number.parseInt(c.req.query('limit') ?? '100', 10), 500);

	const { total, findings } = await queryFindings({ type, severity, webappId, assetId, limit });

	return c.json({
		total,
		findings: findings.map((r) => ({
			id: r.id,
			assetId: r.assetId,
			webappId: r.webappId,
			type: r.type,
			severity: r.severity,
			detail: r.detail,
			evidence: r.evidence,
			sourceTool: r.sourceTool,
			createdAt: r.createdAt,
			meta: r.meta,
		})),
	});
});

/**
 * GET /api/v1/findings/:id
 * 单 finding 详情
 */
findingsApp.get('/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid finding id' }, 400);
	}

	const row = await queryFindingById(id);
	if (!row) {
		return c.json({ error: 'finding not found' }, 404);
	}

	return c.json(row);
});
