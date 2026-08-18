/**
 * /api/v1/webapps 路由
 *
 * GET /api/v1/webapps?score_gt=60&role=business&limit=50  高价值 webapp 列表
 */

import { Hono } from 'hono';
import { queryWebappById, queryWebapps } from '../../storage/models/query.js';

export const webappsApp = new Hono();

/**
 * GET /api/v1/webapps
 *
 * Query:
 *   score_gt:  评分下限（默认 0）
 *   role:      角色筛选（business/admin/api/infra/unknown）
 *   limit:     默认 50，上限 200
 *   offset:    分页偏移
 */
webappsApp.get('/', async (c) => {
	const scoreGt = Number.parseInt(c.req.query('score_gt') ?? '0', 10);
	const role = c.req.query('role');
	const limit = Math.min(Number.parseInt(c.req.query('limit') ?? '50', 10), 200);
	const offset = Number.parseInt(c.req.query('offset') ?? '0', 10);

	const { total, webapps } = await queryWebapps({ scoreGt, role, limit, offset });

	return c.json({
		total,
		webapps: webapps.map((r) => ({
			assetId: r.assetId,
			url: r.url,
			title: r.title,
			statusCode: r.statusCode,
			tech: r.tech,
			host: r.host,
			port: r.port,
			webserver: r.webserver,
			cdn: r.cdn,
			waf: r.waf,
			role: r.role,
			score: r.score,
			scoreBreakdown: r.scoreBreakdown,
			loginPage: r.loginPage,
			hardToAttack: r.hardToAttack,
			fingerprints: r.fingerprints,
			meta: r.meta,
			firstSeen: r.firstSeen,
			lastSeen: r.lastSeen,
			// 发现标记（密钥/敏感路径/sourcemap）
			findingCount: r.findingCount,
			findingTypes: r.findingTypes,
			findingMaxSeverity: r.findingMaxSeverity,
		})),
	});
});

/**
 * GET /api/v1/webapps/:id
 * 单 webapp 详情
 */
webappsApp.get('/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid webapp id' }, 400);
	}

	const row = await queryWebappById(id);
	if (!row) {
		return c.json({ error: 'webapp not found' }, 404);
	}

	return c.json(row);
});

/**
 * POST /api/v1/webapps/:id/deep-scan
 * 一键深挖：对单个 webapp 立即触发 deep-scan（dirscan/jsmining/history_url/source_collect）
 * 同步执行（可能耗时 5-30 分钟），返回各任务结果摘要。
 * 7 天内已深挖的任务自动跳过（除非 ?force=true）。
 */
webappsApp.post('/:id/deep-scan', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid webapp id' }, 400);
	}
	const force = c.req.query('force') === 'true';

	const existing = await queryWebappById(id);
	if (!existing) {
		return c.json({ error: 'webapp not found' }, 404);
	}

	const startAt = Date.now();
	try {
		const { deepScanWebapp } = await import('../../pipeline/deep_scan.js');
		const result = await deepScanWebapp(id, { force });
		// 深挖完成 → 终评（基于深挖证据重新评分 + 复核）
		let finalScore: number | null = null;
		let finalLevel: string | null = null;
		try {
			const { scoreWebappFinal } = await import('../../scoring/pipeline.js');
			const fin = await scoreWebappFinal(id);
			finalScore = fin.score;
			finalLevel = fin.level;
			console.log(`[api] 终评 ${result.url}: ${fin.score} L${fin.level}`);
		} catch (err) {
			console.warn(`[api] 终评失败 ${id} (non-blocking):`, err);
		}
		return c.json({
			webappId: result.webappId,
			url: result.url,
			ranTasks: result.ranTasks,
			skippedTasks: result.skippedTasks,
			failedTasks: result.failedTasks,
			summaries: result.summaries,
			durationMs: Date.now() - startAt,
			finalScore,
			finalLevel,
		});
	} catch (err) {
		console.error(`[api] deep-scan ${id} failed:`, err);
		return c.json(
			{ error: `deep-scan failed: ${err instanceof Error ? err.message : String(err)}` },
			500,
		);
	}
});
