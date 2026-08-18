/**
 * ck-recon REST API 服务入口（M5.1）
 *
 * 基于 Hono + @hono/node-server
 *
 * 路由挂载：
 *   /api/v1/seeds         → seeds.ts
 *   /api/v1/assets        → assets.ts
 *   /api/v1/webapps       → webapps.ts
 *   /api/v1/findings      → findings.ts
 *   /api/v1/sources       → sources_route.ts (M4 已实现)
 *   /api/v1/scan_runs     → scan_runs.ts
 *   /healthz              → 健康检查
 *
 * 启动：node dist/api/server.js 或 tsx src/api/server.ts
 */

import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import { getConfig } from '../config.js';
import { pgHealthCheck } from '../storage/pg.js';
import { getPg } from '../storage/pg.js';
import { redisHealthCheck } from '../storage/redis.js';

import { commandApp } from '../../api/command_route.js';
import { configApp } from '../../api/config_route.js';
import { reviewApp } from '../../api/review_route.js';
import { assetsApp } from './routes/assets.js';
import { findingsApp } from './routes/findings.js';
import { scanRunsApp } from './routes/scan_runs.js';
import { seedsApp } from './routes/seeds.js';
import { webappsApp } from './routes/webapps.js';
import { sourcesApp } from './sources_route.js';

const app = new Hono();

// 健康检查
app.get('/healthz', async (c) => {
	const pgOk = await pgHealthCheck();
	const redisOk = await redisHealthCheck();
	let assetCount = 0;
	try {
		const pool = getPg();
		const { rows } = await pool.query('SELECT COUNT(*) AS n FROM assets');
		assetCount = Number.parseInt(rows[0].n, 10);
	} catch {
		// ignore
	}
	return c.json({
		status: pgOk && redisOk ? 'ok' : 'degraded',
		postgres: pgOk,
		redis: redisOk,
		assetCount,
		version: '0.1.0',
	});
});

// 挂载 API v1 路由
app.route('/api/v1/seeds', seedsApp);
app.route('/api/v1/assets', assetsApp);
app.route('/api/v1/webapps', webappsApp);
app.route('/api/v1/findings', findingsApp);
app.route('/api/v1/sources', sourcesApp);
app.route('/api/v1/scan_runs', scanRunsApp);

// M4 复审控制台 API
app.route('/api/review', reviewApp);

// 统一指挥台 API（M4 前端支撑）
app.route('/api/command', commandApp);

// 指挥台「设置」API（配置 AI Key / 模型 / 范围，写 .env + 热加载）
app.route('/api/config', configApp);

// 统一指挥台（Vue3 + Vite 构建产物）——主入口
app.get('/', (c) => c.redirect('/command/'));
app.get('/command', (c) => c.redirect('/command/'));
app.get('/command/', serveStatic({ root: './frontend/dist', path: 'index.html' }));
// Vite 构建产物的静态资源（JS/CSS）
app.use('/assets/*', serveStatic({ root: './frontend/dist' }));

// M4 复审控制台（单页 SPA，旧版保留）
app.get('/review', (c) => c.redirect('/review/'));
app.get('/review/', serveStatic({ root: './web', path: 'review.html' }));

// Web UI（单文件 SPA，web/index.html，ck-recon 控制台旧版保留）
app.use('/web/*', serveStatic({ root: './web' }));
app.get('/web', (c) => c.redirect('/web/'));
app.get('/web/', serveStatic({ root: './web', path: 'index.html' }));

// 根路径 API 说明（/api 前缀访问时）
app.get('/api', (c) => {
	return c.json({
		name: 'ck-recon',
		version: '0.1.0',
		endpoints: [
			'GET  /healthz',
			'POST /api/v1/seeds',
			'GET  /api/v1/seeds/:id',
			'GET  /api/v1/assets?seed_id=&type=',
			'GET  /api/v1/assets/:id/metadata',
			'GET  /api/v1/webapps?score_gt=60',
			'GET  /api/v1/findings?type=sourcemap',
			'GET  /api/v1/sources/:webappId',
			'GET  /api/v1/sources/:webappId/download',
			'GET  /api/v1/scan_runs?asset_id=',
		],
	});
});

/**
 * 启动 REST API + Web 控制台（合并后：ck-finder server）
 * 可选 --mcp 同时启动 MCP server（:8788）
 */
export async function startServer(opts: { enableMcp?: boolean } = {}): Promise<void> {
	const cfg = getConfig();
	const port = cfg.server.restPort;

	serve({ fetch: app.fetch, port }, (info) => {
		console.log(`[ck-finder] REST API server listening on http://0.0.0.0:${info.port}`);
		console.log(`[ck-finder] health check: http://localhost:${info.port}/healthz`);
		console.log(`[ck-finder] API docs:      http://localhost:${info.port}/`);
	});

	// 启动时恢复滞留任务：上次进程中断遗留的 running scan_runs/seed 会被清理
	recoverStaleScanRuns().catch((err) => {
		console.warn(`[ck-finder] 启动恢复滞留任务失败: ${err instanceof Error ? err.message : String(err)}`);
	});

	if (opts.enableMcp) {
		const { startHttp } = await import('./mcp_server.js');
		await startHttp();
	}
}

/** 把超过 30 分钟仍 running 的 scan_runs 标 failed，并把无 running 子任务的 running seed 判定 done/failed */
async function recoverStaleScanRuns(): Promise<void> {
	const { getPg } = await import('../storage/pg.js');
	const pool = getPg();
	const cutoff = new Date(Date.now() - 30 * 60 * 1000).toISOString();
	const { rowCount: stale } = await pool.query(
		`UPDATE scan_runs SET status = 'failed', error = '进程中断（启动恢复）', finished_at = now()
		 WHERE status = 'running' AND started_at < $1`,
		[cutoff],
	);
	await pool.query(
		`UPDATE seeds s SET status = CASE
		   WHEN (SELECT COUNT(*)::int FROM assets a WHERE a.seed_id = s.id) > 0 THEN 'done'
		   ELSE 'failed'
		 END
		 WHERE s.status = 'running'
		   AND NOT EXISTS (SELECT 1 FROM scan_runs r WHERE r.seed_id = s.id AND r.status = 'running')`,
	);
	// 恢复滞留的 running 意图：服务器启动时无存活 worker，所有 running 意图都是上次进程遗留的孤儿，直接标 failed
	const { rowCount: orphanIntents } = await pool.query(
		`UPDATE exploration_intents SET status = 'failed', result_summary = COALESCE(result_summary, 'worker 进程中断（启动恢复）'), updated_at = now()
		 WHERE status = 'running'`,
	);
	if (stale && stale > 0) console.log(`[ck-finder] 启动恢复：清理 ${stale} 个滞留 scan_runs`);
	if (orphanIntents && orphanIntents > 0) console.log(`[ck-finder] 启动恢复：清理 ${orphanIntents} 个滞留意图`);
}

export { app };
