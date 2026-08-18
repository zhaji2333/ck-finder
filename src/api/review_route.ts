/**
 * M4 复审控制台 API（挂载到 Hono server /api/review/*）
 *
 * - GET  /api/review/findings       待审/已审 finding 列表
 * - GET  /api/review/findings/:id   finding 详情（含 evidence/reviews）
 * - POST /api/review/findings/:id/decision  人工裁决：approve/decline/adjust/submit
 * - POST /api/review/findings/:id/deepen    人工打回继续深挖（带定向指令）
 * - GET  /api/review/intel          情报库
 * - GET  /api/review/board          看板（finding 统计）
 */
import { Hono } from 'hono';
import { listPendingReviews, runReview } from '../agents/reviewer.js';
import { getConfig } from '../recon/config.js';
import { FindingStore } from '../validation/finding_store.js';
import { IntelStore } from '../validation/intel_store.js';
import { ReviewStore } from '../validation/review_store.js';

export const reviewApp = new Hono();

/** finding 详情序列化（含证据与复审记录） */
async function findingDetail(id: string) {
	const store = new FindingStore();
	const reviewStore = new ReviewStore();
	const finding = await store.getFinding(id);
	if (!finding) return null;
	const reviews = await reviewStore.listReviewsByFinding(id);
	return { finding, reviews };
}

/** 待审列表 + AI 初审（可选触发） */
reviewApp.get('/findings', async (c) => {
	const status = c.req.query('status') ?? 'pending';
	const seedId = c.req.query('seed_id');
	const store = new FindingStore();
	const findings = await store.listFindings({
		seedId,
		reviewStatus: status as never,
		limit: Number(c.req.query('limit') ?? 50),
	});
	return c.json({ total: findings.length, findings });
});

reviewApp.get('/findings/:id', async (c) => {
	const detail = await findingDetail(c.req.param('id'));
	if (!detail) return c.json({ error: 'finding not found' }, 404);
	return c.json(detail);
});

/** 触发 AI 初审（对待审 finding 跑 runReview） */
reviewApp.post('/findings/:id/review', async (c) => {
	const id = c.req.param('id');
	const store = new FindingStore();
	const finding = await store.getFinding(id);
	if (!finding) return c.json({ error: 'finding not found' }, 404);
	const cfg = getConfig();
	const outcome = await runReview({
		finding,
		scope: [...cfg.agent.scope, ...cfg.scopeGate.allowed],
		enabled: Boolean(cfg.llm.apiKey),
	});
	return c.json({ id, outcome });
});

/** 待审队列批量 AI 初审（control-plane 用） */
reviewApp.post('/review-pending', async (c) => {
	const cfg = getConfig();
	const pending = await listPendingReviews(20);
	const results = [];
	for (const f of pending) {
		const outcome = await runReview({
			finding: f,
			scope: [...cfg.agent.scope, ...cfg.scopeGate.allowed],
			enabled: Boolean(cfg.llm.apiKey),
		});
		results.push({ findingId: f.id, verdict: outcome.verdict, reproduced: outcome.reproduced });
	}
	return c.json({ total: results.length, results });
});

/**
 * 人工裁决：approve（通过→confirmed）/ decline（驳回→dismissed）/ adjust（调级）/ submit（标记提交）
 * body: { action, severity?, note? }
 */
reviewApp.post('/findings/:id/decision', async (c) => {
	const id = c.req.param('id');
	const body = (await c.req.json().catch(() => ({}))) as {
		action?: string;
		severity?: string;
		note?: string;
	};
	const action = body.action;
	const store = new FindingStore();
	const finding = await store.getFinding(id);
	if (!finding) return c.json({ error: 'finding not found' }, 404);

	if (action === 'approve') {
		await store.updateReviewStatus(id, 'confirmed');
		// M4.4：确认后自动提炼情报（指纹/端点/凭证）
		let intelExtracted = 0;
		try {
			const { harvestIntelFromFinding } = await import('../validation/intel_harvest.js');
			intelExtracted = await harvestIntelFromFinding(finding, finding.seedId);
		} catch {
			intelExtracted = 0;
		}
		return c.json({ id, reviewStatus: 'confirmed', intelExtracted });
	}
	if (action === 'decline') {
		await store.updateReviewStatus(id, 'dismissed');
		return c.json({ id, reviewStatus: 'dismissed' });
	}
	if (action === 'submit') {
		await store.updateReviewStatus(id, 'confirmed');
		await store.updateStatus(id, 'confirmed');
		return c.json({ id, status: 'confirmed', submitted: true });
	}
	return c.json({ error: `unknown action: ${action}` }, 400);
});

/** 人工打回继续深挖（带定向指令） */
reviewApp.post('/findings/:id/deepen', async (c) => {
	const id = c.req.param('id');
	const body = (await c.req.json().catch(() => ({}))) as { directive?: string };
	if (!body.directive) return c.json({ error: 'missing directive' }, 400);
	const store = new FindingStore();
	const finding = await store.getFinding(id);
	if (!finding) return c.json({ error: 'finding not found' }, 404);
	const count = await store.setDeepen(id, body.directive);
	await store.updateReviewStatus(id, 'reviewed');
	return c.json({ id, deepenCount: count, directive: body.directive });
});

/** 情报库 */
reviewApp.get('/intel', async (c) => {
	const store = new IntelStore();
	const stats = await store.stats();
	const kind = c.req.query('kind');
	if (kind) {
		// 列出该类全部
		const pool = (await import('../recon/storage/pg.js')).getPg();
		const { rows } = await pool.query(
			'SELECT * FROM intel_entries WHERE kind = $1 ORDER BY hit_count DESC LIMIT 100',
			[kind],
		);
		return c.json({ stats, entries: rows });
	}
	return c.json({ stats });
});

/** 看板统计 */
reviewApp.get('/board', async (c) => {
	const pool = (await import('../recon/storage/pg.js')).getPg();
	const { rows } = await pool.query(
		'SELECT review_status, COUNT(*)::int AS n FROM validation_findings GROUP BY review_status',
	);
	const counts: Record<string, number> = {};
	for (const r of rows) counts[r.review_status as string] = Number(r.n);
	const { rows: sev } = await pool.query(
		'SELECT severity, COUNT(*)::int AS n FROM validation_findings GROUP BY severity',
	);
	const bySeverity: Record<string, number> = {};
	for (const r of sev) bySeverity[r.severity as string] = Number(r.n);
	return c.json({ counts, bySeverity });
});
