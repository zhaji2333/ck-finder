/**
 * 探索图存储（M2）
 *
 * 基于 PostgreSQL（与收集引擎同库，复用 getPg 连接池）。
 * 图三要素：
 *   - intents：planner 派发的意图（pending→running→done/failed），锚点 asset_id 可 JOIN webapps 评分/角色
 *   - facts：worker 收集到的确定性信息（summary 摘要进上下文，raw_json 落盘）
 *   - activities：任务级事件流水（意图派发/完成/预算/越权拦截）
 *
 * 依赖感知调度：claimNext 只领「依赖全部 done」且 pending 的意图，防环。
 */
import { randomUUID } from 'node:crypto';
import { getPg } from '../recon/storage/pg.js';

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

export type IntentStatus = 'pending' | 'running' | 'done' | 'failed' | 'canceled';

export interface CreateIntentInput {
	seedId: string;
	intentType: string;
	description: string;
	priority?: number;
	scopeAnchor: string;
	assetId?: string | null;
	dependencies?: string[];
	depth?: number;
}

export interface ExplorationIntent {
	id: string;
	seedId: string;
	intentType: string;
	description: string;
	status: IntentStatus;
	priority: number;
	scopeAnchor: string;
	assetId: string | null;
	dependencies: string[];
	depth: number;
	resultSummary: string | null;
	createdAt: string;
	updatedAt: string;
}

export interface ExplorationFact {
	id: string;
	intentId: string;
	seedId: string;
	assetId: string | null;
	factType: string;
	summary: string;
	rawJson: string | null;
	createdAt: string;
}

export interface GraphActivity {
	id: string;
	seedId: string;
	activityType: string;
	message: string;
	meta: Record<string, unknown>;
	createdAt: string;
}

// ---------------------------------------------------------------------------
// 行 → 对象
// ---------------------------------------------------------------------------

function rowToIntent(r: Record<string, unknown>): ExplorationIntent {
	return {
		id: r.id as string,
		seedId: r.seed_id as string,
		intentType: r.intent_type as string,
		description: r.description as string,
		status: r.status as IntentStatus,
		priority: Number(r.priority) || 5,
		scopeAnchor: r.scope_anchor as string,
		assetId: (r.asset_id as string | null) ?? null,
		dependencies: (r.dependencies as string[] | null) ?? [],
		depth: Number(r.depth) || 0,
		resultSummary: (r.result_summary as string | null) ?? null,
		createdAt: r.created_at as string,
		updatedAt: r.updated_at as string,
	};
}

function rowToFact(r: Record<string, unknown>): ExplorationFact {
	return {
		id: r.id as string,
		intentId: r.intent_id as string,
		seedId: r.seed_id as string,
		assetId: (r.asset_id as string | null) ?? null,
		factType: r.fact_type as string,
		summary: r.summary as string,
		rawJson: (r.raw_json as string | null) ?? null,
		createdAt: r.created_at as string,
	};
}

function rowToActivity(r: Record<string, unknown>): GraphActivity {
	return {
		id: r.id as string,
		seedId: r.seed_id as string,
		activityType: r.activity_type as string,
		message: r.message as string,
		meta: (r.meta as Record<string, unknown>) ?? {},
		createdAt: r.created_at as string,
	};
}

// ---------------------------------------------------------------------------
// 存储类
// ---------------------------------------------------------------------------

export class ExplorationStore {
	// ---------------------------------------------------------------------
	// intents
	// ---------------------------------------------------------------------

	async createIntent(input: CreateIntentInput): Promise<ExplorationIntent> {
		const id = randomUUID();
		const pool = getPg();
		await pool.query(
			`INSERT INTO exploration_intents
			 (id, seed_id, intent_type, description, priority, scope_anchor, asset_id, dependencies, depth)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			[
				id,
				input.seedId,
				input.intentType,
				input.description,
				input.priority ?? 5,
				input.scopeAnchor,
				input.assetId ?? null,
				input.dependencies ?? [],
				input.depth ?? 0,
			],
		);
		const row = await this.getIntent(id);
		if (!row) throw new Error(`intent create failed: ${id}`);
		return row;
	}

	async getIntent(id: string): Promise<ExplorationIntent | null> {
		const pool = getPg();
		const { rows } = await pool.query('SELECT * FROM exploration_intents WHERE id = $1', [id]);
		return rows.length > 0 ? rowToIntent(rows[0]) : null;
	}

	async listIntents(seedId: string): Promise<ExplorationIntent[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM exploration_intents WHERE seed_id = $1 ORDER BY created_at',
			[seedId],
		);
		return rows.map(rowToIntent);
	}

	async updateIntentStatus(
		id: string,
		status: IntentStatus,
		resultSummary?: string | null,
	): Promise<void> {
		const pool = getPg();
		await pool.query(
			`UPDATE exploration_intents
			 SET status = $2, result_summary = COALESCE($3, result_summary), updated_at = now()
			 WHERE id = $1`,
			[id, status, resultSummary ?? null],
		);
	}

	/**
	 * 领用下一条可执行意图：pending + 依赖全部 done + 按 priority/created_at 排序。
	 * 原子性：事务内 SELECT ... FOR UPDATE SKIP LOCKED 防多 worker 竞争。
	 */
	async claimNext(seedId: string): Promise<ExplorationIntent | null> {
		const pool = getPg();
		const client = await pool.connect();
		try {
			await client.query('BEGIN');
			const { rows } = await client.query(
				`SELECT i.*
				 FROM exploration_intents i
				 WHERE i.seed_id = $1
				   AND i.status = 'pending'
				   AND NOT EXISTS (
				     SELECT 1 FROM exploration_intents d
				     WHERE d.id::text = ANY(i.dependencies) AND d.status <> 'done'
				   )
				 ORDER BY i.priority ASC, i.created_at ASC
				 LIMIT 1
				 FOR UPDATE SKIP LOCKED`,
				[seedId],
			);
			if (rows.length === 0) {
				await client.query('COMMIT');
				return null;
			}
			await client.query(
				`UPDATE exploration_intents SET status = 'running', updated_at = now()
				 WHERE id = $1`,
				[rows[0].id],
			);
			await client.query('COMMIT');
			// SELECT 发生在 UPDATE 前，返回对象需反映实际已流转的状态
			return { ...rowToIntent(rows[0]), status: 'running' };
		} catch (err) {
			await client.query('ROLLBACK');
			throw err;
		} finally {
			client.release();
		}
	}

	/** 统计某 seed 下各状态意图数（预算判断用） */
	async countByStatus(seedId: string): Promise<Record<string, number>> {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT status, COUNT(*)::int AS n FROM exploration_intents
			 WHERE seed_id = $1 GROUP BY status`,
			[seedId],
		);
		const out: Record<string, number> = {};
		for (const r of rows) out[r.status as string] = Number(r.n);
		return out;
	}

	/** 未完成任务数（崩溃恢复用） */
	async countUnfinished(seedId: string): Promise<number> {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT COUNT(*)::int AS n FROM exploration_intents
			 WHERE seed_id = $1 AND status IN ('pending', 'running')`,
			[seedId],
		);
		return Number(rows[0]?.n ?? 0);
	}

	// ---------------------------------------------------------------------
	// facts
	// ---------------------------------------------------------------------

	async insertFact(input: {
		intentId: string;
		seedId: string;
		assetId?: string | null;
		factType: string;
		summary: string;
		rawJson?: unknown;
	}): Promise<ExplorationFact> {
		const id = randomUUID();
		const pool = getPg();
		const raw = input.rawJson === undefined ? null : JSON.stringify(input.rawJson);
		await pool.query(
			`INSERT INTO exploration_facts (id, intent_id, seed_id, asset_id, fact_type, summary, raw_json)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			[id, input.intentId, input.seedId, input.assetId ?? null, input.factType, input.summary, raw],
		);
		const { rows } = await pool.query('SELECT * FROM exploration_facts WHERE id = $1', [id]);
		return rowToFact(rows[0]);
	}

	async listFacts(seedId: string): Promise<ExplorationFact[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM exploration_facts WHERE seed_id = $1 ORDER BY created_at',
			[seedId],
		);
		return rows.map(rowToFact);
	}

	/** 统计 seed 下事实条数（仅 COUNT，不加载 raw_json，避免 worker 热路径全量扫描） */
	async countFacts(seedId: string): Promise<number> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT COUNT(*)::int AS n FROM exploration_facts WHERE seed_id = $1',
			[seedId],
		);
		return Number(rows[0]?.n ?? 0);
	}

	async factsByAsset(assetId: string): Promise<ExplorationFact[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM exploration_facts WHERE asset_id = $1 ORDER BY created_at',
			[assetId],
		);
		return rows.map(rowToFact);
	}

	// ---------------------------------------------------------------------
	// activities
	// ---------------------------------------------------------------------

	async logActivity(
		seedId: string,
		activityType: string,
		message: string,
		meta: Record<string, unknown> = {},
	): Promise<void> {
		const pool = getPg();
		await pool.query(
			`INSERT INTO exploration_activities (seed_id, activity_type, message, meta)
			 VALUES ($1, $2, $3, $4)`,
			[seedId, activityType, message, JSON.stringify(meta)],
		);
	}

	async listActivities(seedId: string, limit = 50): Promise<GraphActivity[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM exploration_activities WHERE seed_id = $1 ORDER BY created_at DESC LIMIT $2',
			[seedId, limit],
		);
		return rows.map(rowToActivity);
	}

	/** 锚点资产存在性校验（planner 提交意图时用，防锚到不存在的资产） */
	async assetExists(assetId: string): Promise<boolean> {
		const pool = getPg();
		const { rows } = await pool.query('SELECT 1 FROM assets WHERE id = $1', [assetId]);
		return rows.length > 0;
	}
}
