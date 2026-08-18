import { type HuntTarget, runDirectHunt } from './hunt.js';
/**
 * 持久化任务队列（M5.1 + M5.4）
 *
 * 支撑 7×24 挂机挖洞：
 *   - 任务持久化（hunt_tasks 表，状态机 queued→running→done/failed/timeout）
 *   - 并发调度（worker 池，从队列取任务执行，AutoHunter 每目标 1 worker）
 *   - 预算：每任务意图数上限 + planner 轮数 + 墙钟超时
 *   - 心跳：worker 执行中定期更新 heartbeat_at
 *   - 崩溃恢复：启动扫描 running/queued 任务重新入队（restore_on_startup）
 */
import { getPg } from './recon/storage/pg.js';

export type HuntTaskStatus = 'queued' | 'running' | 'done' | 'failed' | 'timeout';

export interface EnqueueTarget {
	url: string;
	cookie?: string;
	username?: string;
	password?: string;
	authorization?: string;
}

export interface HuntTask {
	id: string;
	seedId: string;
	targetUrl: string;
	status: HuntTaskStatus;
	priority: number;
	maxIntents: number;
	maxRounds: number;
	credentials: Record<string, string> | null;
	heartbeatAt: string | null;
	startedAt: string | null;
	finishedAt: string | null;
	wallTimeoutMs: number;
	resultSummary: string | null;
	error: string | null;
	retryCount: number;
	createdAt: string;
}

function rowToTask(r: Record<string, unknown>): HuntTask {
	return {
		id: r.id as string,
		seedId: r.seed_id as string,
		targetUrl: r.target_url as string,
		status: r.status as HuntTaskStatus,
		priority: Number(r.priority) || 5,
		maxIntents: Number(r.max_intents) || 20,
		maxRounds: Number(r.max_rounds) || 3,
		credentials: (r.credentials as Record<string, string> | null) ?? null,
		heartbeatAt: (r.heartbeat_at as string | null) ?? null,
		startedAt: (r.started_at as string | null) ?? null,
		finishedAt: (r.finished_at as string | null) ?? null,
		wallTimeoutMs: Number(r.wall_timeout_ms) || 30 * 60 * 1000,
		resultSummary: (r.result_summary as string | null) ?? null,
		error: (r.error as string | null) ?? null,
		retryCount: Number(r.retry_count) || 0,
		createdAt: r.created_at as string,
	};
}

export class HuntQueue {
	/** 入队一批目标（每个目标一个 task） */
	async enqueue(
		targets: EnqueueTarget[],
		opts: {
			priority?: number;
			maxIntents?: number;
			maxRounds?: number;
			wallTimeoutMs?: number;
		} = {},
	): Promise<string[]> {
		const pool = getPg();
		const ids: string[] = [];
		for (const t of targets) {
			// 复用 seed（host:port 作 seed，防跨目标串扰）
			const { normalizeSeed } = await import('./recon/seeds/normalizer.js');
			const { upsertSeed } = await import('./recon/storage/models/asset.js');
			const host = (() => {
				try {
					return new URL(t.url).host;
				} catch {
					return t.url;
				}
			})();
			const normalized = normalizeSeed(host.includes(':') ? `http://${host}` : host);
			const seedId = await upsertSeed(normalized);
			const { rows } = await pool.query(
				`INSERT INTO hunt_tasks (seed_id, target_url, status, priority, max_intents, max_rounds, credentials, wall_timeout_ms)
				 VALUES ($1,$2,'queued',$3,$4,$5,$6,$7) RETURNING id`,
				[
					seedId,
					t.url,
					opts.priority ?? 5,
					opts.maxIntents ?? 20,
					opts.maxRounds ?? 3,
					t.cookie || t.username || t.authorization
						? JSON.stringify({
								cookie: t.cookie,
								username: t.username,
								password: t.password,
								authorization: t.authorization,
							})
						: null,
					opts.wallTimeoutMs ?? 30 * 60 * 1000,
				],
			);
			ids.push(rows[0].id as string);
		}
		return ids;
	}

	/** 领用下一条 queued 任务（原子：FOR UPDATE SKIP LOCKED） */
	async claimNext(): Promise<HuntTask | null> {
		const pool = getPg();
		const client = await pool.connect();
		try {
			await client.query('BEGIN');
			const { rows } = await client.query(
				`SELECT * FROM hunt_tasks WHERE status = 'queued' ORDER BY priority ASC, created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED`,
			);
			if (rows.length === 0) {
				await client.query('COMMIT');
				return null;
			}
			await client.query(
				`UPDATE hunt_tasks SET status='running', started_at=now(), heartbeat_at=now(), updated_at=now() WHERE id=$1`,
				[rows[0].id],
			);
			await client.query('COMMIT');
			return rowToTask({ ...rows[0], status: 'running' });
		} catch (err) {
			await client.query('ROLLBACK');
			throw err;
		} finally {
			client.release();
		}
	}

	/** 心跳（worker 执行中定期调用） */
	async heartbeat(taskId: string): Promise<void> {
		const pool = getPg();
		await pool.query(`UPDATE hunt_tasks SET heartbeat_at=now(), updated_at=now() WHERE id=$1`, [
			taskId,
		]);
	}

	/** 更新任务状态 */
	async updateStatus(
		taskId: string,
		status: HuntTaskStatus,
		resultSummary?: string,
		error?: string,
	): Promise<void> {
		const pool = getPg();
		await pool.query(
			`UPDATE hunt_tasks SET status=$2, finished_at=CASE WHEN $2 IN ('done','failed','timeout') THEN now() ELSE finished_at END,
			 result_summary=COALESCE($3, result_summary), error=COALESCE($4, error), updated_at=now() WHERE id=$1`,
			[taskId, status, resultSummary ?? null, error ?? null],
		);
	}

	/** 崩溃恢复：启动时把 running/queued 的超时任务重新入队（restore_on_startup） */
	async recover(graceMs = 5 * 60 * 1000): Promise<number> {
		const pool = getPg();
		// running 且心跳超时（墙钟超时或心跳停滞）→ 重新 queued（retry_count < 2）
		const { rows } = await pool.query(
			`UPDATE hunt_tasks SET status='queued', retry_count=retry_count+1, updated_at=now()
			 WHERE status='running' AND heartbeat_at < now() - $1::interval
			   AND retry_count < 2
			 RETURNING id`,
			[`${Math.floor(graceMs / 1000)} seconds`],
		);
		// 已超墙钟的 running → timeout
		await pool.query(
			`UPDATE hunt_tasks SET status='timeout', finished_at=now(), updated_at=now()
			 WHERE status='running' AND started_at IS NOT NULL AND now() - started_at > (wall_timeout_ms * interval '1 millisecond')`,
		);
		return rows.length;
	}

	/** 统计各状态任务数 */
	async stats(): Promise<Record<string, number>> {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT status, COUNT(*)::int AS n FROM hunt_tasks GROUP BY status`,
		);
		const out: Record<string, number> = {};
		for (const r of rows) out[r.status as string] = Number(r.n);
		return out;
	}

	/** 列出任务 */
	async list(limit = 50): Promise<HuntTask[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT * FROM hunt_tasks ORDER BY created_at DESC LIMIT $1`,
			[limit],
		);
		return rows.map(rowToTask);
	}
}

/**
 * 运行队列调度循环（M5.1 并发 + M5.4 心跳/预算）
 * 崩溃恢复：先 recover 超时任务，再并发执行 queued 任务。
 */
export async function runQueue(concurrency = 4, persistent = false): Promise<void> {
	const queue = new HuntQueue();
	// 崩溃恢复
	const recovered = await queue.recover();
	if (recovered > 0) console.log(`[queue] 崩溃恢复 ${recovered} 个超时任务重新入队`);

	console.log(`[queue] 启动调度（并发 ${concurrency}${persistent ? '，长驻轮询' : ''}）`);
	const workers = Array.from({ length: concurrency }, async () => {
		for (;;) {
			const task = await queue.claimNext();
			if (!task) {
				// 非长驻：队列清空即退出；长驻：空队列轮询等待新任务（7×24）
				if (!persistent) break;
				await new Promise((r) => setTimeout(r, 2000));
				continue;
			}
			console.log(`[queue] 执行任务 ${task.id.slice(0, 8)}: ${task.targetUrl}`);
			// 心跳（每 30s）
			const hb = setInterval(() => queue.heartbeat(task.id).catch(() => {}), 30_000);
			try {
				const creds = task.credentials ?? {};
				const targets: HuntTarget[] = [{ url: task.targetUrl, ...creds }];
				await runDirectHunt({ targets, concurrency: 1, timeoutMs: task.wallTimeoutMs });
				await queue.updateStatus(task.id, 'done', 'hunt completed');
				console.log(`[queue] 任务 ${task.id.slice(0, 8)} 完成`);
			} catch (err) {
				const msg = err instanceof Error ? err.message : String(err);
				await queue.updateStatus(task.id, 'failed', undefined, msg);
				console.log(`[queue] 任务 ${task.id.slice(0, 8)} 失败: ${msg.slice(0, 80)}`);
			} finally {
				clearInterval(hb);
			}
		}
	});
	await Promise.all(workers);
	console.log('[queue] 队列清空，调度结束');
}
