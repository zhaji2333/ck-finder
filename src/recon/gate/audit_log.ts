/**
 * 全量审计日志
 *
 * 安全层红线（架构文档 §一 1.2 风险与对策 #2）：
 * 所有工具调用、Scope Gate 决策、LLM 调用、数据写入都留痕到 audit_log 表。
 *
 * MVP 阶段：同步写入 PostgreSQL，简单可靠。
 * 后续可优化为批量异步写入（如 Buffer + flush）。
 */

import { getPg } from '../storage/pg.js';

export type AuditActor = string; // system / tool:<name> / llm:<provider> / user:<id>
export type AuditAction =
	| 'tool_call'
	| 'tool_end'
	| 'tool_error'
	| 'scope_decision'
	| 'llm_call'
	| 'data_write'
	| 'source_download'
	| 'seed_submit'
	| 'asset_create'
	| 'scan_start'
	| 'scan_finish'
	| 'agent_decision';
export type AuditDecision = 'allow' | 'deny' | 'pass' | 'fail' | 'info';

export interface AuditEntry {
	actor: AuditActor;
	action: AuditAction;
	target?: string | null;
	decision: AuditDecision;
	reason?: string | null;
	meta?: Record<string, unknown> | null;
}

/**
 * 写入审计日志
 *
 * 失败时仅打印错误，不抛异常（审计不能阻塞业务）。
 * 设置环境变量 CKRECON_AUDIT_DISABLED=1 可跳过写入（用于测试）。
 */
export async function auditLog(entry: AuditEntry): Promise<void> {
	if (process.env.CKRECON_AUDIT_DISABLED === '1') return;
	try {
		const pool = getPg();
		await pool.query(
			`INSERT INTO audit_log (actor, action, target, decision, reason, meta)
       VALUES ($1, $2, $3, $4, $5, $6)`,
			[
				entry.actor,
				entry.action,
				entry.target ?? null,
				entry.decision,
				entry.reason ?? null,
				entry.meta ? JSON.stringify(entry.meta) : null,
			],
		);
	} catch (err) {
		// 审计失败不能阻塞业务，仅打印
		console.error('[audit_log] write failed:', err instanceof Error ? err.message : err);
		console.error('[audit_log] entry:', JSON.stringify(entry));
	}
}

/**
 * 批量写入审计日志（用于高频场景，如批量入库）
 */
export async function auditLogBatch(entries: AuditEntry[]): Promise<void> {
	if (entries.length === 0) return;
	try {
		const pool = getPg();
		// 构造多值 INSERT
		const values: unknown[] = [];
		const placeholders: string[] = [];
		entries.forEach((entry, i) => {
			const base = i * 6;
			placeholders.push(
				`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6})`,
			);
			values.push(
				entry.actor,
				entry.action,
				entry.target ?? null,
				entry.decision,
				entry.reason ?? null,
				entry.meta ? JSON.stringify(entry.meta) : null,
			);
		});
		await pool.query(
			`INSERT INTO audit_log (actor, action, target, decision, reason, meta)
       VALUES ${placeholders.join(', ')}`,
			values,
		);
	} catch (err) {
		console.error('[audit_log] batch write failed:', err instanceof Error ? err.message : err);
	}
}

/**
 * 查询审计日志（用于 REST API）
 */
export interface AuditQueryOptions {
	actor?: string;
	action?: string;
	decision?: string;
	target?: string;
	since?: Date;
	until?: Date;
	limit?: number;
	offset?: number;
}

export async function queryAuditLog(opts: AuditQueryOptions = {}) {
	const pool = getPg();
	const conditions: string[] = [];
	const values: unknown[] = [];
	let idx = 1;
	if (opts.actor) {
		conditions.push(`actor = $${idx++}`);
		values.push(opts.actor);
	}
	if (opts.action) {
		conditions.push(`action = $${idx++}`);
		values.push(opts.action);
	}
	if (opts.decision) {
		conditions.push(`decision = $${idx++}`);
		values.push(opts.decision);
	}
	if (opts.target) {
		conditions.push(`target = $${idx++}`);
		values.push(opts.target);
	}
	if (opts.since) {
		conditions.push(`ts >= $${idx++}`);
		values.push(opts.since);
	}
	if (opts.until) {
		conditions.push(`ts <= $${idx++}`);
		values.push(opts.until);
	}
	const limit = opts.limit ?? 100;
	const offset = opts.offset ?? 0;
	values.push(limit, offset);

	const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
	const { rows } = await pool.query(
		`SELECT id, ts, actor, action, target, decision, reason, meta
     FROM audit_log
     ${where}
     ORDER BY ts DESC
     LIMIT $${idx++} OFFSET $${idx++}`,
		values,
	);
	return rows;
}
