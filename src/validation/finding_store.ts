/**
 * 漏洞 finding 存储（M3）
 *
 * 独立于收集引擎的 findings（那是 secret/sourcemap 等收集线索）。
 * validation_findings 表存「挖洞结论」，带强制证据 schema（validateEvidence 拒收 + DB CHECK 双保险）。
 */
import { randomUUID } from 'node:crypto';
import { getPg } from '../recon/storage/pg.js';
import { computeDedupKey } from './dedup.js';
import { type FindingEvidence, type VulnType, validateEvidence } from './schema.js';

export type FindingStatus = 'pending' | 'confirmed' | 'dismissed';
export type ReviewStatus = 'pending' | 'reviewed' | 'confirmed' | 'dismissed' | 'escalated';

export interface InsertFindingInput {
	seedId: string;
	intentId?: string | null;
	assetId?: string | null;
	vulnName: string;
	vulnType: VulnType | string;
	severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
	url: string;
	port?: number | null;
	summary: string;
	evidence: unknown; // validateEvidence 校验
}

export interface ValidationFinding extends Omit<InsertFindingInput, 'evidence'> {
	id: string;
	status: FindingStatus;
	reviewStatus: ReviewStatus;
	deepenCount: number;
	deepenDirective: string | null;
	supersededBy: string | null;
	evidence: FindingEvidence;
	createdAt: string;
	updatedAt: string;
}

function rowToFinding(r: Record<string, unknown>): ValidationFinding {
	return {
		id: r.id as string,
		seedId: r.seed_id as string,
		intentId: (r.intent_id as string | null) ?? null,
		assetId: (r.asset_id as string | null) ?? null,
		vulnName: r.vuln_name as string,
		vulnType: r.vuln_type as VulnType,
		severity: r.severity as ValidationFinding['severity'],
		url: r.url as string,
		port: (r.port as number | null) ?? null,
		summary: r.summary as string,
		evidence: r.evidence as unknown as FindingEvidence,
		status: r.status as FindingStatus,
		reviewStatus: (r.review_status as ReviewStatus) ?? 'pending',
		deepenCount: Number(r.deepen_count) || 0,
		deepenDirective: (r.deepen_directive as string | null) ?? null,
		supersededBy: (r.superseded_by as string | null) ?? null,
		createdAt: r.created_at as string,
		updatedAt: r.updated_at as string,
	};
}

export class FindingStore {
	/**
	 * 插入 finding：evidence 先过 validateEvidence（缺字段抛错拒收），再查重（重复返回 null），再入库。
	 * DB 层还有 CHECK 约束兜底。
	 */
	async insertFinding(input: InsertFindingInput): Promise<ValidationFinding | null> {
		const evidence = validateEvidence(input.evidence); // 缺字段抛错 → 拒收

		// 查重（M3.9）：全局 dedup_key 已存在 → 返回 null。DB 层 UNIQUE 约束 + ON CONFLICT 兜底（防 TOCTOU 竞态）
		const dedupKey = computeDedupKey(input.url, String(input.vulnType));
		const pool = getPg();
		const id = randomUUID();
		const result = await pool.query(
			`INSERT INTO validation_findings
			 (id, seed_id, intent_id, asset_id, vuln_name, vuln_type, severity, url, port, summary, evidence, status, dedup_key)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',$12)
			 ON CONFLICT (dedup_key) DO NOTHING`,
			[
				id,
				input.seedId,
				input.intentId ?? null,
				input.assetId ?? null,
				input.vulnName,
				input.vulnType,
				input.severity,
				input.url,
				input.port ?? null,
				input.summary,
				JSON.stringify(evidence),
				dedupKey,
			],
		);
		if (result.rowCount === 0) return null; // 重复（ON CONFLICT DO NOTHING）
		const { rows } = await pool.query('SELECT * FROM validation_findings WHERE id = $1', [id]);
		return rowToFinding(rows[0]);
	}

	async listFindings(params: {
		seedId?: string;
		assetId?: string;
		status?: FindingStatus;
		reviewStatus?: ReviewStatus;
		severity?: string;
		/** 只返回 created_at 严格晚于此时间的 finding（ISO 字符串） */
		createdAfter?: string;
		limit?: number;
	}): Promise<ValidationFinding[]> {
		const where: string[] = [];
		const values: unknown[] = [];
		let idx = 1;
		if (params.seedId) {
			where.push(`seed_id = $${idx++}`);
			values.push(params.seedId);
		}
		if (params.assetId) {
			where.push(`asset_id = $${idx++}`);
			values.push(params.assetId);
		}
		if (params.status) {
			where.push(`status = $${idx++}`);
			values.push(params.status);
		}
		if (params.reviewStatus) {
			where.push(`review_status = $${idx++}`);
			values.push(params.reviewStatus);
		}
		if (params.severity) {
			where.push(`severity = $${idx++}`);
			values.push(params.severity);
		}
		if (params.createdAfter) {
			where.push(`created_at > $${idx++}`);
			values.push(params.createdAfter);
		}
		const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
		const limit = params.limit ?? 100;
		values.push(limit);
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT * FROM validation_findings ${whereSql}
			 ORDER BY
			   CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
			   created_at DESC
			 LIMIT $${idx}`,
			values,
		);
		return rows.map(rowToFinding);
	}

	async getFinding(id: string): Promise<ValidationFinding | null> {
		const pool = getPg();
		const { rows } = await pool.query('SELECT * FROM validation_findings WHERE id = $1', [id]);
		return rows.length > 0 ? rowToFinding(rows[0]) : null;
	}

	/** 按 uuid 前缀解析 finding（review 命令 --id 支持前 8 位） */
	async getFindingByPrefix(prefix: string): Promise<ValidationFinding | null> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM validation_findings WHERE id::text LIKE $1 LIMIT 1',
			[`${prefix}%`],
		);
		return rows.length > 0 ? rowToFinding(rows[0]) : null;
	}

	async updateStatus(id: string, status: FindingStatus): Promise<void> {
		const pool = getPg();
		await pool.query(
			'UPDATE validation_findings SET status = $2, updated_at = now() WHERE id = $1',
			[id, status],
		);
	}

	async countByStatus(seedId: string): Promise<Record<string, number>> {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT status, COUNT(*)::int AS n FROM validation_findings
			 WHERE seed_id = $1 GROUP BY status`,
			[seedId],
		);
		const out: Record<string, number> = {};
		for (const r of rows) out[r.status as string] = Number(r.n);
		return out;
	}

	// ---------------------------------------------------------------------
	// M4 闭环
	// ---------------------------------------------------------------------

	/** 更新 review 状态（pending→reviewed/confirmed/dismissed/escalated） */
	async updateReviewStatus(id: string, reviewStatus: ReviewStatus): Promise<void> {
		const pool = getPg();
		await pool.query(
			'UPDATE validation_findings SET review_status = $2, updated_at = now() WHERE id = $1',
			[id, reviewStatus],
		);
	}

	/** 设置深挖指令（打回回炉时用）；deepen_count 递增（DEEPEN_CAP 防死循环） */
	async setDeepen(id: string, directive: string): Promise<number> {
		const pool = getPg();
		const { rows } = await pool.query(
			`UPDATE validation_findings
			 SET deepen_directive = $2, deepen_count = deepen_count + 1, updated_at = now()
			 WHERE id = $1
			 RETURNING deepen_count`,
			[id, directive],
		);
		return Number(rows[0]?.deepen_count ?? 0);
	}

	/** 标记被 superseded（原 finding 让位给深挖重派） */
	async supersede(id: string, supersededBy: string): Promise<void> {
		const pool = getPg();
		await pool.query(
			'UPDATE validation_findings SET superseded_by = $2, updated_at = now() WHERE id = $1',
			[id, supersededBy],
		);
	}
}
