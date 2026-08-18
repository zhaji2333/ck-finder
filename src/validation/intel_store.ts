/**
 * intel 情报库（M4.4，借鉴 AutoHunter intel.py）
 *
 * 跨任务复用验证过的情报：cred（凭证）/ endpoint（有效路径）/ fingerprint（指纹→打法）。
 * worker 启动时按目标 host 指纹/root 域触发式注入（命中才注入，零命中零开销）。
 */
import { randomUUID } from 'node:crypto';
import { getPg } from '../recon/storage/pg.js';

export type IntelKind = 'cred' | 'endpoint' | 'fingerprint';
export type IntelConfidence = 'verified' | 'likely';

export interface IntelEntry {
	id: string;
	kind: IntelKind;
	matchKey: string;
	payload: Record<string, unknown>;
	confidence: IntelConfidence;
	sourceFindingId: string | null;
	hitCount: number;
	createdAt: string;
}

function rowToIntel(r: Record<string, unknown>): IntelEntry {
	return {
		id: r.id as string,
		kind: r.kind as IntelKind,
		matchKey: r.match_key as string,
		payload: r.payload as Record<string, unknown>,
		confidence: r.confidence as IntelConfidence,
		sourceFindingId: (r.source_finding_id as string | null) ?? null,
		hitCount: Number(r.hit_count) || 0,
		createdAt: r.created_at as string,
	};
}

/** 提取 root 域（host → root domain） */
export function rootDomain(host: string): string {
	const parts = host
		.toLowerCase()
		.replace(/^www\./, '')
		.split('.');
	// 取最后两段（简单启发式，兼容 .com.cn 这类会取错，够用即可）
	return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

export class IntelStore {
	/**
	 * 记录情报（查重：同 kind+match_key 只更新 hit_count，不重复插）
	 * confidence 只升不降（likely → verified 可升级）
	 */
	async recordIntel(input: {
		kind: IntelKind;
		matchKey: string;
		payload: Record<string, unknown>;
		confidence: IntelConfidence;
		sourceFindingId?: string | null;
	}): Promise<IntelEntry> {
		const pool = getPg();
		const existing = await pool.query(
			'SELECT * FROM intel_entries WHERE kind = $1 AND match_key = $2',
			[input.kind, input.matchKey],
		);
		if (existing.rows.length > 0) {
			const row = existing.rows[0];
			// confidence 只升不降；hit_count 递增
			const newConf =
				row.confidence === 'verified' || input.confidence === 'verified' ? 'verified' : 'likely';
			await pool.query(
				`UPDATE intel_entries
				 SET payload = $3, confidence = $4, hit_count = hit_count + 1, last_seen = now()
				 WHERE kind = $1 AND match_key = $2`,
				[input.kind, input.matchKey, JSON.stringify(input.payload), newConf],
			);
			const { rows } = await pool.query(
				'SELECT * FROM intel_entries WHERE kind = $1 AND match_key = $2',
				[input.kind, input.matchKey],
			);
			return rowToIntel(rows[0]);
		}
		const id = randomUUID();
		await pool.query(
			`INSERT INTO intel_entries (id, kind, match_key, payload, confidence, source_finding_id)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			[
				id,
				input.kind,
				input.matchKey,
				JSON.stringify(input.payload),
				input.confidence,
				input.sourceFindingId ?? null,
			],
		);
		const { rows } = await pool.query('SELECT * FROM intel_entries WHERE id = $1', [id]);
		return rowToIntel(rows[0]);
	}

	/** 按 kind + matchKey 查询（worker 注入用，命中才返回） */
	async lookupIntel(kind: IntelKind, matchKey: string, limit = 4): Promise<IntelEntry[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			`SELECT * FROM intel_entries WHERE kind = $1 AND match_key = $2
			 ORDER BY CASE confidence WHEN 'verified' THEN 0 ELSE 1 END, hit_count DESC, last_seen DESC
			 LIMIT $3`,
			[kind, matchKey, limit],
		);
		return rows.map(rowToIntel);
	}

	/** 多 key 匹配（指纹列表/根域列表） */
	async lookupIntelMany(kind: IntelKind, matchKeys: string[], limit = 4): Promise<IntelEntry[]> {
		if (matchKeys.length === 0) return [];
		const pool = getPg();
		const placeholders = matchKeys.map((_, i) => `$${i + 1}`).join(',');
		const { rows } = await pool.query(
			`SELECT * FROM intel_entries WHERE kind = $1 AND match_key IN (${placeholders})
			 ORDER BY CASE confidence WHEN 'verified' THEN 0 ELSE 1 END, hit_count DESC, last_seen DESC
			 LIMIT $${matchKeys.length + 1}`,
			[kind, ...matchKeys, limit],
		);
		return rows.map(rowToIntel);
	}

	async stats(): Promise<Record<string, number>> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT kind, COUNT(*)::int AS n FROM intel_entries GROUP BY kind',
		);
		const out: Record<string, number> = {};
		for (const r of rows) out[r.kind as string] = Number(r.n);
		return out;
	}
}
