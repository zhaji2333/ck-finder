/**
 * Reviewer 复审存储（M4）
 *
 * review_reviews 表记录 AI 初审/人工复审的判定。
 * reproduced 只由系统复现验证设置（不信任 LLM 自填）。
 */
import { randomUUID } from 'node:crypto';
import { getPg } from '../recon/storage/pg.js';

export type ReviewVerdict = 'accepted' | 'ignored' | 'deepen';

export interface ReviewRecord {
	id: string;
	findingId: string;
	verdict: ReviewVerdict;
	severityFinal: string | null;
	score: number | null;
	reasoning: string;
	reproduced: boolean;
	reviewerModel: string | null;
	createdAt: string;
}

function rowToReview(r: Record<string, unknown>): ReviewRecord {
	return {
		id: r.id as string,
		findingId: r.finding_id as string,
		verdict: r.verdict as ReviewVerdict,
		severityFinal: (r.severity_final as string | null) ?? null,
		score: r.score === null ? null : Number(r.score),
		reasoning: r.reasoning as string,
		reproduced: Boolean(r.reproduced),
		reviewerModel: (r.reviewer_model as string | null) ?? null,
		createdAt: r.created_at as string,
	};
}

export class ReviewStore {
	async insertReview(input: {
		findingId: string;
		verdict: ReviewVerdict;
		severityFinal?: string | null;
		score?: number | null;
		reasoning: string;
		reproduced?: boolean;
		reviewerModel?: string | null;
	}): Promise<ReviewRecord> {
		const id = randomUUID();
		const pool = getPg();
		await pool.query(
			`INSERT INTO review_reviews
			 (id, finding_id, verdict, severity_final, score, reasoning, reproduced, reviewer_model)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			[
				id,
				input.findingId,
				input.verdict,
				input.severityFinal ?? null,
				input.score ?? null,
				input.reasoning,
				input.reproduced === true,
				input.reviewerModel ?? null,
			],
		);
		const { rows } = await pool.query('SELECT * FROM review_reviews WHERE id = $1', [id]);
		return rowToReview(rows[0]);
	}

	async listReviewsByFinding(findingId: string): Promise<ReviewRecord[]> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM review_reviews WHERE finding_id = $1 ORDER BY created_at',
			[findingId],
		);
		return rows.map(rowToReview);
	}

	async latestReview(findingId: string): Promise<ReviewRecord | null> {
		const pool = getPg();
		const { rows } = await pool.query(
			'SELECT * FROM review_reviews WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1',
			[findingId],
		);
		return rows.length > 0 ? rowToReview(rows[0]) : null;
	}
}
