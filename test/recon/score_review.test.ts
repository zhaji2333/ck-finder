import { describe, expect, it } from 'vitest';
import { parseScoreReviewResponse } from '../../src/recon/scoring/llm_score_review.js';

describe('parseScoreReviewResponse', () => {
	it('标准响应解析', () => {
		const r = parseScoreReviewResponse(
			JSON.stringify({
				roleConfirmed: true,
				suggestedRole: null,
				scoreAdjustment: 5,
				isHighValue: true,
				reasoning: '管理后台特征明确',
			}),
		);
		expect(r.parseError).toBe(false);
		expect(r.roleConfirmed).toBe(true);
		expect(r.suggestedRole).toBeNull();
		expect(r.scoreAdjustment).toBe(5);
		expect(r.isHighValue).toBe(true);
		expect(r.reasoning).toContain('管理后台');
		expect(r.probePaths).toEqual([]);
	});

	it('probePaths 解析（证据不足时 LLM 提议探测路径）', () => {
		const r = parseScoreReviewResponse(
			JSON.stringify({
				roleConfirmed: true,
				suggestedRole: null,
				scoreAdjustment: 0,
				isHighValue: true,
				reasoning: '疑似 CMS，需验证后台',
				probePaths: ['/wp-admin', '/api', 'https://evil.com/x', 42, '/login'],
			}),
		);
		expect(r.probePaths).toEqual(['/wp-admin', '/api', '/login']); // 最多3个，过滤非法
	});

	it('角色被推翻：建议角色生效，调整 clamp 到 [-15,15]', () => {
		const r = parseScoreReviewResponse(
			JSON.stringify({
				roleConfirmed: false,
				suggestedRole: 'static',
				scoreAdjustment: -20,
				isHighValue: false,
				reasoning: '静态站被误分为 admin',
			}),
		);
		expect(r.roleConfirmed).toBe(false);
		expect(r.suggestedRole).toBe('static');
		expect(r.scoreAdjustment).toBe(-15); // clamp
		expect(r.isHighValue).toBe(false);
	});

	it('非法建议角色回退 null，调整 clamp 到 [-15,15]', () => {
		const r = parseScoreReviewResponse(
			JSON.stringify({
				roleConfirmed: false,
				suggestedRole: 'hacker',
				scoreAdjustment: 999,
				isHighValue: false,
				reasoning: '',
			}),
		);
		expect(r.suggestedRole).toBeNull();
		expect(r.scoreAdjustment).toBe(15);
	});

	it('默认值：isHighValue 缺省为 false（宁缺毋滥）', () => {
		const r = parseScoreReviewResponse(
			JSON.stringify({
				roleConfirmed: true,
				suggestedRole: null,
				scoreAdjustment: 0,
				reasoning: '',
			}),
		);
		expect(r.isHighValue).toBe(false);
	});

	it('解析失败返回兜底（不认定高价值）', () => {
		const r = parseScoreReviewResponse('garbage');
		expect(r.parseError).toBe(true);
		expect(r.isHighValue).toBe(false);
		expect(r.scoreAdjustment).toBe(0);
	});
});
