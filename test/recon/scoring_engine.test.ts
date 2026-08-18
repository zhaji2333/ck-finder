/**
 * M2.2 评分引擎单测
 */
import { describe, expect, it } from 'vitest';
import { type ScoreInput, scoreWebapp } from '../../src/recon/scoring/engine.js';

describe('scoreWebapp', () => {
	it('admin 角色基础分 85', () => {
		const r = scoreWebapp({
			role: 'admin',
			roleConfidence: 0.9,
			loginPage: true,
			fingerprintCount: 1,
			hasAdminPath: true,
			cdn: false,
			waf: false,
		} satisfies ScoreInput);
		expect(r.score).toBe(100); // 85 + 10 + 5 + 5 = 105 → clamp 100
		expect(r.hardToAttack).toBe(false);
		expect(r.breakdown).toHaveLength(4);
	});

	it('static 无登录减分到 10', () => {
		const r = scoreWebapp({
			role: 'static',
			roleConfidence: 0.55,
			loginPage: false,
			fingerprintCount: 0,
			hasAdminPath: false,
			cdn: false,
			waf: false,
		} satisfies ScoreInput);
		// 30 + (-5 低置信) + (-20 静态无登录) = 5
		expect(r.score).toBe(5);
	});

	it('CDN+WAF 双重防护减 15', () => {
		const r = scoreWebapp({
			role: 'business',
			roleConfidence: 0.8,
			loginPage: true,
			fingerprintCount: 0,
			hasAdminPath: false,
			cdn: true,
			waf: true,
		} satisfies ScoreInput);
		// 65 + 10 + (-15) = 60
		expect(r.score).toBe(60);
		expect(r.hardToAttack).toBe(true);
	});

	it('unknown 角色置信度低减 5', () => {
		const r = scoreWebapp({
			role: 'unknown',
			roleConfidence: 0.3,
			loginPage: false,
			fingerprintCount: 0,
			hasAdminPath: false,
			cdn: false,
			waf: false,
		} satisfies ScoreInput);
		// 40 + (-5 低置信) = 35
		expect(r.score).toBe(35);
	});

	it('middleware + 命中指纹 + WAF', () => {
		const r = scoreWebapp({
			role: 'middleware',
			roleConfidence: 0.88,
			loginPage: false,
			fingerprintCount: 2,
			hasAdminPath: false,
			cdn: false,
			waf: true,
		} satisfies ScoreInput);
		// 60 + 5 + (-5) = 60
		expect(r.score).toBe(60);
	});

	it('分数不为负数', () => {
		const r = scoreWebapp({
			role: 'static',
			roleConfidence: 0.2,
			loginPage: false,
			fingerprintCount: 0,
			hasAdminPath: false,
			cdn: true,
			waf: true,
		} satisfies ScoreInput);
		expect(r.score).toBeGreaterThanOrEqual(0);
	});

	it('breakdown 含基础分项', () => {
		const r = scoreWebapp({
			role: 'api',
			roleConfidence: 0.9,
			loginPage: false,
			fingerprintCount: 0,
			hasAdminPath: false,
			cdn: false,
			waf: false,
		} satisfies ScoreInput);
		expect(r.breakdown[0].name).toBe('base');
		expect(r.breakdown[0].delta).toBe(75);
	});
});
