import { describe, expect, it } from 'vitest';
import { type ScoreInput, scoreWebapp } from '../../src/recon/scoring/engine.js';

function baseInput(overrides: Partial<ScoreInput> = {}): ScoreInput {
	return {
		role: 'business',
		roleConfidence: 0.9,
		loginPage: false,
		fingerprintCount: 0,
		hasAdminPath: false,
		cdn: false,
		waf: false,
		...overrides,
	};
}

describe('scoreWebapp 技术栈上下文规则', () => {
	it('无上下文输入时行为不变（回归保护）', () => {
		const r = scoreWebapp(baseInput());
		expect(r.score).toBe(65);
		expect(r.breakdown.find((b) => b.name === 'vuln_component')).toBeUndefined();
	});

	it('命中已知漏洞组件 → +8', () => {
		const r = scoreWebapp(baseInput({ vulnHintCount: 2 }));
		expect(r.score).toBe(73);
		const item = r.breakdown.find((b) => b.name === 'vuln_component');
		expect(item?.delta).toBe(8);
	});

	it('CMS 指纹 → +2（Nday 稀缺，价值降低）', () => {
		const r = scoreWebapp(baseInput({ fingerprints: ['WordPress'] }));
		expect(r.score).toBe(67);
		expect(r.breakdown.find((b) => b.name === 'cms_known')?.delta).toBe(2);
	});

	it('现代前端框架（webpack/vue）→ +6（sourcemap 还原潜力）', () => {
		const r = scoreWebapp(baseInput({ tech: ['webpack', 'vue'], fingerprints: ['vue框架'] }));
		expect(r.score).toBe(71);
		expect(r.breakdown.find((b) => b.name === 'modern_frontend')?.delta).toBe(6);
	});

	it('Next.js 站（node.js/webpack/react）触发前端加分', () => {
		const r = scoreWebapp(
			baseInput({ tech: ['next.js:7.0.3', 'react', 'tengine', 'node.js', 'webpack'] }),
		);
		expect(r.breakdown.find((b) => b.name === 'modern_frontend')?.delta).toBe(6);
	});

	it('开发设施指纹 → +5', () => {
		const r = scoreWebapp(baseInput({ fingerprints: ['jenkins'] }));
		expect(r.score).toBe(70);
		expect(r.breakdown.find((b) => b.name === 'dev_tool')?.delta).toBe(5);
	});

	it('非开发/CMS/前端指纹不加分', () => {
		const r = scoreWebapp(baseInput({ fingerprints: ['nginx'], tech: ['cloudflare'] }));
		expect(r.breakdown.find((b) => b.name === 'cms_known')).toBeUndefined();
		expect(r.breakdown.find((b) => b.name === 'dev_tool')).toBeUndefined();
		expect(r.breakdown.find((b) => b.name === 'modern_frontend')).toBeUndefined();
	});

	it('纯 SPA 客户端（非 api/backend 角色）→ -5', () => {
		const r = scoreWebapp(baseInput({ role: 'business', siteArchitecture: 'spa' }));
		expect(r.breakdown.find((b) => b.name === 'spa_client_only')?.delta).toBe(-5);
	});

	it('SPA 但角色是 api → 不减分', () => {
		const r = scoreWebapp(baseInput({ role: 'api', siteArchitecture: 'spa' }));
		expect(r.breakdown.find((b) => b.name === 'spa_client_only')).toBeUndefined();
	});

	it('CMS + 漏洞组件叠加', () => {
		const r = scoreWebapp(
			baseInput({ fingerprints: ['thinkphp'], vulnHintCount: 1, loginPage: true }),
		);
		// 65 + 8 + 2 + 10 = 85
		expect(r.score).toBe(85);
	});
});
