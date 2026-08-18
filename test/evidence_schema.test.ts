/**
 * finding 证据 schema 测试：强制五件套，缺字段拒收。
 */
import { describe, expect, it } from 'vitest';
import { buildEvidence, validateEvidence } from '../src/validation/schema.js';

const validEvidence = {
	poc: 'curl -X POST http://x/login -d "username=admin&password=admin"',
	raw_request: 'POST /login HTTP/1.1\nHost: x\n\nusername=admin&password=admin',
	raw_response: 'HTTP/1.1 302 Found\nLocation: /dashboard',
	kill_chain: {
		chain: [
			{ step: '输入点', detail: '登录接口无弱口令防护' },
			{ step: '触发', detail: '尝试 admin/admin 登录成功' },
		],
		summary: '弱口令直接进入后台',
	},
	self_check: {
		reproducible: true,
		prerequisites: '目标在授权范围',
		impact: '未授权访问',
		severity: 'high',
		priority: 'P1',
	},
};

describe('validateEvidence', () => {
	it('完整证据通过校验', () => {
		const ev = validateEvidence(validEvidence);
		expect(ev.poc).toContain('curl');
		expect(ev.kill_chain.chain).toHaveLength(2);
		expect(ev.self_check.priority).toBe('P1');
	});

	it('缺 poc → 拒收', () => {
		const { poc: _poc, ...rest } = validEvidence;
		expect(() => validateEvidence(rest)).toThrow('poc');
	});

	it('缺 raw_response → 拒收', () => {
		const e = { ...validEvidence, raw_response: '' };
		expect(() => validateEvidence(e)).toThrow('raw_response');
	});

	it('kill_chain 空 chain → 拒收', () => {
		const e = {
			...validEvidence,
			kill_chain: { chain: [], summary: '空' },
		};
		expect(() => validateEvidence(e)).toThrow('chain');
	});

	it('self_check 缺字段 → 拒收', () => {
		const { self_check: _sc, ...rest } = validEvidence;
		expect(() => validateEvidence({ ...rest, self_check: { reproducible: true } })).toThrow(
			'self_check',
		);
	});

	it('非对象 → 拒收', () => {
		expect(() => validateEvidence(null)).toThrow('evidence');
	});

	it('buildEvidence 构造合法证据', () => {
		const ev = buildEvidence({
			poc: 'curl x',
			rawRequest: 'GET / HTTP/1.1',
			rawResponse: 'HTTP/1.1 200 OK',
			killChainSteps: [{ step: 'a', detail: 'b' }],
			killChainSummary: 's',
			selfCheck: {
				reproducible: true,
				prerequisites: '无',
				impact: '无',
				severity: 'low',
				priority: 'P2',
			},
		});
		expect(ev.raw_request).toBe('GET / HTTP/1.1');
	});
});
