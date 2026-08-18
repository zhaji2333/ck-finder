import { describe, expect, it } from 'vitest';
import { parseArchAnalysisResponse } from '../../src/recon/scoring/llm_arch_analysis.js';
import { parseAttackSurfaceResponse } from '../../src/recon/scoring/llm_attack_surface.js';
import { parsePageClassifyResponse } from '../../src/recon/scoring/llm_page_classify.js';

// =============================================================================
// LLM 分析①：页面语义分类
// =============================================================================

describe('parsePageClassifyResponse', () => {
	it('标准响应解析', () => {
		const r = parsePageClassifyResponse(
			JSON.stringify({
				items: [
					{ path: '/login', role: 'login', reason: '登录页' },
					{ path: '/admin/dashboard', role: 'admin', reason: '后台' },
					{ path: '/api/v1/upload', role: 'upload', reason: '上传' },
				],
			}),
		);
		expect(r.parseError).toBe(false);
		expect(r.items).toHaveLength(3);
		expect(r.items[0]).toEqual({ path: '/login', role: 'login', reason: '登录页' });
	});

	it('非法角色回退 other，非法项丢弃', () => {
		const r = parsePageClassifyResponse(
			JSON.stringify({
				items: [
					{ path: '/x', role: 'hacker_role', reason: '' },
					{ path: '', role: 'login', reason: '' },
					'not-an-object',
				],
			}),
		);
		expect(r.items).toHaveLength(1);
		expect(r.items[0].role).toBe('other');
	});

	it('解析失败返回空兜底', () => {
		const r = parsePageClassifyResponse('garbage');
		expect(r.parseError).toBe(true);
		expect(r.items).toEqual([]);
	});
});

// =============================================================================
// LLM 分析②：接口聚类攻击面地图
// =============================================================================

describe('parseAttackSurfaceResponse', () => {
	it('标准响应解析', () => {
		const r = parseAttackSurfaceResponse(
			JSON.stringify({
				attackSurface: {
					auth: ['/api/login', '/api/token/refresh'],
					upload: ['/api/upload'],
					other: [],
				},
				summary: '典型业务站，认证接口集中',
				recommendations: ['测试认证绕过', '测试上传类型限制'],
			}),
		);
		expect(r.parseError).toBe(false);
		expect(r.attackSurface.auth).toEqual(['/api/login', '/api/token/refresh']);
		expect(r.attackSurface.upload).toHaveLength(1);
		expect(r.attackSurface.other).toEqual([]);
		expect(r.summary).toContain('认证');
		expect(r.recommendations).toHaveLength(2);
	});

	it('非法分组数据被过滤', () => {
		const r = parseAttackSurfaceResponse(
			JSON.stringify({
				attackSurface: { auth: ['/api/login', 42, null] },
				summary: '',
				recommendations: [],
			}),
		);
		expect(r.attackSurface.auth).toEqual(['/api/login']);
	});

	it('解析失败返回空兜底', () => {
		const r = parseAttackSurfaceResponse('garbage');
		expect(r.parseError).toBe(true);
		expect(r.attackSurface).toEqual({});
	});
});

// =============================================================================
// LLM 分析③：架构级分析
// =============================================================================

describe('parseArchAnalysisResponse', () => {
	it('标准响应解析', () => {
		const r = parseArchAnalysisResponse(
			JSON.stringify({
				rendering: 'csr',
				apiStyle: 'rest',
				authMechanism: 'jwt',
				thirdParty: ['google-analytics', 'wechat-pay'],
				frameworkDetail: 'Vue 3 + Element Plus',
				notes: 'SPA，接口全部 /api/v1',
			}),
		);
		expect(r.parseError).toBe(false);
		expect(r.rendering).toBe('csr');
		expect(r.apiStyle).toBe('rest');
		expect(r.authMechanism).toBe('jwt');
		expect(r.thirdParty).toHaveLength(2);
		expect(r.frameworkDetail).toContain('Vue');
	});

	it('非法枚举值回退 null，大小写归一化', () => {
		const r = parseArchAnalysisResponse(
			JSON.stringify({
				rendering: 'CSR',
				apiStyle: 'soap',
				authMechanism: 'quantum',
				thirdParty: 'not-array',
				frameworkDetail: '',
				notes: '',
			}),
		);
		expect(r.rendering).toBe('csr');
		expect(r.apiStyle).toBeNull();
		expect(r.authMechanism).toBeNull();
		expect(r.thirdParty).toEqual([]);
	});

	it('解析失败返回空兜底', () => {
		const r = parseArchAnalysisResponse('garbage');
		expect(r.parseError).toBe(true);
		expect(r.rendering).toBeNull();
	});
});
