import { beforeEach, describe, expect, it } from 'vitest';
import { parseSourceAuditResponse } from '../../src/recon/pipeline/source_audit.js';
import { extractJsonContent } from '../../src/recon/scoring/llm_client.js';
import {
	parseLlmJsEndpoints,
	resetLlmJsExtractState,
	shouldExtractByLlm,
} from '../../src/recon/scoring/llm_js_extract.js';
import { parseTechDetectResponse } from '../../src/recon/scoring/llm_tech_detect.js';

describe('extractJsonContent', () => {
	it('普通 JSON 原样返回', () => {
		expect(extractJsonContent('{"a":1}')).toBe('{"a":1}');
	});

	it('剥离 ```json 代码块', () => {
		expect(extractJsonContent('```json\n{"a":1}\n```')).toBe('{"a":1}');
	});
});

describe('parseTechDetectResponse', () => {
	it('标准响应', () => {
		const r = parseTechDetectResponse(
			JSON.stringify({
				framework: ['angularjs', 'bootstrap'],
				language: ['php'],
				buildTool: ['webpack'],
				architecture: 'mpa',
				reasoning: 'ng-app 挂载点',
			}),
		);
		expect(r.framework).toEqual(['angularjs', 'bootstrap']);
		expect(r.language).toEqual(['php']);
		expect(r.buildTool).toEqual(['webpack']);
		expect(r.architecture).toBe('mpa');
	});

	it('非法架构回退 null，非法字段丢弃', () => {
		const r = parseTechDetectResponse(
			JSON.stringify({
				framework: ['vue', 42],
				language: [],
				buildTool: [],
				architecture: 'quantum',
				reasoning: '',
			}),
		);
		expect(r.framework).toEqual(['vue']);
		expect(r.architecture).toBeNull();
	});

	it('解析失败返回空兜底', () => {
		const r = parseTechDetectResponse('not json at all');
		expect(r.framework).toEqual([]);
		expect(r.architecture).toBeNull();
	});

	it('大小写归一化', () => {
		const r = parseTechDetectResponse(
			JSON.stringify({
				framework: ['Vue'],
				language: ['PHP'],
				buildTool: ['Webpack'],
				architecture: 'SPA',
				reasoning: '',
			}),
		);
		expect(r.framework).toEqual(['vue']);
		expect(r.language).toEqual(['php']);
		expect(r.architecture).toBe('spa');
	});
});

describe('shouldExtractByLlm / parseLlmJsEndpoints', () => {
	beforeEach(() => resetLlmJsExtractState());

	it('正则命中 ≥3 不触发', () => {
		expect(shouldExtractByLlm({ ruleHitCount: 3, contentLength: 10_000 })).toBe(false);
	});

	it('文件太小/太大不触发', () => {
		expect(shouldExtractByLlm({ ruleHitCount: 0, contentLength: 500 })).toBe(false);
		expect(shouldExtractByLlm({ ruleHitCount: 0, contentLength: 500_000 })).toBe(false);
	});

	it('适中文件 + 正则少 → 触发', () => {
		expect(shouldExtractByLlm({ ruleHitCount: 1, contentLength: 50_000 })).toBe(true);
	});

	it('解析 endpoints：路径规范化 + 排除静态资源', () => {
		const r = parseLlmJsEndpoints(
			JSON.stringify({
				endpoints: [
					{ path: '/api/v1/login', method: 'post', params: ['name'] },
					{ path: '/static/app.js', method: 'GET', params: [] },
					{ path: '/api/users/123', method: 'get', params: [] },
				],
			}),
		);
		expect(r).toHaveLength(2);
		expect(r[0]).toEqual({ path: '/api/v1/login', method: 'POST', params: ['name'] });
		expect(r[1].method).toBe('GET');
	});

	it('解析失败返回空数组', () => {
		expect(parseLlmJsEndpoints('garbage')).toEqual([]);
	});
});

describe('parseSourceAuditResponse', () => {
	it('标准响应解析', () => {
		const r = parseSourceAuditResponse(
			JSON.stringify({
				highValueFindings: [
					{
						type: 'hardcoded_secret',
						severity: 'critical',
						detail: 'AWS Key 硬编码',
						evidence: 'src/config/aws.ts',
						suggestedNext: ['验证 Key 有效性'],
					},
					{
						type: 'admin_endpoint',
						severity: 'high',
						detail: '发现后台接口',
						evidence: 'src/api/admin.ts',
						suggestedNext: [],
					},
					{ detail: '没有 severity 的项' },
				],
				attackSurfaceMap: { admin: ['/api/admin/login'], user: ['/api/users'] },
				techStack: ['React 18', 'TypeScript'],
				recommendations: ['优先验证 AWS Key'],
			}),
		);
		expect(r.highValueFindings).toHaveLength(3);
		expect(r.highValueFindings[0].severity).toBe('critical');
		expect(r.highValueFindings[0].suggestedNext).toEqual(['验证 Key 有效性']);
		expect(r.highValueFindings[1].severity).toBe('high');
		expect(r.highValueFindings[2].severity).toBe('medium'); // 默认
		expect(r.attackSurfaceMap.admin).toEqual(['/api/admin/login']);
		expect(r.techStack).toEqual(['React 18', 'TypeScript']);
		expect(r.recommendations).toHaveLength(1);
	});

	it('解析失败返回空兜底', () => {
		const r = parseSourceAuditResponse('not json');
		expect(r.highValueFindings).toEqual([]);
		expect(r.attackSurfaceMap).toEqual({});
	});
});
