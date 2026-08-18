/**
 * provider 派生视图测试（合并后：本地查询层 → Agent 消费视图）
 */
import { describe, expect, it } from 'vitest';
import { type ReconProviderAssetsParams, toWebappView } from '../src/recon/provider.js';

describe('toWebappView 派生视图（Agent 排序/决策字段）', () => {
	const base = {
		assetId: 'w1',
		url: 'https://admin.example.com',
		title: null,
		statusCode: 200,
		tech: ['react', 'webpack'],
		host: 'admin.example.com',
		port: 443,
		webserver: 'nginx/1.24.0',
		cdn: false,
		waf: null,
		role: 'admin',
		score: 88,
		scoreBreakdown: [{ name: 'base', delta: 85, reason: '角色=admin 基础分' }],
		loginPage: true,
		hardToAttack: false,
		fingerprints: ['vue框架'],
		meta: {
			score_stage: 'final',
			task_level: 'L2',
			deep_scan_done: true,
			score_review: {
				from_llm: true,
				is_high_value: true,
				role_confirmed: true,
				score_adjustment: 0,
			},
			cve_hints: [{ component: 'fastjson', cve: 'CVE-2022-12345', severity: 'high' }],
		},
		findingCount: 3,
		findingTypes: ['secret', 'sensitive_path'],
		findingMaxSeverity: 'high',
		firstSeen: 't',
		lastSeen: 't',
	};

	it('解析完整行并提取派生视图', () => {
		const view = toWebappView(base as never);
		expect(view.score).toBe(88);
		expect(view.scoreStage).toBe('final');
		expect(view.isHighValue).toBe(true);
		expect(view.taskLevel).toBe('L2');
		expect(view.cveHints).toHaveLength(1);
		expect(view.findingMaxSeverity).toBe('high');
	});

	it('meta 缺失时派生字段为 null（不 crash）', () => {
		const view = toWebappView({ ...base, meta: {} } as never);
		expect(view.scoreStage).toBeNull();
		expect(view.isHighValue).toBeNull();
		expect(view.taskLevel).toBeNull();
		expect(view.cveHints).toEqual([]);
	});

	it('score_review 为 null 时 isHighValue 为 null', () => {
		const view = toWebappView({
			...base,
			meta: { score_review: null, score_stage: 'initial' },
		} as never);
		expect(view.isHighValue).toBeNull();
		expect(view.scoreStage).toBe('initial');
	});
});

describe('ReconProvider 参数类型（编译期约束）', () => {
	it('assets 参数接口形状正确', () => {
		const p: ReconProviderAssetsParams = { minScore: 60, limit: 50 };
		expect(p.minScore).toBe(60);
	});
});
