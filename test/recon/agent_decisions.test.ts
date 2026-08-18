import { describe, expect, it } from 'vitest';
import { parsePlannerDecision } from '../../src/recon/agents/llm_planner.js';
import { parseStopJudgeResponse } from '../../src/recon/agents/llm_stop_judge.js';
import { isHighRiskAction } from '../../src/recon/gate/llm_judge.js';
import { parseTaskSelectResponse } from '../../src/recon/scoring/llm_task_select.js';
import { normalizeSeed } from '../../src/recon/seeds/normalizer.js';

// =============================================================================
// 决策点 1：Planner 解析 + 范围护栏
// =============================================================================

describe('parsePlannerDecision', () => {
	const urlSeed = normalizeSeed('https://example.com/login');

	it('标准决策解析', () => {
		const { decision, parseError } = parsePlannerDecision(
			JSON.stringify({
				mode: 'full',
				options: { skipNmap: true, maxSubdomains: 500, ports: '80,443' },
				deepScanLevel: 'l2',
				reasoning: '业务站值得深挖',
			}),
			{
				seed: urlSeed,
				defaults: { maxSubdomains: 1000, maxCompanyDomains: 50, skipNmap: false, skipHttpx: false },
				hasHistory: false,
			},
		);
		expect(parseError).toBe(false);
		expect(decision.mode).toBe('site'); // URL 种子 full → 护栏改 site
		expect(decision.options.skipNmap).toBe(true);
		expect(decision.options.maxSubdomains).toBe(500);
		expect(decision.options.ports).toBe('80,443');
		expect(decision.deepScanLevel).toBe('l2');
		expect(decision.guardNotes.length).toBeGreaterThan(0);
	});

	it('URL 种子建议 full 被护栏拦截为 site', () => {
		const { decision } = parsePlannerDecision(
			JSON.stringify({ mode: 'full', options: {}, deepScanLevel: 'none', reasoning: '' }),
			{
				seed: urlSeed,
				defaults: { maxSubdomains: 1000, maxCompanyDomains: 50, skipNmap: false, skipHttpx: false },
				hasHistory: false,
			},
		);
		expect(decision.mode).toBe('site');
		expect(decision.guardNotes.some((g) => g.includes('护栏'))).toBe(true);
	});

	it('域名种子可建议 full', () => {
		const domainSeed = normalizeSeed('example.com');
		const { decision } = parsePlannerDecision(
			JSON.stringify({ mode: 'full', options: {}, deepScanLevel: 'l1', reasoning: '' }),
			{
				seed: domainSeed,
				defaults: { maxSubdomains: 1000, maxCompanyDomains: 50, skipNmap: false, skipHttpx: false },
				hasHistory: false,
			},
		);
		expect(decision.mode).toBe('full');
	});

	it('maxSubdomains 越界被 clamp 到 [50, 2000]', () => {
		const domainSeed = normalizeSeed('example.com');
		const { decision } = parsePlannerDecision(
			JSON.stringify({
				mode: null,
				options: { maxSubdomains: 99999 },
				deepScanLevel: 'none',
				reasoning: '',
			}),
			{
				seed: domainSeed,
				defaults: { maxSubdomains: 1000, maxCompanyDomains: 50, skipNmap: false, skipHttpx: false },
				hasHistory: false,
			},
		);
		expect(decision.options.maxSubdomains).toBe(2000);
	});

	it('非法 JSON 返回 parseError 兜底', () => {
		const { parseError } = parsePlannerDecision('garbage', {
			seed: urlSeed,
			defaults: { maxSubdomains: 1000, maxCompanyDomains: 50, skipNmap: false, skipHttpx: false },
			hasHistory: false,
		});
		expect(parseError).toBe(true);
	});
});

// =============================================================================
// 决策点 2：任务选择解析（只增不减语义在 pipeline 侧）
// =============================================================================

describe('parseTaskSelectResponse', () => {
	it('标准响应：addTasks 过滤非法任务名', () => {
		const r = parseTaskSelectResponse(
			JSON.stringify({
				addTasks: ['jsmining', 'dirscan', 'not_a_task', 'source_collect'],
				removeTasks: ['history_url'],
				reasoning: 'API 站',
			}),
		);
		expect(r.addTasks).toEqual(['jsmining', 'dirscan', 'source_collect']);
		expect(r.removeTasks).toEqual(['history_url']);
		expect(r.parseError).toBe(false);
	});

	it('大小写归一化', () => {
		const r = parseTaskSelectResponse(
			JSON.stringify({ addTasks: ['JSMINING'], removeTasks: [], reasoning: '' }),
		);
		expect(r.addTasks).toEqual(['jsmining']);
	});

	it('非法 JSON 返回空兜底', () => {
		const r = parseTaskSelectResponse('not json');
		expect(r.addTasks).toEqual([]);
		expect(r.parseError).toBe(true);
	});
});

// =============================================================================
// 决策点 3：高危动作清单
// =============================================================================

describe('HIGH_RISK_ACTIONS', () => {
	it('高危动作识别', () => {
		expect(isHighRiskAction('nmap_sv_scan')).toBe(true);
		expect(isHighRiskAction('nmap_udp_scan')).toBe(true);
		expect(isHighRiskAction('dirsearch_brute')).toBe(true);
		expect(isHighRiskAction('port_scan_high_rate')).toBe(true);
	});

	it('非高危动作放行', () => {
		expect(isHighRiskAction('httpx_probe')).toBe(false);
		expect(isHighRiskAction('subfinder_query')).toBe(false);
	});
});

// =============================================================================
// 决策点 4：停止/继续判断解析
// =============================================================================

describe('parseStopJudgeResponse', () => {
	it('继续 + 合法任务', () => {
		const r = parseStopJudgeResponse(
			JSON.stringify({ continueDeep: true, suggestedNext: 'jsmining', reasoning: '有JS无接口' }),
		);
		expect(r.continueDeep).toBe(true);
		expect(r.suggestedNext).toBe('jsmining');
		expect(r.parseError).toBe(false);
	});

	it('不继续', () => {
		const r = parseStopJudgeResponse(
			JSON.stringify({ continueDeep: false, suggestedNext: null, reasoning: '已够用' }),
		);
		expect(r.continueDeep).toBe(false);
		expect(r.suggestedNext).toBeNull();
	});

	it('非法任务名 → null', () => {
		const r = parseStopJudgeResponse(
			JSON.stringify({ continueDeep: true, suggestedNext: 'sql_injection', reasoning: '' }),
		);
		expect(r.suggestedNext).toBeNull();
	});

	it('非法 JSON 兜底为不继续', () => {
		const r = parseStopJudgeResponse('garbage');
		expect(r.continueDeep).toBe(false);
		expect(r.parseError).toBe(true);
	});
});
