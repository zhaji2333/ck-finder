import { describe, expect, it } from 'vitest';
import {
	type TaskGateResult,
	type TechProfile,
	adjustByTechProfile,
	computeTaskGate,
} from '../../src/recon/gate/task_gate.js';

const emptyProfile: TechProfile = {
	fingerprints: [],
	tech: [],
	framework: [],
	architecture: null,
	webpackDetected: false,
	sourceAvailable: false,
	isApi: false,
};

/** 构造一个 L2 基础门控（无技术画像调整前） */
function l2Gate(): TaskGateResult {
	return computeTaskGate({ score: 70, role: 'business', hardToAttack: false, vulnHintCount: 0 });
}

describe('adjustByTechProfile', () => {
	it('无技术信号时保持原任务', () => {
		const gate = adjustByTechProfile(l2Gate(), emptyProfile);
		expect(gate.suggestedNext.sort()).toEqual([
			'dirscan',
			'history_url',
			'jsmining',
			'source_collect',
		]);
		expect(gate.reason).not.toContain('SPA');
	});

	it('SPA 站（vue）保证 jsmining + source_collect，即使 L1', () => {
		const l1 = computeTaskGate({
			score: 50,
			role: 'business',
			hardToAttack: false,
			vulnHintCount: 0,
		});
		const gate = adjustByTechProfile(l1, {
			...emptyProfile,
			framework: ['vue'],
			architecture: 'spa',
			webpackDetected: true,
		});
		expect(gate.suggestedNext).toContain('jsmining');
		expect(gate.suggestedNext).toContain('source_collect');
		expect(gate.reason).toContain('SPA');
	});

	it('CMS 站（wordpress）+ CDN/WAF 减半后补回 dirscan + history_url', () => {
		// CDN+WAF 会把任务减半成仅 history_url（无 dirscan）
		const halved = computeTaskGate({
			score: 70,
			role: 'business',
			hardToAttack: true,
			vulnHintCount: 0,
		});
		expect(halved.suggestedNext).toEqual(['history_url']);
		const gate = adjustByTechProfile(halved, {
			...emptyProfile,
			fingerprints: ['wordpress'],
		});
		expect(gate.suggestedNext).toContain('dirscan');
		expect(gate.suggestedNext).toContain('history_url');
		expect(gate.reason).toContain('CMS');
	});

	it('sourcemap 可用 → 强制 source_collect', () => {
		// L1 本无 source_collect
		const l1 = computeTaskGate({
			score: 50,
			role: 'business',
			hardToAttack: false,
			vulnHintCount: 0,
		});
		const gate = adjustByTechProfile(l1, {
			...emptyProfile,
			sourceAvailable: true,
		});
		expect(gate.suggestedNext).toContain('source_collect');
		expect(gate.reason).toContain('source_collect');
	});

	it('API 站 → 保证 jsmining', () => {
		const l1 = computeTaskGate({
			score: 50,
			role: 'business',
			hardToAttack: false,
			vulnHintCount: 0,
		});
		const gate = adjustByTechProfile(l1, { ...emptyProfile, isApi: true });
		expect(gate.suggestedNext).toContain('jsmining');
	});

	it('纯静态站（无技术信号）L1 剪枝为 L0', () => {
		const l1 = computeTaskGate({
			score: 50,
			role: 'static',
			hardToAttack: false,
			vulnHintCount: 0,
		});
		const gate = adjustByTechProfile(l1, { ...emptyProfile, architecture: 'static' });
		expect(gate.level).toBe('L0');
		expect(gate.suggestedNext).toEqual([]);
	});

	it('L0 直接返回不调整', () => {
		const l0 = computeTaskGate({
			score: 10,
			role: 'business',
			hardToAttack: false,
			vulnHintCount: 0,
		});
		const gate = adjustByTechProfile(l0, { ...emptyProfile, sourceAvailable: true });
		expect(gate).toBe(l0);
	});
});
