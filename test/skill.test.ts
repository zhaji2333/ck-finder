/**
 * skill_load 工具测试：白名单 + 内容读取。
 */
import { describe, expect, it } from 'vitest';
import { SKILL_NAMES, skillLoadTool } from '../src/tools/skill.js';

describe('skill_load', () => {
	it('白名单包含 14 个技能', () => {
		expect(SKILL_NAMES).toHaveLength(14);
		expect(SKILL_NAMES).toContain('injection-vulns');
		expect(SKILL_NAMES).toContain('auth-access-control');
		expect(SKILL_NAMES).toContain('recon-js-analysis');
	});

	it('加载合法技能返回全文', async () => {
		const res = await skillLoadTool.execute(
			'call-1',
			{ skill: 'injection-vulns' },
			undefined,
			undefined,
		);
		const text = res.content.find((c) => c.type === 'text')?.text ?? '';
		expect(text).toContain('injection-vulns');
		expect(text).toContain('SQL');
		expect(res.details.lines).toBeGreaterThan(50);
	});

	it('非白名单技能被拒绝', async () => {
		await expect(
			skillLoadTool.execute('call-2', { skill: '../../etc/passwd' }, undefined, undefined),
		).rejects.toThrow('未知技能');
	});

	it('每个白名单技能文件都存在且可读', async () => {
		for (const name of SKILL_NAMES) {
			const res = await skillLoadTool.execute('call-x', { skill: name }, undefined, undefined);
			const text = res.content.find((c) => c.type === 'text')?.text ?? '';
			expect(text).toContain(name);
		}
	});
});
