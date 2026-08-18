/**
 * M2 安全层测试：Scope Gate 越权拦截（不依赖真实 PG，mock 最小依赖）。
 *
 * buildScopeGateChecker 依赖 getConfig（读 config.agent.scope + scopeGate.allowed）。
 * 测试通过真实 config 单例 + 显式 scope 参数验证拦截逻辑。
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resetConfigForTest } from '../src/recon/config.js';
import { buildScopeGateChecker } from '../src/security/gate.js';

/** 构造 pi BeforeToolCallContext 的最小形态 */
function ctx(toolName: string, args: Record<string, unknown>) {
	return { toolCall: { name: toolName }, args } as never;
}

beforeEach(() => {
	resetConfigForTest();
	process.env.DEEPSEEK_API_KEY = 'test-key';
	process.env.CKFINDER_SCOPE = '';
	process.env.SCOPE_ALLOWED = '';
});

afterEach(() => {
	resetConfigForTest();
});

describe('Scope Gate（M2）', () => {
	it('web_fetch 目标在授权域名内 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['example.com'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'https://api.example.com/login' }));
		expect(result).toBeUndefined();
	});

	it('web_fetch 泛域名 *.example.com 匹配子域 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['*.example.com'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'https://deep.example.com' }));
		expect(result).toBeUndefined();
	});

	it('web_fetch 目标越权（不在范围）→ 拦截 block=true', async () => {
		const gate = buildScopeGateChecker({ scope: ['example.com'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'https://evil.com/admin' }));
		expect(result).toBeDefined();
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain('不在授权范围');
	});

	it('未设置范围 → fail-closed 拦截', async () => {
		const gate = buildScopeGateChecker({ scope: [], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'https://example.com' }));
		expect(result?.block).toBe(true);
		expect(result?.reason).toContain('未设置授权范围');
	});

	it('IP 授权命中 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['1.2.3.4'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'http://1.2.3.4:8080/status' }));
		expect(result).toBeUndefined();
	});

	it('CIDR 授权命中 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['10.0.0.0/8'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'http://10.1.2.3/x' }));
		expect(result).toBeUndefined();
	});

	it('保留/内网地址即使显式列入域名也拒绝（SSRF 面）', async () => {
		const gate = buildScopeGateChecker({ scope: ['localhost'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'http://127.0.0.1:9200/' }));
		expect(result?.block).toBe(true);
	});

	it('recon_* 只读工具不校验目标 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['example.com'], forceEnabled: true });
		const result = await gate(ctx('recon_assets', { minScore: 60 }));
		expect(result).toBeUndefined();
	});

	it('解析失败的目标 → 拦截', async () => {
		const gate = buildScopeGateChecker({ scope: ['example.com'], forceEnabled: true });
		const result = await gate(ctx('web_fetch', { url: 'not-a-url' }));
		expect(result?.block).toBe(true);
	});

	// ---- M3 验证工具 ----
	it('http_req 越权目标 → 拦截', async () => {
		const gate = buildScopeGateChecker({ scope: ['192.0.2.10'], forceEnabled: true });
		const result = await gate(ctx('http_req', { url: 'http://evil.com:8080/admin' }));
		expect(result?.block).toBe(true);
	});

	it('http_req 授权 IP（多端口）→ 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['192.0.2.10'], forceEnabled: true });
		const result = await gate(ctx('http_req', { url: 'http://192.0.2.10:8082/login' }));
		expect(result).toBeUndefined();
	});

	it('nuclei_scan 授权目标 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['192.0.2.10'], forceEnabled: true });
		const result = await gate(ctx('nuclei_scan', { target: 'http://192.0.2.10:8080/' }));
		expect(result).toBeUndefined();
	});

	it('sqlmap_run 越权目标 → 拦截', async () => {
		const gate = buildScopeGateChecker({ scope: ['192.0.2.10'], forceEnabled: true });
		const result = await gate(ctx('sqlmap_run', { url: 'http://other.net/x?id=1' }));
		expect(result?.block).toBe(true);
	});

	it('auth_brute 授权登录接口 → 放行', async () => {
		const gate = buildScopeGateChecker({ scope: ['192.0.2.10'], forceEnabled: true });
		const result = await gate(ctx('auth_brute', { url: 'http://192.0.2.10:8082/login' }));
		expect(result).toBeUndefined();
	});

	it('dir_brute 越权目标 → 拦截', async () => {
		const gate = buildScopeGateChecker({ scope: ['192.0.2.10'], forceEnabled: true });
		const result = await gate(ctx('dir_brute', { url: 'http://119.3.154.80:80/' }));
		expect(result?.block).toBe(true);
	});
});
