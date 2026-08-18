/**
 * 爆破工具（M3）：目录爆破（低危自动放行）+ 弱口令尝试（授权内护栏放行 / 越权 fail-closed）
 *
 * 安全设计（防锁账号 + 越权护栏）：
 *   - dir_brute：复用 dirsearch（默认字典自动放行 + executor 全局限速）
 *   - auth_brute：
 *       * 目标在授权 scope → 放行，但带护栏：Top20 弱口令 + 每账号 ≤3 次 + 总尝试 ≤50 + 间隔限速
 *       * 目标不在授权 scope → fail-closed deny + 审计
 *       * 每账号超过次数限制 → 停止该账号（防锁）
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';
import { auditLog } from '../recon/gate/audit_log.js';
import { type DirsearchOptions, runDirsearch } from '../recon/tools/dirsearch.js';
import { hostInScopeSync } from '../security/scope_util.js';

// ---------------------------------------------------------------------------
// 弱口令字典（Top 常用，防锁护栏：默认不覆盖每账号 3 次限制）
// ---------------------------------------------------------------------------

const WEAK_PASSWORDS = [
	'123456',
	'password',
	'admin',
	'12345678',
	'123456789',
	'1234',
	'12345',
	'qwerty',
	'abc123',
	'111111',
	'admin123',
	'root',
	'test',
	'123123',
	'1q2w3e4r',
	'admin888',
	'1234567',
	'654321',
	'password123',
	'000000',
];

const DEFAULT_ACCOUNTS = ['admin', 'root', 'test'];

// ---------------------------------------------------------------------------
// dir_brute —— 目录爆破（低危，默认自动放行）
// ---------------------------------------------------------------------------

const dirBruteParams = Type.Object({
	url: Type.String({ description: '目标 URL（目录爆破的基准 URL），如 http://192.0.2.10:8080/' }),
	wordlist: Type.Optional(
		Type.String({
			description: '自定义字典路径（高危，走审批；默认用 dirsearch 自带字典自动放行）',
		}),
	),
	timeoutMs: Type.Optional(
		Type.Integer({ description: '超时毫秒，默认 5 分钟', minimum: 30_000, maximum: 20 * 60_000 }),
	),
});

export interface DirBruteDetails {
	total: number;
	found: Array<{ path: string; status: number }>;
}

export const dirBruteTool: AgentTool<typeof dirBruteParams, DirBruteDetails> = {
	name: 'dir_brute',
	label: '目录爆破',
	description:
		'对目标 URL 做目录爆破（dirsearch），发现隐藏路径/管理后台/备份文件等。低危操作（默认字典 + 限速自动放行）。\n' +
		'配合 file-handling / cloud-infra-supply-chain 技能使用。受授权范围约束。',
	parameters: dirBruteParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<DirBruteDetails>> => {
		const opts: DirsearchOptions = {
			url: params.url,
			timeoutMs: params.timeoutMs ?? 5 * 60 * 1000,
		};
		// 显式大字典 → 高危（走审批门），默认自动放行
		if (params.wordlist) {
			opts.wordlist = params.wordlist;
		}
		const records = await runDirsearch(opts);
		const found = records
			.filter((r) => r.status >= 200 && r.status < 400)
			.map((r) => ({ path: r.path, status: r.status }));
		return {
			content: [
				{
					type: 'text',
					text:
						found.length > 0
							? `目录爆破发现 ${found.length} 个路径:\n${found.map((f) => `  ${f.status} ${f.path}`).join('\n')}`
							: `目录爆破完成，未发现有效路径（共探测 ${records.length} 个）`,
				},
			],
			details: { total: records.length, found },
		};
	},
};

// ---------------------------------------------------------------------------
// auth_brute —— 弱口令尝试（授权内护栏放行 / 越权 fail-closed）
// ---------------------------------------------------------------------------

const authBruteParams = Type.Object({
	url: Type.String({ description: '登录接口 URL（POST），如 http://192.0.2.10:8082/login.php' }),
	userParam: Type.String({ description: '用户名参数名，如 username / user / name' }),
	passParam: Type.String({ description: '密码参数名，如 password / pass / pwd' }),
	// 可选：指定账号列表（不指定默认 admin/root/test）
	accounts: Type.Optional(
		Type.Array(Type.String(), {
			description: '待尝试的账号（默认 admin/root/test，每账号最多 3 个口令）',
		}),
	),
	successKeyword: Type.Optional(
		Type.String({
			description: '登录成功标识（响应含此关键词才判定成功），如 "dashboard" 或 "success"',
		}),
	),
});

export interface AuthBruteDetails {
	total: number;
	attempts: number;
	success: Array<{ account: string; password: string }>;
	blocked: boolean;
	reason?: string;
}

/** 从登录页 URL 提取 host 供 scope 校验 */
function hostOf(url: string): string | null {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return null;
	}
}

export const authBruteTool: AgentTool<typeof authBruteParams, AuthBruteDetails> = {
	name: 'auth_brute',
	label: '弱口令尝试',
	description:
		'对登录接口尝试弱口令（Top20 常用口令 + 每账号≤3 次 + 总≤50 + 间隔限速，防锁账号）。\n' +
		'仅允许对授权范围内目标执行；越权目标直接拒绝（fail-closed）。\n' +
		'配合 auth-access-control 技能使用。成功后可结合 http_req 携带会话 Cookie 进后台验证。',
	parameters: authBruteParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<AuthBruteDetails>> => {
		const host = hostOf(params.url);
		const inScope = host ? hostInScopeSync(host) : false;

		// 越权护栏：目标不在授权 scope → fail-closed deny
		if (!inScope) {
			await auditLog({
				actor: 'tool:auth_brute',
				action: 'scope_decision',
				target: params.url,
				decision: 'deny',
				reason: 'auth_brute 目标不在授权范围（fail-closed）',
			});
			return {
				content: [
					{
						type: 'text',
						text: `auth_brute 已拒绝：目标 ${params.url} 不在授权范围（fail-closed，未发起任何尝试）`,
					},
				],
				details: { total: 0, attempts: 0, success: [], blocked: true, reason: 'out of scope' },
			};
		}

		// 护栏：每账号 ≤3 口令 + 总尝试 ≤50
		const accounts = (
			params.accounts && params.accounts.length > 0 ? params.accounts : DEFAULT_ACCOUNTS
		).slice(0, 10);
		const perAccount = 3;
		const totalCap = 50;

		const success: Array<{ account: string; password: string }> = [];
		let attempts = 0;

		for (const account of accounts) {
			if (attempts >= totalCap) break;
			let acctAttempts = 0;
			for (const password of WEAK_PASSWORDS) {
				if (acctAttempts >= perAccount || attempts >= totalCap) break;
				attempts++;
				acctAttempts++;

				// 限速：间隔 800ms（防锁账号 + 防触发风控）
				await new Promise((r) => setTimeout(r, 800));

				const ok = await tryLogin(
					params.url,
					params.userParam,
					params.passParam,
					account,
					password,
					params.successKeyword,
				);
				if (ok) {
					success.push({ account, password });
					await auditLog({
						actor: 'tool:auth_brute',
						action: 'data_write',
						target: params.url,
						decision: 'pass',
						reason: `弱口令命中: ${account} / ${password}（授权范围内）`,
					});
					break; // 该账号命中即停，防继续尝试
				}
			}
		}

		return {
			content: [
				{
					type: 'text',
					text:
						success.length > 0
							? `弱口令命中 ${success.length} 个:\n${success.map((s) => `  ${s.account} / ${s.password}`).join('\n')}\n（共尝试 ${attempts} 次，均在授权范围内 + 防锁护栏内）`
							: `弱口令未命中（共尝试 ${attempts} 次，护栏：每账号≤3/总≤50/间隔限速）`,
				},
			],
			details: { total: accounts.length * perAccount, attempts, success, blocked: false },
		};
	},
};

/** 单次登录尝试（POST 表单） */
async function tryLogin(
	url: string,
	userParam: string,
	passParam: string,
	account: string,
	password: string,
	successKeyword?: string,
): Promise<boolean> {
	try {
		const body = new URLSearchParams();
		body.set(userParam, account);
		body.set(passParam, password);
		const resp = await fetch(url, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				'user-agent': 'ck-finder/0.3 (+authorized security testing)',
			},
			body: body.toString(),
			redirect: 'manual', // 登录成功常 302
			signal: AbortSignal.timeout(8000),
		});
		const text = await resp.text();
		const location = (resp.headers.get('location') ?? '').toLowerCase();
		// 成功判定（需显式成功信号，防假阳性——不能「任意 3xx 或任意 200」都算成功）：
		// 1) 3xx 且重定向目标不是登录/错误页（排除 /login?error=1 这种假成功）
		// 2) 响应含显式成功关键词（successKeyword 或 JSON success:true / token）
		// 3) 200 且下发了新会话 cookie（Set-Cookie，登录成功通常换发会话）
		if (resp.status >= 300 && resp.status < 400) {
			return !/(login|signin|error|fail|invalid|retry|denied)/.test(location);
		}
		if (successKeyword && text.includes(successKeyword)) return true;
		const lower = text.toLowerCase();
		if (
			lower.includes('"success":true') ||
			lower.includes('success":true') ||
			lower.includes('"token"')
		) {
			return true;
		}
		if (resp.status === 200 && resp.headers.get('set-cookie')) return true;
		return false;
	} catch {
		return false;
	}
}
