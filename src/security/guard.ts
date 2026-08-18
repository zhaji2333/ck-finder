/**
 * 安全 guard（M3.8/M3.10）：全局安全红线 R1-R5 + 低价值动作拦截
 *
 * 借鉴 AutoHunter guard.py 企业红线 + _low_value_shell_reason：
 *   - 数据破坏/修改/脱库（R1/R2/R3）→ 硬拦截
 *   - 密码/后门/压测（R3）→ 硬拦截
 *   - 低价值动作（宽端口 nmap/无模板 nuclei/泛爆破/sleep）→ 拦截
 *
 * 被拦截写 audit_log（decision=deny, fail-closed），不静默。
 * 用于 run_shell / sqlmap / nuclei 等任意命令执行前校验。
 */
import { auditLog } from '../recon/gate/audit_log.js';

/** 数据修改/删除/脱库红线（R1/R2）——硬拦截 */
const DATA_DESTRUCTION_PATTERNS: RegExp[] = [
	// 数据库破坏
	/\b(DROP|TRUNCATE|DELETE FROM|INSERT INTO|UPDATE\s+\w+\s+SET)\b/i,
	// 密码/后门
	/\b(passwd|chpasswd|set\s+password)\b/,
	/(冰蝎|哥斯拉|weevely|webshell|一句话木马)/i,
	/\bcrontab\s+-\s*e\b/,
	// 破坏性系统命令（R3）
	/\brm\s+-rf\s+\//,
	/\bmkfs\.|dd\s+if=.*of=\/dev\//,
	/\bshutdown\b|\breboot\b|\bpoweroff\b/,
	/\bsystemctl\s+(stop|disable)\s+(redis|postgresql|mysql)\b/,
	/\bkillall\b/,
	// 压测/大爆破（R3）
	/\b(ab|wrk|siege|hydra|medusa)\b/,
	/rockyou/,
];

/** sqlmap 脱库/写入（R2）——硬拦截 */
const SQLMAP_BANNED_ARGS = [
	'--dump',
	'--dump-all',
	'--os-shell',
	'--os-cmd',
	'--file-write',
	'--file-read',
	'--sql-shell',
	'--sql-query',
];

/** 低价值动作（AutoHunter _low_value_shell_reason 借鉴） */
const LOW_VALUE_PATTERNS: RegExp[] = [
	// 宽端口 nmap
	/nmap.*-(p\s*-|p\s*1-|p\s*0-|p-)/,
	/nmap.*(--top-ports\s+1\d{2,})/,
	// 无模板 nuclei（泛扫，无 -t/-tags/-id）
	/nuclei(?!.*-(t|tags|id)\s)/,
	// 泛目录爆破（dirsearch/ffuf/gobuster/feroxbuster，无高价值词）
	/(dirsearch|ffuf|gobuster|feroxbuster).*(?!.*(api|swagger|actuator))/,
	// 长 sleep
	/sleep\s+([3-9]\d|\d{3,})/,
	// 大字典爆破
	/-w\s+\/usr\/share\/wordlists\/rockyou/,
];

export interface GuardResult {
	allowed: boolean;
	reason?: string;
}

/** 命令级校验（run_shell 用）：红线 + 低价值 */
export function guardCommand(command: string): GuardResult {
	// 红线（R1-R3）
	for (const re of DATA_DESTRUCTION_PATTERNS) {
		if (re.test(command)) {
			return { allowed: false, reason: `安全红线拦截（数据修改/删除/破坏性）: ${re}` };
		}
	}
	// 低价值动作
	for (const re of LOW_VALUE_PATTERNS) {
		if (re.test(command)) {
			return { allowed: false, reason: `低价值动作拦截: ${re}` };
		}
	}
	return { allowed: true };
}

/** 工具参数级校验（sqlmap/nuclei 适配器用） */
export function guardToolArgs(tool: string, args: string[]): GuardResult {
	const joined = args.join(' ');
	if (tool === 'sqlmap') {
		for (const banned of SQLMAP_BANNED_ARGS) {
			if (args.some((a) => a === banned || a.startsWith(banned))) {
				return {
					allowed: false,
					reason: `sqlmap 红线拦截（${banned}：禁止脱库/写文件/系统命令，仅存在性验证）`,
				};
			}
		}
	}
	if (tool === 'nuclei') {
		// 无模板选择（-t/-tags/-id）→ 低价值泛扫拦截
		if (!args.some((a) => a === '-t' || a === '-tags' || a === '-id')) {
			return { allowed: false, reason: 'nuclei 泛扫拦截（须指定 -t/-tags/-id 模板选择）' };
		}
	}
	void joined;
	return { allowed: true };
}

/** 拦截并写审计（fail-closed） */
export async function guardAndAudit(
	tool: string,
	target: string | null,
	reason: string,
): Promise<void> {
	await auditLog({
		actor: `guard:${tool}`,
		action: 'scope_decision',
		target: target ?? 'n/a',
		decision: 'deny',
		reason: `安全 guard 拦截: ${reason}`,
		meta: { guard: true, failClosed: true },
	});
}
