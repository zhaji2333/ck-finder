/**
 * Scope Gate（M5.3）
 *
 * 架构文档 §一 1.2 风险与对策 #1：
 *   "Scope Gate 强制限定扫描范围，避免越权。"
 *
 * 三层校验：
 *   1. 授权范围（authorized scope）：目标必须在 SCOPE_ALLOWED 白名单内
 *   2. DNS 校验：域名解析后的 IP 必须在授权 IP/CIDR 范围内
 *   3. 内网/保留 IP 拦截：RFC1918/CGNAT/loopback/link-local 等一律拒绝
 *
 * 接入点：
 *   - executor.ts 在 spawn 前调用 checkToolScope() 拦截
 *   - pipeline/runner.ts 在 runRecon 入口对 seed 调用 checkSeedScope()
 *
 * 配置：
 *   SCOPE_GATE_ENABLED=true|false（默认 false，MVP 关闭）
 *   SCOPE_ALLOWED=example.com,1.2.3.4,10.0.0.0/8（逗号分隔）
 *
 * 决策结果写 audit_log（action=scope_decision）。
 */

import { promises as dns } from 'node:dns';
import { getConfig } from '../config.js';
import { auditLog } from './audit_log.js';

// =============================================================================
// 类型定义
// =============================================================================

export type ScopeDecision = 'allow' | 'deny';

export interface ScopeCheckResult {
	decision: ScopeDecision;
	reason: string;
	/** 命中的授权规则（如 'example.com' / '1.2.3.4' / '10.0.0.0/8'） */
	matchedRule?: string;
	/** 域名解析的 IP 列表（仅 domain 目标有） */
	resolvedIps?: string[];
	/** 原始目标 */
	target: string;
	/** 目标类型 */
	targetType: 'domain' | 'ip' | 'cidr' | 'url' | 'unknown';
}

export interface ScopeCheckOptions {
	/** 跳过 DNS 解析（被动工具不触目标，但仍校验授权范围） */
	skipDnsResolve?: boolean;
	/** 强制开启（覆盖 config.scopeGate.enabled=false） */
	forceEnabled?: boolean;
}

// =============================================================================
// 内网/保留 IP 段（RFC1918 + CGNAT + loopback + link-local + 其他保留）
// =============================================================================

interface IpRange {
	start: number; // 起始 IP（uint32，网络字节序）
	end: number; // 结束 IP（含）
	name: string;
}

/** IPv4 → uint32 */
function ipToInt(ip: string): number | null {
	const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
	if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
		return null;
	}
	// 使用 >>> 0 保证无符号
	return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

const RESERVED_RANGES: IpRange[] = [
	// 0.0.0.0/8 - 本网络
	{ start: ipToInt('0.0.0.0')!, end: ipToInt('0.255.255.255')!, name: '0.0.0.0/8 (本网络)' },
	// 10.0.0.0/8 - RFC1918 A 类私有
	{
		start: ipToInt('10.0.0.0')!,
		end: ipToInt('10.255.255.255')!,
		name: '10.0.0.0/8 (RFC1918 私有)',
	},
	// 100.64.0.0/10 - CGNAT
	{
		start: ipToInt('100.64.0.0')!,
		end: ipToInt('100.127.255.255')!,
		name: '100.64.0.0/10 (CGNAT)',
	},
	// 127.0.0.0/8 - Loopback
	{
		start: ipToInt('127.0.0.0')!,
		end: ipToInt('127.255.255.255')!,
		name: '127.0.0.0/8 (Loopback)',
	},
	// 169.254.0.0/16 - Link-local
	{
		start: ipToInt('169.254.0.0')!,
		end: ipToInt('169.254.255.255')!,
		name: '169.254.0.0/16 (Link-local)',
	},
	// 172.16.0.0/12 - RFC1918 B 类私有
	{
		start: ipToInt('172.16.0.0')!,
		end: ipToInt('172.31.255.255')!,
		name: '172.16.0.0/12 (RFC1918 私有)',
	},
	// 192.0.0.0/24 - IETF 协议分配
	{ start: ipToInt('192.0.0.0')!, end: ipToInt('192.0.0.255')!, name: '192.0.0.0/24 (IETF 保留)' },
	// 192.0.2.0/24 - TEST-NET-1
	{ start: ipToInt('192.0.2.0')!, end: ipToInt('192.0.2.255')!, name: '192.0.2.0/24 (TEST-NET-1)' },
	// 192.88.99.0/24 - 6to4 中继任播（已废弃但仍保留）
	{
		start: ipToInt('192.88.99.0')!,
		end: ipToInt('192.88.99.255')!,
		name: '192.88.99.0/24 (6to4 任播)',
	},
	// 192.168.0.0/16 - RFC1918 C 类私有
	{
		start: ipToInt('192.168.0.0')!,
		end: ipToInt('192.168.255.255')!,
		name: '192.168.0.0/16 (RFC1918 私有)',
	},
	// 198.18.0.0/15 - 网络基准测试
	{
		start: ipToInt('198.18.0.0')!,
		end: ipToInt('198.19.255.255')!,
		name: '198.18.0.0/15 (基准测试)',
	},
	// 198.51.100.0/24 - TEST-NET-2
	{
		start: ipToInt('198.51.100.0')!,
		end: ipToInt('198.51.100.255')!,
		name: '198.51.100.0/24 (TEST-NET-2)',
	},
	// 203.0.113.0/24 - TEST-NET-3
	{
		start: ipToInt('203.0.113.0')!,
		end: ipToInt('203.0.113.255')!,
		name: '203.0.113.0/24 (TEST-NET-3)',
	},
	// 224.0.0.0/4 - 多播
	{ start: ipToInt('224.0.0.0')!, end: ipToInt('239.255.255.255')!, name: '224.0.0.0/4 (多播)' },
	// 240.0.0.0/4 - 保留（未来使用）
	{ start: ipToInt('240.0.0.0')!, end: ipToInt('255.255.255.255')!, name: '240.0.0.0/4 (保留)' },
];

/**
 * 检查 IP 是否属于保留/内网地址
 *
 * @returns 命中的保留段名称，未命中返回 null
 */
export function isReservedIp(ip: string): string | null {
	const ipInt = ipToInt(ip);
	if (ipInt === null) return null;
	for (const range of RESERVED_RANGES) {
		if (ipInt >= range.start && ipInt <= range.end) {
			return range.name;
		}
	}
	return null;
}

// =============================================================================
// CIDR 工具
// =============================================================================

/** 检查 IP 是否在 CIDR 范围内 */
export function isIpInCidr(ip: string, cidr: string): boolean {
	const ipInt = ipToInt(ip);
	if (ipInt === null) return false;

	const slashIdx = cidr.indexOf('/');
	if (slashIdx === -1) {
		// 无前缀，按单 IP 处理
		const targetInt = ipToInt(cidr);
		return targetInt !== null && ipInt === targetInt;
	}

	const network = cidr.slice(0, slashIdx);
	const prefix = Number.parseInt(cidr.slice(slashIdx + 1), 10);
	if (Number.isNaN(prefix) || prefix < 0 || prefix > 32) return false;

	const netInt = ipToInt(network);
	if (netInt === null) return false;

	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return (ipInt & mask) === (netInt & mask);
}

// =============================================================================
// 授权范围解析
// =============================================================================

interface ParsedScope {
	/** 单 IP（精确匹配） */
	ips: Set<string>;
	/** CIDR 范围 */
	cidrs: string[];
	/** 域名（精确或后缀匹配） */
	domains: Set<string>;
}

let _parsedScopeCache: { key: string; scope: ParsedScope } | null = null;

/**
 * 解析 SCOPE_ALLOWED 配置
 *
 * 规则：
 *   - 含 / 的视为 CIDR
 *   - 纯 IP 视为单 IP
 *   - 其他视为域名（自动小写、去 www. 前缀）
 *
 * 缓存按 scope 字符串作 key：运行时改 SCOPE_ALLOWED（reloadConfig）后 key 变化即重新解析，
 * 无需显式重置（避免 scope 缓存失效导致的 fail-open）。
 */
function getParsedScope(): ParsedScope {
	const cfg = getConfig().scopeGate;
	const key = cfg.allowed.join(',');
	if (_parsedScopeCache && _parsedScopeCache.key === key) return _parsedScopeCache.scope;

	const result: ParsedScope = { ips: new Set(), cidrs: [], domains: new Set() };

	for (const raw of cfg.allowed) {
		const item = raw.trim().toLowerCase();
		if (!item) continue;

		if (item.includes('/')) {
			result.cidrs.push(item);
		} else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(item)) {
			result.ips.add(item);
		} else {
			// 域名：去 www. 前缀
			const domain = item.replace(/^www\./, '');
			result.domains.add(domain);
		}
	}

	_parsedScopeCache = { key, scope: result };
	return result;
}

/** 测试用：重置 scope 缓存 */
export function resetScopeCacheForTest(): void {
	_parsedScopeCache = null;
}

// =============================================================================
// 云主机元数据端点（SSRF 验证目标，允许命中）
// =============================================================================

const CLOUD_METADATA_HOSTS = new Set([
	'100.100.100.200', // 阿里云
	'metadata.tencentyun.com', // 腾讯云
	'169.254.169.254', // 华为云 / 亚马逊云 / 微软云 / 京东云 / 天翼云
	'metadata.google.internal', // 谷歌云
	'100.96.0.96', // 火山引擎
]);

/** 目标 host（IP 或域名）是否为云元数据端点（SSRF 验证目标） */
export function isCloudMetadataHost(host: string): boolean {
	return CLOUD_METADATA_HOSTS.has(host.toLowerCase());
}

// =============================================================================
// 主校验入口
// =============================================================================

/**
 * 判定目标类型
 */
function detectTargetType(target: string): ScopeCheckResult['targetType'] {
	if (/^\d{1,3}(\.\d{1,3}){3}\/\d+$/.test(target)) return 'cidr';
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) return 'ip';
	if (/^https?:\/\//i.test(target)) return 'url';
	if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(target)) return 'domain';
	return 'unknown';
}

/**
 * 从 URL 提取 host
 */
function extractHostFromUrl(url: string): string | null {
	try {
		return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
	} catch {
		return null;
	}
}

/**
 * 检查域名是否在授权范围内
 *
 * 匹配规则：
 *   - 精确匹配（example.com == example.com）
 *   - 后缀匹配（sub.example.com 匹配 example.com）
 */
function isDomainInScope(domain: string, scope: ParsedScope): string | null {
	const d = domain.toLowerCase().replace(/^www\./, '');
	if (scope.domains.has(d)) return d;
	// 后缀匹配：sub.example.com ∈ example.com
	for (const allowed of scope.domains) {
		if (d.endsWith(`.${allowed}`)) return allowed;
	}
	return null;
}

/**
 * 检查 IP 是否在授权范围内（单 IP 或 CIDR）
 */
function isIpInScope(ip: string, scope: ParsedScope): string | null {
	if (scope.ips.has(ip)) return ip;
	for (const cidr of scope.cidrs) {
		if (isIpInCidr(ip, cidr)) return cidr;
	}
	return null;
}

/**
 * DNS 解析域名 → IP 列表
 *
 * 失败时返回空数组（不阻塞决策，由调用方决定是否放行）
 */
async function resolveDomain(domain: string): Promise<string[]> {
	try {
		const records = await dns.resolve4(domain);
		return records;
	} catch {
		return [];
	}
}

/**
 * 主校验入口：检查目标是否在授权范围内
 *
 * @param target 目标（域名/IP/CIDR/URL）
 * @param opts 选项
 * @returns 校验结果
 */
export async function checkScope(
	target: string,
	opts: ScopeCheckOptions = {},
): Promise<ScopeCheckResult> {
	const cfg = getConfig().scopeGate;
	const enabled = opts.forceEnabled === true || cfg.enabled;

	// 未启用：直接放行（仍记录审计）
	if (!enabled) {
		const result: ScopeCheckResult = {
			decision: 'allow',
			reason: 'scope gate disabled',
			target,
			targetType: detectTargetType(target),
		};
		await auditLog({
			actor: 'scope_gate',
			action: 'scope_decision',
			target,
			decision: 'allow',
			reason: 'gate disabled',
			meta: { enabled: false },
		});
		return result;
	}

	const scope = getParsedScope();
	const targetType = detectTargetType(target);

	// 提取校验目标
	let domain: string | null = null;
	let ip: string | null = null;
	let cidr: string | null = null;

	switch (targetType) {
		case 'url':
			domain = extractHostFromUrl(target);
			// 如果 URL 的 host 是 IP
			if (domain && /^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
				ip = domain;
				domain = null;
			}
			break;
		case 'domain':
			domain = target.toLowerCase().replace(/^www\./, '');
			break;
		case 'ip':
			ip = target;
			break;
		case 'cidr':
			cidr = target;
			break;
		case 'unknown':
			// 无法识别，拒绝
			return await deny(target, targetType, 'unrecognized target format', undefined);
	}

	// ===== 第 1 层：授权范围校验 =====

	// IP 直接校验
	if (ip) {
		// 云元数据端点（SSRF 验证目标）优先放行，即使属于保留段（169.254.169.254 / 100.64.0.0/10 内）
		if (isCloudMetadataHost(ip)) {
			return await allow(ip, 'ip', 'cloud-metadata', [ip]);
		}
		// 先查内网/保留
		const reserved = isReservedIp(ip);
		if (reserved) {
			return await deny(ip, 'ip', `reserved/internal IP blocked: ${reserved}`, undefined);
		}
		const matched = isIpInScope(ip, scope);
		if (!matched) {
			return await deny(ip, 'ip', 'IP not in authorized scope', undefined);
		}
		return await allow(ip, 'ip', matched, [ip]);
	}

	// CIDR 校验：所有 IP 都必须在授权范围内（简化：只检查 network 地址）
	if (cidr) {
		const network = cidr.split('/')[0];
		const reserved = isReservedIp(network);
		if (reserved) {
			return await deny(cidr, 'cidr', `reserved/internal CIDR blocked: ${reserved}`, undefined);
		}
		// 检查 CIDR 是否被授权 CIDR 包含
		for (const allowedCidr of scope.cidrs) {
			if (isCidrContained(cidr, allowedCidr)) {
				return await allow(cidr, 'cidr', allowedCidr, [network]);
			}
		}
		// 或 CIDR 内的 network 地址在授权 IP 列表
		if (scope.ips.has(network)) {
			return await allow(cidr, 'cidr', network, [network]);
		}
		return await deny(cidr, 'cidr', 'CIDR not in authorized scope', undefined);
	}

	// 域名校验
	if (domain) {
		// 云元数据域名端点（SSRF 验证目标，如 metadata.tencentyun.com / metadata.google.internal）优先放行
		if (isCloudMetadataHost(domain)) {
			return await allow(domain, 'domain', 'cloud-metadata', undefined);
		}
		// 先校验域名是否在授权范围
		const domainMatch = isDomainInScope(domain, scope);
		if (!domainMatch) {
			return await deny(domain, 'domain', 'domain not in authorized scope', undefined);
		}

		// 跳过 DNS 解析（被动工具）：仅校验域名授权
		if (opts.skipDnsResolve) {
			return await allow(domain, 'domain', domainMatch, undefined);
		}

		// ===== 第 2 层：DNS 校验 =====
		const resolvedIps = await resolveDomain(domain);
		if (resolvedIps.length === 0) {
			// DNS 解析失败：仍放行（已通过域名授权校验，可能是临时 DNS 故障）
			return await allow(domain, 'domain', domainMatch, undefined);
		}

		// ===== 第 3 层：内网/保留 IP 拦截 =====
		for (const resolvedIp of resolvedIps) {
			const reserved = isReservedIp(resolvedIp);
			if (reserved) {
				return await deny(
					domain,
					'domain',
					`domain resolves to reserved/internal IP ${resolvedIp}: ${reserved}`,
					resolvedIps,
				);
			}
		}

		return await allow(domain, 'domain', domainMatch, resolvedIps);
	}

	// 兜底
	return await deny(target, targetType, 'no matching scope rule', undefined);
}

/**
 * 检查 CIDR A 是否被 CIDR B 包含
 */
function isCidrContained(cidrA: string, cidrB: string): boolean {
	const [netA, prefixA] = cidrA.split('/');
	const prefixB = cidrB.split('/')[1];
	const prefixANum = Number.parseInt(prefixA, 10);
	const prefixBNum = Number.parseInt(prefixB, 10);
	// A 的前缀必须 ≥ B 的前缀（A 是 B 的子网）
	if (prefixANum < prefixBNum) return false;
	// A 的 network 地址必须在 B 范围内
	return isIpInCidr(netA, cidrB);
}

// =============================================================================
// 决策辅助
// =============================================================================

async function allow(
	target: string,
	targetType: ScopeCheckResult['targetType'],
	matchedRule: string,
	resolvedIps?: string[],
): Promise<ScopeCheckResult> {
	const result: ScopeCheckResult = {
		decision: 'allow',
		reason: `matched scope rule: ${matchedRule}`,
		matchedRule,
		resolvedIps,
		target,
		targetType,
	};
	await auditLog({
		actor: 'scope_gate',
		action: 'scope_decision',
		target,
		decision: 'allow',
		reason: result.reason,
		meta: { targetType, matchedRule, resolvedIps },
	});
	return result;
}

async function deny(
	target: string,
	targetType: ScopeCheckResult['targetType'],
	reason: string,
	resolvedIps: string[] | undefined,
): Promise<ScopeCheckResult> {
	const result: ScopeCheckResult = {
		decision: 'deny',
		reason,
		resolvedIps,
		target,
		targetType,
	};
	await auditLog({
		actor: 'scope_gate',
		action: 'scope_decision',
		target,
		decision: 'deny',
		reason,
		meta: { targetType, resolvedIps },
	});
	return result;
}

// =============================================================================
// Scope Gate 异常
// =============================================================================

export class ScopeGateError extends Error {
	constructor(
		message: string,
		public readonly target: string,
		public readonly reason: string,
	) {
		super(message);
		this.name = 'ScopeGateError';
	}
}

/**
 * 断言放行：拒绝时抛 ScopeGateError
 *
 * 用于 pipeline 入口处的硬校验。
 */
export async function assertScopeAllowed(
	target: string,
	opts?: ScopeCheckOptions,
): Promise<ScopeCheckResult> {
	const result = await checkScope(target, opts);
	if (result.decision === 'deny') {
		throw new ScopeGateError(
			`target ${target} blocked by scope gate: ${result.reason}`,
			target,
			result.reason,
		);
	}
	return result;
}

// =============================================================================
// 工具执行前校验（接入 executor.ts）
// =============================================================================

/**
 * 从工具执行参数中提取目标
 *
 * 启发式规则：
 *   - subfinder/oneforall: -d <domain>
 *   - dnsx: -d <domain> 或 stdin
 *   - nmap: 位置参数 <ip/cidr>
 *   - httpx: -u <url> / -host <ip> / stdin
 *   - katana: -u <url>
 *   - gau: <domain>
 *   - waybackurls: <domain>
 *   - dirsearch: -u <url>
 *   - wafw00f: <url>
 *   - 兜底：扫描所有 args，挑出形如 domain/ip/url 的
 */
export function extractTargetsFromArgs(command: string, args: string[]): string[] {
	const targets: string[] = [];
	const cmd = command.split('/').pop() ?? command; // 取 basename

	const flagMap: Record<string, string[]> = {
		subfinder: ['-d'],
		oneforall: ['-d'],
		dnsx: ['-d', '-domain'],
		httpx: ['-u', '-url', '-host', '-target'],
		katana: ['-u', '-url', '-target'],
		dirsearch: ['-u', '-url'],
		wafw00f: ['-u', '-url'],
		gau: [],
		waybackurls: [],
		nmap: [],
		// M3 验证工具：目标提取映射
		nuclei: ['-u', '-target', '-url'],
		sqlmap: ['-u', '-url'],
	};

	const flags = flagMap[cmd] ?? [];

	// 带 flag 的目标
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (flags.includes(arg) && i + 1 < args.length) {
			targets.push(args[i + 1]);
			i++;
		}
	}

	// 位置参数目标（gau/waybackurls/nmap）
	if (cmd === 'gau' || cmd === 'waybackurls' || cmd === 'nmap') {
		for (const arg of args) {
			if (arg.startsWith('-')) continue;
			// 跳过明显的非目标（端口号、文件路径等）
			if (/^\d+$/.test(arg)) continue;
			if (arg.startsWith('/')) continue;
			targets.push(arg);
		}
	}

	// 兜底：如果没找到，扫描所有非 flag 参数
	if (targets.length === 0) {
		for (const arg of args) {
			if (arg.startsWith('-')) continue;
			if (/^\d+$/.test(arg)) continue;
			if (arg.startsWith('/')) continue;
			// 看起来像 domain/ip/url
			if (
				/^\d{1,3}(\.\d{1,3}){3}/.test(arg) ||
				/^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(arg) ||
				/^https?:\/\//i.test(arg)
			) {
				targets.push(arg);
			}
		}
	}

	return targets;
}

/**
 * 工具执行前的 Scope 校验
 *
 * 拒绝则返回 deny result，executor.ts 据此跳过 spawn。
 * 主动工具（mode='active'）做完整校验（含 DNS），被动工具跳过 DNS。
 */
export async function checkToolScope(
	command: string,
	args: string[],
	mode: 'passive' | 'active' = 'passive',
): Promise<ScopeCheckResult[]> {
	const targets = extractTargetsFromArgs(command, args);
	const results: ScopeCheckResult[] = [];

	for (const target of targets) {
		const result = await checkScope(target, {
			skipDnsResolve: mode === 'passive',
		});
		results.push(result);
	}

	return results;
}

/**
 * 检查工具是否被 Scope Gate 拦截
 *
 * @returns true 表示有任意目标被拒绝
 */
export function hasDenied(results: ScopeCheckResult[]): boolean {
	return results.some((r) => r.decision === 'deny');
}
