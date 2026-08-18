/**
 * Scope 校验共享工具（M3）
 *
 * 从 security/gate.ts 提取的 scope 解析 + host 匹配逻辑，
 * 供 Scope Gate（pi beforeToolCall）与爆破工具（auth_brute 越权护栏）复用。
 */
import { getConfig } from '../recon/config.js';
import { isCloudMetadataHost, isIpInCidr, isReservedIp } from '../recon/gate/scope_gate.js';

export { isCloudMetadataHost };

export interface ParsedScope {
	domains: Set<string>;
	ips: Set<string>;
	cidrs: string[];
}

export function parseScope(scope: string[]): ParsedScope {
	const out: ParsedScope = { domains: new Set(), ips: new Set(), cidrs: [] };
	for (const raw of scope) {
		const item = raw.trim().toLowerCase();
		if (!item) continue;
		if (item.includes('/')) {
			out.cidrs.push(item);
		} else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(item)) {
			out.ips.add(item);
		} else if (item.startsWith('*.')) {
			out.domains.add(item.slice(2));
		} else {
			out.domains.add(item.replace(/^www\./, ''));
		}
	}
	return out;
}

/** 生效 scope：CKFINDER_SCOPE/--scope 与收集引擎 SCOPE_ALLOWED 取并集 */
export function effectiveScope(explicitScope: string[]): string[] {
	const cfg = getConfig();
	return [...new Set([...explicitScope, ...cfg.scopeGate.allowed])];
}

export function extractHostFromUrl(url: string): string | null {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return null;
	}
}

/** host（IP 或域名）是否命中授权范围 */
export function hostInScope(host: string, scope: ParsedScope): boolean {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
		if (scope.ips.has(host)) return true;
		return scope.cidrs.some((c) => isIpInCidr(host, c));
	}
	const lower = host.toLowerCase();
	if (scope.domains.has(lower)) return true;
	for (const d of scope.domains) {
		if (lower === d || lower.endsWith(`.${d}`)) return true;
	}
	return false;
}

/** 同步便捷版（给不需要 pi context 的工具/命令用）：host 是否在授权内 */
export function hostInScopeSync(host: string, explicitScope?: string[]): boolean {
	const scope = explicitScope ?? [];
	const effective = effectiveScope(scope);
	if (effective.length === 0) return false;
	return hostInScope(host, parseScope(effective));
}

/** host 是否为保留/内网 IP */
export function isReservedHost(host: string): boolean {
	return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) && isReservedIp(host) !== null;
}
