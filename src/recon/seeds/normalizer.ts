/**
 * 种子归一化器
 *
 * 任意输入字符串 → 统一 Seed{seed_type, value, value_norm, parsed}
 * 6 种入口：domain / url / ip / cidr / ip_port / company_name
 *
 * 归一化规则：
 * - 全部小写（除公司名）
 * - 去协议、去末尾斜杠、去端口（80/443 默认端口）
 * - CIDR 标准化为 network 地址
 */

import type { Seed, SeedType } from './types.js';
import { SeedNormalizeError } from './types.js';

// 简单 IP 正则（IPv4，足够 MVP 使用，IPv6 留待后续）
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

// 域名正则：标签（字母数字-）+ 点 + TLD（≥2 字母）
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

// CIDR 正则：IPv4/前缀
const CIDR_RE =
	/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/([0-9]|[12]\d|3[0-2])$/;

/**
 * 主入口：归一化种子
 * @param input 用户原始输入字符串
 * @returns Seed 对象
 * @throws SeedNormalizeError
 */
export function normalizeSeed(input: string): Seed {
	const trimmed = input.trim();
	if (!trimmed) {
		throw new SeedNormalizeError('empty input', input);
	}

	// 通用预清洗：去末尾斜杠（仅对非 URL 输入；URL 保留路径处理）
	const looksLikeUrl = /^https?:\/\//i.test(trimmed) || /^[\w.-]+(:\d+)?\/.+/.test(trimmed);
	const cleaned = looksLikeUrl ? trimmed : trimmed.replace(/\/+$/, '');

	// 按优先级判定：URL > CIDR > IP:Port > IP > Domain > Company Name
	// 1. URL（含协议；或不含协议但有非根路径，如 example.com/path）
	if (
		/^https?:\/\//i.test(cleaned) ||
		(/^[\w.-]+(:\d+)?\/.+/.test(cleaned) && !CIDR_RE.test(cleaned))
	) {
		return normalizeUrl(cleaned);
	}

	// 2. CIDR
	if (CIDR_RE.test(cleaned)) {
		return normalizeCidr(cleaned);
	}

	// 3. IP:Port
	if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(cleaned)) {
		return normalizeIpPort(cleaned);
	}

	// 4. IP
	if (IPV4_RE.test(cleaned)) {
		return normalizeIp(cleaned);
	}

	// 5. Domain
	if (DOMAIN_RE.test(cleaned)) {
		return normalizeDomain(cleaned);
	}

	// 6. Company Name（兜底：含中文或非上述格式的字符串）
	return normalizeCompanyName(cleaned);
}

/**
 * 显式按类型归一化（用于 REST API / SDK 已知类型的场景）
 */
export function normalizeSeedAs(input: string, seedType: SeedType): Seed {
	const trimmed = input.trim();
	if (!trimmed) {
		throw new SeedNormalizeError('empty input', input);
	}
	switch (seedType) {
		case 'domain':
			return normalizeDomain(trimmed);
		case 'url':
			return normalizeUrl(trimmed);
		case 'ip':
			return normalizeIp(trimmed);
		case 'cidr':
			return normalizeCidr(trimmed);
		case 'ip_port':
			return normalizeIpPort(trimmed);
		case 'company_name':
			return normalizeCompanyName(trimmed);
		default:
			throw new SeedNormalizeError(`unknown seed type: ${seedType as string}`, input);
	}
}

function normalizeDomain(input: string): Seed {
	const value = input
		.toLowerCase()
		.replace(/\/+$/, '')
		.replace(/^www\./, '');
	if (!DOMAIN_RE.test(value)) {
		throw new SeedNormalizeError(`invalid domain: ${input}`, input);
	}
	return {
		value: input,
		valueNorm: value,
		seedType: 'domain',
		parsed: { kind: 'domain', domain: value },
	};
}

function normalizeUrl(input: string): Seed {
	let url: URL;
	try {
		url = new URL(input.startsWith('http') ? input : `http://${input}`);
	} catch {
		throw new SeedNormalizeError(`invalid url: ${input}`, input);
	}
	const scheme = url.protocol.replace(':', '').toLowerCase();
	const host = url.hostname.toLowerCase().replace(/^www\./, '');
	// 显式端口（非默认）才保留
	const defaultPort = scheme === 'https' ? 443 : 80;
	const port = url.port ? Number.parseInt(url.port, 10) : defaultPort;
	const explicitPort = port !== defaultPort ? port : null;

	// 路径：去末尾斜杠，根路径统一为 /
	let path = url.pathname.replace(/\/+$/, '');
	if (!path) path = '/';

	// 域名提取（去掉端口）
	const domain = host.split(':')[0];
	if (!DOMAIN_RE.test(domain) && !IPV4_RE.test(domain)) {
		throw new SeedNormalizeError(`invalid url host: ${host}`, input);
	}

	// 归一化 URL：scheme://host[:port]/path（不包含 query 和 fragment，作为去重键）
	const valueNorm = `${scheme}://${host}${explicitPort ? `:${explicitPort}` : ''}${path}`;

	return {
		value: input,
		valueNorm,
		seedType: 'url',
		parsed: {
			kind: 'url',
			url: valueNorm,
			scheme,
			host,
			port: explicitPort,
			path,
			domain,
		},
	};
}

function normalizeIp(input: string): Seed {
	const value = input.toLowerCase().trim();
	if (!IPV4_RE.test(value)) {
		throw new SeedNormalizeError(`invalid ip: ${input}`, input);
	}
	return {
		value: input,
		valueNorm: value,
		seedType: 'ip',
		parsed: { kind: 'ip', ip: value },
	};
}

function normalizeCidr(input: string): Seed {
	const value = input.toLowerCase().trim();
	if (!CIDR_RE.test(value)) {
		throw new SeedNormalizeError(`invalid cidr: ${input}`, input);
	}
	const [ipPart, prefixPart] = value.split('/');
	const prefix = Number.parseInt(prefixPart, 10);

	// 将 IP 转为 network 地址（掩码后）
	const ip = normalizeIpToNetwork(ipPart, prefix);
	const valueNorm = `${ip}/${prefix}`;

	return {
		value: input,
		valueNorm,
		seedType: 'cidr',
		parsed: { kind: 'cidr', cidr: valueNorm, ip, prefix },
	};
}

function normalizeIpPort(input: string): Seed {
	const value = input.toLowerCase().trim();
	const m = value.match(/^(\d{1,3}(\.\d{1,3}){3}):(\d+)$/);
	if (!m) {
		throw new SeedNormalizeError(`invalid ip:port: ${input}`, input);
	}
	const ip = m[1];
	const port = Number.parseInt(m[3], 10);
	if (port < 1 || port > 65535) {
		throw new SeedNormalizeError(`port out of range: ${port}`, input);
	}
	if (!IPV4_RE.test(ip)) {
		throw new SeedNormalizeError(`invalid ip in ip:port: ${ip}`, input);
	}
	return {
		value: input,
		valueNorm: `${ip}:${port}`,
		seedType: 'ip_port',
		parsed: { kind: 'ip_port', ip, port },
	};
}

function normalizeCompanyName(input: string): Seed {
	const value = input.trim();
	if (!value) {
		throw new SeedNormalizeError('empty company name', input);
	}
	// 公司名归一化：去前后空格、合并连续空格，大小写保留（公司名有大小写语义）
	const valueNorm = value.replace(/\s+/g, ' ');
	return {
		value: input,
		valueNorm,
		seedType: 'company_name',
		parsed: { kind: 'company_name', company: valueNorm },
	};
}

/**
 * 将 IP 转为 CIDR 的 network 地址
 * 例：10.0.0.5/24 → 10.0.0.0
 */
function normalizeIpToNetwork(ip: string, prefix: number): string {
	const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
	const ipNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	const networkNum = (ipNum & mask) >>> 0;
	return [
		(networkNum >>> 24) & 0xff,
		(networkNum >>> 16) & 0xff,
		(networkNum >>> 8) & 0xff,
		networkNum & 0xff,
	].join('.');
}
