/**
 * dnsx 适配器
 *
 * DNS 解析 + 存活验证
 * 命令：dnsx -d <domain> -a -resp -json -silent
 *       echo "<domain>" | dnsx -a -resp -json -silent
 * 输出：JSONL，每行 {"host":"...","a":["1.2.3.4"],"resolver":"1.1.1.1",...}
 *
 * 官方：https://github.com/projectdiscovery/dnsx
 */

import { execTool } from '../adapters/executor.js';
import { jsonlParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface DnsxRecord {
	host: string;
	a?: string[];
	aaaa?: string[];
	cname?: string[];
	ns?: string[];
	mx?: string[];
	txt?: string[];
	resolver?: string;
	// dnsx 0.x 字段：status_code（仅 HTTP 模式）
	status_code?: string;
}

export interface DnsxOptions {
	/** 单个域名 */
	domain?: string;
	/** 域名列表（stdin 传入，优先于 domain） */
	domains?: string[];
	/** 解析记录类型 */
	recordTypes?: ('a' | 'aaaa' | 'cname' | 'ns' | 'mx' | 'txt')[];
	/** 超时 */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存（仅 domain 单参模式生效） */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'dnsx',
	mode: 'passive',
	description: 'DNS 解析 + 存活验证（ProjectDiscovery）',
	defaultArgs: ['-resp', '-json', '-silent'],
	defaultTimeoutMs: 3 * 60 * 1000,
};

registerTool(TOOL_DEF);

const parser = jsonlParser<DnsxRecord>('dnsx');

export async function runDnsx(opts: DnsxOptions): Promise<DnsxRecord[]> {
	const recordTypeArgs: string[] = [];
	const types = opts.recordTypes ?? ['a'];
	for (const t of types) {
		recordTypeArgs.push(`-${t}`);
	}

	const args = [...recordTypeArgs, ...(TOOL_DEF.defaultArgs ?? []), ...(opts.extraArgs ?? [])];

	// stdin 模式（多域名）
	if (opts.domains && opts.domains.length > 0) {
		const stdin = opts.domains.join('\n');
		const result = await execTool<DnsxRecord>(
			{
				command: 'dnsx',
				args,
				mode: 'passive',
				timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
				stdin,
			},
			parser,
		);
		return result.records;
	}

	// 单域名模式
	if (!opts.domain) {
		throw new Error('dnsx: either domain or domains must be provided');
	}
	args.unshift('-d', opts.domain);

	const cacheKey =
		opts.useCache !== false
			? buildCacheKey('dnsx', 'domain', opts.domain, types.sort().join(','))
			: undefined;

	const result = await execTool<DnsxRecord>(
		{
			command: 'dnsx',
			args,
			mode: 'passive',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		parser,
		cacheKey,
	);

	return result.records;
}
