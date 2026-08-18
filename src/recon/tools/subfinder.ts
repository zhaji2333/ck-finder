/**
 * subfinder 适配器
 *
 * 子域发现主力工具（被动源）
 * 命令：subfinder -d <domain> -json -silent
 * 输出：JSONL，每行 {"host":"sub.example.com","source":"crtsh",...}
 *
 * 官方：https://github.com/projectdiscovery/subfinder
 */

import { execTool } from '../adapters/executor.js';
import { jsonlParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface SubfinderRecord {
	host: string;
	source?: string;
}

export interface SubfinderOptions {
	/** 目标域名 */
	domain: string;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'subfinder',
	mode: 'passive',
	description: '子域发现主力工具（被动源，ProjectDiscovery）',
	defaultArgs: ['-json', '-silent'],
	defaultTimeoutMs: 5 * 60 * 1000,
};

registerTool(TOOL_DEF);

const parser = jsonlParser<SubfinderRecord>('subfinder');

/**
 * 执行 subfinder 获取子域列表
 *
 * 默认参数：-json -silent
 * 通过 extraArgs 可加 -all（多源聚合，更慢但更全）、-timeout <s>（单源超时）、-t <n>（并发数）等。
 */
export async function runSubfinder(opts: SubfinderOptions): Promise<SubfinderRecord[]> {
	const args = [
		'-d',
		opts.domain,
		'-timeout',
		'30', // 单源超时 30 秒，避免某个被动源卡住
		...(TOOL_DEF.defaultArgs ?? []),
		...(opts.extraArgs ?? []),
	];

	const cacheKey =
		opts.useCache !== false ? buildCacheKey('subfinder', 'domain', opts.domain) : undefined;

	const result = await execTool<SubfinderRecord>(
		{
			command: 'subfinder',
			args,
			mode: 'passive',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		parser,
		cacheKey,
	);

	// 去重（subfinder 可能从多源返回同一子域）
	const seen = new Set<string>();
	const out: SubfinderRecord[] = [];
	for (const r of result.records) {
		const host = r.host?.toLowerCase().trim();
		if (!host || seen.has(host)) continue;
		seen.add(host);
		out.push({ host, source: r.source });
	}
	return out;
}
