/**
 * waybackurls 适配器
 *
 * 从 Wayback Machine / Common Crawl / Virustotal 抓取域名历史 URL（被动源）
 * 命令：waybackurls <domain>
 * 输出：每行一个 URL（纯文本，无 JSON 模式）
 *
 * 官方：https://github.com/tomnomnom/waybackurls
 */

import { execTool } from '../adapters/executor.js';
import { plainParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface WaybackurlsRecord {
	/** 完整 URL */
	url: string;
}

export interface WaybackurlsOptions {
	/** 目标域名（不带协议） */
	domain: string;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'waybackurls',
	mode: 'passive',
	description: 'Wayback Machine / Common Crawl / Virustotal 历史 URL（tomnomnom）',
	defaultArgs: [],
	defaultTimeoutMs: 5 * 60 * 1000,
};

registerTool(TOOL_DEF);

const parser = plainParser<WaybackurlsRecord>('waybackurls', (line) => {
	const trimmed = line.trim();
	if (!trimmed || !/^https?:\/\//i.test(trimmed)) return null;
	return { url: trimmed };
});

/**
 * 执行 waybackurls 获取域名历史 URL
 */
export async function runWaybackurls(opts: WaybackurlsOptions): Promise<WaybackurlsRecord[]> {
	const cacheKey =
		opts.useCache !== false ? buildCacheKey('waybackurls', 'domain', opts.domain) : undefined;

	const result = await execTool<WaybackurlsRecord>(
		{
			command: 'waybackurls',
			args: [opts.domain],
			mode: 'passive',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		parser,
		cacheKey,
	);

	// 去重
	const seen = new Set<string>();
	const out: WaybackurlsRecord[] = [];
	for (const r of result.records) {
		const urlLower = r.url.toLowerCase().trim();
		if (!urlLower || seen.has(urlLower)) continue;
		seen.add(urlLower);
		out.push({ url: urlLower });
	}
	return out;
}
