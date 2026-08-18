/**
 * gau 适配器（GetAllUrls）
 *
 * 从 Wayback/Common Crawl/URLScan 等抓取历史 URL（被动源）
 * 命令：gau --threads <n> <domain>
 * 输出：每行一个 URL（纯文本）
 *
 * 相比 waybackurls：gau 支持多源（AlienVault/URLScan/CommonCrawl/Wayback）+ 并发，通常更全。
 * 官方：https://github.com/lc/gau
 */

import { execTool } from '../adapters/executor.js';
import { plainParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface GauRecord {
	url: string;
}

export interface GauOptions {
	domain: string;
	/** 并发线程数（默认 5） */
	threads?: number;
	/** 启用的源（默认全部：wayback,commoncrawl,otx,urlscan） */
	providers?: string[];
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'gau',
	mode: 'passive',
	description: 'GetAllUrls — 多源历史 URL（Wayback/CommonCrawl/OTX/URLScan）',
	defaultArgs: ['--threads', '5'],
	defaultTimeoutMs: 5 * 60 * 1000,
};

registerTool(TOOL_DEF);

const parser = plainParser<GauRecord>('gau', (line) => {
	const trimmed = line.trim();
	if (!trimmed || !/^https?:\/\//i.test(trimmed)) return null;
	return { url: trimmed };
});

export async function runGau(opts: GauOptions): Promise<GauRecord[]> {
	const args: string[] = [...(TOOL_DEF.defaultArgs ?? [])];
	if (opts.threads && opts.threads > 0) {
		// 替换默认 threads
		const idx = args.indexOf('--threads');
		if (idx >= 0) {
			args[idx + 1] = String(opts.threads);
		} else {
			args.push('--threads', String(opts.threads));
		}
	}
	if (opts.providers && opts.providers.length > 0) {
		args.push('--providers', opts.providers.join(','));
	}
	args.push(...(opts.extraArgs ?? []));
	args.push(opts.domain);

	const cacheKey =
		opts.useCache !== false ? buildCacheKey('gau', 'domain', opts.domain) : undefined;

	const result = await execTool<GauRecord>(
		{
			command: 'gau',
			args,
			mode: 'passive',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		parser,
		cacheKey,
	);

	const seen = new Set<string>();
	const out: GauRecord[] = [];
	for (const r of result.records) {
		const urlLower = r.url.toLowerCase().trim();
		if (!urlLower || seen.has(urlLower)) continue;
		seen.add(urlLower);
		out.push({ url: urlLower });
	}
	return out;
}
