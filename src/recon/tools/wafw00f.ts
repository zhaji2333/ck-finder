/**
 * wafw00f 适配器
 *
 * WAF 识别（主动工具）
 * 命令：wafw00f -a <url>
 * 输出：纯文本，含 "is behind Cloudflare" 等字样
 *
 * 官方：https://github.com/EnableSecurity/wafw00f
 *
 * 用途：补全 httpx 的 waf 字段（httpx 的 -waf 不如 wafw00f 全），
 *       识别厂商后写入 webapps.waf 和 webapps.meta.waf_name
 */

import { execTool } from '../adapters/executor.js';
import { plainParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface Wafw00fRecord {
	/** 目标 URL */
	url: string;
	/** 是否检测到 WAF */
	hasWaf: boolean;
	/** WAF 厂商名（如 Cloudflare、阿里云盾、长亭雷池） */
	wafName?: string;
	/** 原始输出行 */
	raw: string;
}

export interface Wafw00fOptions {
	/** 目标 URL */
	url: string;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'wafw00f',
	mode: 'active',
	description: 'WAF 识别（EnableSecurity）',
	defaultArgs: ['-a'],
	defaultTimeoutMs: 60_000,
};

registerTool(TOOL_DEF);

const parser = plainParser<Wafw00fRecord>('wafw00f', (line) => {
	const trimmed = line.trim();
	if (!trimmed) return null;

	// wafw00f 输出格式：
	//   "https://example.com is behind Cloudflare"
	//   "https://example.com is behind Incapsula (Incapsula Inc.)"
	//   "[&] None: https://example.com"  （未检测到 WAF）
	//   "[!] This site seems to be behind a WAF or some sort of security solution"
	const urlMatch = trimmed.match(/(https?:\/\/[^\s]+)/i);
	const url = urlMatch?.[1] ?? '';
	if (!url) return null;

	let hasWaf = false;
	let wafName: string | undefined;

	if (/is behind (.+)/i.test(trimmed)) {
		hasWaf = true;
		const m = trimmed.match(/is behind (.+)/i);
		if (m) wafName = m[1].replace(/[^\w\s\-().]/g, '').trim();
	} else if (/None/i.test(trimmed) || /not behind/i.test(trimmed)) {
		hasWaf = false;
	} else if (/behind a WAF/i.test(trimmed)) {
		hasWaf = true;
		wafName = 'Unknown';
	}

	return { url, hasWaf, wafName, raw: trimmed };
});

export async function runWafw00f(opts: Wafw00fOptions): Promise<Wafw00fRecord[]> {
	const args = [...(TOOL_DEF.defaultArgs ?? []), opts.url];
	const cacheKey = opts.useCache !== false ? buildCacheKey('wafw00f', 'url', opts.url) : undefined;

	const result = await execTool<Wafw00fRecord>(
		{
			command: 'wafw00f',
			args,
			mode: 'active',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		parser,
		cacheKey,
	);

	// 取第一条有 WAF 信息的记录
	return result.records;
}

/**
 * 便捷方法：判断 URL 是否有 WAF，返回 WAF 名称（无则 null）
 */
export async function detectWaf(
	url: string,
	opts: { timeoutMs?: number } = {},
): Promise<string | null> {
	const records = await runWafw00f({ url, timeoutMs: opts.timeoutMs });
	const hit = records.find((r) => r.hasWaf && r.wafName);
	return hit?.wafName ?? null;
}
