/**
 * httpx 适配器（ProjectDiscovery 版）
 *
 * 存活 URL 探测 + title/status/tech/CDN/WAF 检测
 * 命令：echo "<url>" | httpx -json -title -tech-detect -status-code -follow-redirects
 * 输出：JSONL，每行 {"url":"...","status_code":200,"title":"...","tech":["...",...],...}
 *
 * 官方：https://github.com/projectdiscovery/httpx
 *
 * 注意：本工具指 PD 版 httpx（/opt/homebrew/bin/httpx），不是 Python 版 httpx
 */

import { execTool } from '../adapters/executor.js';
import { jsonlParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface HttpxRecord {
	url: string;
	input?: string;
	location?: string;
	title?: string;
	status_code?: number;
	content_length?: number;
	// 技术栈数组（httpx -tech-detect 输出，逗号分隔字符串或数组）
	tech?: string[] | string;
	// webserver（如 nginx、Apache）
	webserver?: string;
	content_type?: string;
	host?: string;
	port?: number;
	scheme?: string;
	method?: string;
	// CDN 相关
	cdn?: boolean;
	cdn_name?: string;
	// WAF（httpx -waf 检测，M3 启用）
	waf?: string;
	// 旁站
	a?: string[];
	// 指纹（cname 链）
	cnames?: string[];
	// M2 新增：响应 body preview（-bp 4096）
	body_preview?: string;
	// M2 新增：favicon mmh3 hash（-favicon，httpx 输出字段名是 favicon）
	favicon?: number;
	// M2 新增：完整响应 header 对象（-irh，httpx 输出 header 字段是 object）
	header?: Record<string, string>;
}

export interface HttpxOptions {
	/** 单个 URL */
	url?: string;
	/** URL 列表（stdin 传入，优先于 url） */
	urls?: string[];
	/** 是否跟随重定向 */
	followRedirects?: boolean;
	/** 是否检测技术栈 */
	techDetect?: boolean;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存（仅 url 单参模式生效） */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'httpx',
	mode: 'active',
	description: '存活 URL 探测 + title/status/tech/CDN/WAF 检测（ProjectDiscovery）',
	// M2 增加 -irh（响应 header）+ -favicon（icon hash）+ -bp 4096（body preview，用于指纹库匹配）
	defaultArgs: [
		'-json',
		'-title',
		'-status-code',
		'-tech-detect',
		'-follow-redirects',
		'-silent',
		'-timeout',
		'8',
		'-threads',
		'20',
		'-irh', // include response header
		'-favicon', // mmh3 hash of /favicon.ico
		'-bp',
		'4096', // body preview first 4096 chars（指纹匹配够用，避免大 body 占内存）
	],
	defaultTimeoutMs: 10 * 60 * 1000,
};

registerTool(TOOL_DEF);

const parser = jsonlParser<HttpxRecord>('httpx');

export async function runHttpx(opts: HttpxOptions): Promise<HttpxRecord[]> {
	const args: string[] = [];
	// 不重复加 -tech-detect/-follow-redirects（已在 defaultArgs 中）
	args.push(...(TOOL_DEF.defaultArgs ?? []));
	args.push(...(opts.extraArgs ?? []));

	// stdin 模式（多 URL）
	if (opts.urls && opts.urls.length > 0) {
		const stdin = opts.urls.join('\n');
		const result = await execTool<HttpxRecord>(
			{
				command: 'httpx',
				args,
				mode: 'active',
				timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
				stdin,
			},
			parser,
		);
		return result.records.map(normalizeRecord);
	}

	// 单 URL 模式
	if (!opts.url) {
		throw new Error('httpx: either url or urls must be provided');
	}

	const cacheKey = opts.useCache !== false ? buildCacheKey('httpx', 'url', opts.url) : undefined;

	// httpx 单 URL 模式通过 -u 传参（也可走 stdin，保持一致用 stdin）
	const result = await execTool<HttpxRecord>(
		{
			command: 'httpx',
			args,
			mode: 'active',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
			stdin: opts.url,
		},
		parser,
		cacheKey,
	);

	return result.records.map(normalizeRecord);
}

/** 标准化 httpx 记录：tech 字段统一为数组 */
function normalizeRecord(r: HttpxRecord): HttpxRecord {
	let tech: string[] | undefined;
	if (Array.isArray(r.tech)) {
		tech = r.tech.map((t) => t.toLowerCase().trim()).filter(Boolean);
	} else if (typeof r.tech === 'string') {
		tech = r.tech
			.split(',')
			.map((t) => t.toLowerCase().trim())
			.filter(Boolean);
	}
	return { ...r, tech };
}
