/**
 * katana 适配器（ProjectDiscovery）
 *
 * 现代 Web 爬虫，支持 JS 渲染（headless Chrome），可抓：
 * - 页面中的所有 URL（含子页）
 * - JS 文件
 * - 表单/接口
 *
 * 命令：katana -u <url> -j -d <depth> -nc
 * 输出：JSONL，每行 {"timestamp":"...","request":{"method":"GET","endpoint":"https://...","tag":"a","attribute":"href","source":"..."},"response":{...}}
 *
 * 官方：https://github.com/projectdiscovery/katana
 *
 * 注意：katana 是主动工具，会请求目标。
 * 注意：-silent 会覆盖 -j 输出格式（变为纯 URL），所以不能用 -silent。
 */

import { execTool } from '../adapters/executor.js';
import { jsonlParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

export interface KatanaRecord {
	/** 抓取到的 URL（对应 katana JSONL 的 request.endpoint） */
	url: string;
	/** HTTP 方法（GET/POST 等） */
	method?: string;
	/** 标签来源（a/script/form/link/iframe 等） */
	tag?: string;
	/** 来源属性（href/src/action 等） */
	attribute?: string;
	/** 抓取深度 */
	depth?: number;
	/** 父页面 URL（对应 katana JSONL 的 request.source） */
	source?: string;
}

export interface KatanaOptions {
	/** 目标 URL */
	url: string;
	/** 抓取深度（默认 2） */
	depth?: number;
	/** 并发（默认 10） */
	concurrency?: number;
	/** 跟随重定向的次数（默认 10） */
	redirectCount?: number;
	/** 启用 headless 模式（JS 渲染，慢但更全，默认 false） */
	headless?: boolean;
	/** 只抓同域（默认 true，防止跑偏到外链） */
	sameDomain?: boolean;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'katana',
	mode: 'active',
	description: '现代 Web 爬虫（ProjectDiscovery），抓 URL/JS/接口',
	// 注意：-silent 会把 JSONL 输出变为纯 URL，不能用；用 -nc（no-color）替代
	defaultArgs: ['-j', '-nc'],
	defaultTimeoutMs: 5 * 60 * 1000,
};

registerTool(TOOL_DEF);

/** katana JSONL 原始结构 */
interface KatanaRawLine {
	timestamp?: string;
	request?: {
		method?: string;
		endpoint?: string;
		tag?: string;
		attribute?: string;
		source?: string;
	};
	response?: {
		status_code?: number;
	};
	error?: string;
}

const parser = jsonlParser<KatanaRawLine>('katana');

export async function runKatana(opts: KatanaOptions): Promise<KatanaRecord[]> {
	const args: string[] = [...(TOOL_DEF.defaultArgs ?? [])];
	args.push('-u', opts.url);
	args.push('-d', String(opts.depth ?? 2));
	args.push('-c', String(opts.concurrency ?? 10));
	args.push('-rd', String(opts.redirectCount ?? 10));
	if (opts.headless) {
		args.push('-headless');
	}
	// 范围控制：sameDomain=true 用 -fs fqdn 严格限定同一 host（默认 rdn 会包含子域，扩大范围）
	if (opts.sameDomain === true) {
		args.push('-fs', 'fqdn');
	} else if (opts.sameDomain === false) {
		args.push('-ns');
	}
	// -nc 已经在 defaultArgs 里了，这里不再重复
	args.push(...(opts.extraArgs ?? []));

	const cacheKey =
		opts.useCache !== false
			? buildCacheKey('katana', 'url', opts.url, `d${opts.depth ?? 2}`)
			: undefined;

	const result = await execTool<KatanaRawLine>(
		{
			command: 'katana',
			args,
			mode: 'active',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		parser,
		cacheKey,
	);

	// 转换为 KatanaRecord（提取 request.endpoint 为 url）
	const seen = new Set<string>();
	const out: KatanaRecord[] = [];
	for (const r of result.records) {
		const url = r.request?.endpoint;
		if (!url) continue;
		// 跳过 katana 的 error 行
		if (r.error) continue;
		const method = r.request?.method ?? 'GET';
		const key = `${method}|${url}`;
		if (seen.has(key)) continue;
		seen.add(key);
		out.push({
			url,
			method,
			tag: r.request?.tag,
			attribute: r.request?.attribute,
			source: r.request?.source,
		});
	}
	return out;
}
