/**
 * ParamSpider 适配器
 *
 * 从 Wayback Machine 抓取目标域名的带参数 URL（被动源）
 * 命令：python3 -m paramspider.main -d <domain> -s
 * 输出：stdout 流式（-s）+ results/<domain>.txt 文件
 *
 * ParamSpider 特色：
 *   - 过滤掉静态资源扩展名（.js/.css/.png 等）
 *   - 把参数值替换成 FUZZ 占位符（便于后续 fuzz）
 *   - 只保留带 ? 的 URL（参数化 URL）
 *
 * 官方：https://github.com/devanshbatham/ParamSpider
 * 部署：git clone 到 tools/paramspider_src，依赖 colorama
 *
 * 注意：
 *   - paramspider 输出目录固定为 cwd/results/，必须设 cwd=项目根目录
 *   - stdout 含 ANSI 颜色码和 INFO 日志，需要过滤
 *   - 必须用 -s 流式输出（否则只写文件不输出 stdout）
 */

import { existsSync } from 'node:fs';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { execTool } from '../adapters/executor.js';
import { plainParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { getConfig } from '../config.js';
import { buildCacheKey } from '../storage/cache.js';

export interface ParamSpiderRecord {
	/** 完整 URL（参数值已替换为 FUZZ 占位符） */
	url: string;
	/** URL 路径（不含 query） */
	path: string;
	/** 参数名列表 */
	params: string[];
}

export interface ParamSpiderOptions {
	/** 目标域名（不带协议） */
	domain: string;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 启用 L2 缓存 */
	useCache?: boolean;
	/** 参数占位符（默认 FUZZ） */
	placeholder?: string;
	/** 代理（可选） */
	proxy?: string;
}

const TOOL_DEF: ToolDefinition = {
	name: 'paramspider',
	mode: 'passive',
	description: 'Wayback Machine 参数化 URL 挖掘（devanshbatham/ParamSpider）',
	defaultArgs: ['-s'],
	defaultTimeoutMs: 5 * 60 * 1000,
};

registerTool(TOOL_DEF);

// 使用 plain parser 拿原始行，再自行清洗
const rawParser = plainParser<string>('paramspider', (line) => {
	const trimmed = line.trim();
	if (!trimmed) return null;
	return trimmed;
});

/**
 * 执行 ParamSpider 获取参数化 URL
 *
 * 实现细节：
 *   1. 设置 cwd = paramspiderDir（让模块可被 -m 找到，且 results/ 落地到已知位置）
 *   2. 命令：python3 -m paramspider.main -d <domain> -s [-p FUZZ] [--proxy ...]
 *   3. 过滤 stdout：去掉 ANSI 颜色码、INFO 日志、banner，只保留 URL 行
 *   4. 从 results/<domain>.txt 补充读取（防止 stdout 被截断）
 *   5. 解析每条 URL 的 path + 参数名
 */
export async function runParamSpider(opts: ParamSpiderOptions): Promise<ParamSpiderRecord[]> {
	const cfg = getConfig().tool;
	const paramspiderDir = cfg.paramspiderDir;
	if (!paramspiderDir) {
		console.warn('[paramspider] PARAMSPIDER_DIR not configured, skipping');
		return [];
	}

	const python = cfg.paramspiderPython || 'python3';
	const placeholder = opts.placeholder ?? 'FUZZ';
	const proxy = opts.proxy ?? cfg.paramspiderProxy;
	const cacheKey =
		opts.useCache !== false ? buildCacheKey('paramspider', 'domain', opts.domain) : undefined;

	const args = ['-m', 'paramspider.main', '-d', opts.domain, '-s', '-p', placeholder];
	if (proxy) {
		args.push('--proxy', proxy);
	}

	const result = await execTool<string>(
		{
			command: python,
			args,
			cwd: paramspiderDir,
			mode: 'passive',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
		},
		rawParser,
		cacheKey,
	);

	// 从 stdout 收集 URL 行（注意：ParamSpider 的 -s 输出实际走 stderr，stdout 可能为空）
	const stdoutUrls = new Set<string>();
	for (const line of result.records) {
		const cleaned = stripAnsiAndLog(line);
		if (cleaned && /^https?:\/\//i.test(cleaned) && cleaned.includes('?')) {
			stdoutUrls.add(cleaned);
		}
	}

	// 从 results/<domain>.txt 补充读取（防 stdout 被截断）
	const resultsFile = join(paramspiderDir, 'results', `${opts.domain}.txt`);
	if (existsSync(resultsFile)) {
		try {
			const fileContent = await readFile(resultsFile, 'utf8');
			for (const line of fileContent.split('\n')) {
				const trimmed = line.trim();
				if (trimmed?.includes('?')) {
					stdoutUrls.add(trimmed);
				}
			}
		} catch {
			// 读取失败忽略
		}
	}

	// 解析 URL → 提取 path + 参数名
	const records: ParamSpiderRecord[] = [];
	for (const url of stdoutUrls) {
		try {
			const parsed = new URL(url);
			const path = parsed.pathname || '/';
			const params: string[] = [];
			const searchParams = parsed.searchParams;
			for (const key of searchParams.keys()) {
				if (!params.includes(key)) params.push(key);
			}
			records.push({ url, path, params });
		} catch {
			// URL 解析失败跳过
		}
	}

	return records;
}

/**
 * 清除 ANSI 颜色码和 ParamSpider 的 INFO 日志行
 */
function stripAnsiAndLog(line: string): string {
	// 去 ANSI 颜色码
	const noAnsi = line.replace(/\x1b\[[0-9;]*m/g, '');
	// 过滤 INFO 日志和 banner
	const trimmed = noAnsi.trim();
	if (!trimmed) return '';
	if (trimmed.startsWith('[INFO]')) return '';
	if (trimmed.startsWith('with <3')) return '';
	if (trimmed.includes('ParamSpider')) return '';
	if (/^[_\/\\]/.test(trimmed)) return ''; // banner ASCII art
	return trimmed;
}

/**
 * 清理 ParamSpider 输出目录（测试/重跑时用）
 */
export async function cleanupParamSpiderResults(domain: string): Promise<void> {
	const cfg = getConfig().tool;
	if (!cfg.paramspiderDir) return;
	const resultsDir = join(cfg.paramspiderDir, 'results');
	if (existsSync(resultsDir)) {
		await rm(join(resultsDir, `${domain}.txt`), { force: true });
	}
}
