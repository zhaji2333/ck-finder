/**
 * dirsearch 适配器
 *
 * 目录/文件爆破（主动工具，门控：仅 L1+ webapp 才跑）
 * 命令：dirsearch -u <url> --format=json -o <outfile>
 *
 * 输出格式（JSON 文件）：
 *   {
 *     "info": {...},
 *     "results": [
 *       {"url":"https://x.com/admin","status":200,"content-length":1024,"redirect":"","content-type":"text/html"},
 *       ...
 *     ]
 *   }
 *
 * 官方：https://github.com/maurosoria/dirsearch
 *
 * 设计要点：
 * - 默认用小字典（common.txt），避免大字典拖慢
 * - 限速：默认 10 req/s（主动工具 RPS 限速）
 * - 排除 404，只入库有响应的端点
 * - stdout 全是日志，必须用 -o 输出到文件再读
 */

import { accessSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { execTool } from '../adapters/executor.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { getConfig } from '../config.js';
import { buildCacheKey } from '../storage/cache.js';

/**
 * 在 PATH 中查找可执行文件，返回绝对路径（找不到返回原命令名，让 spawn 报错）
 */
function findInPath(cmd: string): string {
	if (cmd.includes('/')) return cmd;
	for (const dir of (process.env.PATH ?? '').split(delimiter)) {
		if (!dir) continue;
		const abs = join(dir, cmd);
		try {
			accessSync(abs);
			return abs;
		} catch {
			// continue
		}
	}
	return cmd;
}

export interface DirsearchRecord {
	/** 端点路径，如 /admin（从 url 提取） */
	path: string;
	/** 完整 URL */
	url: string;
	/** HTTP 状态码 */
	status: number;
	/** Content-Length */
	'content-length'?: number;
	/** Content-Type */
	'content-type'?: string;
	/** 重定向 URL（status 3xx） */
	redirect?: string;
}

export interface DirsearchOptions {
	/** 目标 URL（含协议） */
	url: string;
	/** 字典文件路径（默认用 dirsearch 内置 common.txt） */
	wordlist?: string;
	/** 后缀过滤（如 php,asp,jsp,html） */
	extensions?: string[];
	/** 排除的状态码（默认 404） */
	excludeStatus?: number[];
	/** 递归扫描深度（默认 0，不递归） */
	recursive?: number;
	/** 线程数（默认 5） */
	threads?: number;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'dirsearch',
	mode: 'active',
	description: '目录/文件爆破（maurosoria）',
	defaultArgs: ['--format=json', '-q'],
	defaultTimeoutMs: 5 * 60 * 1000,
};

registerTool(TOOL_DEF);

interface DirsearchRawResult {
	url: string;
	status: number;
	'content-length'?: number;
	'content-type'?: string;
	redirect?: string;
	path?: string;
}

interface DirsearchJsonOutput {
	info?: Record<string, unknown>;
	results: DirsearchRawResult[];
}

export async function runDirsearch(opts: DirsearchOptions): Promise<DirsearchRecord[]> {
	// 临时输出文件（dirsearch 不写 stdout，必须用 -o）
	const tmpDir = await mkdtemp(join(tmpdir(), 'dirsearch-'));
	const outFile = join(tmpDir, 'out.json');

	const args: string[] = [...(TOOL_DEF.defaultArgs ?? [])];
	args.push('-u', opts.url);
	args.push('-o', outFile);
	args.push('-t', String(opts.threads ?? 5));
	if (opts.wordlist) {
		args.push('-w', opts.wordlist);
	}
	if (opts.extensions && opts.extensions.length > 0) {
		args.push('-x', opts.extensions.join(','));
	}
	if (opts.excludeStatus && opts.excludeStatus.length > 0) {
		args.push('--exclude-status', opts.excludeStatus.join(','));
	} else {
		args.push('--exclude-status', '404');
	}
	if (opts.recursive && opts.recursive > 0) {
		args.push('-r', '-R', String(opts.recursive));
	}
	args.push(...(opts.extraArgs ?? []));

	const cacheKey =
		opts.useCache !== false
			? buildCacheKey('dirsearch', 'url', opts.url, `ext=${(opts.extensions ?? []).join(',')}`)
			: undefined;

	// dirsearch 可能是 pip 安装的可执行命令，也可能是 python <path>/dirsearch.py
	// 通过 DIRSEARCH_PATH 配置切换调用方式
	// 注意：python3 走 PATH，不能走 resolveCommand（否则会被 TOOLS_BIN_DIR 拼成 <binDir>/python3）
	const cfg = getConfig().tool;
	let command = 'dirsearch';
	let commandArgs = args;
	if (cfg.dirsearchPath) {
		// 用 python 调 dirsearch.py，python 解释器本身在 PATH 中
		// 在 command 前加路径分隔符标记，让 resolveCommand 跳过
		command = cfg.dirsearchPython || 'python3';
		if (!command.includes('/')) {
			// 标记为已绝对路径（用 / 前缀让 resolveCommand 跳过 binDir 拼接）
			// 但 python3 本身没有 /，所以我们用一个特殊技巧：传绝对路径
			const pythonAbs = findInPath(command);
			if (pythonAbs) command = pythonAbs;
		}
		commandArgs = [cfg.dirsearchPath, ...args];
	}

	// 自定义 parser：从输出文件读取并解析 JSON
	const parser = {
		name: 'dirsearch',
		format: 'json' as const,
		parse(_input: string): DirsearchRecord[] {
			// 这里不依赖 stdout（dirsearch 的 stdout 全是日志）
			// 实际文件读取在外部完成
			return [];
		},
	};

	try {
		const result = await execTool<DirsearchRecord>(
			{
				command,
				args: commandArgs,
				mode: 'active',
				timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
				// 决策点3：显式自定义字典（非内置默认小字典）视为高危爆破，需 LLM 审批
				...(opts.wordlist ? { judgeAction: 'dirsearch_brute' } : {}),
			},
			parser,
			cacheKey,
		);

		// 从输出文件读取真正的 JSON 结果
		let fileContent = '';
		try {
			fileContent = await readFile(outFile, 'utf8');
		} catch {
			// 文件不存在或读取失败，返回空
			return [];
		}

		if (!fileContent.trim()) return [];

		let parsed: DirsearchJsonOutput;
		try {
			parsed = JSON.parse(fileContent) as DirsearchJsonOutput;
		} catch {
			return [];
		}

		// 转换为 DirsearchRecord，从 url 提取 path
		const out: DirsearchRecord[] = [];
		for (const r of parsed.results ?? []) {
			if (!r.url) continue;
			let path: string;
			try {
				const u = new URL(r.url);
				path = u.pathname + (u.search ? u.search : '');
			} catch {
				// url 可能只是路径
				path = r.path ?? r.url;
			}
			out.push({
				path,
				url: r.url,
				status: r.status,
				'content-length': r['content-length'],
				'content-type': r['content-type'],
				redirect: r.redirect || undefined,
			});
		}

		// 去重（按 path）
		const seen = new Set<string>();
		const deduped: DirsearchRecord[] = [];
		for (const r of out) {
			if (seen.has(r.path)) continue;
			seen.add(r.path);
			deduped.push(r);
		}

		// 标记 result.records 为已解析（用于 execTool 的审计计数）
		result.records = deduped;
		return deduped;
	} finally {
		// 清理临时文件
		try {
			await rm(tmpDir, { recursive: true, force: true });
		} catch {
			// ignore
		}
	}
}
