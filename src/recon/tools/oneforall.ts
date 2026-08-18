/**
 * OneForAll 适配器
 *
 * 子域发现工具（被动源聚合 + 主动爆破 + DNS 解析 + HTTP 探测）
 * 项目：https://github.com/shmilylty/OneForAll
 *
 * 命令格式：
 *   python oneforall.py --target <domain> --fmt json --path <output> \
 *     --brute <bool> --req <bool> --cdn <bool> --takeover <bool> run
 *
 * 输出：JSON 数组文件（--path 指定），每条记录包含：
 *   subdomain / ip / cname / cdn / source / alive / resolve / public / cidr / asn / org / addr / isp
 *
 * 注意：OneForAll 不会把结果输出到 stdout，必须用 --path 指定文件路径，再读取该文件。
 *       所以本适配器不走 execTool（execTool 走 stdout），直接用 child_process.spawn。
 */

import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { cacheGet, cacheSet } from '../storage/cache.js';

export interface OneForAllRecord {
	/** 子域名（小写） */
	subdomain: string;
	/** 解析到的 IP（逗号分隔字符串，OneForAll 输出格式） */
	ip?: string | null;
	/** CNAME 链（逗号分隔字符串） */
	cname?: string | null;
	/** 是否 CDN */
	cdn?: boolean | string | null;
	/** 来源模块 */
	source?: string | null;
	/** 是否存活（HTTP 探测后） */
	alive?: number | boolean | null;
	/** 是否解析成功 */
	resolve?: number | boolean | null;
	/** 是否公网 IP */
	public?: number | boolean | null;
	/** CIDR */
	cidr?: string | null;
	/** ASN */
	asn?: string | null;
	/** ORG */
	org?: string | null;
	/** ISP */
	isp?: string | null;
	/** 地理地址 */
	addr?: string | null;
	/** 端口 */
	port?: number | null;
}

export interface OneForAllOptions {
	/** 目标域名 */
	domain: string;
	/** 超时（毫秒），默认 10 分钟 */
	timeoutMs?: number;
	/** 启用 L2 缓存 */
	useCache?: boolean;
	/** 覆盖默认配置：是否爆破 */
	brute?: boolean;
	/** 覆盖默认配置：是否 HTTP 探测（默认 false，我们用 httpx 单独做） */
	httpProbe?: boolean;
	/** 覆盖默认配置：是否 CDN 检查 */
	cdnCheck?: boolean;
	/** 覆盖默认配置：是否接管检查 */
	takeover?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'oneforall',
	mode: 'passive',
	description: '子域发现工具（被动源聚合 + 主动爆破，OneForAll）',
	defaultTimeoutMs: 10 * 60 * 1000,
};

registerTool(TOOL_DEF);

/**
 * 执行 OneForAll 获取子域列表
 *
 * 默认配置（从 config 读）：
 * - brute=true（爆破）
 * - httpProbe=false（HTTP 探测交给 httpx）
 * - cdnCheck=false（CDN 库较老，交给 httpx -cdn）
 * - takeover=false（接管检查慢）
 *
 * 返回的记录会去重（按 subdomain），保留每条记录的元信息（ip/cname/cdn/source）。
 */
export async function runOneForAll(opts: OneForAllOptions): Promise<OneForAllRecord[]> {
	const cfg = getConfig().oneforall;
	const brute = opts.brute ?? cfg.brute;
	const httpProbe = opts.httpProbe ?? cfg.httpProbe;
	const cdnCheck = opts.cdnCheck ?? cfg.cdnCheck;
	const takeover = opts.takeover ?? cfg.takeover;
	const timeoutMs = opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs ?? 10 * 60 * 1000;

	// L2 缓存
	const cacheKey =
		opts.useCache !== false
			? `oneforall:domain:${opts.domain}:brute=${brute}:http=${httpProbe}:cdn=${cdnCheck}`
			: undefined;
	if (cacheKey) {
		const cached = await cacheGet<OneForAllRecord[]>(cacheKey);
		if (cached) {
			await auditLog({
				actor: 'tool:oneforall',
				action: 'tool_call',
				target: opts.domain,
				decision: 'pass',
				reason: 'L2 cache hit',
				meta: { cached: true, count: cached.length },
			});
			return cached;
		}
	}

	// 临时输出文件
	const tmpDir = await mkdtemp(join(tmpdir(), 'ofa-'));
	const outputPath = join(tmpDir, 'result.json');

	// 构造 Python 命令（优先用 venv 内的 python）
	// 注意：OneForAll 0.4.5 的 oneforall.py CLI 只支持 --target/--targets/--brute/--req/--takeover/--port/--fmt/--path/--alive/--show
	// --cdn 不在 CLI 参数里（在 config/setting.py），所以这里不传
	const pythonBin = cfg.python || resolve(cfg.dir, '.venv/bin/python');
	const args = [
		'oneforall.py',
		'--target',
		opts.domain,
		'--fmt',
		'json',
		'--path',
		outputPath,
		'--brute',
		String(brute),
		'--req',
		String(httpProbe),
		'--takeover',
		String(takeover),
		'--alive',
		'False', // 导出全部子域（含未存活），由后续 dnsx/httpx 验证
		'run',
	];

	const startedAt = Date.now();
	let exitCode: number | null = null;
	let stderr = '';

	try {
		const result = await new Promise<{ ok: boolean; stderr: string; exitCode: number | null }>(
			(resolvePromise) => {
				const child = spawn(pythonBin, args, {
					cwd: cfg.dir,
					stdio: ['ignore', 'ignore', 'pipe'],
					env: process.env,
				});
				let stderrBuf = '';
				child.stderr?.on('data', (chunk: Buffer) => {
					stderrBuf += chunk.toString('utf8');
					if (stderrBuf.length > 256 * 1024) stderrBuf = stderrBuf.slice(-256 * 1024);
				});
				const timer = setTimeout(() => {
					if (!child.killed) {
						child.kill('SIGTERM');
						setTimeout(() => {
							if (!child.killed) child.kill('SIGKILL');
						}, 2000);
					}
				}, timeoutMs);
				child.on('error', () => {
					clearTimeout(timer);
					resolvePromise({ ok: false, stderr: stderrBuf, exitCode: null });
				});
				child.on('close', (code, signal) => {
					clearTimeout(timer);
					if (signal === 'SIGTERM' || signal === 'SIGKILL') {
						resolvePromise({
							ok: false,
							stderr: `${stderrBuf}\nkilled by ${signal}`,
							exitCode: code,
						});
					} else if (code === 0) {
						resolvePromise({ ok: true, stderr: stderrBuf, exitCode: code });
					} else {
						resolvePromise({ ok: false, stderr: stderrBuf, exitCode: code });
					}
				});
			},
		);
		exitCode = result.exitCode;
		stderr = result.stderr;

		if (!result.ok) {
			throw new Error(
				`oneforall exited with code=${exitCode}, stderr tail:\n${stderr.slice(-2000)}`,
			);
		}

		// 读取 JSON 输出
		const raw = await readFile(outputPath, 'utf8');
		let parsed: OneForAllRecord[] = [];
		try {
			const data = JSON.parse(raw);
			parsed = Array.isArray(data) ? data : [data];
		} catch (err) {
			throw new Error(
				`oneforall: failed to parse output JSON: ${err instanceof Error ? err.message : String(err)}`,
			);
		}

		// 过滤 + 去重
		const seen = new Set<string>();
		const out: OneForAllRecord[] = [];
		for (const r of parsed) {
			const host = (r.subdomain ?? '').toLowerCase().trim();
			if (!host || seen.has(host)) continue;
			// OneForAll 会保留大量爆破字典里没解析的子域（resolve=0），保留它们让后续 dnsx 自己再验证一次
			// （OneForAll 用的解析器可能与我们 dnsx 的不同，部分它能解析我们也能）
			seen.add(host);
			out.push({ ...r, subdomain: host });
		}

		// L2 缓存写入
		if (cacheKey) {
			await cacheSet(cacheKey, out, { ttlSec: 3600 });
		}

		// 审计
		await auditLog({
			actor: 'tool:oneforall',
			action: 'tool_call',
			target: opts.domain,
			decision: 'allow',
			meta: {
				durationMs: Date.now() - startedAt,
				exitCode,
				recordCount: out.length,
				brute,
				httpProbe,
				cdnCheck,
			},
		});

		return out;
	} finally {
		// 清理临时目录
		try {
			await rm(tmpDir, { recursive: true, force: true });
		} catch {
			// ignore
		}
	}
}
