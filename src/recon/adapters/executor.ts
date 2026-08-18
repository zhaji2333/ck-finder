/**
 * 统一工具执行器
 *
 * 职责：
 * 1. 用 child_process.spawn 执行外部 CLI 工具
 * 2. 超时控制（kill 子进程组）
 * 3. 并发限速（p-limit 全局并发 + 主动工具 RPS 限速）
 * 4. stdout/stderr 捕获（带大小上限防 OOM）
 * 5. 可选 parser 解析输出为结构化记录
 * 6. 全量审计（写入 audit_log）
 *
 * 使用：
 *   const result = await execTool({
 *     command: 'subfinder',
 *     args: ['-d', 'example.com', '-json'],
 *   }, jsonlParser('subfinder'));
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import pLimit from 'p-limit';
import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { checkToolScope, hasDenied } from '../gate/scope_gate.js';
import { cacheGet, cacheSet } from '../storage/cache.js';
import type { OutputParser, ToolExecParams, ToolExecStatus, ToolResult } from './types.js';
import { ToolExecError } from './types.js';

/**
 * 解析工具命令路径
 *
 * 规则：
 * 1. 如果 command 已含路径分隔符（如 /usr/local/bin/gau），原样返回
 * 2. 否则查 TOOLS_BIN_DIR，若 join(binDir, command) 存在则返回该绝对路径
 * 3. 否则原样返回 command（交给 PATH 解析，避免 binDir 下未安装的工具被误拼成不存在路径）
 */
function resolveCommand(command: string): string {
	if (command.includes('/')) return command;
	const binDir = getConfig().tool.binDir;
	if (binDir) {
		const abs = join(binDir, command);
		if (existsSync(abs)) return abs;
	}
	return command;
}

// 全局并发限速器（所有工具共享）
let _globalLimit: ReturnType<typeof pLimit> | null = null;
let _activeRpsLimit: Map<number, number> | null = null; // 上次主动工具执行时间戳

function getGlobalLimit() {
	if (!_globalLimit) {
		const cfg = getConfig().tool;
		_globalLimit = pLimit(cfg.concurrency);
	}
	return _globalLimit;
}

/** 简易 RPS 限速（主动工具）：保证两次主动工具调用间隔 ≥ 1000/rps ms */
async function applyRpsLimit(rps: number): Promise<void> {
	if (rps <= 0) return;
	const interval = 1000 / rps;
	const now = Date.now();
	if (_activeRpsLimit === null) _activeRpsLimit = new Map();
	const last = _activeRpsLimit.get(0) ?? 0;
	const elapsed = now - last;
	if (elapsed < interval) {
		await new Promise<void>((resolve) => setTimeout(resolve, interval - elapsed));
	}
	_activeRpsLimit.set(0, Date.now());
}

/**
 * 执行外部工具
 *
 * @param params 执行参数
 * @param parser 可选输出解析器
 * @param cacheKey 可选缓存键；提供则启用 L2 缓存
 */
export async function execTool<T = unknown>(
	params: ToolExecParams,
	parser?: OutputParser<T>,
	cacheKey?: string,
): Promise<ToolResult<T>> {
	// L2 缓存命中检查
	if (cacheKey) {
		const cached = await cacheGet<ToolResult<T>>(cacheKey);
		if (cached) {
			await auditLog({
				actor: `tool:${params.command}`,
				action: 'tool_call',
				target: cacheKey,
				decision: 'pass',
				reason: 'L2 cache hit, skip execution',
				meta: { cached: true },
			});
			return cached;
		}
	}

	// Scope Gate 校验：拒绝则跳过执行
	const scopeResults = await checkToolScope(params.command, params.args, params.mode ?? 'passive');
	if (hasDenied(scopeResults)) {
		const denied = scopeResults.filter((r) => r.decision === 'deny');
		const reasons = denied.map((r) => `${r.target}: ${r.reason}`).join('; ');
		const result: ToolResult<T> = {
			tool: params.command,
			status: 'failed',
			exitCode: null,
			durationMs: 0,
			stdout: '',
			stderr: '',
			records: [],
			error: `blocked by scope gate: ${reasons}`,
		};
		await auditLog({
			actor: `tool:${params.command}`,
			action: 'tool_call',
			target: params.args.join(' '),
			decision: 'deny',
			reason: reasons,
			meta: { scopeBlocked: true, targets: denied.map((r) => r.target) },
		});
		return result;
	}

	// 决策点 3：高危动作 LLM 审批（适配器显式声明 judgeAction 时）
	//   deny → 跳过执行返回 failed（不抛错，管道已有失败处理）；allow/未声明 → 正常执行
	if (params.judgeAction) {
		const { judgeAction } = await import('../gate/llm_judge.js');
		const judge = await judgeAction({
			action: params.judgeAction,
			target: params.args.join(' ').slice(0, 500),
			context: { command: params.command, mode: params.mode ?? 'passive' },
		});
		if (judge.decision !== 'allow') {
			const result: ToolResult<T> = {
				tool: params.command,
				status: 'failed',
				exitCode: null,
				durationMs: 0,
				stdout: '',
				stderr: '',
				records: [],
				error: `blocked by LLM Judge (${params.judgeAction}): ${judge.reasoning}`,
			};
			await auditLog({
				actor: `tool:${params.command}`,
				action: 'tool_call',
				target: params.args.join(' '),
				decision: 'deny',
				reason: `LLM Judge denied ${params.judgeAction}: ${judge.reasoning}`,
				meta: { judgeBlocked: true, judgeAction: params.judgeAction, fromLlm: judge.fromLlm },
			});
			return result;
		}
	}

	// 全局并发 + 主动工具限速
	const limit = getGlobalLimit();
	const result = await limit(async () => {
		if (params.mode === 'active') {
			const cfg = getConfig().tool;
			await applyRpsLimit(cfg.activeRps);
		}
		return await runSpawn<T>(params, parser);
	});

	// L2 缓存写入（仅成功结果）
	if (cacheKey && result.status === 'ok') {
		await cacheSet(cacheKey, result, { ttlSec: 3600 });
	}

	// 审计
	await auditLog({
		actor: `tool:${params.command}`,
		action: 'tool_call',
		target: params.args.join(' '),
		decision: result.status === 'ok' ? 'allow' : 'fail',
		reason: result.error ?? `exit=${result.exitCode}`,
		meta: {
			durationMs: result.durationMs,
			status: result.status,
			recordCount: result.records.length,
		},
	});

	return result;
}

async function runSpawn<T>(
	params: ToolExecParams,
	parser?: OutputParser<T>,
): Promise<ToolResult<T>> {
	const cfg = getConfig().tool;
	const timeoutMs = params.timeoutMs ?? cfg.timeoutSec * 1000;
	const maxStdoutBytes = params.maxStdoutBytes ?? 10 * 1024 * 1024; // 10MB
	const startedAt = Date.now();

	return new Promise<ToolResult<T>>((resolve) => {
		const env = { ...process.env, ...params.env };
		const child = spawn(resolveCommand(params.command), params.args, {
			cwd: params.cwd ?? process.cwd(),
			env,
			stdio: ['pipe', 'pipe', 'pipe'],
			detached: false,
		});

		let stdoutBuf = '';
		let stderrBuf = '';
		let stdoutBytes = 0;
		let stderrBytes = 0;
		let timed = false;
		let settled = false;

		const timer = setTimeout(() => {
			timed = true;
			// 杀死子进程（先 SIGTERM 给清理机会，1 秒后 SIGKILL）
			if (!child.killed) {
				child.kill('SIGTERM');
				setTimeout(() => {
					if (!child.killed) child.kill('SIGKILL');
				}, 1000);
			}
		}, timeoutMs);

		// stdin 注入
		if (params.stdin !== undefined && child.stdin) {
			child.stdin.end(params.stdin);
		} else if (child.stdin) {
			child.stdin.end();
		}

		if (params.captureStdout !== false && child.stdout) {
			child.stdout.on('data', (chunk: Buffer) => {
				if (stdoutBytes < maxStdoutBytes) {
					stdoutBuf += chunk.toString('utf8');
					stdoutBytes += chunk.length;
				}
			});
		}
		if (child.stderr) {
			child.stderr.on('data', (chunk: Buffer) => {
				if (stderrBytes < 512 * 1024) {
					stderrBuf += chunk.toString('utf8');
					stderrBytes += chunk.length;
				}
			});
		}

		const finalize = (status: ToolExecStatus, exitCode: number | null, error?: string) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			const durationMs = Date.now() - startedAt;

			const records: T[] = [];
			if (status === 'ok' && parser && stdoutBuf) {
				try {
					records.push(...parser.parse(stdoutBuf));
				} catch (parseErr) {
					// 解析失败不影响工具执行结果，但在 error 中标注
					if (!error)
						error = `parse failed: ${parseErr instanceof Error ? parseErr.message : String(parseErr)}`;
				}
			}

			const result: ToolResult<T> = {
				tool: params.command,
				status,
				exitCode,
				durationMs,
				stdout: stdoutBuf,
				stderr: stderrBuf,
				records,
				error,
			};
			resolve(result);
		};

		child.on('error', (err) => {
			finalize('failed', null, `spawn error: ${err.message}`);
		});

		child.on('close', (code, signal) => {
			if (timed) {
				finalize('timeout', code, `timed out after ${timeoutMs}ms`);
			} else if (signal === 'SIGTERM' || signal === 'SIGKILL') {
				finalize('canceled', code, `killed by signal ${signal}`);
			} else if (code === 0) {
				finalize('ok', code);
			} else {
				finalize('failed', code, `non-zero exit: ${code}`);
			}
		});
	});
}

/**
 * 把工具输出落地到文件（用于 raw_output_path 字段）
 */
export async function dumpRawOutput(
	tool: string,
	content: string,
	outputDir: string,
): Promise<string> {
	const ts = new Date().toISOString().replace(/[:.]/g, '-');
	const filePath = resolve(outputDir, `${tool}-${ts}.txt`);
	await mkdir(dirname(filePath), { recursive: true });
	await writeFile(filePath, content, 'utf8');
	return filePath;
}

/**
 * 便捷方法：执行工具并断言成功，失败抛 ToolExecError
 */
export async function execToolOrThrow<T>(
	params: ToolExecParams,
	parser?: OutputParser<T>,
	cacheKey?: string,
): Promise<ToolResult<T>> {
	const result = await execTool(params, parser, cacheKey);
	if (result.status !== 'ok') {
		throw new ToolExecError(
			result.error ?? `tool ${params.command} failed`,
			params.command,
			result.status,
			result.exitCode,
			result.stderr,
		);
	}
	return result;
}
