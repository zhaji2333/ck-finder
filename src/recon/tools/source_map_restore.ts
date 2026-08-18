/**
 * source-map 还原器（M4.3）
 *
 * 使用 Mozilla 的 source-map 库（已安装 ^0.7.4）把 .map 文件还原为原始源码。
 *
 * 流程：
 *   1. 读取 .map 文件内容
 *   2. 用 SourceMapConsumer 解析
 *   3. 遍历 sources 数组，逐个用 sourceContentFor() 取出原始源码
 *   4. 按 sources 路径写入 sources/<domain>/src/ 目录
 *
 * 输出：
 *   - restoredFiles: 还原成功的文件列表（相对路径）
 *   - failedFiles: 还原失败的文件（无 sourcesContent）
 *   - entryPoints: 推断的入口文件（webpack:///webpack/bootstrap、main.tsx 等）
 *
 * 注意：
 *   - source-map 0.7.4 是回调风格，需要 Promise 包装
 *   - 部分老 .map 没有 sourcesContent 字段（只有映射关系），无法还原源码，只能记录路径
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { SourceMapConsumer } from 'source-map';
import { auditLog } from '../gate/audit_log.js';

export interface RestoreResult {
	/** 还原的文件数 */
	restoredCount: number;
	/** 失败数（无 sourcesContent） */
	failedCount: number;
	/** 还原的文件相对路径列表（相对 srcDir） */
	restoredFiles: string[];
	/** 失败的文件路径列表（仅有路径无内容） */
	failedFiles: string[];
	/** 推断的入口文件 */
	entryPoints: string[];
	/** 总写入字节数 */
	totalBytes: number;
	/** 还原耗时（ms） */
	durationMs: number;
}

export interface RestoreOptions {
	/** .map 文件路径（本地） */
	mapFilePath: string;
	/** 还原源码落地目录（sources/<domain>/src/） */
	outputDir: string;
	/** 是否保留 webpack 前缀（如 webpack:///./src/） */
	keepWebpackPrefix?: boolean;
}

/**
 * 还原单个 .map 文件到源码目录
 *
 * @returns 还原结果（文件列表、入口、字节数）
 */
export async function restoreSourceMap(opts: RestoreOptions): Promise<RestoreResult> {
	const startTs = Date.now();
	const result: RestoreResult = {
		restoredCount: 0,
		failedCount: 0,
		restoredFiles: [],
		failedFiles: [],
		entryPoints: [],
		totalBytes: 0,
		durationMs: 0,
	};

	// 读取 .map 文件
	let mapContent: string;
	try {
		const { readFile } = await import('node:fs/promises');
		mapContent = await readFile(opts.mapFilePath, 'utf8');
	} catch (err) {
		await auditLog({
			actor: 'tool:source_map_restore',
			action: 'tool_call',
			target: opts.mapFilePath,
			decision: 'deny',
			reason: `read map file failed: ${err instanceof Error ? err.message : String(err)}`,
		});
		result.durationMs = Date.now() - startTs;
		return result;
	}

	let mapData: unknown;
	try {
		mapData = JSON.parse(mapContent);
	} catch (err) {
		await auditLog({
			actor: 'tool:source_map_restore',
			action: 'tool_call',
			target: opts.mapFilePath,
			decision: 'deny',
			reason: `parse map JSON failed: ${err instanceof Error ? err.message : String(err)}`,
		});
		result.durationMs = Date.now() - startTs;
		return result;
	}

	// source-map 0.7.4 是回调风格，用 Promise 包装
	const consumer = await new Promise<SourceMapConsumer>((resolvePromise, reject) => {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		new SourceMapConsumer(mapData as any).then(resolvePromise, reject);
	});

	try {
		// sources 数组包含所有原始文件路径
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const sources = (consumer as any).sources as string[];

		for (const sourcePath of sources) {
			// 跳过 webpack 内部文件（如 webpack:///webpack/bootstrap）
			// 但保留有源码的 webpack:///.//xxx
			const normalizedPath = normalizeSourcePath(sourcePath, opts.keepWebpackPrefix !== false);
			if (!normalizedPath || isInternalWebpackPath(sourcePath)) {
				continue;
			}

			// 尝试获取原始源码
			let sourceContent: string | null = null;
			try {
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				sourceContent = (consumer as any).sourceContentFor(sourcePath, true);
			} catch {
				// 忽略，标记为 failed
			}

			if (!sourceContent) {
				result.failedCount++;
				result.failedFiles.push(normalizedPath);
				continue;
			}

			// 写入文件
			const outPath = resolve(opts.outputDir, normalizedPath);
			try {
				await mkdir(dirname(outPath), { recursive: true });
				await writeFile(outPath, sourceContent, 'utf8');
				result.restoredCount++;
				result.restoredFiles.push(normalizedPath);
				result.totalBytes += Buffer.byteLength(sourceContent, 'utf8');

				// 检测入口文件
				if (isEntryPoint(sourcePath, sourceContent)) {
					result.entryPoints.push(normalizedPath);
				}
			} catch (_err) {
				result.failedCount++;
				result.failedFiles.push(normalizedPath);
			}
		}

		// 如果入口为空，取 sources 的第一个常见入口名
		if (result.entryPoints.length === 0) {
			const guessed = guessEntryPoint(sources);
			if (guessed)
				result.entryPoints.push(guessEntryPath(guessed, opts.keepWebpackPrefix !== false));
		}
	} finally {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		(consumer as any).destroy();
	}

	result.durationMs = Date.now() - startTs;

	await auditLog({
		actor: 'tool:source_map_restore',
		action: 'tool_call',
		target: opts.mapFilePath,
		decision: 'pass',
		reason: `restored=${result.restoredCount} failed=${result.failedCount} bytes=${result.totalBytes} entries=${result.entryPoints.length}`,
		meta: {
			mapFile: opts.mapFilePath,
			restoredCount: result.restoredCount,
			failedCount: result.failedCount,
			totalBytes: result.totalBytes,
			durationMs: result.durationMs,
		},
	});

	return result;
}

// =============================================================================
// 内部工具函数
// =============================================================================

/**
 * 标准化 source-map 中的源文件路径
 *
 * source-map 路径格式多样：
 *   - webpack:///./src/main.tsx     → src/main.tsx
 *   - webpack:///src/main.tsx      → src/main.tsx
 *   - webpack:///../node_modules/   → node_modules/...（保留依赖）
 *   - ./src/main.tsx                → src/main.tsx
 *   - ../shared/utils.ts            → shared/utils.ts
 *
 * @param keepWebpackPrefix 是否保留 webpack:/// 前缀（默认 false，去掉）
 */
function normalizeSourcePath(sourcePath: string, keepWebpackPrefix: boolean): string | null {
	let p = sourcePath;

	// 去掉 webpack:/// 协议前缀
	if (!keepWebpackPrefix) {
		p = p.replace(/^webpack:\/\/\//, '');
		p = p.replace(/^webpack:\/\//, '');
		p = p.replace(/^webpack:/, '');
	}

	// 去掉开头的 ./
	p = p.replace(/^\.\//, '');
	// 去掉开头的 ../（不能确定上层目录，直接保留相对名）
	p = p.replace(/^(\.\.\/)+/, '');

	// 防止路径穿越（去掉开头的 /）
	p = p.replace(/^\/+/, '');

	// 过滤空路径和特殊路径
	if (!p || p.startsWith('data:')) return null;

	return p;
}

/**
 * 判断是否是 webpack 内部路径（不还原）
 *
 *   - webpack:///webpack/bootstrap
 *   - webpack:///webpack/runtime/...
 *   - webpack/internal
 */
function isInternalWebpackPath(sourcePath: string): boolean {
	return (
		/webpack:\/\/\/webpack\/(bootstrap|runtime)/i.test(sourcePath) ||
		/webpack:\/\/internal/i.test(sourcePath)
	);
}

/**
 * 推断文件是否是入口文件
 *
 * 启发式规则：
 *   - 文件名包含 main/index/app/entry/bootstrap
 *   - 内容包含 createApp(/render(/ReactDOM
 *   - 内容包含 import.*from ['"]react/vue/next/nuxt
 */
function isEntryPoint(sourcePath: string, content: string): boolean {
	const lowerPath = sourcePath.toLowerCase();
	if (/\b(main|index|app|entry|bootstrap|client|server)\.(t|j)sx?$/i.test(lowerPath)) {
		return true;
	}
	// 内容检测（前 1000 字符）
	const head = content.slice(0, 1000);
	if (/createApp\s*\(|ReactDOM\.render|hydrateRoot|createRoot/i.test(head)) {
		return true;
	}
	return false;
}

/**
 * 从 sources 列表猜测入口文件
 */
function guessEntryPoint(sources: string[]): string | null {
	// 优先级：main > index > app > entry
	const patterns = [
		/\bmain\.(t|j)sx?$/i,
		/\bindex\.(t|j)sx?$/i,
		/\bapp\.(t|j)sx?$/i,
		/\bentry\.(t|j)sx?$/i,
		/\bclient\.(t|j)sx?$/i,
	];
	for (const p of patterns) {
		const hit = sources.find((s) => p.test(s));
		if (hit) return hit;
	}
	return null;
}

function guessEntryPath(sourcePath: string, keepWebpackPrefix: boolean): string {
	const n = normalizeSourcePath(sourcePath, keepWebpackPrefix);
	return n ?? sourcePath;
}
