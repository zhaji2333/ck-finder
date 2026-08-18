/**
 * /api/v1/sources REST 路由（M4.5）
 *
 * 基于 Hono 的最小实现，提供：
 *   GET  /api/v1/sources                    列出所有源码包（分页）
 *   GET  /api/v1/sources/:webappId          列出 webapp 的源码包
 *   GET  /api/v1/sources/:webappId/index    读取 INDEX.json
 *   GET  /api/v1/sources/:webappId/files    目录浏览（列出 source_dir 下的文件）
 *   GET  /api/v1/sources/:webappId/download 下载 tar.gz（首次访问时打包并缓存）
 *   GET  /api/v1/sources/dump/:id           查询单条记录
 *
 * 注意：完整 REST 服务在 M5 实现，这里只导出 Hono app，由 M5 的 server.ts 挂载。
 */

import { existsSync } from 'node:fs';
import { readFile, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, normalize, relative } from 'node:path';
import { Hono } from 'hono';
import * as tar from 'tar';
import {
	listSourceDumps,
	querySourceDumpById,
	querySourceDumpsByWebapp,
	updateArchivePath,
} from '../storage/models/source_dump.js';

export const sourcesApp = new Hono();

/**
 * GET /api/v1/sources
 * 列出所有源码包（分页）
 *
 * Query: ?limit=50&offset=0&onlyRestored=true
 */
sourcesApp.get('/', async (c) => {
	const limit = Number.parseInt(c.req.query('limit') ?? '50', 10);
	const offset = Number.parseInt(c.req.query('offset') ?? '0', 10);
	const onlyRestored = c.req.query('onlyRestored') === 'true';

	const { records, total } = await listSourceDumps({ limit, offset, onlyRestored });
	return c.json({ total, records });
});

/**
 * GET /api/v1/sources/:webappId
 * 列出 webapp 的所有源码包
 */
sourcesApp.get('/:webappId', async (c) => {
	const webappId = c.req.param('webappId');
	// UUID 格式校验
	if (!/^[0-9a-f-]{36}$/i.test(webappId)) {
		return c.json({ error: 'invalid webappId' }, 400);
	}

	const records = await querySourceDumpsByWebapp(webappId);
	if (records.length === 0) {
		return c.json({ error: 'no source dumps found for this webapp' }, 404);
	}
	return c.json({ records });
});

/**
 * GET /api/v1/sources/:webappId/index
 * 读取 INDEX.json
 */
sourcesApp.get('/:webappId/index', async (c) => {
	const webappId = c.req.param('webappId');
	if (!/^[0-9a-f-]{36}$/i.test(webappId)) {
		return c.json({ error: 'invalid webappId' }, 400);
	}

	const records = await querySourceDumpsByWebapp(webappId);
	if (records.length === 0) {
		return c.json({ error: 'no source dumps found' }, 404);
	}

	const dump = records[0];
	const indexPath = join(dump.sourceDir, dump.indexPath ?? 'INDEX.json');
	if (!existsSync(indexPath)) {
		return c.json({ error: 'INDEX.json not found' }, 404);
	}

	try {
		const content = await readFile(indexPath, 'utf8');
		return c.json(JSON.parse(content));
	} catch (err) {
		return c.json(
			{ error: `read INDEX.json failed: ${err instanceof Error ? err.message : err}` },
			500,
		);
	}
});

/**
 * GET /api/v1/sources/:webappId/files
 * 目录浏览（列出 source_dir 下的文件，支持 ?subdir= 缩小范围）
 *
 * Query: ?subdir=src&limit=500
 */
sourcesApp.get('/:webappId/files', async (c) => {
	const webappId = c.req.param('webappId');
	if (!/^[0-9a-f-]{36}$/i.test(webappId)) {
		return c.json({ error: 'invalid webappId' }, 400);
	}

	const records = await querySourceDumpsByWebapp(webappId);
	if (records.length === 0) {
		return c.json({ error: 'no source dumps found' }, 404);
	}

	const dump = records[0];
	const subdirRaw = c.req.query('subdir') ?? '';
	const limit = Number.parseInt(c.req.query('limit') ?? '500', 10);

	// 防止路径穿越
	const baseDir = normalize(dump.sourceDir);
	const targetDir = normalize(join(baseDir, subdirRaw));
	if (!targetDir.startsWith(baseDir)) {
		return c.json({ error: 'invalid subdir (path traversal detected)' }, 400);
	}

	if (!existsSync(targetDir)) {
		return c.json({ error: `directory not found: ${subdirRaw}` }, 404);
	}

	// 递归列出文件（最多 limit 个）
	const files: { path: string; size: number; isDir: boolean }[] = [];
	await listFilesRecursive(targetDir, baseDir, files, limit);

	return c.json({
		baseDir: relative(process.cwd(), baseDir),
		subdir: subdirRaw,
		count: files.length,
		truncated: files.length >= limit,
		files,
	});
});

/**
 * GET /api/v1/sources/:webappId/download
 * 下载 tar.gz（首次访问时打包并缓存到 source_dumps.archive_path）
 */
sourcesApp.get('/:webappId/download', async (c) => {
	const webappId = c.req.param('webappId');
	if (!/^[0-9a-f-]{36}$/i.test(webappId)) {
		return c.json({ error: 'invalid webappId' }, 400);
	}

	const records = await querySourceDumpsByWebapp(webappId);
	if (records.length === 0) {
		return c.json({ error: 'no source dumps found' }, 404);
	}

	const dump = records[0];
	if (!existsSync(dump.sourceDir)) {
		return c.json({ error: 'source directory not found on disk' }, 404);
	}

	// 如果已有 archive_path 且文件存在，直接返回
	let archivePath = dump.archivePath ?? '';
	if (!archivePath || !existsSync(archivePath)) {
		// 打包 tar.gz
		const tmpFile = join(tmpdir(), `source_${webappId}_${Date.now()}.tar.gz`);
		try {
			await tar.create(
				{
					gzip: true,
					file: tmpFile,
					cwd: dump.sourceDir,
				},
				['.'], // 打包整个 sourceDir
			);
			archivePath = tmpFile;
			await updateArchivePath(dump.id, archivePath);
		} catch (err) {
			return c.json(
				{ error: `tar.gz create failed: ${err instanceof Error ? err.message : err}` },
				500,
			);
		}
	}

	// 返回文件流
	const buffer = await readFile(archivePath);
	c.header('Content-Type', 'application/gzip');
	c.header('Content-Disposition', `attachment; filename="source_${webappId}.tar.gz"`);
	c.header('Content-Length', String(buffer.length));
	return c.body(buffer);
});

/**
 * GET /api/v1/sources/dump/:id
 * 查询单条记录
 */
sourcesApp.get('/dump/:id', async (c) => {
	const id = c.req.param('id');
	if (!/^[0-9a-f-]{36}$/i.test(id)) {
		return c.json({ error: 'invalid id' }, 400);
	}
	const record = await querySourceDumpById(id);
	if (!record) {
		return c.json({ error: 'not found' }, 404);
	}
	return c.json(record);
});

// =============================================================================
// 内部：递归列出文件
// =============================================================================

async function listFilesRecursive(
	currentDir: string,
	baseDir: string,
	out: { path: string; size: number; isDir: boolean }[],
	limit: number,
): Promise<void> {
	if (out.length >= limit) return;
	let entries: string[];
	try {
		entries = await readdir(currentDir);
	} catch {
		return;
	}
	for (const entry of entries) {
		if (out.length >= limit) return;
		const fullPath = join(currentDir, entry);
		let s;
		try {
			s = await stat(fullPath);
		} catch {
			continue;
		}
		const relPath = relative(baseDir, fullPath);
		if (s.isDirectory()) {
			out.push({ path: relPath, size: 0, isDir: true });
			// 递归（但限制深度避免过大）
			const depth = relPath.split('/').length;
			if (depth < 10) {
				await listFilesRecursive(fullPath, baseDir, out, limit);
			}
		} else {
			out.push({ path: relPath, size: s.size, isDir: false });
		}
	}
}
