/**
 * source_dumps 表的 CRUD model（M4.5）
 *
 * 表结构（migrations/001_init.sql 第 240-265 行）：
 *   id, webapp_id, source_dir, file_count, size_bytes, index_path,
 *   restored, complete, entry_points, archive_path, created_at, updated_at
 *
 * 功能：
 *   - upsertSourceDump: 写入/更新记录（source_collect.ts 已直接用 pool.query 实现，
 *     这里提供更高层的封装 + archive_path 更新）
 *   - querySourceDumpsByWebapp: 查询单 webapp 的所有源码包
 *   - querySourceDumpById: 查询单条
 *   - listSourceDumps: 列表（分页）
 *   - updateArchivePath: 更新 tar.gz 路径
 */

import { getPg } from '../pg.js';

export interface SourceDumpRecord {
	id: string;
	webappId: string;
	sourceDir: string;
	fileCount: number;
	sizeBytes: number;
	indexPath: string | null;
	restored: boolean;
	complete: boolean;
	entryPoints: string[];
	archivePath: string | null;
	createdAt: Date;
	updatedAt: Date;
}

interface SourceDumpRow {
	id: string;
	webapp_id: string;
	source_dir: string;
	file_count: number;
	size_bytes: string; // BIGINT 返回 string
	index_path: string | null;
	restored: boolean;
	complete: boolean;
	entry_points: string[];
	archive_path: string | null;
	created_at: Date;
	updated_at: Date;
}

function rowToRecord(r: SourceDumpRow): SourceDumpRecord {
	return {
		id: r.id,
		webappId: r.webapp_id,
		sourceDir: r.source_dir,
		fileCount: r.file_count,
		sizeBytes: Number.parseInt(r.size_bytes, 10),
		indexPath: r.index_path,
		restored: r.restored,
		complete: r.complete,
		entryPoints: r.entry_points ?? [],
		archivePath: r.archive_path,
		createdAt: r.created_at,
		updatedAt: r.updated_at,
	};
}

/**
 * 查询 webapp 的所有源码包
 */
export async function querySourceDumpsByWebapp(webappId: string): Promise<SourceDumpRecord[]> {
	const pool = getPg();
	const { rows } = await pool.query<SourceDumpRow>(
		'SELECT * FROM source_dumps WHERE webapp_id = $1 ORDER BY updated_at DESC',
		[webappId],
	);
	return rows.map(rowToRecord);
}

/**
 * 查询单条源码包
 */
export async function querySourceDumpById(id: string): Promise<SourceDumpRecord | null> {
	const pool = getPg();
	const { rows } = await pool.query<SourceDumpRow>('SELECT * FROM source_dumps WHERE id = $1', [
		id,
	]);
	return rows.length > 0 ? rowToRecord(rows[0]) : null;
}

/**
 * 列表（分页）
 */
export async function listSourceDumps(
	opts: {
		limit?: number;
		offset?: number;
		onlyRestored?: boolean;
	} = {},
): Promise<{ records: SourceDumpRecord[]; total: number }> {
	const pool = getPg();
	const limit = opts.limit ?? 50;
	const offset = opts.offset ?? 0;
	const where = opts.onlyRestored ? 'WHERE restored = true' : '';

	const { rows: countRows } = await pool.query(`SELECT COUNT(*) AS n FROM source_dumps ${where}`);
	const total = Number.parseInt(countRows[0].n, 10);

	const { rows } = await pool.query<SourceDumpRow>(
		`SELECT s.*, w.url AS webapp_url FROM source_dumps s
     LEFT JOIN webapps w ON s.webapp_id = w.asset_id
     ${where}
     ORDER BY s.updated_at DESC
     LIMIT $1 OFFSET $2`,
		[limit, offset],
	);
	return { records: rows.map(rowToRecord), total };
}

/**
 * 更新 archive_path（生成 tar.gz 后调用）
 */
export async function updateArchivePath(id: string, archivePath: string): Promise<void> {
	const pool = getPg();
	await pool.query('UPDATE source_dumps SET archive_path = $2, updated_at = now() WHERE id = $1', [
		id,
		archivePath,
	]);
}

/**
 * 删除源码包记录（不删文件）
 */
export async function deleteSourceDump(id: string): Promise<void> {
	const pool = getPg();
	await pool.query('DELETE FROM source_dumps WHERE id = $1', [id]);
}
