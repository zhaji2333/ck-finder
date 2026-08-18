/**
 * 数据库迁移运行器（合并后：作为 ck-finder 的 migrate 命令）
 *
 * 用法：
 *   ck-finder migrate                 # 执行所有未应用的迁移
 *   ck-finder migrate --status        # 查看迁移状态
 *
 * 迁移文件在 migrations/ 目录（NNN_description.sql），已应用的记录在 schema_migrations 表。
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import pg from 'pg';

const { Client } = pg;
const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = resolve(__dirname, '../../migrations');

/** 判断是否为直接运行入口（tsx 下 argv[1] 可能是 symlink，需归一化比较） */
function isMainEntry(): boolean {
	const entry = process.argv[1];
	if (!entry) return false;
	try {
		return import.meta.url === pathToFileURL(resolve(entry)).href;
	} catch {
		return false;
	}
}

export async function runMigrateCli(args: string[]): Promise<void> {
	const cmd = args[0] ?? 'up';

	const client = new Client({
		host: process.env.PG_HOST ?? '127.0.0.1',
		port: Number.parseInt(process.env.PG_PORT ?? '5432', 10),
		user: process.env.PG_USER ?? 'ckrecon',
		password: process.env.PG_PASSWORD ?? 'ckrecon_dev',
		database: process.env.PG_DB ?? 'ckrecon',
	});

	await client.connect();
	console.log(
		`[migrate] connected to ${process.env.PG_HOST ?? '127.0.0.1'}:${process.env.PG_PORT ?? '5432'}/${process.env.PG_DB ?? 'ckrecon'}`,
	);

	try {
		// 确保 schema_migrations 表存在
		await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version     TEXT PRIMARY KEY,
        applied_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        description TEXT
      );
    `);

		if (cmd === '--status' || cmd === 'status') {
			const { rows } = await client.query(
				'SELECT version, applied_at, description FROM schema_migrations ORDER BY version',
			);
			console.log('[migrate] applied migrations:');
			for (const row of rows) {
				console.log(
					`  ✓ ${row.version}  ${row.description ?? ''}  (${row.applied_at.toISOString()})`,
				);
			}
			return;
		}

		if (cmd === 'up' || cmd === undefined) {
			await migrateUp(client);
			return;
		}

		console.error(`[migrate] unknown command: ${cmd}`);
		console.error('Usage: ck-finder migrate [--status]');
		process.exitCode = 1;
	} finally {
		await client.end();
	}
}

async function migrateUp(client: pg.Client) {
	const files = readdirSync(MIGRATIONS_DIR)
		.filter((f) => f.endsWith('.sql'))
		.sort();

	console.log(`[migrate] found ${files.length} migration files`);

	const { rows: applied } = await client.query('SELECT version FROM schema_migrations');
	const appliedSet = new Set(applied.map((r) => r.version));

	let count = 0;
	for (const file of files) {
		const version = file.replace(/\.sql$/, '');
		if (appliedSet.has(version)) {
			console.log(`[migrate] skip ${version} (already applied)`);
			continue;
		}

		const filePath = join(MIGRATIONS_DIR, file);
		const sql = readFileSync(filePath, 'utf8');
		const description = extractDescription(sql, version);

		console.log(`[migrate] applying ${version} ...`);
		try {
			await client.query('BEGIN');
			await client.query(sql);
			await client.query(
				'INSERT INTO schema_migrations (version, description) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING',
				[version, description],
			);
			await client.query('COMMIT');
			console.log(`[migrate] ✓ ${version} applied`);
			count++;
		} catch (err) {
			await client.query('ROLLBACK');
			console.error(`[migrate] ✗ ${version} failed:`, err instanceof Error ? err.message : err);
			throw err;
		}
	}

	console.log(`[migrate] done, ${count} migration(s) applied`);
}

function extractDescription(sql: string, version: string): string {
	// 从 SQL 注释中提取描述（第一行非空注释）
	for (const line of sql.split('\n')) {
		const m = line.match(/^--\s*(.+)$/);
		if (m && !m[1].startsWith('=') && !m[1].toLowerCase().includes('ck-recon')) {
			return m[1].trim();
		}
	}
	return version;
}

// 直接运行（node/tsx src/recon/migrate.ts 或 scripts 转发）时执行
if (isMainEntry()) {
	runMigrateCli(process.argv.slice(2)).catch((err) => {
		console.error('[migrate] fatal:', err);
		process.exit(1);
	});
}
