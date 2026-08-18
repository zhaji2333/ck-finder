/**
 * PostgreSQL 连接池
 *
 * 业务代码统一用 getPg() 获取 Pool，避免散落的 new Pool 实例。
 */

import pg from 'pg';
import { getConfig } from '../config.js';

let _pool: pg.Pool | null = null;

export function getPg(): pg.Pool {
	if (!_pool) {
		const cfg = getConfig().db;
		_pool = new pg.Pool({
			host: cfg.host,
			port: cfg.port,
			user: cfg.user,
			password: cfg.password,
			database: cfg.database,
			max: cfg.poolMax,
			idleTimeoutMillis: 30_000,
			connectionTimeoutMillis: 5_000,
		});
	}
	return _pool;
}

/** 测试连接 + 关闭池（用于优雅退出与测试） */
export async function closePg(): Promise<void> {
	if (_pool) {
		await _pool.end();
		_pool = null;
	}
}

/** 健康检查：返回数据库版本字符串 */
export async function pgHealthCheck(): Promise<string> {
	const pool = getPg();
	const { rows } = await pool.query('SELECT version() AS v');
	return rows[0]?.v ?? 'unknown';
}
