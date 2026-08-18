/**
 * Redis 客户端（ioredis）
 *
 * 用于 L2 探测结果缓存 + 限速计数器 + 分布式锁。
 *
 * 合并后修复：Redis 不可用时**降级**而非崩溃。
 * 原实现无 error 监听，ioredis 连接失败触发 unhandled 'error' 事件导致 Node 进程 crash。
 * 现在挂 error 监听（只打日志），命令 reject 由调用方 try/catch 吞掉 → 缓存不可用，
 * 管道/查询照常降级运行。
 */

import { Redis } from 'ioredis';
import { getConfig } from '../config.js';

let _redis: Redis | null = null;
let _redisDown = false;

export function getRedis(): Redis {
	if (!_redis) {
		const cfg = getConfig().redis;
		_redis = new Redis({
			host: cfg.host,
			port: cfg.port,
			db: cfg.db,
			lazyConnect: false,
			maxRetriesPerRequest: 3,
			enableReadyCheck: true,
		});
		// 降级修复：任何 Redis 错误只记录，不让进程崩溃
		_redis.on('error', (err: Error) => {
			if (!_redisDown) {
				_redisDown = true;
				console.warn(`[redis] 连接异常，降级为缓存不可用（继续运行）: ${err.message}`);
			}
		});
		_redis.on('ready', () => {
			if (_redisDown) {
				console.log('[redis] 连接恢复');
			}
			_redisDown = false;
		});
	}
	return _redis;
}

/** Redis 当前是否可用（供 doctor / 状态显示） */
export function redisAvailable(): boolean {
	return _redis !== null && !_redisDown && _redis.status === 'ready';
}

export async function closeRedis(): Promise<void> {
	if (_redis) {
		await _redis.quit();
		_redis = null;
		_redisDown = false;
	}
}

export async function redisHealthCheck(): Promise<string> {
	const r = getRedis();
	const pong = await r.ping();
	return pong === 'PONG' ? 'PONG' : 'unhealthy';
}
