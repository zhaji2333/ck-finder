/**
 * L2 探测结果缓存
 *
 * 设计（对应架构文档 §4.5 四层缓存设计）：
 * - L1 提供商前缀缓存：DeepSeek/OpenAI 内置，本层不涉及
 * - L2 探测结果缓存：本模块实现，按「资产+工具+TTL」缓存原始结果，避免重扫
 * - L3 语义缓存：远期，M5+
 * - L4 元数据仓库：直接查 PostgreSQL，0 token
 *
 * 缓存键：recon:{tool}:{targetType}:{targetNorm}
 * 例如：recon:subfinder:domain:example.com
 *
 * 命中策略：工具执行器在调用外部工具前先查 L2，命中则直接返回缓存结果，
 * 跳过实际工具调用；未命中则执行工具，结果写入 L2。
 */

import { getRedis } from './redis.js';

export interface CacheOptions {
	/** TTL 秒数，0 表示不缓存 */
	ttlSec?: number;
	/** 自定义键后缀（如参数 hash） */
	suffix?: string;
}

const DEFAULT_TTL_SEC = 3600; // 默认 1 小时

/**
 * 构造缓存键
 * @param tool 工具名（subfinder/dnsx/nmap/httpx ...）
 * @param targetType 目标类型（domain/ip/url/webapp ...）
 * @param targetNorm 归一化目标值
 * @param suffix 可选后缀（参数/选项 hash）
 */
export function buildCacheKey(
	tool: string,
	targetType: string,
	targetNorm: string,
	suffix?: string,
): string {
	const base = `recon:${tool}:${targetType}:${targetNorm}`;
	return suffix ? `${base}:${suffix}` : base;
}

/**
 * 读取缓存
 * @returns 缓存的反序列化结果；未命中返回 null
 */
export async function cacheGet<T>(key: string): Promise<T | null> {
	const redis = getRedis();
	const raw = await redis.get(key);
	if (raw === null) return null;
	try {
		return JSON.parse(raw) as T;
	} catch {
		// 损坏数据，删除
		await redis.del(key);
		return null;
	}
}

/**
 * 写入缓存
 */
export async function cacheSet<T>(key: string, value: T, opts: CacheOptions = {}): Promise<void> {
	const ttl = opts.ttlSec ?? DEFAULT_TTL_SEC;
	if (ttl <= 0) return;
	const redis = getRedis();
	const raw = JSON.stringify(value);
	await redis.set(key, raw, 'EX', ttl);
}

/**
 * 删除缓存
 */
export async function cacheDel(key: string): Promise<void> {
	const redis = getRedis();
	await redis.del(key);
}

/**
 * 按模式批量删除（如 recon:subfinder:*）
 * 注意：KEYS 在生产环境大库上会阻塞，这里用 SCAN
 */
export async function cacheDelPattern(pattern: string): Promise<number> {
	const redis = getRedis();
	let count = 0;
	let cursor = '0';
	do {
		const [next, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
		cursor = next;
		if (keys.length > 0) {
			await redis.del(...keys);
			count += keys.length;
		}
	} while (cursor !== '0');
	return count;
}

/**
 * 查询缓存状态（命中率/键数）
 */
export async function cacheStats(): Promise<{ keys: number; hits: number; misses: number }> {
	const redis = getRedis();
	// 只统计 recon: 前缀的键
	let count = 0;
	let cursor = '0';
	do {
		const [next, keys] = await redis.scan(cursor, 'MATCH', 'recon:*', 'COUNT', 100);
		cursor = next;
		count += keys.length;
	} while (cursor !== '0');

	// hits/misses 由调用方在 cacheGet 时累加（这里返回 Redis INFO 中的总数字）
	const info = await redis.info('stats');
	const parsed = parseRedisInfo(info);
	const hits = parsed.keyspace_hits ?? 0;
	const misses = parsed.keyspace_misses ?? 0;

	return { keys: count, hits, misses };
}

function parseRedisInfo(info: string): Record<string, number> {
	const out: Record<string, number> = {};
	for (const line of info.split('\n')) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) continue;
		const [k, v] = trimmed.split(':');
		if (k && v !== undefined) {
			const n = Number.parseInt(v, 10);
			if (!Number.isNaN(n)) out[k] = n;
		}
	}
	return out;
}

/**
 * 高阶工具：带 L2 缓存的工具执行包装
 *
 * 用法：
 *   const result = await withCache('subfinder', 'domain', 'example.com', async () => {
 *     return await runSubfinder('example.com');
 *   });
 */
export async function withCache<T>(
	tool: string,
	targetType: string,
	targetNorm: string,
	fn: () => Promise<T>,
	opts: CacheOptions = {},
): Promise<T> {
	const key = buildCacheKey(tool, targetType, targetNorm, opts.suffix);
	const cached = await cacheGet<T>(key);
	if (cached !== null) {
		return cached;
	}
	const result = await fn();
	await cacheSet(key, result, opts);
	return result;
}
