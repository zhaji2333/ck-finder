/**
 * 环境自检：Node 版本 / DeepSeek Key / PG / Redis / 收集引擎状态 / 工具二进制探测。
 */
import { getConfig } from './recon/config.js';
import { closePg, pgHealthCheck } from './recon/storage/pg.js';
import { closeRedis, redisHealthCheck } from './recon/storage/redis.js';
import { type BinInfo, check as checkBin } from './tools/binary.js';

export async function checkToolchain(): Promise<void> {
	console.log('[doctor] ck-finder 环境自检\n');

	// Node 版本
	const [major] = process.versions.node.split('.').map(Number);
	console.log(
		`[doctor] Node ${process.versions.node} ${(major ?? 0) >= 22 ? 'OK' : 'FAIL: 需要 >= 22'}`,
	);

	// DeepSeek API Key（config 需要它，缺失则跳过依赖 config 的检查）
	try {
		getConfig();
		console.log('[doctor] DEEPSEEK_API_KEY OK 已设置');
	} catch {
		console.log('[doctor] DEEPSEEK_API_KEY FAIL: 复制 .env.example 为 .env');
		console.log('[doctor] 其余检查跳过（配置不可用）');
		return;
	}

	// PostgreSQL
	try {
		const v = await pgHealthCheck();
		console.log(`[doctor] PostgreSQL OK (${v})`);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.log(`[doctor] PostgreSQL MISS: ${msg}`);
	}

	// Redis
	try {
		const pong = await redisHealthCheck();
		console.log(`[doctor] Redis OK (${pong})`);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.log(`[doctor] Redis MISS（降级为缓存不可用，不影响扫描）: ${msg}`);
	}

	// 收集引擎数据概览（PG 可用时）
	try {
		const { queryWebapps } = await import('./recon/storage/models/query.js');
		const { total } = await queryWebapps({ scoreGt: 60, limit: 1 });
		console.log(`[doctor] 收集引擎: webapps(score>60) >= ${total}（可用）`);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.log(`[doctor] 收集引擎: 暂不可用（${msg}）`);
	}

	// 工具二进制
	console.log('[doctor] 工具链:');
	const tools: Record<string, string> = {
		subfinder: 'subfinder',
		dnsx: 'dnsx',
		httpx: 'httpx',
		nmap: 'nmap',
		nuclei: 'nuclei',
		katana: 'katana',
		dirsearch: 'dirsearch',
	};
	const entries: Array<[string, string]> = Object.entries(tools);
	const results = await Promise.all(
		entries.map(async ([name, bin]) => [name, await checkBin(bin)] as [string, BinInfo]),
	);
	for (const [name, info] of results) {
		const icon = info.found ? 'OK' : 'MISS';
		console.log(
			`  ${icon} ${name}: ${info.found ? `${info.path} (${info.version ?? '?'})` : `未找到 ${info.wanted ?? name}`}`,
		);
	}
	const missing = results.filter(([, info]) => !info.found);
	if (missing.length > 0) {
		console.log(`\n[doctor] 缺失工具（收集/验证需要）: ${missing.map(([n]) => n).join(', ')}`);
		console.log('[doctor] 安装参考: bash scripts/install_tools.sh');
	}

	await Promise.all([closePg(), closeRedis()]);
}
