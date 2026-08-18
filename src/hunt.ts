import { buildAttackSurfaceIntent } from './agents/playbook.js';
import { runWorker } from './agents/worker.js';
/**
 * 直接打目标挖洞（M4.10，对齐 AutoHunter：免收集 + 凭据注入 + 多 worker 并发）
 *
 * 用法: ck-finder hunt --targets "http://host:8080,http://host:8082/login.html" [--concurrency 4]
 *
 * 与 runCampaign（收集驱动）的区别：
 *   - 不跑 runRecon（免 nmap/httpx/评分/dirscan 全收集，省 5-8 分钟/目标）
 *   - 直接对目标 URL 建 webapp 记录 → 派「攻击面遍历」意图 → worker 用 http_req 挖
 *   - 支持登录凭据注入（CKFINDER_HUNT_CREDENTIALS：cookie/账密/authorization）
 *   - 多目标并发（默认 4，AutoHunter 同款）
 */
import { ExplorationStore } from './graph/store.js';
import { getConfig } from './recon/config.js';

export interface HuntTarget {
	/** 目标 URL（含路径，如 http://host:8082/login.html） */
	url: string;
	/** 登录凭据（可选：cookie/账密/authorization） */
	cookie?: string;
	username?: string;
	password?: string;
	authorization?: string;
}

export interface HuntOptions {
	targets: HuntTarget[];
	/** 并发数（默认 4，AutoHunter 同款） */
	concurrency?: number;
	/** 每目标超时（默认 20 分钟） */
	timeoutMs?: number;
	/** 初始引导提示词（注入 worker 提示词） */
	goal?: string;
	onLog?: (msg: string) => void;
}

function log(o: HuntOptions, msg: string): void {
	o.onLog?.(msg);
	console.log(`[hunt] ${msg}`);
}

/** 目标 URL → host（含端口，凭据匹配用） */
function hostOf(url: string): string {
	try {
		return new URL(url).host; // 含端口，如 192.0.2.10:8082
	} catch {
		return url.toLowerCase();
	}
}

/** 目标 URL → hostname（scope 校验用，不含端口） */
function hostnameOf(url: string): string {
	try {
		return new URL(url).hostname.toLowerCase();
	} catch {
		return url.toLowerCase();
	}
}

/** 从 config 或 HuntTarget 拿该 host 的凭据 */
function credentialFor(
	target: HuntTarget,
): { cookie?: string; username?: string; password?: string; authorization?: string } | null {
	const cfg = getConfig();
	const host = hostOf(target.url);
	const fromCfg = cfg.agent.huntCredentials[host];
	const cred =
		fromCfg ?? (target.cookie || target.username || target.authorization ? target : null);
	return cred;
}

/** 为单个目标建 webapp 记录（免 runRecon，直接入库） */
async function ensureWebapp(seedId: string, targetUrl: string): Promise<string | null> {
	const pool = (await import('./recon/storage/pg.js')).getPg();
	const u = new URL(targetUrl);
	const origin = `${u.protocol}//${u.host}`;
	const { upsertWebapp } = await import('./recon/storage/models/asset.js');
	try {
		const assetId = await upsertWebapp(targetUrl, origin, {
			seedId,
			discoveredBy: 'direct-hunt',
			scheme: u.protocol.replace(':', ''),
			host: u.hostname,
			port: Number(u.port) || (u.protocol === 'https:' ? 443 : 80),
			path: u.pathname,
			finalUrl: targetUrl,
			title: targetUrl,
			statusCode: 200,
		});
		return assetId;
	} catch {
		// webapp 已存在或创建失败 → 查已有
		const { rows } = await pool.query(
			'SELECT a.id FROM assets a WHERE a.seed_id = $1 AND a.value_norm = $2 LIMIT 1',
			[seedId, origin],
		);
		return rows[0]?.id ?? null;
	}
}

/** 执行单个目标的挖洞（攻击面遍历意图 → worker） */
async function huntTarget(
	o: HuntOptions,
	target: HuntTarget,
	seedId: string,
	store: ExplorationStore,
): Promise<void> {
	const cred = credentialFor(target);
	// 攻击面遍历从 origin（根站）开始，而非登录页路径——确保覆盖全站攻击面
	const rootUrl = (() => {
		try {
			const u = new URL(target.url);
			return `${u.protocol}//${u.host}/`;
		} catch {
			return target.url;
		}
	})();
	const tmpl = buildAttackSurfaceIntent(rootUrl);

	// 凭据注入提示（AutoHunter auth_bootstrap）
	const credHint = cred?.cookie
		? `\n【登录态】目标已提供 Cookie: ${cred.cookie.slice(0, 60)}，http_req 请携带 cookie=${cred.cookie}`
		: cred?.username
			? `\n【登录态】目标已提供凭据 ${cred.username}/****，请先登录获取会话（http_req 登录成功后带 cookie）`
			: cred?.authorization
				? `\n【登录态】目标已提供 Authorization: Bearer ${cred.authorization.slice(0, 40)}...，http_req 请携带`
				: '';

	// 入库意图（用返回值，保证与 DB 一致）
	const intent = await store.createIntent({
		seedId,
		intentType: tmpl.intentType,
		description: tmpl.description + credHint,
		priority: 1,
		scopeAnchor: hostnameOf(target.url),
		depth: 0,
	});

	log(o, `[${target.url}] worker 开始（凭据${cred ? '✓' : '✗'}）`);
	const result = await runWorker({
		seedId,
		scope: [hostnameOf(target.url), ...getConfig().agent.scope],
		modelId: 'deepseek-v4-flash',
		store,
		intent,
		goal: o.goal,
		timeoutMs: o.timeoutMs ?? 20 * 60 * 1000,
	});
	log(o, `[${target.url}] worker 完成: ${result.status} fact=${result.factCount}`);
}

/**
 * 主入口：直接打多个目标。
 */
export async function runDirectHunt(o: HuntOptions): Promise<void> {
	const concurrency = Math.min(o.concurrency ?? 4, o.targets.length);
	const store = new ExplorationStore();

	// 每个目标建一个 seed（隔离意图/finding）
	log(o, `目标 ${o.targets.length} 个，并发 ${concurrency}`);

	let cursor = 0;
	const workers = Array.from({ length: concurrency }, async () => {
		for (;;) {
			const i = cursor++;
			if (i >= o.targets.length) return;
			const target = o.targets[i]!;
			try {
				const { normalizeSeed } = await import('./recon/seeds/normalizer.js');
				const { upsertSeed, updateSeedStatus } = await import('./recon/storage/models/asset.js');
				// 用 host:port 作为 seed（防跨目标串扰），hostOf 已含端口
				const seedValue = hostOf(target.url);
				const normalized = normalizeSeed(
					seedValue.includes(':') && !seedValue.startsWith('http')
						? `http://${seedValue}`
						: seedValue,
				);
				const seedId = await upsertSeed(normalized);
				await updateSeedStatus(seedId, 'running');
				// 标记为挖洞任务（区分收集任务，前端显示 ⚔ 挖洞 标签）
				await (await import('./recon/storage/pg.js'))
					.getPg()
					.query(`UPDATE seeds SET meta = meta || '{"hunt":true}'::jsonb WHERE id = $1`, [seedId]);
				// 建 webapp 记录（免 runRecon）
				await ensureWebapp(seedId, target.url);
				await huntTarget(o, target, seedId, store);
				// 挖洞完成：seed 标 done（否则一直 pending，任务列表状态误导）
				await updateSeedStatus(seedId, 'done');
			} catch (e) {
				log(o, `[${target.url}] 失败: ${e instanceof Error ? e.message : String(e)}`);
			}
		}
	});
	await Promise.all(workers);
	log(o, `全部 ${o.targets.length} 目标挖洞完成`);
}
