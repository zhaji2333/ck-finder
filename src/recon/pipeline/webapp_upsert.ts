/**
 * httpx 记录 → webapp 资产入库（共享模块）
 *
 * 从 runner.ts 拆出，供 domain 管道与单站管道（single_site.ts）复用：
 * - 把 httpx 探测结果批量入库为 webapp 资产
 * - 入库时用 body/header/title/server/favicon 做指纹库匹配
 * - CDN 厂商名 + CNAME 链记入 webapp.meta
 */

import { type FingerMatchResult, matchFingerprints } from '../scoring/fingerprints.js';
import { upsertWebapp, upsertWebappFingerprints } from '../storage/models/asset.js';
import type { HttpxRecord } from '../tools/httpx.js';

/** 把 httpx 记录批量入库为 webapp 资产，返回去重后的入库数 */
export async function upsertWebappRecords(
	seedId: string,
	records: HttpxRecord[],
	parentAssetId: string,
): Promise<number> {
	const insertedIds = new Set<string>();
	for (const r of records) {
		if (!r.url) continue;
		let parsedUrl: URL;
		try {
			parsedUrl = new URL(r.url);
		} catch {
			continue;
		}
		const scheme = parsedUrl.protocol.replace(':', '');
		const host = parsedUrl.hostname.toLowerCase();
		const defaultPort = scheme === 'https' ? 443 : 80;
		const port = parsedUrl.port ? Number.parseInt(parsedUrl.port, 10) : defaultPort;
		const urlNorm = `${scheme}://${host}${port !== defaultPort ? `:${port}` : ''}${parsedUrl.pathname.replace(/\/+$/, '') || '/'}`;

		// 指纹匹配：用 httpx 抓到的 body/header/title/server/favicon 做指纹库匹配
		let fingerprintHits: FingerMatchResult[] = [];
		try {
			fingerprintHits = matchFingerprints({
				body: r.body_preview,
				header: r.header
					? Object.entries(r.header)
							.map(([k, v]) => `${k}: ${v}`)
							.join('\r\n')
					: undefined,
				title: r.title ?? undefined,
				server: r.webserver ?? undefined,
				icon_hash: r.favicon ? String(r.favicon) : undefined,
			});
		} catch {
			// 指纹库未加载等异常不阻塞
		}
		const fingerprintNames = fingerprintHits.map((h) => h.name);

		const webappId = await upsertWebapp(r.url, urlNorm, {
			seedId,
			parentId: parentAssetId,
			discoveredBy: 'httpx',
			scheme,
			host,
			port,
			path: parsedUrl.pathname || '/',
			finalUrl: r.location ?? r.url,
			title: r.title,
			statusCode: r.status_code,
			tech: Array.isArray(r.tech) ? r.tech : r.tech ? [r.tech] : [],
			webserver: r.webserver,
			cdn: r.cdn,
			waf: r.waf,
			bodyPreview: r.body_preview,
			responseHeader: r.header,
			faviconHash: r.favicon,
			fingerprints: fingerprintNames,
		});

		// 写指纹命中证据（webapp_fingerprints 表）
		if (fingerprintHits.length > 0) {
			try {
				await upsertWebappFingerprints(
					webappId,
					fingerprintHits.map((h) => ({
						name: h.name,
						branchIndex: h.branchIndex,
						evidence: h.evidence.map((e) => ({ field: e.field, op: e.op, value: e.value })),
					})),
				);
			} catch {
				// 指纹证据写失败不阻塞
			}
		}

		// CDN 厂商名 + CNAME 链记入 asset meta（httpx -cdn 输出 cdn_name 字段）
		if (r.cdn_name || r.cnames?.length) {
			try {
				const pool = (await import('../storage/pg.js')).getPg();
				await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE url_norm = $2', [
					JSON.stringify({
						cdn_name: r.cdn_name ?? null,
						cnames: r.cnames ?? [],
					}),
					urlNorm,
				]);
			} catch {
				// meta 写失败不阻塞主流程
			}
		}
		insertedIds.add(webappId);
	}
	return insertedIds.size;
}
