/**
 * LLM 受控请求执行器（llm_probe）
 *
 * 需求：LLM 评分复核时"证据不足"，可以提议探测特定路径——由系统带护栏发包，证据回填后再终判。
 *
 * 安全护栏（铁律）：
 *   1. 只允许相对路径或同 host 的绝对 URL（绝对 URL 强制校验 host === webapp.host，否则丢弃）
 *   2. 每 webapp 每次复核最多 1 轮探测（≤3 个路径）
 *   3. 单请求超时 8s，响应 body 上限 200KB（预览截 500 字）
 *   4. 并发 1（串行探测），全程 audit_log（tool=llm_probe）
 *   5. 探测失败不影响判定（用现有证据）
 *   6. 只发 GET 请求，不做任何攻击性探测
 */

import { auditLog } from '../gate/audit_log.js';

export interface ProbePath {
	path: string;
	status: number | null;
	title?: string;
	contentType?: string;
	/** 页面预览（500 字内，去空白） */
	bodyPreview?: string;
	error?: string;
}

export interface ProbeOptions {
	/** 每轮最多探测数（默认 3） */
	maxProbes?: number;
	/** 单请求超时（ms，默认 8000） */
	timeoutMs?: number;
}

/**
 * 受控探测一组路径（同 host 约束）
 *
 * @param baseUrl 目标站点根（如 https://example.com）
 * @param paths LLM 提议的路径（相对路径或同 host 绝对 URL）
 * @param webappId 审计用
 * @returns 探测结果（按输入顺序，被护栏丢弃的标记 error）
 */
export async function probePaths(
	baseUrl: string,
	paths: string[],
	webappId: string,
	opts: ProbeOptions = {},
): Promise<ProbePath[]> {
	const maxProbes = opts.maxProbes ?? 3;
	const timeoutMs = opts.timeoutMs ?? 8_000;

	let base: URL;
	try {
		base = new URL(baseUrl);
	} catch {
		return paths
			.slice(0, maxProbes)
			.map((p) => ({ path: p, status: null, error: 'invalid baseUrl' }));
	}
	const baseHost = base.hostname.toLowerCase();

	// 护栏：过滤路径（最多 maxProbes 个）
	const allowed: string[] = [];
	const rejected: string[] = [];
	for (const p of paths.slice(0, maxProbes * 2)) {
		if (allowed.length >= maxProbes) {
			rejected.push(p);
			continue;
		}
		try {
			if (p.startsWith('http://') || p.startsWith('https://')) {
				const u = new URL(p);
				if (u.hostname.toLowerCase() === baseHost) {
					allowed.push(p);
				} else {
					rejected.push(p);
				}
			} else if (p.startsWith('/')) {
				allowed.push(p);
			} else {
				rejected.push(p);
			}
		} catch {
			rejected.push(p);
		}
	}

	const results: ProbePath[] = [];
	for (const p of rejected) {
		results.push({ path: p, status: null, error: 'blocked by guardrail (cross-host or non-path)' });
	}

	// 串行探测（并发 1）
	for (const p of allowed) {
		const target = p.startsWith('http') ? p : `${base.origin}${p}`;
		const r = await probeOne(target, timeoutMs);
		results.push({ path: p, ...r });
		await auditLog({
			actor: 'tool:llm_probe',
			action: 'tool_call',
			target: target.slice(0, 300),
			decision: r.status !== null ? 'allow' : 'fail',
			reason: r.error ?? `HTTP ${r.status}`,
			meta: { webappId, path: p, status: r.status, timeoutMs },
		});
	}

	return results;
}

async function probeOne(url: string, timeoutMs: number): Promise<Omit<ProbePath, 'path'>> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await fetch(url, {
			method: 'GET',
			signal: controller.signal,
			headers: {
				'User-Agent': 'Mozilla/5.0 (compatible; ck-recon/0.1; llm-probe)',
				Accept: 'text/html,application/json,*/*',
			},
			redirect: 'follow',
		});
		clearTimeout(timer);
		if (!resp.ok) {
			return {
				status: resp.status,
				contentType: resp.headers.get('content-type') ?? undefined,
				error: undefined,
			};
		}
		const text = await resp.text();
		if (text.length > 200_000) {
			return {
				status: resp.status,
				contentType: resp.headers.get('content-type') ?? undefined,
				error: 'body too large',
			};
		}
		const title = text.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim();
		return {
			status: resp.status,
			title,
			contentType: resp.headers.get('content-type') ?? undefined,
			bodyPreview: text.replace(/\s+/g, ' ').trim().slice(0, 500),
		};
	} catch (err) {
		clearTimeout(timer);
		return { status: null, error: err instanceof Error ? err.message.slice(0, 120) : String(err) };
	}
}
