/**
 * M2.6 Metadata 快照
 *
 * 把单个 webapp 的所有相关信息聚合成一个 JSON 快照，便于：
 * - 渗透 Agent 直接消费
 * - 持久化到 webapp_snapshots 表
 * - REST API 返回
 *
 * Schema v1.1：
 *   {
 *     "schema_version": "1.1",
 *     "webapp": { url, host, port, scheme, path, title, status_code, webserver, tech, ... },
 *     "role": { role, confidence, rule_id, evidence, source: 'rule'|'llm'|'fingerprint' },
 *     "score": { score, hard_to_attack, breakdown: [...] },
 *     "task_gate": { level, suggested_next: [...], reason },
 *     "fingerprints": [{ name, branch_index, evidence }, ...],
 *     "known_cve_hints": [{ component, type, cve, severity, description, suggested_next, evidence }, ...],
 *     "endpoints": [],                  // M3 填充
 *     "js_apis": [],                     // M3/M4 填充
 *     "params": [],                      // M3 填充
 *     "flags": { cdn, waf, cdn_name, cnames, login_page },  // M3 完善
 *     "source_available": null,          // M4 填充
 *     "site": { framework, language, build_tool, architecture, js_file_count, webpack_detected, source_available },  // v1.1 单站模式
 *     "snapshot_at": "2026-..."
 *   }
 */

import { getPg } from '../storage/pg.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface WebappSnapshot {
	schema_version: string;
	webapp: {
		id: string;
		url: string;
		url_norm: string;
		final_url?: string | null;
		host: string;
		port: number;
		scheme: string;
		path: string;
		title?: string | null;
		status_code?: number | null;
		webserver?: string | null;
		tech: string[];
		body_preview?: string | null;
		favicon_hash?: number | null;
		cdn: boolean;
		cdn_name?: string | null;
		waf?: string | null;
		first_seen: string;
		last_seen: string;
	};
	role: {
		role: string;
		confidence: number;
		rule_id: string;
		evidence: string;
		/** 来源：'rule' | 'fingerprint' | 'llm' */
		source: string;
	};
	score: {
		score: number;
		hard_to_attack: boolean;
		breakdown: Array<{ name: string; delta: number; reason: string }>;
		/** v1.3 LLM 评分复核（高分认定），未复核为 null */
		review: {
			role_confirmed: boolean;
			suggested_role: string | null;
			score_adjustment: number;
			is_high_value: boolean;
			reasoning: string;
			from_llm: boolean;
		} | null;
		/** v1.3 评分阶段：initial（初评）| final（终评，深挖后） */
		stage: string;
	};
	task_gate: {
		level: string;
		suggested_next: string[];
		reason: string;
	};
	fingerprints: Array<{
		name: string;
		branch_index: number;
		evidence: Array<{ field: string; op: string; value: string }>;
		matched_at: string;
	}>;
	known_cve_hints: Array<{
		component: string;
		type: string;
		cve: string;
		severity: string;
		description: string;
		suggested_next: string;
		evidence: string;
	}>;
	// M3+ 填充的字段，M2 阶段先留空数组
	endpoints: unknown[];
	js_apis: unknown[];
	params: unknown[];
	flags: {
		cdn: boolean;
		cdn_name?: string | null;
		waf?: string | null;
		cnames?: string[];
		login_page: boolean;
		hard_to_attack: boolean;
	};
	source_available: boolean | null;
	/** v1.2：单站模式收集的站信息（框架/语言/构建工具/架构 + LLM 架构级分析），未分析时为 null */
	site: {
		framework: string[] | null;
		language: string[] | null;
		build_tool: string[] | null;
		architecture: string | null;
		js_file_count: number | null;
		webpack_detected: boolean | null;
		source_available: boolean | null;
		/** v1.2 LLM 架构级分析 */
		rendering: string | null;
		api_style: string | null;
		auth_mechanism: string | null;
		third_party: string[] | null;
	} | null;
	/** v1.2 LLM 接口聚类攻击面地图（auth/upload/export/payment/debug/admin/user 分组），未分析时为 null */
	attack_surface: {
		groups: Record<string, string[]>;
		summary: string;
		recommendations: string[];
	} | null;
	snapshot_at: string;
}

// =============================================================================
// 快照生成
// =============================================================================

/**
 * 为单个 webapp 生成 metadata 快照
 *
 * @param webappId webapp 资产 ID（assets.id）
 * @returns 完整快照对象
 */
export async function generateSnapshot(webappId: string): Promise<WebappSnapshot> {
	const pool = getPg();

	// 1. 查 webapp 主表
	const { rows: webappRows } = await pool.query(
		`SELECT asset_id, url, url_norm, final_url, host, port, scheme, path, title, status_code,
            webserver, tech, body_preview, favicon_hash, cdn, waf, role, score, score_breakdown,
            hard_to_attack, login_page, suggested_next, meta, first_seen, last_seen
     FROM webapps WHERE asset_id = $1`,
		[webappId],
	);
	if (webappRows.length === 0) {
		throw new Error(`webapp not found: ${webappId}`);
	}
	const w = webappRows[0];
	const meta = w.meta ?? {};

	// 2. 查指纹命中
	const { rows: fpRows } = await pool.query(
		`SELECT fingerprint, branch_index, evidence, matched_at
     FROM webapp_fingerprints WHERE webapp_id = $1`,
		[webappId],
	);

	// 3. 查 LLM 分类（如果有）
	const { rows: llmRows } = await pool.query(
		`SELECT role, confidence, reasoning, provider, model FROM llm_classifications
     WHERE webapp_id = $1 ORDER BY created_at DESC LIMIT 1`,
		[webappId],
	);

	// 4. 查已保存的 CVE hint（来自 vuln_hints 表，如果有）
	//    M2.3 阶段 vuln_hints 是即时计算的，不持久化。
	//    这里从 webapp meta.cve_hints 读（如果存在），否则空数组。
	const cveHints = (meta.cve_hints as WebappSnapshot['known_cve_hints']) ?? [];

	// 5. M3：查询 endpoints / js_apis / params（深度扫描产出）
	const [endpointRows, jsApiRows, paramRows] = await Promise.all([
		pool.query(
			`SELECT url, path, method, source, status_code, discovered_at
       FROM endpoints WHERE webapp_id = $1
       ORDER BY discovered_at DESC LIMIT 500`,
			[webappId],
		),
		pool.query(
			`SELECT api_path, method, params, source_js, found_at
       FROM js_apis WHERE webapp_id = $1
       ORDER BY found_at DESC LIMIT 500`,
			[webappId],
		),
		pool.query(
			`SELECT param, source, context, discovered_at
       FROM params WHERE webapp_id = $1
       ORDER BY discovered_at DESC LIMIT 500`,
			[webappId],
		),
	]);

	// 6. 组装 snapshot
	const siteSection: WebappSnapshot['site'] = {
		framework: meta.site_framework ?? null,
		language: meta.site_language ?? null,
		build_tool: meta.site_build_tool ?? null,
		architecture: meta.site_architecture ?? null,
		js_file_count: typeof meta.site_js_file_count === 'number' ? meta.site_js_file_count : null,
		webpack_detected:
			typeof meta.site_webpack_detected === 'boolean' ? meta.site_webpack_detected : null,
		source_available: typeof meta.source_available === 'boolean' ? meta.source_available : null,
		// v1.2 LLM 架构级分析
		rendering: typeof meta.site_rendering === 'string' ? meta.site_rendering : null,
		api_style: typeof meta.site_api_style === 'string' ? meta.site_api_style : null,
		auth_mechanism: typeof meta.site_auth_mechanism === 'string' ? meta.site_auth_mechanism : null,
		third_party: Array.isArray(meta.site_third_party) ? (meta.site_third_party as string[]) : null,
	};

	// v1.2 LLM 攻击面地图
	const attackSurfaceSection: WebappSnapshot['attack_surface'] = meta.attack_surface
		? {
				groups: meta.attack_surface as Record<string, string[]>,
				summary: typeof meta.attack_surface_summary === 'string' ? meta.attack_surface_summary : '',
				recommendations: Array.isArray(meta.attack_surface_recommendations)
					? (meta.attack_surface_recommendations as string[])
					: [],
			}
		: null;

	const snapshot: WebappSnapshot = {
		schema_version: '1.3',
		webapp: {
			id: w.asset_id,
			url: w.url,
			url_norm: w.url_norm,
			final_url: w.final_url,
			host: w.host,
			port: w.port,
			scheme: w.scheme,
			path: w.path,
			title: w.title,
			status_code: w.status_code,
			webserver: w.webserver,
			tech: w.tech ?? [],
			body_preview: w.body_preview,
			favicon_hash: w.favicon_hash,
			cdn: w.cdn,
			cdn_name: meta.cdn_name ?? null,
			waf: w.waf,
			first_seen: w.first_seen?.toISOString(),
			last_seen: w.last_seen?.toISOString(),
		},
		role: {
			role: w.role ?? 'unknown',
			confidence: meta.role_confidence ?? 0,
			rule_id: meta.role_rule_id ?? 'unknown',
			evidence: meta.role_evidence ?? '',
			source: llmRows.length > 0 ? 'llm' : (meta.role_source ?? 'rule'),
		},
		score: {
			score: w.score,
			hard_to_attack: w.hard_to_attack,
			breakdown: w.score_breakdown ?? [],
			review: meta.score_review
				? (meta.score_review as {
						role_confirmed: boolean;
						suggested_role: string | null;
						score_adjustment: number;
						is_high_value: boolean;
						reasoning: string;
						from_llm: boolean;
					})
				: null,
			stage: typeof meta.score_stage === 'string' ? meta.score_stage : 'initial',
		},
		task_gate: {
			level: meta.task_level ?? 'L0',
			suggested_next: w.suggested_next ?? [],
			reason: meta.task_reason ?? '',
		},
		fingerprints: fpRows.map(
			(r: {
				fingerprint: string;
				branch_index: number;
				evidence: unknown;
				matched_at: { toISOString: () => string };
			}) => ({
				name: r.fingerprint,
				branch_index: r.branch_index,
				evidence: r.evidence as Array<{ field: string; op: string; value: string }>,
				matched_at: r.matched_at?.toISOString(),
			}),
		),
		known_cve_hints: cveHints,
		endpoints: endpointRows.rows,
		js_apis: jsApiRows.rows,
		params: paramRows.rows,
		flags: {
			cdn: w.cdn,
			cdn_name: meta.cdn_name ?? null,
			waf: w.waf,
			cnames: meta.cnames ?? [],
			login_page: w.login_page,
			hard_to_attack: w.hard_to_attack,
		},
		source_available: typeof meta.source_available === 'boolean' ? meta.source_available : null,
		site: siteSection,
		attack_surface: attackSurfaceSection,
		snapshot_at: new Date().toISOString(),
	};

	return snapshot;
}

/**
 * 持久化快照到 webapp_snapshots 表
 */
export async function saveSnapshot(webappId: string, snapshot: WebappSnapshot): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO webapp_snapshots (webapp_id, snapshot, schema_version)
     VALUES ($1, $2, $3)`,
		[webappId, JSON.stringify(snapshot), snapshot.schema_version],
	);
}

/**
 * 生成 + 持久化快照
 */
export async function generateAndSaveSnapshot(webappId: string): Promise<WebappSnapshot> {
	const snapshot = await generateSnapshot(webappId);
	await saveSnapshot(webappId, snapshot);
	return snapshot;
}
