/**
 * M2 评分流水线
 *
 * 串联 M2 所有模块：
 *   指纹匹配（已在 pipeline 入库时跑）→ 角色规则 → LLM 兜底 → 评分 → 漏洞关联 → 任务门控 → 持久化 → 快照
 *
 * 调用入口：
 *   1. pipeline.runner 在 webapp 入库后调 `scoreWebappById(webappId)`
 *   2. CLI 单独调 `scoreSeed(seedId)` 给整批 webapp 跑评分
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { type TechProfile, adjustByTechProfile, computeTaskGate } from '../gate/task_gate.js';
import { getPg } from '../storage/pg.js';
import { scoreWebapp } from './engine.js';
import { classifyByLlm } from './llm_classifier.js';
import { type AssetRole, type RoleMatchInput, matchRole } from './roles.js';
import { generateAndSaveSnapshot } from './snapshot.js';
import { type VulnHint, matchVulnHints } from './vuln_hints.js';

// =============================================================================
// 单个 webapp 评分
// =============================================================================

interface WebappRow {
	asset_id: string;
	url: string;
	url_norm: string;
	host: string;
	path: string;
	title: string | null;
	tech: string[];
	webserver: string | null;
	body_preview: string | null;
	response_header: Record<string, string> | null;
	fingerprints: string[];
	cdn: boolean;
	waf: string | null;
	login_page: boolean;
	status_code: number | null;
	meta: Record<string, unknown> | null;
}

async function loadWebapp(webappId: string): Promise<WebappRow | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT asset_id, url, url_norm, host, path, title, tech, webserver, body_preview, response_header,
            fingerprints, cdn, waf, login_page, status_code, meta
     FROM webapps WHERE asset_id = $1`,
		[webappId],
	);
	return rows[0] ?? null;
}

function headerToString(h: Record<string, string> | null): string | undefined {
	if (!h) return undefined;
	return Object.entries(h)
		.map(([k, v]) => `${k}: ${v}`)
		.join('\r\n');
}

/**
 * 给单个 webapp 跑完整 M2 评分流水线
 *
 * @param webappId webapp 资产 ID
 * @param opts.skipLlm 跳过 LLM 兜底（默认 false）
 * @returns 评分结果摘要
 */
export async function scoreWebappById(
	webappId: string,
	opts: { skipLlm?: boolean } = {},
): Promise<{
	role: string;
	roleConfidence: number;
	roleSource: string;
	score: number;
	hardToAttack: boolean;
	level: string;
	suggestedNext: string[];
	vulnHints: VulnHint[];
}> {
	const w = await loadWebapp(webappId);
	if (!w) throw new Error(`webapp not found: ${webappId}`);

	// 1. 角色规则匹配（含指纹优先）
	const roleInput: RoleMatchInput = {
		host: w.host,
		path: w.path,
		title: w.title,
		tech: w.tech ?? [],
		webserver: w.webserver,
		statusCode: w.status_code,
		loginPage: w.login_page,
		fingerprints: w.fingerprints ?? [],
	};
	let roleMatch = matchRole(roleInput);
	let roleSource = roleMatch.ruleId.startsWith('fingerprint:') ? 'fingerprint' : 'rule';

	// 2. LLM 兜底：confidence < 0.7 才调
	if (!opts.skipLlm && roleMatch.confidence < 0.7) {
		try {
			const llmResult = await classifyByLlm({
				webappId,
				url: w.url,
				host: w.host,
				path: w.path,
				title: w.title,
				tech: w.tech ?? [],
				webserver: w.webserver ?? undefined,
				fingerprints: w.fingerprints ?? [],
				bodyPreview: w.body_preview,
				ruleRole: roleMatch.role,
				ruleConfidence: roleMatch.confidence,
			});
			// LLM 结果置信度更高才采纳
			if (llmResult.fromLlm && llmResult.confidence > roleMatch.confidence) {
				roleMatch = {
					role: llmResult.role,
					confidence: llmResult.confidence,
					ruleId: `llm:${llmResult.provider}/${llmResult.model}`,
					evidence: llmResult.reasoning,
				};
				roleSource = 'llm';
			}
		} catch (err) {
			// LLM 失败不阻塞，继续用规则结果
			console.warn(`[scoring] LLM fallback failed for ${webappId}:`, err);
		}
	}

	// 3. 漏洞组件关联（先于评分，供评分上下文使用）
	const vulnHints = matchVulnHints({
		fingerprints: w.fingerprints ?? [],
		tech: w.tech ?? [],
		title: w.title,
		body: w.body_preview,
		header: headerToString(w.response_header),
	});

	// 3.5 技术栈画像（来自指纹/tech/单站分析 meta）→ 评分上下文 + 任务规划
	const meta = w.meta ?? {};
	const siteFramework = Array.isArray(meta.site_framework) ? (meta.site_framework as string[]) : [];
	const techProfile: TechProfile = {
		fingerprints: w.fingerprints ?? [],
		tech: w.tech ?? [],
		framework: siteFramework,
		architecture: typeof meta.site_architecture === 'string' ? meta.site_architecture : null,
		webpackDetected: meta.site_webpack_detected === true,
		sourceAvailable: meta.source_available === true,
		isApi:
			roleMatch.role === 'api' ||
			/(^|\/)(api|graphql|swagger)(\/|$)/i.test(w.path) ||
			/^api\./i.test(w.host),
	};

	// 4. 评分（含技术栈上下文：已知漏洞组件/CMS/开发设施/纯 SPA）
	const scoreResult = scoreWebapp({
		role: roleMatch.role,
		roleConfidence: roleMatch.confidence,
		loginPage: w.login_page,
		fingerprintCount: (w.fingerprints ?? []).length,
		hasAdminPath: /(^|\/)(admin|manage|console|dashboard|backend)(\/|$)/i.test(w.path),
		cdn: w.cdn,
		waf: !!w.waf,
		vulnHintCount: vulnHints.length,
		fingerprints: w.fingerprints ?? [],
		tech: w.tech ?? [],
		siteArchitecture: techProfile.architecture,
	});

	// 4.5 LLM 评分复核：规则分达到阈值（默认 70）必须过 LLM 认定，防止"高分莫名其妙"
	let scoreReview: Awaited<ReturnType<typeof import('./llm_score_review.js').reviewScoreByLlm>> =
		null;
	let finalScore = scoreResult.score;
	const finalBreakdown = [...scoreResult.breakdown];
	if (
		getConfig().llm.scoreReviewEnabled &&
		scoreResult.score >= getConfig().llm.scoreReviewThreshold
	) {
		try {
			const { reviewScoreByLlm } = await import('./llm_score_review.js');
			scoreReview = await reviewScoreByLlm({
				webappId,
				url: w.url,
				host: w.host,
				path: w.path,
				title: w.title,
				tech: w.tech ?? [],
				fingerprints: w.fingerprints ?? [],
				webserver: w.webserver,
				bodyPreview: w.body_preview,
				role: roleMatch.role,
				roleSource,
				score: scoreResult.score,
				breakdown: scoreResult.breakdown,
			});
			if (scoreReview) {
				finalScore = Math.max(0, Math.min(100, scoreResult.score + scoreReview.scoreAdjustment));
				if (scoreReview.scoreAdjustment !== 0) {
					finalBreakdown.push({
						name: 'llm_review',
						delta: scoreReview.scoreAdjustment,
						reason: `LLM 评分复核: ${scoreReview.reasoning}`,
					});
				}
				// 角色被推翻 → 用建议角色重算基础分
				if (!scoreReview.roleConfirmed && scoreReview.suggestedRole) {
					roleMatch = {
						role: scoreReview.suggestedRole,
						confidence: Math.min(roleMatch.confidence, 0.6),
						ruleId: `llm_review:${scoreReview.suggestedRole}`,
						evidence: scoreReview.reasoning,
					};
					roleSource = 'llm_review';
					const rescore = scoreWebapp({
						role: roleMatch.role,
						roleConfidence: roleMatch.confidence,
						loginPage: w.login_page,
						fingerprintCount: (w.fingerprints ?? []).length,
						hasAdminPath: /(^|\/)(admin|manage|console|dashboard|backend)(\/|$)/i.test(w.path),
						cdn: w.cdn,
						waf: !!w.waf,
						vulnHintCount: vulnHints.length,
						fingerprints: w.fingerprints ?? [],
						tech: w.tech ?? [],
						siteArchitecture: techProfile.architecture,
					});
					finalScore = Math.max(0, Math.min(100, rescore.score + scoreReview.scoreAdjustment));
					finalBreakdown.length = 0;
					finalBreakdown.push(...rescore.breakdown);
					if (scoreReview.scoreAdjustment !== 0) {
						finalBreakdown.push({
							name: 'llm_review',
							delta: scoreReview.scoreAdjustment,
							reason: `LLM 评分复核: ${scoreReview.reasoning}`,
						});
					}
				}
				console.log(
					`[scoring] score_review ${w.url}: score ${scoreResult.score} → ${finalScore} highValue=${scoreReview.isHighValue} (${scoreReview.reasoning})`,
				);
			}
		} catch (err) {
			console.warn('[scoring] score_review LLM failed (non-blocking):', err);
		}
	}

	// 5. 任务门控（用复核后的分数；未获 LLM 高价值认定的不升级 L2/L3）
	let gate = computeTaskGate({
		score: finalScore,
		role: roleMatch.role,
		hardToAttack: scoreResult.hardToAttack,
		vulnHintCount: vulnHints.length,
	});
	if (scoreReview && !scoreReview.isHighValue && (gate.level === 'L2' || gate.level === 'L3')) {
		gate = {
			...gate,
			level: 'L1',
			suggestedNext: ['dirscan', 'history_url'],
			reason: `${gate.reason}; LLM 评分复核未认定高价值（isHighValue=false），强制降级 → L1`,
		};
		console.log(`[scoring] score_review 未认定高价值，${w.url} 降级 L2/L3 → L1`);
	}
	gate = adjustByTechProfile(gate, techProfile);

	// 5.5 决策点 2：LLM 任务选择兜底（规则画像信息不足时补充建议，只增不减）
	if (
		getConfig().llm.taskSelectEnabled &&
		gate.level !== 'L0' &&
		(w.fingerprints ?? []).length === 0 &&
		siteFramework.length === 0 &&
		techProfile.architecture === null
	) {
		try {
			const { selectTasksByLlm } = await import('./llm_task_select.js');
			const llmSel = await selectTasksByLlm({
				webappId,
				url: w.url,
				host: w.host,
				path: w.path,
				title: w.title,
				tech: w.tech ?? [],
				fingerprints: w.fingerprints ?? [],
				framework: siteFramework,
				architecture: techProfile.architecture,
				score: scoreResult.score,
				role: roleMatch.role,
				level: gate.level,
				ruleTasks: gate.suggestedNext,
			});
			if (llmSel && llmSel.addTasks.length > 0) {
				const merged = [...gate.suggestedNext];
				for (const t of llmSel.addTasks) {
					if (!merged.includes(t)) merged.push(t);
				}
				gate = {
					...gate,
					suggestedNext: merged,
					reason: `${gate.reason}; LLM 补充任务 [${llmSel.addTasks.join(',')}]${llmSel.rejectedRemovals.length > 0 ? `（移除建议被忽略: [${llmSel.rejectedRemovals.join(',')}]）` : ''}`,
				};
				console.log(
					`[scoring] task_select LLM: add=[${llmSel.addTasks.join(',')}] → suggested=[${merged.join(',')}]`,
				);
			}
		} catch (err) {
			console.warn('[scoring] task_select LLM failed (non-blocking):', err);
		}
	}

	// 6. 持久化到 webapps 表
	const pool = getPg();
	const headerStr = headerToString(w.response_header);
	await pool.query(
		`UPDATE webapps
     SET role = $1,
         score = $2,
         score_breakdown = $3,
         hard_to_attack = $4,
         login_page = $5,
         suggested_next = $6,
         meta = meta || $7::jsonb
     WHERE asset_id = $8`,
		[
			roleMatch.role,
			finalScore,
			JSON.stringify(finalBreakdown),
			scoreResult.hardToAttack,
			w.login_page,
			gate.suggestedNext,
			JSON.stringify({
				role_confidence: roleMatch.confidence,
				role_rule_id: roleMatch.ruleId,
				role_evidence: roleMatch.evidence,
				role_source: roleSource,
				task_level: gate.level,
				task_reason: gate.reason,
				cve_hints: vulnHints,
				// LLM 评分复核结果（高分认定）
				...(scoreReview
					? {
							score_review: {
								role_confirmed: scoreReview.roleConfirmed,
								suggested_role: scoreReview.suggestedRole,
								score_adjustment: scoreReview.scoreAdjustment,
								is_high_value: scoreReview.isHighValue,
								reasoning: scoreReview.reasoning,
								from_llm: scoreReview.fromLlm,
							},
							score_reviewed_at: new Date().toISOString(),
						}
					: {}),
				// 同时把 header 字符串塞进 meta，便于后续 vuln_hints 复查
				...(headerStr ? { header_str: headerStr.slice(0, 4000) } : {}),
			}),
			webappId,
		],
	);

	await auditLog({
		actor: 'system',
		action: 'data_write',
		target: webappId,
		decision: 'pass',
		reason: 'scoring_complete',
		meta: {
			role: roleMatch.role,
			roleSource,
			score: finalScore,
			level: gate.level,
			vulnHintCount: vulnHints.length,
			...(scoreReview
				? {
						scoreReview: {
							adjustment: scoreReview.scoreAdjustment,
							highValue: scoreReview.isHighValue,
						},
					}
				: {}),
		},
	});

	// 7. 生成 + 持久化快照
	try {
		await generateAndSaveSnapshot(webappId);
	} catch (err) {
		console.warn(`[scoring] snapshot save failed for ${webappId}:`, err);
	}

	return {
		role: roleMatch.role,
		roleConfidence: roleMatch.confidence,
		roleSource,
		score: finalScore,
		hardToAttack: scoreResult.hardToAttack,
		level: gate.level,
		suggestedNext: gate.suggestedNext,
		vulnHints,
	};
}

// =============================================================================
// 终评（深挖后基于证据重新评分）
// =============================================================================

/**
 * 终评：deep-scan 完成后，基于真实证据（JS 接口数/页面分类/敏感发现/sourcemap/技术栈画像）重新评分
 *
 * 与初评的区别：
 *   - 初评：只有 httpx 指纹/标题/tech，分数基于猜测 → 只做门控
 *   - 终评：深挖证据齐全（接口/端点/发现/画像），带证据重评 → 真实价值
 *
 * 规则：先规则重评（engine 证据项），≥阈值再过 LLM 复核（forceRefresh，防止初评虚高延续）
 */
export async function scoreWebappFinal(webappId: string): Promise<{
	webappId: string;
	score: number;
	level: string;
	role: string;
	suggestedNext: string[];
}> {
	const pool = getPg();
	const { rows } = await pool.query(
		'SELECT w.*, a.seed_id FROM webapps w JOIN assets a ON w.asset_id = a.id WHERE w.asset_id = $1',
		[webappId],
	);
	if (rows.length === 0) throw new Error(`webapp not found: ${webappId}`);
	const w = rows[0];
	const meta = w.meta ?? {};

	// 1. 深挖证据统计
	const [{ rows: epRows }, { rows: apiRows }, { rows: findingRows }] = await Promise.all([
		pool.query('SELECT page_role FROM endpoints WHERE webapp_id = $1', [webappId]),
		pool.query('SELECT COUNT(*)::int AS n FROM js_apis WHERE webapp_id = $1', [webappId]),
		// 终评只认"硬"发现（sensitive_path/sourcemap）；secret 正则误报率高不作评分证据（仍展示给 Agent）
		pool.query(
			`SELECT COUNT(*)::int AS n FROM findings WHERE webapp_id = $1 AND type IN ('sensitive_path','sourcemap')`,
			[webappId],
		),
	]);
	const hvEndpoints = (epRows ?? []).filter((e: { page_role?: string }) =>
		['login', 'admin', 'upload', 'export', 'payment'].includes(e.page_role ?? ''),
	).length;
	const jsApiCount = apiRows[0]?.n ?? 0;
	const findingCount = findingRows[0]?.n ?? 0;
	const sourceAvailable = meta.source_available === true;

	// 2. 技术栈画像（深挖已补齐）
	const siteFramework = Array.isArray(meta.site_framework) ? (meta.site_framework as string[]) : [];
	const techProfile: TechProfile = {
		fingerprints: w.fingerprints ?? [],
		tech: w.tech ?? [],
		framework: siteFramework,
		architecture: typeof meta.site_architecture === 'string' ? meta.site_architecture : null,
		webpackDetected: meta.site_webpack_detected === true,
		sourceAvailable,
		isApi:
			w.role === 'api' ||
			/(^|\/)(api|graphql|swagger)(\/|$)/i.test(w.path) ||
			/^api\./i.test(w.host),
	};

	// 3. 漏洞组件关联（终评用）
	const vulnHints = matchVulnHints({
		fingerprints: w.fingerprints ?? [],
		tech: w.tech ?? [],
		title: w.title,
		body: w.body_preview,
		header: headerToString(w.response_header),
	});

	// 4. 带证据重评
	const scoreResult = scoreWebapp({
		role: w.role as AssetRole,
		roleConfidence: (meta.role_confidence as number) ?? 0,
		loginPage: w.login_page,
		fingerprintCount: (w.fingerprints ?? []).length,
		hasAdminPath: /(^|\/)(admin|manage|console|dashboard|backend)(\/|$)/i.test(w.path),
		cdn: w.cdn,
		waf: !!w.waf,
		vulnHintCount: vulnHints.length,
		fingerprints: w.fingerprints ?? [],
		tech: w.tech ?? [],
		siteArchitecture: techProfile.architecture,
		jsApiCount,
		highValueEndpointCount: hvEndpoints,
		findingCount,
		sourceAvailable,
		deepScanned: true,
	});

	// 5. LLM 复核（终评 ≥ 阈值才复核，forceRefresh 防止初评虚高延续）
	let finalScore = scoreResult.score;
	const finalBreakdown = [...scoreResult.breakdown];
	if (getConfig().llm.scoreReviewEnabled && finalScore >= getConfig().llm.scoreReviewThreshold) {
		try {
			const { reviewScoreByLlm } = await import('./llm_score_review.js');
			const review = await reviewScoreByLlm(
				{
					webappId,
					url: w.url,
					host: w.host,
					path: w.path,
					title: w.title,
					tech: w.tech ?? [],
					fingerprints: w.fingerprints ?? [],
					webserver: w.webserver,
					bodyPreview: w.body_preview,
					role: w.role as AssetRole,
					roleSource: (meta.role_source as string) ?? 'rule',
					score: finalScore,
					breakdown: finalBreakdown,
				},
				{ forceRefresh: true },
			);
			if (review) {
				finalScore = Math.max(0, Math.min(100, finalScore + review.scoreAdjustment));
				if (review.scoreAdjustment !== 0) {
					finalBreakdown.push({
						name: 'llm_review_final',
						delta: review.scoreAdjustment,
						reason: `终评 LLM 复核: ${review.reasoning}`,
					});
				}
				// 未认定高价值 → 强制压到高价值阈值以下（防"高分但 LLM 不认"）
				if (!review.isHighValue && finalScore >= getConfig().llm.scoreReviewThreshold) {
					const over = finalScore - (getConfig().llm.scoreReviewThreshold - 1);
					finalScore = getConfig().llm.scoreReviewThreshold - 1;
					finalBreakdown.push({
						name: 'llm_high_value_denied',
						delta: -over,
						reason: `终评 LLM 未认定高价值（${review.reasoning}），压回 ${finalScore}`,
					});
					console.log(`[scoring] 终评未认定高价值 ${w.url}：${finalScore}（${review.reasoning}）`);
				}
			}
		} catch (err) {
			console.warn('[scoring] 终评复核失败 (non-blocking):', err);
		}
	}

	// 6. 门控（终评分 → 技术栈画像调整）
	let gate = computeTaskGate({
		score: finalScore,
		role: w.role as AssetRole,
		hardToAttack: scoreResult.hardToAttack,
		vulnHintCount: vulnHints.length,
	});
	gate = adjustByTechProfile(gate, techProfile);

	// 7. 持久化（标记终评）
	await pool.query(
		`UPDATE webapps
     SET score = $1, score_breakdown = $2, suggested_next = $3,
         meta = meta || $4::jsonb
     WHERE asset_id = $5`,
		[
			finalScore,
			JSON.stringify(finalBreakdown),
			gate.suggestedNext,
			JSON.stringify({
				score_stage: 'final',
				final_score_at: new Date().toISOString(),
				final_evidence: {
					jsApiCount,
					highValueEndpoints: hvEndpoints,
					findings: findingCount,
					sourceAvailable,
				},
			}),
			webappId,
		],
	);

	await auditLog({
		actor: 'system',
		action: 'data_write',
		target: webappId,
		decision: 'pass',
		reason: 'final_scoring_complete',
		meta: {
			score: finalScore,
			level: gate.level,
			evidence: { jsApiCount, hvEndpoints, findingCount, sourceAvailable },
		},
	});

	// 8. 刷新快照
	try {
		await generateAndSaveSnapshot(webappId);
	} catch {
		// 快照失败不阻塞
	}

	console.log(
		`[final-scoring] ${w.url} → ${finalScore} L${gate.level} (jsApi=${jsApiCount} hvEp=${hvEndpoints} findings=${findingCount} src=${sourceAvailable})`,
	);
	return {
		webappId,
		score: finalScore,
		level: gate.level,
		role: w.role,
		suggestedNext: gate.suggestedNext,
	};
}

// =============================================================================
// 批量评分（按 seedId）
// =============================================================================

/**
 * 给指定 seed 下的所有 webapp 跑评分
 *
 * @param seedId 种子 ID
 * @param opts.skipLlm 跳过 LLM 兜底
 * @returns 评分摘要列表
 */
export async function scoreBySeed(
	seedId: string,
	opts: { skipLlm?: boolean } = {},
): Promise<Array<{ webappId: string; url: string } & Awaited<ReturnType<typeof scoreWebappById>>>> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT w.asset_id, w.url
     FROM webapps w
     JOIN assets a ON w.asset_id = a.id
     WHERE a.seed_id = $1
     ORDER BY w.last_seen DESC`,
		[seedId],
	);

	console.log(`[scoring] ${rows.length} webapps to score for seed ${seedId}`);
	const results: Array<
		{ webappId: string; url: string } & Awaited<ReturnType<typeof scoreWebappById>>
	> = [];
	for (const row of rows) {
		try {
			const r = await scoreWebappById(row.asset_id, opts);
			results.push({
				webappId: row.asset_id,
				url: row.url,
				...r,
			});
			console.log(
				`[scoring] ${row.url} → role=${r.role}(${r.roleSource}) score=${r.score} level=${r.level} cve_hints=${r.vulnHints.length}`,
			);
		} catch (err) {
			console.error(`[scoring] failed for ${row.url}:`, err);
		}
	}

	// 评分后自动深挖：达到最低级别的 webapp 自动触发 deep-scan（L2/L3 高分资产）
	await autoDeepScanAfterScoring(seedId, results);

	return results;
}

/**
 * 评分后自动深挖（AUTO_DEEP_SCAN_ENABLED，默认开）
 *
 * 对评分结果中达到最低级别（默认 L2）的 webapp 逐个跑 deep-scan。
 * deep-scan 内部有 7 天重复扫描保护（isWebappScannedRecently），天然防重；
 * 单 webapp 失败不影响其他。
 */
async function autoDeepScanAfterScoring(
	seedId: string,
	results: Array<{ webappId: string; url: string } & Awaited<ReturnType<typeof scoreWebappById>>>,
): Promise<void> {
	const cfg = getConfig().llm;
	if (!cfg.autoDeepScanEnabled) return;
	const minLevel = cfg.autoDeepScanMinLevel;

	const targets = results.filter((r) => {
		if (minLevel === 'L2') return r.level === 'L2' || r.level === 'L3';
		if (minLevel === 'L3') return r.level === 'L3';
		return true; // L1
	});
	if (targets.length === 0) {
		console.log(`[scoring] auto deep-scan: 无 ${minLevel}+ webapp，跳过`);
		return;
	}
	console.log(
		`[scoring] auto deep-scan: ${targets.length} 个 ${minLevel}+ webapp 自动深挖（seed=${seedId}）`,
	);

	const { deepScanWebapp } = await import('../pipeline/deep_scan.js');
	const { updateSeedProgress } = await import('../storage/models/asset.js');
	let done = 0;
	let failed = 0;
	for (const t of targets) {
		try {
			// skipRecent: 7 天内已扫过的任务（尤其 dirscan 全字典）跳过，避免重复全扫拖慢
			const r = await deepScanWebapp(t.webappId, { skipRecent: true });
			done++;
			console.log(
				`[auto-deep-scan] ${t.url}: ran=[${r.ranTasks.join(',')}] skipped=[${r.skippedTasks.join(',')}]`,
			);
			// 深挖完成 → 终评（基于深挖证据重新评分 + 复核）
			try {
				const final = await scoreWebappFinal(t.webappId);
				console.log(`[auto-deep-scan] 终评 ${t.url}: ${final.score} L${final.level} (deepScan 后)`);
			} catch (err) {
				console.warn(`[auto-deep-scan] 终评失败 ${t.url}:`, err);
			}
		} catch (err) {
			failed++;
			console.error(`[auto-deep-scan] ${t.url} 失败:`, err);
		}
		// 进度
		try {
			await updateSeedProgress(seedId, {
				stage: 'deep_scan',
				stageLabel: '自动深挖',
				stageIndex: 6,
				totalStages: 7,
				deepScan: { done, total: targets.length, current: t.url },
				updatedAt: new Date().toISOString(),
			});
		} catch {
			// 进度写失败不阻塞
		}
	}
	console.log(`[scoring] auto deep-scan 完成: ${targets.length} webapps, failed=${failed}`);
}
