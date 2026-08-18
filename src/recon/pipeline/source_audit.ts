/**
 * 源码审计（source-auditor 接入）
 *
 * M4 source_collect 还原源码 + 生成 INDEX.json 后，用 LLM 审计源码，
 * 提取渗透测试线索（隐藏接口/硬编码密钥/敏感配置/调试入口）。
 *
 * 设计原则：
 *   - system prompt 直接复用 src/agents/source-auditor.md（agents/loader.ts 加载）
 *   - 只读关键文件（package.json + 入口 + config/env 类 + 前 N 个非 node_modules 文件），总量 ≤30KB
 *   - 结果缓存到 source_audits 表（webapp_id + source_dir + provider + model UNIQUE）
 *   - findings 入库（type='source_audit'），meta 存 attackSurfaceMap/techStack/recommendations
 *   - 只发现报告、不做验证（符合 ck-recon 定位）
 *   - LLM 失败 / 解析失败 → 返回 null，不阻塞主流程
 */

import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { loadAgentPrompt } from '../agents/loader.js';
import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { callDeepSeek, extractJsonContent } from '../scoring/llm_client.js';
import { insertFinding } from '../storage/models/recon.js';
import { getPg } from '../storage/pg.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface SourceAuditOptions {
	/** 审计文件总量上限（字节，默认 30KB） */
	maxSnippetBytes?: number;
	/** 最多读多少个文件（默认 20） */
	maxFiles?: number;
	/** 强制重跑（忽略缓存） */
	force?: boolean;
}

export interface SourceAuditFinding {
	type: string;
	severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
	detail: string;
	evidence: string;
	suggestedNext: string[];
}

export interface SourceAuditResult {
	webappId: string;
	url: string;
	sourceDir: string;
	findings: SourceAuditFinding[];
	attackSurfaceMap: Record<string, string[]>;
	techStack: string[];
	recommendations: string[];
	filesAudited: string[];
	auditedBytes: number;
	/** 是否走了 LLM（false = 缓存命中） */
	fromCache: boolean;
	provider: string;
	model: string;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

// =============================================================================
// 缓存（PG 表 source_audits）
// =============================================================================

async function getCached(
	webappId: string,
	sourceDir: string,
	provider: string,
	model: string,
): Promise<SourceAuditResult | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT summary, finding_count FROM source_audits
     WHERE webapp_id = $1 AND source_dir = $2 AND provider = $3 AND model = $4
     ORDER BY created_at DESC LIMIT 1`,
		[webappId, sourceDir, provider, model],
	);
	if (rows.length === 0) return null;
	const s = rows[0].summary;
	return {
		webappId,
		url: s.url ?? '',
		sourceDir,
		findings: s.findings ?? [],
		attackSurfaceMap: s.attackSurfaceMap ?? {},
		techStack: s.techStack ?? [],
		recommendations: s.recommendations ?? [],
		filesAudited: s.filesAudited ?? [],
		auditedBytes: s.auditedBytes ?? 0,
		fromCache: true,
		provider,
		model,
	};
}

async function saveCache(
	webappId: string,
	sourceDir: string,
	provider: string,
	model: string,
	result: Omit<SourceAuditResult, 'fromCache' | 'provider' | 'model'>,
	rawResponse: unknown,
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO source_audits (webapp_id, source_dir, provider, model, summary, finding_count, raw_response)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (webapp_id, source_dir, provider, model) DO UPDATE
       SET summary = EXCLUDED.summary,
           finding_count = EXCLUDED.finding_count,
           raw_response = EXCLUDED.raw_response,
           created_at = now()`,
		[
			webappId,
			sourceDir,
			provider,
			model,
			JSON.stringify({
				url: result.url,
				findings: result.findings,
				attackSurfaceMap: result.attackSurfaceMap,
				techStack: result.techStack,
				recommendations: result.recommendations,
				filesAudited: result.filesAudited,
				auditedBytes: result.auditedBytes,
			}),
			result.findings.length,
			JSON.stringify(rawResponse ?? null),
		],
	);
}

// =============================================================================
// 关键文件选取
// =============================================================================

async function pickKeyFiles(
	indexJson: { files?: string[]; entryPoints?: string[] },
	sourceDir: string,
	maxFiles: number,
	maxBytes: number,
): Promise<{ files: Array<{ path: string; content: string }>; auditedBytes: number }> {
	const allFiles = (indexJson.files ?? []).filter((f) => !/node_modules|\.map$/i.test(f));

	// 优先级排序
	const priority = (f: string): number => {
		const name = f.toLowerCase();
		if (name === 'package.json') return 0;
		if (/(config|env|setting|secret|credential|auth)/.test(name)) return 1;
		if (/\.(env|ini|conf)$/.test(name)) return 2;
		if (/api|router|route|service/.test(name)) return 3;
		return 4;
	};
	const entrySet = new Set((indexJson.entryPoints ?? []).slice(0, 3));
	const sorted = [...allFiles].sort((a, b) => {
		const pa = entrySet.has(a) ? -1 : priority(a);
		const pb = entrySet.has(b) ? -1 : priority(b);
		return pa - pb;
	});

	const out: Array<{ path: string; content: string }> = [];
	let totalBytes = 0;
	for (const rel of sorted) {
		if (out.length >= maxFiles) break;
		if (totalBytes >= maxBytes) break;
		try {
			const abs = join(sourceDir, rel);
			if (!existsSync(abs)) continue;
			const content = await readFile(abs, 'utf8');
			if (!content || content.length > 100_000) continue; // 单个文件超 100KB 跳过
			// 保留文件开头 + 结尾（配置一般在开头，密钥可能在中间）
			const snippet =
				content.length > 4_000
					? `${content.slice(0, 2_000)}\n...\n${content.slice(-2_000)}`
					: content;
			if (totalBytes + snippet.length > maxBytes) continue;
			out.push({ path: rel, content: snippet });
			totalBytes += snippet.length;
		} catch {
			// 读失败跳过
		}
	}
	return { files: out, auditedBytes: totalBytes };
}

// =============================================================================
// Prompt 拼装与解析
// =============================================================================

function buildUserPrompt(
	url: string,
	indexJson: Record<string, unknown>,
	keyFiles: Array<{ path: string; content: string }>,
): string {
	const asArray = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
	return JSON.stringify(
		{
			webappId: indexJson.webappId,
			url,
			indexJson: {
				stats: indexJson.stats ?? {},
				entryPoints: asArray(indexJson.entryPoints).slice(0, 10),
				endpoints: asArray(indexJson.endpoints).slice(0, 100),
				secrets: asArray(indexJson.secrets).slice(0, 50),
				files: asArray(indexJson.files).slice(0, 200),
			},
			sourceSnippets: Object.fromEntries(keyFiles.map((f) => [f.path, f.content])),
		},
		null,
		2,
	);
}

export function parseSourceAuditResponse(content: string): {
	highValueFindings: SourceAuditFinding[];
	attackSurfaceMap: Record<string, string[]>;
	techStack: string[];
	recommendations: string[];
} {
	const fallback = {
		highValueFindings: [],
		attackSurfaceMap: {},
		techStack: [],
		recommendations: [],
	};
	try {
		const obj = JSON.parse(extractJsonContent(content)) as {
			highValueFindings?: unknown;
			attackSurfaceMap?: unknown;
			techStack?: unknown;
			recommendations?: unknown;
		};
		const findings: SourceAuditFinding[] = [];
		if (Array.isArray(obj.highValueFindings)) {
			for (const f of obj.highValueFindings) {
				if (!f || typeof f !== 'object') continue;
				const item = f as {
					type?: unknown;
					severity?: unknown;
					detail?: unknown;
					evidence?: unknown;
					suggestedNext?: unknown;
				};
				if (typeof item.detail !== 'string') continue;
				const severity =
					typeof item.severity === 'string'
						? (item.severity.toLowerCase() as SourceAuditFinding['severity'])
						: 'medium';
				findings.push({
					type: typeof item.type === 'string' ? item.type : 'source_audit',
					severity: (SEVERITIES as readonly string[]).includes(severity) ? severity : 'medium',
					detail: item.detail.slice(0, 500),
					evidence: typeof item.evidence === 'string' ? item.evidence.slice(0, 1000) : '',
					suggestedNext: Array.isArray(item.suggestedNext)
						? item.suggestedNext.filter((s): s is string => typeof s === 'string').slice(0, 5)
						: [],
				});
			}
		}
		const normMap = (v: unknown): Record<string, string[]> => {
			if (!v || typeof v !== 'object') return {};
			const out: Record<string, string[]> = {};
			for (const [k, val] of Object.entries(v)) {
				out[k] = Array.isArray(val)
					? val.filter((x): x is string => typeof x === 'string').slice(0, 20)
					: [];
			}
			return out;
		};
		return {
			highValueFindings: findings,
			attackSurfaceMap: normMap(obj.attackSurfaceMap),
			techStack: Array.isArray(obj.techStack)
				? obj.techStack.filter((t): t is string => typeof t === 'string').slice(0, 20)
				: [],
			recommendations: Array.isArray(obj.recommendations)
				? obj.recommendations.filter((r): r is string => typeof r === 'string').slice(0, 10)
				: [],
		};
	} catch {
		return fallback;
	}
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 对还原后的源码做 LLM 审计
 *
 * @param input 输入信息
 * @returns 审计结果；失败时返回 null（不阻塞主流程）
 */
export async function auditSourceDump(
	input: {
		webappId: string;
		url: string;
		sourceDir: string;
	},
	opts: SourceAuditOptions = {},
): Promise<SourceAuditResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.proModel; // source-auditor 定义用 pro（.env 可按需配置，如 deepseek-v4-flash）
	const maxSnippetBytes = opts.maxSnippetBytes ?? 30_000;
	const maxFiles = opts.maxFiles ?? 20;

	// 1. 查缓存
	if (!opts.force) {
		try {
			const cached = await getCached(input.webappId, input.sourceDir, provider, model);
			if (cached) {
				await auditLog({
					actor: `llm:${provider}`,
					action: 'llm_call',
					target: input.webappId,
					decision: 'info',
					reason: 'source_audit cache hit',
					meta: { model, sourceDir: input.sourceDir, findingCount: cached.findings.length },
				});
				return cached;
			}
		} catch {
			// 缓存查失败不阻塞
		}
	}

	// 2. 读 INDEX.json
	const indexPath = join(input.sourceDir, 'INDEX.json');
	let indexJson: Record<string, unknown>;
	try {
		if (!existsSync(indexPath)) {
			console.warn(`[source_audit] INDEX.json not found: ${indexPath}`);
			return null;
		}
		indexJson = JSON.parse(await readFile(indexPath, 'utf8')) as Record<string, unknown>;
	} catch (err) {
		console.warn(
			`[source_audit] INDEX.json read failed: ${err instanceof Error ? err.message : err}`,
		);
		return null;
	}

	// 3. 选关键文件
	const { files: keyFiles, auditedBytes } = await pickKeyFiles(
		indexJson as { files?: string[]; entryPoints?: string[] },
		input.sourceDir,
		maxFiles,
		maxSnippetBytes,
	);
	if (keyFiles.length === 0) {
		console.warn(`[source_audit] no auditable source files in ${input.sourceDir}`);
		return null;
	}

	// 4. 拼 prompt（system 复用 source-auditor.md）
	let systemPrompt: string;
	try {
		systemPrompt = await loadAgentPrompt('source-auditor');
	} catch {
		systemPrompt = `你是源码审计助手。输出 JSON：{"highValueFindings":[{"type","severity","detail","evidence","suggestedNext"}],"attackSurfaceMap":{},"techStack":[],"recommendations":[]}`;
	}
	const userPrompt = buildUserPrompt(input.url, indexJson, keyFiles);

	// 5. 调用 LLM（maxTokens 给足：deepseek-v4-flash 是推理模型，reasoning 先消耗输出预算）
	let raw;
	let errorMsg: string | null = null;
	try {
		raw = await callDeepSeek(systemPrompt, userPrompt, { model, maxTokens: 4000 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'llm_call',
			target: input.webappId,
			decision: 'fail',
			reason: `source_audit failed: ${errorMsg ?? `empty response (finish=${raw?.choices?.[0]?.finish_reason ?? '?'})`}`,
			meta: { model, sourceDir: input.sourceDir },
		});
		return null;
	}

	// 6. 解析
	const parsed = parseSourceAuditResponse(raw.choices[0].message.content);
	const result: SourceAuditResult = {
		webappId: input.webappId,
		url: input.url,
		sourceDir: input.sourceDir,
		findings: parsed.highValueFindings,
		attackSurfaceMap: parsed.attackSurfaceMap,
		techStack: parsed.techStack,
		recommendations: parsed.recommendations,
		filesAudited: keyFiles.map((f: { path: string }) => f.path),
		auditedBytes,
		fromCache: false,
		provider,
		model,
	};

	// 7. findings 入库（每个 highValueFinding 一条）
	for (const f of result.findings) {
		try {
			await insertFinding({
				assetId: input.webappId,
				webappId: input.webappId,
				type: 'source_audit',
				severity: f.severity,
				detail: `${f.detail}${f.suggestedNext.length > 0 ? `（建议：${f.suggestedNext.slice(0, 3).join('；')}）` : ''}`,
				evidence: f.evidence,
				sourceTool: 'source_audit',
				meta: {
					findingType: f.type,
					sourceDir: input.sourceDir,
					attackSurfaceMap: result.attackSurfaceMap,
					techStack: result.techStack,
				},
			});
		} catch {
			// 单条入库失败不阻塞
		}
	}

	// 8. 审计 + 缓存 + meta 标记
	await auditLog({
		actor: `llm:${provider}`,
		action: 'llm_call',
		target: input.webappId,
		decision: 'allow',
		reason: `source_audit: ${result.findings.length} findings from ${keyFiles.length} files`,
		meta: {
			model,
			sourceDir: input.sourceDir,
			findingCount: result.findings.length,
			filesAudited: keyFiles.length,
			auditedBytes,
			usage: raw.usage,
		},
	});
	try {
		await saveCache(input.webappId, input.sourceDir, provider, model, result, raw);
		const pool = getPg();
		await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
			JSON.stringify({
				source_audited_at: new Date().toISOString(),
				source_audit_findings: result.findings.length,
			}),
			input.webappId,
		]);
	} catch {
		// 缓存/meta 写失败不阻塞
	}

	console.log(
		`[source_audit] ${result.findings.length} findings from ${keyFiles.length} files ` +
			`(tech=[${result.techStack.join(',')}])`,
	);
	return result;
}
