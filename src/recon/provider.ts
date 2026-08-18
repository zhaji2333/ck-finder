/**
 * ReconProvider：ck-finder 消费收集引擎的本地数据通道（合并后）
 *
 * 进程内直接调用（不再走 HTTP，M1 适配层已删除）：
 *   - 资产/评分查询  → storage/models/query.ts（本地 PG 只读查询）
 *   - 单资产元数据   → scoring/snapshot.generateSnapshot（进程内只读快照，最安全接入点）
 *   - endpoints/js_apis/params → 从快照本地提取
 *
 * 工具层（src/tools/recon.ts）依赖本接口，字段与 M1 契约保持兼容
 * （recon_assets 的派生视图 scoreStage/isHighValue/taskLevel 等不变）。
 */
import { readFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { generateSnapshot } from './scoring/snapshot.js';
import {
	type WebappQueryRow,
	queryAssets,
	queryAssetsFuzzy,
	queryFindings,
	queryScanRuns,
	querySeedById,
	queryWebapps,
} from './storage/models/query.js';
import { querySourceDumpsByWebapp } from './storage/models/source_dump.js';
import { getPg } from './storage/pg.js';

// ---------------------------------------------------------------------------
// 接口（供工具层依赖）
// ---------------------------------------------------------------------------

export interface ReconProviderAssetsParams {
	seedId?: string | undefined;
	type?: string | undefined;
	pattern?: string | undefined;
	minScore?: number | undefined;
	limit?: number | undefined;
}

export interface ReconProviderFindingsParams {
	type?: string | undefined;
	severity?: string | undefined;
	webappId?: string | undefined;
	assetId?: string | undefined;
	limit?: number | undefined;
}

export interface ReconProviderScanParams {
	seedId?: string | undefined;
	assetId?: string | undefined;
	tool?: string | undefined;
	limit?: number | undefined;
}

export interface ReconProvider {
	/** 任务状态/进度 */
	taskInfo(seedId: string): Promise<Record<string, unknown>>;
	/** 资产查询：minScore 提供 → 评分视图（webapp 列表）；否则资产图 */
	assets(params: ReconProviderAssetsParams): Promise<Record<string, unknown>[]>;
	/** 单资产完整元数据快照 */
	assetDetail(assetId: string): Promise<Record<string, unknown>>;
	/** 端点/JS 接口/参数（从快照提取） */
	endpoints(assetId: string): Promise<{
		endpoints: Array<Record<string, unknown>>;
		jsApis: Array<Record<string, unknown>>;
		params: Array<Record<string, unknown>>;
	}>;
	/** 发现检索 */
	findings(params: ReconProviderFindingsParams): Promise<Record<string, unknown>[]>;
	/** 扫描历史 */
	scanHistory(params: ReconProviderScanParams): Promise<Record<string, unknown>[]>;
	/** 源码包列表（source_dumps） */
	sourceDumps(webappId: string): Promise<Record<string, unknown>[]>;
	/** 源码包审计：INDEX.json 摘要（secrets/endpoints/files）+ 已缓存审计发现 */
	sourceAudit(webappId: string): Promise<Record<string, unknown>>;
	/** 读取源码包内单个文件（路径穿越防护 + 大小截断） */
	sourceRead(webappId: string, relPath: string): Promise<Record<string, unknown>>;
}

// ---------------------------------------------------------------------------
// 本地实现
// ---------------------------------------------------------------------------

/** 从 webapp 行派生 Agent 排序/决策视图（与 M1 契约一致，供测试复用） */
export function toWebappView(w: WebappQueryRow): Record<string, unknown> {
	const meta = w.meta ?? {};
	const scoreReview = (meta.score_review as Record<string, unknown> | null) ?? null;
	return {
		assetId: w.assetId,
		url: w.url,
		score: w.score,
		role: w.role,
		scoreStage: meta.score_stage ?? null,
		isHighValue: scoreReview?.is_high_value ?? null,
		taskLevel: meta.task_level ?? null,
		tech: w.tech,
		loginPage: w.loginPage,
		findingCount: w.findingCount,
		findingTypes: w.findingTypes,
		findingMaxSeverity: w.findingMaxSeverity,
		cveHints: meta.cve_hints ?? [],
	};
}

export const localReconProvider: ReconProvider = {
	async taskInfo(seedId) {
		const seed = await querySeedById(seedId);
		if (!seed) {
			throw new Error(`任务不存在: ${seedId}`);
		}
		return {
			id: seed.id,
			seedType: seed.seedType,
			value: seed.value,
			status: seed.status,
			assetCount: seed.assetCount,
			webappCount: seed.webappCount,
			createdAt: seed.createdAt,
			progress: seed.progress ?? null,
		};
	},

	async assets(params) {
		// 评分路径：走 webapps（minScore → score_gt）
		if (params.minScore !== undefined && params.minScore !== null) {
			const { webapps } = await queryWebapps({
				scoreGt: params.minScore,
				limit: params.limit ?? 50,
			});
			return webapps.map(toWebappView);
		}
		// 模糊匹配（MCP 语义，供 recon_assets pattern 用）
		if (params.pattern) {
			const { assets } = await queryAssetsFuzzy({
				pattern: params.pattern,
				type: params.type,
				limit: params.limit ?? 100,
			});
			return assets as unknown as Record<string, unknown>[];
		}
		// 资产图查询
		const { assets } = await queryAssets({
			seedId: params.seedId,
			type: params.type,
			limit: params.limit ?? 100,
		});
		return assets as unknown as Record<string, unknown>[];
	},

	async assetDetail(assetId) {
		const snapshot = await generateSnapshot(assetId);
		return snapshot as unknown as Record<string, unknown>;
	},

	async endpoints(assetId) {
		const snapshot = await generateSnapshot(assetId);
		return {
			endpoints: (snapshot.endpoints ?? []) as unknown as Array<Record<string, unknown>>,
			jsApis: (snapshot.js_apis ?? []) as unknown as Array<Record<string, unknown>>,
			params: (snapshot.params ?? []) as unknown as Array<Record<string, unknown>>,
		};
	},

	async findings(params) {
		const { findings } = await queryFindings({
			type: params.type,
			severity: params.severity,
			webappId: params.webappId,
			assetId: params.assetId,
			limit: params.limit,
		});
		return findings as unknown as Record<string, unknown>[];
	},

	async scanHistory(params) {
		const { scanRuns } = await queryScanRuns({
			seedId: params.seedId,
			assetId: params.assetId,
			tool: params.tool,
			limit: params.limit,
		});
		return scanRuns as unknown as Record<string, unknown>[];
	},

	async sourceDumps(webappId) {
		const dumps = await querySourceDumpsByWebapp(webappId);
		return dumps.map((d) => ({
			id: d.id,
			webappId: d.webappId,
			sourceDir: d.sourceDir,
			fileCount: d.fileCount,
			restored: d.restored,
			complete: d.complete,
			entryPoints: d.entryPoints,
			indexPath: d.indexPath,
		}));
	},

	async sourceAudit(webappId) {
		const dumps = await querySourceDumpsByWebapp(webappId);
		const dumpsOut: Record<string, unknown>[] = [];
		for (const d of dumps) {
			const indexPath = join(d.sourceDir, d.indexPath ?? 'INDEX.json');
			let index: Record<string, unknown> = {};
			try {
				index = JSON.parse(readFileSync(indexPath, 'utf8')) as Record<string, unknown>;
			} catch {
				index = { sourceAvailable: false };
			}
			const files = Array.isArray(index.files) ? (index.files as string[]) : [];
			dumpsOut.push({
				id: d.id,
				sourceDir: d.sourceDir,
				fileCount: d.fileCount,
				restored: d.restored,
				entryPoints: d.entryPoints,
				index: {
					sourceAvailable: index.sourceAvailable ?? false,
					webpackDetected: index.webpackDetected ?? false,
					frameworks: Array.isArray(index.frameworks) ? index.frameworks : [],
					stats: index.stats ?? {},
					entryPoints: Array.isArray(index.entryPoints) ? index.entryPoints : [],
					endpoints: Array.isArray(index.endpoints) ? (index.endpoints as unknown[]).slice(0, 200) : [],
					secrets: Array.isArray(index.secrets) ? (index.secrets as unknown[]).slice(0, 100) : [],
					files: files.slice(0, 200),
				},
			});
		}
		const out: Record<string, unknown> = { webappId, dumps: dumpsOut, auditFindings: [] };
		// 已缓存源码审计发现（source_audits 表）
		try {
			const { rows } = await getPg().query(
				`SELECT summary, finding_count FROM source_audits
				 WHERE webapp_id = $1 ORDER BY created_at DESC LIMIT 1`,
				[webappId],
			);
			if (rows.length > 0 && rows[0].summary) {
				const s = rows[0].summary as Record<string, unknown>;
				out.auditFindings = Array.isArray(s.findings) ? s.findings : [];
				out.attackSurfaceMap = s.attackSurfaceMap ?? {};
				out.techStack = Array.isArray(s.techStack) ? s.techStack : [];
				out.recommendations = Array.isArray(s.recommendations) ? s.recommendations : [];
			}
		} catch {
			// source_audits 表不存在或查询失败 → 忽略（不阻塞）
		}
		return out;
	},

	async sourceRead(webappId, relPath) {
		const dumps = await querySourceDumpsByWebapp(webappId);
		const d = dumps[0];
		if (!d) throw new Error(`该资产无源码包: ${webappId}`);
		// 路径穿越防护：解析后必须落在 source_dir 内
		const base = resolve(d.sourceDir);
		const target = resolve(base, relPath);
		if (target !== base && !target.startsWith(base + sep)) {
			throw new Error(`非法路径（越出源码包目录）: ${relPath}`);
		}
		const content = readFileSync(target, 'utf8');
		const truncated =
			content.length > 20_000 ? `${content.slice(0, 20_000)}\n...[截断 ${content.length - 20_000} 字节]` : content;
		return { webappId, path: relPath, size: content.length, content: truncated };
	},
};
