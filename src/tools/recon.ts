/**
 * 数据消费工具集（合并后 · 本地调用）
 *
 * 6 个只读工具（D8：工具按需查询，Agent 所见即最新）：
 *   recon_task_info      任务状态/进度（轮询）
 *   recon_assets         资产查询（按评分下限查高价值 webapp，或按 seed/type/pattern 查资产图）
 *   recon_asset_detail   ⭐ 单资产完整元数据快照（渗透验证主数据）
 *   recon_endpoints      端点/JS 接口/参数（从快照本地提取）
 *   recon_findings       发现检索（去重用，避免重复挖）
 *   recon_scan_history   扫描历史（哪些资产已扫过，0 重复扫描）
 *
 * 合并后改为进程内调用本地收集引擎（ReconProvider，src/recon/provider.ts），
 * 不再走 HTTP。错误约定（pi 规范）：执行失败抛错（不编码进 content）。
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';
import type { ReconProvider } from '../recon/provider.js';

// ---------------------------------------------------------------------------
// 参数 schema
// ---------------------------------------------------------------------------

const seedIdSchema = Type.String({
	description: 'ck-recon 任务（种子）ID，UUID 格式。来自 recon_assets 返回或手动提交',
});

const assetIdSchema = Type.String({
	description: 'ck-recon 资产 ID，UUID 格式（webapp 的 assetId）',
});

const severitySchema = Type.Optional(
	Type.Union(
		[
			Type.Literal('critical'),
			Type.Literal('high'),
			Type.Literal('medium'),
			Type.Literal('low'),
			Type.Literal('info'),
		],
		{ description: '严重程度筛选' },
	),
);

// ---------------------------------------------------------------------------
// 工具工厂：绑定 ReconProvider
// ---------------------------------------------------------------------------

export interface ReconToolDetails {
	count: number;
}

function makeResult<T>(
	data: T,
	details: ReconToolDetails,
	summary?: string,
): AgentToolResult<ReconToolDetails> {
	return {
		content: [
			{
				type: 'text',
				text: `${
					(summary ? `${summary}\n` : '') + JSON.stringify(data, null, 2)
				}\n[data_source: local(进程内) · count=${details.count}]`,
			},
		],
		details,
	};
}

export function createReconTools(provider: ReconProvider): AgentTool[] {
	// ---------------------------------------------------------------------
	// 1. recon_task_info —— 任务状态/进度（parameters 即 seedId 字符串）
	// ---------------------------------------------------------------------
	const reconTaskInfo: AgentTool<typeof seedIdSchema, ReconToolDetails> = {
		name: 'recon_task_info',
		label: '任务状态',
		description:
			'查询收集任务（种子）状态与扫描进度。包含 status(pending/running/done/failed)、资产数与 webapp 数、progress 阶段与深挖进度。用于轮询确认扫描是否完成。',
		parameters: seedIdSchema,
		execute: async (_toolCallId, seedId): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.taskInfo(seedId);
			return makeResult(data, { count: 1 });
		},
	};

	// ---------------------------------------------------------------------
	// 2. recon_assets —— 资产查询（评分/资产图双路）
	// ---------------------------------------------------------------------
	const reconAssetsParams = Type.Object({
		minScore: Type.Optional(
			Type.Integer({
				description:
					'评分下限（0-100）。提供时返回评分≥此值的 webapp 列表（含角色/评分/发现标记），这是挑选高价值目标的主查询',
				minimum: 0,
				maximum: 100,
			}),
		),
		seedId: Type.Optional(seedIdSchema),
		type: Type.Optional(
			Type.String({
				description:
					'资产类型筛选：domain/subdomain/ip/url/webapp/company（仅在未提供 minScore 时生效）',
			}),
		),
		pattern: Type.Optional(Type.String({ description: '按资产值模糊匹配（如目标域名关键词）' })),
		limit: Type.Optional(
			Type.Integer({
				description: '返回数量上限，默认 50，最大 200',
				minimum: 1,
				maximum: 200,
			}),
		),
	});
	const reconAssets: AgentTool<typeof reconAssetsParams, ReconToolDetails> = {
		name: 'recon_assets',
		label: '资产查询',
		description:
			'查询已收集的资产。两种模式：\n' +
			'1) 提供 minScore：按评分下限返回高价值 webapp（含角色/评分/评分阶段/LLM高价值认定/发现标记），用于选目标（推荐）\n' +
			'2) 不提供 minScore：查资产图（按 seedId/type/pattern），返回域名/子域/IP/webapp 条目\n' +
			'只读，数据来自收集引擎已入库的元数据，不会对目标发起新请求。',
		parameters: reconAssetsParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.assets({
				seedId: params.seedId,
				type: params.type,
				pattern: params.pattern,
				minScore: params.minScore,
				limit: params.limit,
			});
			return makeResult(
				data,
				{ count: data.length },
				params.minScore !== undefined ? `评分 ≥ ${params.minScore} 的 webapp：` : undefined,
			);
		},
	};

	// ---------------------------------------------------------------------
	// 3. recon_asset_detail —— 完整元数据快照（⭐ 主接口）
	// ---------------------------------------------------------------------
	const reconAssetDetail: AgentTool<typeof assetIdSchema, ReconToolDetails> = {
		name: 'recon_asset_detail',
		label: '资产元数据快照',
		description:
			'⭐ 返回单个 webapp 的完整元数据快照：技术栈/角色/评分明细(含是否 final 终评)/建议深挖任务/指纹/CVE 提示/endpoints/JS 接口/参数/站点架构画像(SPA·渲染·认证机制)/攻击面分组/源码可用性。验证漏洞前先调用本工具吃透目标。',
		parameters: assetIdSchema,
		execute: async (_toolCallId, assetId): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.assetDetail(assetId);
			return makeResult(data, { count: 1 });
		},
	};

	// ---------------------------------------------------------------------
	// 4. recon_endpoints —— 端点/JS 接口/参数
	// ---------------------------------------------------------------------
	const reconEndpoints: AgentTool<typeof assetIdSchema, ReconToolDetails> = {
		name: 'recon_endpoints',
		label: '端点与 JS 接口',
		description:
			'提取单个 webapp 的端点(endpoints，含 page_role 语义：login/admin/upload/export)、JS 中挖出的接口(js_apis)与参数(params)。从元数据快照本地提取，不发起新请求。',
		parameters: assetIdSchema,
		execute: async (_toolCallId, assetId): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.endpoints(assetId);
			const count = data.endpoints.length + data.jsApis.length + data.params.length;
			return makeResult(data, { count });
		},
	};

	// ---------------------------------------------------------------------
	// 5. recon_findings —— 发现检索（去重）
	// ---------------------------------------------------------------------
	const reconFindingsParams = Type.Object({
		webappId: Type.Optional(assetIdSchema),
		severity: severitySchema,
		type: Type.Optional(
			Type.String({
				description:
					'发现类型：secret/sensitive_path/sourcemap/source_audit/github_leak/cve_hint/internal_ip/sensitive_file/info_leak 等',
			}),
		),
		limit: Type.Optional(
			Type.Integer({
				description: '返回数量上限，默认 100，最大 200',
				minimum: 1,
				maximum: 200,
			}),
		),
	});
	const reconFindings: AgentTool<typeof reconFindingsParams, ReconToolDetails> = {
		name: 'recon_findings',
		label: '发现检索',
		description:
			'查询已记录的发现（密钥/敏感路径/sourcemap/源码审计线索等）。用于：1) 目标已有哪些线索，直接跟进；2) 避免重复挖掘已被发现的洞。按严重度排序。',
		parameters: reconFindingsParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.findings({
				webappId: params.webappId,
				severity: params.severity,
				type: params.type,
				limit: params.limit,
			});
			return makeResult(data, { count: data.length });
		},
	};

	// ---------------------------------------------------------------------
	// 6. recon_scan_history —— 扫描历史（0 重复）
	// ---------------------------------------------------------------------
	const reconScanHistoryParams = Type.Object({
		seedId: Type.Optional(seedIdSchema),
		assetId: Type.Optional(assetIdSchema),
		tool: Type.Optional(
			Type.String({
				description: '工具名筛选：subfinder/httpx/dirsearch/source_collect/nuclei 等',
			}),
		),
		limit: Type.Optional(
			Type.Integer({
				description: '返回数量上限，默认 50，最大 100',
				minimum: 1,
				maximum: 100,
			}),
		),
	});
	const reconScanHistory: AgentTool<typeof reconScanHistoryParams, ReconToolDetails> = {
		name: 'recon_scan_history',
		label: '扫描历史',
		description:
			'查询收集引擎的扫描记录（哪些资产被哪个工具扫过、状态、耗时）。用于规划下一步验证时避免重复扫描同一资产（0 重复原则）。',
		parameters: reconScanHistoryParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.scanHistory({
				seedId: params.seedId,
				assetId: params.assetId,
				tool: params.tool,
				limit: params.limit,
			});
			return makeResult(data, { count: data.length });
		},
	};

	// ---------------------------------------------------------------------
	// 7. recon_source —— 源码包审计（source dumps / webpack 还原源码）
	// ---------------------------------------------------------------------
	const reconSourceParams = Type.Object({
		webappId: assetIdSchema,
	});
	const reconSource: AgentTool<typeof reconSourceParams, ReconToolDetails> = {
		name: 'recon_source',
		label: '源码包审计',
		description:
			'审计已收集的源码包（source dumps / webpack source-map 还原源码）。返回源码包列表 + INDEX.json 摘要（硬编码密钥 secrets / 隐藏接口 endpoints / 文件清单 files / 入口 entryPoints / 统计 stats）+ 已缓存的 LLM 源码审计发现。用于挖硬编码凭证、隐藏接口、敏感配置、危险函数（eval/exec/反序列化）等。',
		parameters: reconSourceParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.sourceAudit(params.webappId);
			const count = Array.isArray(data.dumps) ? data.dumps.length : 0;
			return makeResult(data, { count });
		},
	};

	// ---------------------------------------------------------------------
	// 8. recon_source_read —— 读取源码包内单个文件
	// ---------------------------------------------------------------------
	const reconSourceReadParams = Type.Object({
		webappId: assetIdSchema,
		path: Type.String({
			description:
				'源码包内相对文件路径（来自 recon_source 返回的 files 列表），如 src/config/index.js',
		}),
	});
	const reconSourceRead: AgentTool<typeof reconSourceReadParams, ReconToolDetails> = {
		name: 'recon_source_read',
		label: '读取源码文件',
		description:
			'读取源码包内单个文件内容（截断到 20KB）。用于对 recon_source 发现的线索（密钥/接口/危险函数）追看具体实现，坐实漏洞。',
		parameters: reconSourceReadParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<ReconToolDetails>> => {
			const data = await provider.sourceRead(params.webappId, params.path);
			return makeResult(data, { count: 1 });
		},
	};

	return [
		reconTaskInfo,
		reconAssets,
		reconAssetDetail,
		reconEndpoints,
		reconFindings,
		reconScanHistory,
		reconSource,
		reconSourceRead,
	];
}
