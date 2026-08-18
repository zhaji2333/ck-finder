/**
 * ck-recon MCP Server（M5.2）
 *
 * 架构文档 §6.2 规定的 5 个 MCP 工具：
 *   1. query_assets(pattern, type?)        资产查询（按值模糊匹配 + 类型筛选）
 *   2. get_asset_metadata(asset_id)        单 webapp 完整 Metadata 快照（渗透 Agent 主接口）
 *   3. search_findings(keyword, severity?) 发现检索（关键字 + 严重程度）
 *   4. list_source_dumps(webapp_id?)       源码包清单
 *   5. submit_seed(seed)                   下发收集任务（异步触发 runRecon）
 *
 * 传输：
 *   - 默认 stdio（便于 IDE/Agent 直接 spawn）
 *   - 通过 --http 或 MCP_MODE=http 切换到 Streamable HTTP（监听 MCP_PORT）
 *
 * 启动：
 *   tsx src/api/mcp_server.ts                  # stdio 模式
 *   tsx src/api/mcp_server.ts --http           # HTTP 模式（端口取 MCP_PORT，默认 8788）
 *
 * 底层查询逻辑全部复用 storage/models + scoring/snapshot，与 REST 路由保持一致。
 */

import { randomUUID } from 'node:crypto';
import { type IncomingMessage, type ServerResponse, createServer } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

import { getConfig } from '../config.js';
import { runRecon } from '../pipeline/runner.js';
import { generateSnapshot } from '../scoring/snapshot.js';
import { normalizeSeed } from '../seeds/normalizer.js';
import { upsertSeed } from '../storage/models/asset.js';
import { queryAssetsFuzzy, queryFindingsFuzzy } from '../storage/models/query.js';
import { listSourceDumps, querySourceDumpsByWebapp } from '../storage/models/source_dump.js';

// =============================================================================
// 工具实现
// =============================================================================

/**
 * 工具 1：query_assets
 *
 * 资产查询：按 value 模糊匹配 + 类型筛选
 */
async function queryAssetsImpl(args: {
	pattern: string;
	type?: string;
	limit?: number;
}) {
	const { total, assets } = await queryAssetsFuzzy({
		pattern: args.pattern,
		type: args.type,
		limit: Math.min(args.limit ?? 50, 500),
	});

	return {
		content: [
			{
				type: 'text' as const,
				text: JSON.stringify(
					{
						total,
						assets: assets.map((r) => ({
							id: r.id,
							seedId: r.seedId,
							parentId: r.parentId,
							type: r.type,
							value: r.value,
							valueNorm: r.valueNorm,
							discoveredBy: r.discoveredBy,
							alive: r.alive,
							firstSeen: r.firstSeen,
							lastSeen: r.lastSeen,
						})),
					},
					null,
					2,
				),
			},
		],
	};
}

/**
 * 工具 2：get_asset_metadata
 *
 * 返回 webapp 的完整 metadata 快照（含 tech/endpoints/params/sourcemap/suggested_next）
 * 这是渗透 Agent 的主接口。
 */
async function getAssetMetadataImpl(args: { asset_id: string }) {
	try {
		const snapshot = await generateSnapshot(args.asset_id);
		return {
			content: [
				{
					type: 'text' as const,
					text: JSON.stringify(snapshot, null, 2),
				},
			],
		};
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return {
			content: [
				{
					type: 'text' as const,
					text: JSON.stringify({ error: msg }),
				},
			],
			isError: true,
		};
	}
}

/**
 * 工具 3：search_findings
 *
 * 发现检索：关键字 + 严重程度筛选
 */
async function searchFindingsImpl(args: {
	keyword: string;
	severity?: string;
	webapp_id?: string;
	limit?: number;
}) {
	const { total, findings } = await queryFindingsFuzzy({
		keyword: args.keyword,
		severity: args.severity,
		webappId: args.webapp_id,
		limit: Math.min(args.limit ?? 50, 500),
	});

	return {
		content: [
			{
				type: 'text' as const,
				text: JSON.stringify(
					{
						total,
						findings: findings.map((r) => ({
							id: r.id,
							assetId: r.assetId,
							webappId: r.webappId,
							type: r.type,
							severity: r.severity,
							detail: r.detail,
							evidence: r.evidence,
							sourceTool: r.sourceTool,
							createdAt: r.createdAt,
							meta: r.meta,
						})),
					},
					null,
					2,
				),
			},
		],
	};
}

/**
 * 工具 4：list_source_dumps
 *
 * 源码包清单：列出所有源码包或按 webapp 筛选
 */
async function listSourceDumpsImpl(args: {
	webapp_id?: string;
	only_restored?: boolean;
	limit?: number;
}) {
	if (args.webapp_id) {
		const records = await querySourceDumpsByWebapp(args.webapp_id);
		return {
			content: [
				{
					type: 'text' as const,
					text: JSON.stringify({ total: records.length, sourceDumps: records }, null, 2),
				},
			],
		};
	}

	const { records, total } = await listSourceDumps({
		limit: Math.min(args.limit ?? 50, 200),
		offset: 0,
		onlyRestored: args.only_restored === true,
	});

	return {
		content: [
			{
				type: 'text' as const,
				text: JSON.stringify({ total, sourceDumps: records }, null, 2),
			},
		],
	};
}

/**
 * 工具 5：submit_seed
 *
 * 下发收集任务：归一化 + 写 seeds 表 + 异步触发 runRecon
 * 返回 seedId 供后续查询。
 *
 * mode 参数（供其他 Agent 选择收集范围）：
 *   auto（默认）: URL→单站，其余→全量
 *   site: 只收集该站信息（框架/语言/接口/JS/webpack），不枚举子域/端口
 *   full: 全量资产发现
 */
async function submitSeedImpl(args: {
	seed: string;
	mode?: 'auto' | 'site' | 'full';
	useFofa?: boolean;
}) {
	let seedId: string;
	let normalizedValue: string;
	let seedType: string;

	try {
		const normalized = normalizeSeed(args.seed);
		seedId = await upsertSeed(normalized);
		normalizedValue = normalized.valueNorm;
		seedType = normalized.seedType;
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return {
			content: [
				{
					type: 'text' as const,
					text: JSON.stringify({ error: `seed normalize failed: ${msg}` }),
				},
			],
			isError: true,
		};
	}

	// 异步触发扫描（不阻塞 MCP 响应）
	runRecon(args.seed, {
		mode: args.mode ?? 'auto',
		useFofa: args.useFofa,
		maxSubdomains: 1000,
		maxCompanyDomains: 50,
		companyDomainConcurrency: 3,
	})
		.then((result) => {
			console.error(`[mcp] seed ${args.seed} scan completed: ${result.webappCount} webapps`);
		})
		.catch((err) => {
			console.error(`[mcp] seed ${args.seed} scan failed:`, err);
		});

	return {
		content: [
			{
				type: 'text' as const,
				text: JSON.stringify(
					{
						seedId,
						seed: args.seed,
						seedType,
						normalizedValue,
						status: 'queued',
						message:
							'scan started asynchronously. Use query_assets/get_asset_metadata to check results.',
					},
					null,
					2,
				),
			},
		],
	};
}

// =============================================================================
// 服务器注册与启动
// =============================================================================

/**
 * 创建并注册所有 MCP 工具
 */
export function createMcpServer(): McpServer {
	const server = new McpServer(
		{ name: 'ck-recon', version: '0.1.0' },
		{
			instructions:
				'ck-recon 信息收集 Agent MCP Server。可用工具：query_assets（资产查询）、get_asset_metadata（资产元数据快照）、search_findings（发现检索）、list_source_dumps（源码包清单）、submit_seed（下发收集任务）。',
		},
	);

	// 1. query_assets
	server.registerTool(
		'query_assets',
		{
			title: '查询资产',
			description:
				'按 value 模糊匹配查询资产图（domains/subdomains/ips/webapps/urls）。返回资产列表含 ID、类型、值、存活状态。',
			inputSchema: {
				pattern: z.string().min(1).describe('资产值匹配模式（SQL ILIKE 语法，自动加 % 通配符）'),
				type: z
					.enum(['domain', 'subdomain', 'ip', 'url', 'webapp', 'company'])
					.optional()
					.describe('资产类型筛选'),
				limit: z
					.number()
					.int()
					.min(1)
					.max(500)
					.optional()
					.describe('返回数量上限（默认 50，最大 500）'),
			},
		},
		async (args) => await queryAssetsImpl(args),
	);

	// 2. get_asset_metadata
	server.registerTool(
		'get_asset_metadata',
		{
			title: '获取资产元数据快照',
			description:
				'返回指定 webapp 的完整 Metadata 快照（含 tech/endpoints/js_apis/params/flags/score/role/suggested_next）。这是渗透 Agent 的主接口。asset_id 是 webapp 的 UUID。',
			inputSchema: {
				asset_id: z.string().uuid().describe('webapp 的 asset_id（UUID 格式）'),
			},
		},
		async (args) => await getAssetMetadataImpl(args),
	);

	// 3. search_findings
	server.registerTool(
		'search_findings',
		{
			title: '检索发现',
			description:
				'按关键字 + 严重程度检索 findings（sourcemap/secret/cve_hint/internal_ip/sensitive_path/github_leak 等）。关键字匹配 detail 字段（ILIKE）。',
			inputSchema: {
				keyword: z.string().min(1).describe('关键字（匹配 detail 字段，SQL ILIKE 语法，自动加 %）'),
				severity: z
					.enum(['info', 'low', 'medium', 'high', 'critical'])
					.optional()
					.describe('严重程度筛选'),
				webapp_id: z.string().uuid().optional().describe('按 webapp 筛选'),
				limit: z
					.number()
					.int()
					.min(1)
					.max(500)
					.optional()
					.describe('返回数量上限（默认 50，最大 500）'),
			},
		},
		async (args) => await searchFindingsImpl(args),
	);

	// 4. list_source_dumps
	server.registerTool(
		'list_source_dumps',
		{
			title: '源码包清单',
			description:
				'列出 webpack 源码包（source_dumps 表）。可按 webapp 筛选，或只看已还原的（restored=true）。',
			inputSchema: {
				webapp_id: z.string().uuid().optional().describe('按 webapp 筛选'),
				only_restored: z.boolean().optional().describe('只返回已还原源码的（restored=true）'),
				limit: z
					.number()
					.int()
					.min(1)
					.max(200)
					.optional()
					.describe('返回数量上限（默认 50，最大 200）'),
			},
		},
		async (args) => await listSourceDumpsImpl(args),
	);

	// 5. submit_seed
	server.registerTool(
		'submit_seed',
		{
			title: '下发收集任务',
			description:
				'提交种子（公司名/域名/URL/IP/CIDR/IP:端口）触发异步信息收集。返回 seedId 供后续查询。扫描完成后可用 query_assets 查资产、get_asset_metadata 查元数据。\n' +
				'mode 参数（可选）：auto（默认，URL→单站）、site（只收集该站信息：框架/语言/接口/JS/webpack，不枚举子域/端口）、full（全量资产发现）。',
			inputSchema: {
				seed: z
					.string()
					.min(1)
					.describe('种子值（公司名/域名/URL/IP/CIDR/IP:端口）。会自动归一化识别类型。'),
				mode: z
					.enum(['auto', 'site', 'full'])
					.optional()
					.describe(
						'收集范围：auto（默认，URL→单站）/ site（只收集该站，不扩大）/ full（全量资产发现）',
					),
				useFofa: z
					.boolean()
					.optional()
					.describe(
						'是否启用 FOFA 资产补充（默认 true，配置了 FOFA_EMAIL/FOFA_KEY 即生效；域名查 domain=，IP 查 ip=）',
					),
			},
		},
		async (args) => await submitSeedImpl(args),
	);

	return server;
}

/**
 * stdio 模式启动（供 IDE/Agent 直接 spawn）
 */
export async function startStdio(): Promise<void> {
	const server = createMcpServer();
	const transport = new StdioServerTransport();
	await server.connect(transport);
	console.error('[ck-recon] MCP server started on stdio');
}

/**
 * Streamable HTTP 模式启动（监听 MCP_PORT，默认 8788）
 *
 * 实现要点（stateful 模式）：
 *   - 每个 session 分配独立 transport + McpServer 实例
 *   - 通过 Mcp-Session-Id 头路由后续请求
 *   - DELETE 请求关闭 session
 *   - 兼容无 session 的无状态初始化请求
 */
export async function startHttp(): Promise<void> {
	const cfg = getConfig();
	const port = cfg.server.mcpPort;

	// session 路由表
	const sessions = new Map<
		string,
		{ server: McpServer; transport: StreamableHTTPServerTransport }
	>();

	const httpServer = createServer(async (req, res) => {
		try {
			// 健康检查
			if (req.url === '/healthz') {
				res.writeHead(200, { 'Content-Type': 'application/json' });
				res.end(JSON.stringify({ status: 'ok', name: 'ck-recon-mcp' }));
				return;
			}

			// MCP 端点：/mcp
			if (req.url === '/mcp') {
				await handleMcpRequest(req, res, sessions);
				return;
			}

			res.writeHead(404, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ error: 'not found' }));
		} catch (err) {
			console.error('[mcp] request error:', err);
			if (!res.headersSent) {
				res.writeHead(500, { 'Content-Type': 'application/json' });
				res.end(JSON.stringify({ error: 'internal server error' }));
			}
		}
	});

	httpServer.listen(port, () => {
		console.error(`[ck-recon] MCP server listening on http://0.0.0.0:${port}/mcp`);
		console.error(`[ck-recon] health check: http://localhost:${port}/healthz`);
	});
}

/**
 * 处理单个 MCP HTTP 请求
 *
 * 路由策略：
 *   - POST + 无 session 头 + initialize 请求 → 创建新 session
 *   - POST + 有 session 头 → 路由到已有 session
 *   - GET + 有 session 头 → SSE 流（保持连接）
 *   - DELETE + 有 session 头 → 关闭 session
 */
async function handleMcpRequest(
	req: IncomingMessage,
	res: ServerResponse,
	sessions: Map<string, { server: McpServer; transport: StreamableHTTPServerTransport }>,
): Promise<void> {
	const sessionId = req.headers['mcp-session-id'] as string | undefined;
	const method = req.method ?? 'GET';

	// 读取请求体（POST 才有，GET/DELETE 为空）
	const bodyStr = method === 'POST' ? await readRequestBody(req) : '';
	let parsedBody: unknown = undefined;
	if (bodyStr) {
		try {
			parsedBody = JSON.parse(bodyStr);
		} catch {
			// 非 JSON，交由 transport 处理
		}
	}

	// 判断是否 initialize 请求
	const isInitialize = parsedBody !== undefined && isInitializeRequest(parsedBody);

	// 新建 session：仅 POST + initialize + 无现有 session
	if (method === 'POST' && isInitialize && !sessionId) {
		const newSessionId = randomUUID();
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: () => newSessionId,
		});
		const server = createMcpServer();
		await server.connect(transport);
		sessions.set(newSessionId, { server, transport });

		// 清理回调
		transport.onclose = () => {
			sessions.delete(newSessionId);
			console.error(`[mcp] session ${newSessionId} closed`);
		};

		await transport.handleRequest(req, res, parsedBody);
		return;
	}

	// 路由到已有 session
	if (sessionId) {
		const session = sessions.get(sessionId);
		if (!session) {
			res.writeHead(404, { 'Content-Type': 'application/json' });
			res.end(JSON.stringify({ error: 'session not found' }));
			return;
		}

		// DELETE 关闭 session
		if (method === 'DELETE') {
			await session.transport.close();
			sessions.delete(sessionId);
			res.writeHead(200);
			res.end();
			return;
		}

		await session.transport.handleRequest(req, res, parsedBody);
		return;
	}

	// 无 session 且非 initialize
	res.writeHead(400, { 'Content-Type': 'application/json' });
	res.end(
		JSON.stringify({
			error: 'missing Mcp-Session-Id header or invalid initialize request',
		}),
	);
}

/**
 * 读取 HTTP 请求体
 */
function readRequestBody(req: IncomingMessage): Promise<string> {
	return new Promise((resolve, reject) => {
		const chunks: Buffer[] = [];
		req.on('data', (chunk) => chunks.push(chunk));
		req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
		req.on('error', reject);
	});
}

/**
 * 主入口
 */
async function main(): Promise<void> {
	const useHttp = process.argv.includes('--http') || process.env.MCP_MODE === 'http';

	if (useHttp) {
		await startHttp();
	} else {
		await startStdio();
	}
}

main().catch((err) => {
	console.error('[mcp] fatal:', err);
	process.exit(1);
});
