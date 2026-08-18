/**
 * M2/M3 安全层：把 Scope Gate + 审计接入 pi Agent 工具生命周期。
 *
 * - beforeToolCall：拦截有网络/越权面的工具（web_fetch / http_req / nuclei_scan / sqlmap_run / dir_brute / auth_brute），
 *   校验目标在授权范围；越权返回 { block: true, reason }（fail-closed）。recon_* 只读工具放行。
 * - afterToolCall：全部工具调用写 audit_log（复用 ck-recon audit_log.ts）。
 *
 * scope 解析/匹配逻辑在 security/scope_util.ts（与爆破工具护栏共用）。
 */
import type {
	AfterToolCallContext,
	AgentTool,
	BeforeToolCallContext,
} from '@earendil-works/pi-agent-core';
import { auditLog } from '../recon/gate/audit_log.js';
import {
	effectiveScope,
	extractHostFromUrl,
	hostInScope,
	isCloudMetadataHost,
	isReservedHost,
	parseScope,
} from './scope_util.js';

/** 有网络/越权面的工具（需 Scope Gate 校验目标）；recon_* 为只读本地查询，直接放行 */
export const NETWORK_TOOLS = new Set([
	'web_fetch', // M0 侦察抓取
	'http_req', // M3 手工重放
	'nuclei_scan', // M3 nuclei
	'sqlmap_run', // M3 sqlmap
	'dir_brute', // M3 目录爆破
	'auth_brute', // M3 弱口令
]);

export interface ToolGateOptions {
	/** 授权范围（域名/IP/CIDR/url） */
	scope: string[];
	/** 强制启用 Gate（即使 SCOPE_GATE_ENABLED=false） */
	forceEnabled: boolean;
}

/** 从工具名 + 参数提取要校验的目标（url/host），无网络目标返回 null */
function extractTarget(toolName: string, args: Record<string, unknown>): string | null {
	switch (toolName) {
		case 'web_fetch':
		case 'http_req':
		case 'nuclei_scan':
		case 'sqlmap_run':
		case 'dir_brute':
		case 'auth_brute': {
			const url = args.url ?? args.target;
			if (typeof url === 'string' && url) return url;
			return null;
		}
		default:
			return null;
	}
}

/**
 * 构建 pi beforeToolCall 的 Scope Gate 检查器。
 * 返回 undefined = 放行；返回 { block: true, reason } = 拦截。
 */
export function buildScopeGateChecker(options: ToolGateOptions) {
	// 与收集引擎 scope（SCOPE_ALLOWED）取并集
	const effective = effectiveScope(options.scope);
	const parsed = parseScope(effective);

	return async (
		context: BeforeToolCallContext,
	): Promise<{ block: true; reason: string } | undefined> => {
		const toolCall = context.toolCall as { name?: string };
		const toolName = toolCall.name ?? '';
		if (!NETWORK_TOOLS.has(toolName)) return undefined; // 只读/本地工具放行

		const args = (context.args ?? {}) as Record<string, unknown>;
		const target = extractTarget(toolName, args);
		if (!target) return undefined;

		// 无 scope 时默认拒绝（fail-closed）
		if (effective.length === 0) {
			return {
				block: true,
				reason: `未设置授权范围（--scope / CKFINDER_SCOPE），拒绝访问目标 ${target}`,
			};
		}

		const host = extractHostFromUrl(target);
		if (!host) {
			return { block: true, reason: `无法解析目标 host: ${target}` };
		}

		// 云元数据端点（169.254.169.254 / metadata.* 等）：SSRF 验证目标，允许命中
		if (isCloudMetadataHost(host)) {
			return undefined;
		}

		// 显式授权命中（含内网 CIDR 段：用户显式授权即允许）→ 放行
		if (hostInScope(host, parsed)) {
			return undefined;
		}

		// 未命中授权：保留/内网地址给专门提示（防 DNS rebinding / 打到内网字面 IP）
		if (isReservedHost(host)) {
			return { block: true, reason: `目标为保留/内网地址且未在授权内: ${host}` };
		}

		return {
			block: true,
			reason: `目标不在授权范围: ${host}（授权: ${effective.join(', ')}）`,
		};
	};
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

/**
 * 审计所有工具调用（before 记录入参，after 记录结果）。
 * 复用 ck-recon audit_log 表（audit_actor=tool:<name>）。
 */
export function buildAuditLogger(runId: string) {
	return {
		async onToolStart(context: BeforeToolCallContext) {
			const toolCall = context.toolCall as { name?: string };
			const toolName = toolCall.name ?? '';
			const args = (context.args ?? {}) as Record<string, unknown>;
			await auditLog({
				actor: `tool:${toolName}`,
				action: 'tool_call',
				target: extractTarget(toolName, args) ?? 'n/a',
				decision: 'pass',
				reason: 'tool invoked',
				meta: { run_id: runId, args: summary(args) },
			});
		},
		async onToolEnd(context: AfterToolCallContext) {
			const toolCall = context.toolCall as { name?: string };
			const toolName = toolCall.name ?? '';
			await auditLog({
				actor: `tool:${toolName}`,
				action: context.isError ? 'tool_error' : 'tool_end',
				target: 'n/a',
				decision: context.isError ? 'fail' : 'pass',
				reason: context.isError ? 'tool error' : 'completed',
				meta: { run_id: runId },
			});
		},
	};
}

/** 参数摘要（避免敏感信息/大对象进审计） */
function summary(args: Record<string, unknown>): string {
	try {
		const s = JSON.stringify(args);
		return s.length > 500 ? `${s.slice(0, 500)}…` : s;
	} catch {
		return '<unserializable>';
	}
}

/** 有网络面的工具列表（供系统提示词引用） */
export function describeNetworkTools(tools: AgentTool[]): string {
	return tools
		.map((t) => t.name)
		.filter((n) => NETWORK_TOOLS.has(n))
		.join(', ');
}
