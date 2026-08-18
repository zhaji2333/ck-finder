/**
 * LLM 分析 ①：页面语义分类（高价值入口定位）
 *
 * 对收集到的 endpoints（katana/dirscan），LLM 判断每个页面的语义角色：
 *   login/admin/api_doc/upload/export/payment/debug/auth/business/static/other
 *
 * 价值：渗透 Agent 不再从几百个路径里人肉找入口，
 * 直接拿到"登录页/后台/上传点/导出点"清单。
 *
 * 预算：每 webapp 1 次调用（≤100 个 endpoint），meta.page_classified_at 防重复
 * 失败：返回 null，不影响主流程
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export const PAGE_ROLES = [
	'login',
	'admin',
	'api_doc',
	'upload',
	'export',
	'payment',
	'debug',
	'auth',
	'business',
	'static',
	'other',
] as const;

export type PageRole = (typeof PAGE_ROLES)[number];

export interface PageClassifyInput {
	webappId: string;
	url: string;
	endpoints: Array<{ path: string; method: string; source: string }>;
}

export interface PageClassifyResult {
	items: Array<{ path: string; role: PageRole; reason: string }>;
	fromLlm: boolean;
	provider: string;
	model: string;
}

// =============================================================================
// Prompt 与解析
// =============================================================================

function buildPrompt(input: PageClassifyInput): { system: string; user: string } {
	const system = `你是 Web 应用页面语义分类专家。给定一个站点的路径清单，判断每个路径对应的页面类型。

角色定义：
- login: 登录/注册/找回密码页
- admin: 管理后台页面
- api_doc: API 文档（swagger/api-docs/graphql playground 等）
- upload: 文件上传功能
- export: 文件导出/下载/报表功能
- payment: 支付/下单/订单相关
- debug: 调试接口/测试页/开发工具
- auth: 认证/授权相关接口（token/oauth/session）
- business: 业务功能页
- static: 静态资源/纯展示页
- other: 无法判断

输出 JSON：
{"items": [{"path": "/login", "role": "login", "reason": "登录页路径"}]}

要求：
1. 只对能明确判断的路径给出分类，模糊的用 other
2. 每项必须包含输入的完整 path（原样返回，不要改写）
3. 最多返回 100 项

只输出 JSON。`;

	const user = JSON.stringify({
		url: input.url,
		endpoints: input.endpoints.slice(0, 100),
	});
	return { system, user };
}

export function parsePageClassifyResponse(content: string): {
	items: Array<{ path: string; role: PageRole; reason: string }>;
	parseError: boolean;
} {
	const fallback = { items: [], parseError: true };
	let obj: { items?: unknown };
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}
	if (!Array.isArray(obj.items)) return fallback;
	const items: Array<{ path: string; role: PageRole; reason: string }> = [];
	for (const raw of obj.items) {
		if (!raw || typeof raw !== 'object') continue;
		const it = raw as { path?: unknown; role?: unknown; reason?: unknown };
		if (typeof it.path !== 'string' || !it.path) continue;
		const role = typeof it.role === 'string' ? (it.role.toLowerCase() as PageRole) : 'other';
		items.push({
			path: it.path.slice(0, 500),
			role: (PAGE_ROLES as readonly string[]).includes(role) ? role : 'other',
			reason: typeof it.reason === 'string' ? it.reason.slice(0, 100) : '',
		});
	}
	return { items, parseError: false };
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 页面语义分类（LLM 分析 ①）
 *
 * @returns 分类结果；失败/无 endpoint 时返回 null
 */
export async function classifyPagesByLlm(
	input: PageClassifyInput,
): Promise<PageClassifyResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	if (input.endpoints.length === 0) return null;

	const { system, user } = buildPrompt(input);
	let raw;
	let errorMsg: string | null = null;
	try {
		raw = await callDeepSeek(system, user, { model, maxTokens: 2000 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'fail',
			reason: `page_classify failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	const parsed = parsePageClassifyResponse(raw.choices[0].message.content);
	if (parsed.parseError) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'deny',
			reason: 'page_classify parse failed',
			meta: { model },
		});
		return null;
	}

	// 落库：更新 endpoints.page_role
	let updated = 0;
	try {
		const { updateEndpointPageRoles } = await import('../storage/models/recon.js');
		updated = await updateEndpointPageRoles(input.webappId, parsed.items);
	} catch {
		// 落库失败不阻塞
	}

	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.webappId,
		decision: 'allow',
		reason: `page_classify: ${parsed.items.length} items classified, ${updated} updated`,
		meta: { model, itemCount: parsed.items.length, updated, usage: raw.usage },
	});

	// meta 标记防重复
	try {
		const pool = getPg();
		await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
			JSON.stringify({ page_classified_at: new Date().toISOString() }),
			input.webappId,
		]);
	} catch {
		// 忽略
	}

	return { items: parsed.items, fromLlm: true, provider, model };
}
