/**
 * LLM 分析 ②：接口聚类攻击面地图
 *
 * 对 JS 提取的接口（js_apis），LLM 聚合成攻击面分组：
 *   auth/upload/export/payment/debug/admin/user/other
 *
 * 价值：渗透 Agent 拿到的是"攻击面地图"而不是接口列表——
 *   auth 组 = 认证绕过测试点，upload 组 = 文件上传测试点...
 *
 * 预算：每 webapp 1 次调用（≤150 个接口），meta.attack_surface_at 防重复
 * 失败：返回 null，不影响主流程
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface AttackSurfaceInput {
	webappId: string;
	url: string;
	jsApis: Array<{ apiPath: string; method: string; params: string[] }>;
}

export interface AttackSurfaceResult {
	/** 攻击面分组：组名 → 接口路径列表 */
	attackSurface: Record<string, string[]>;
	summary: string;
	recommendations: string[];
	fromLlm: boolean;
	provider: string;
	model: string;
}

// =============================================================================
// Prompt 与解析
// =============================================================================

function buildPrompt(input: AttackSurfaceInput): { system: string; user: string } {
	const system = `你是 Web 应用攻击面分析专家。给定从 JS 中提取的接口清单，按攻击面类型聚类。

分组定义：
- auth: 认证/授权（login/logout/token/oauth/refresh/verify）
- admin: 管理后台接口（user管理/配置/权限设置）
- upload: 文件上传
- export: 文件导出/下载/报表
- payment: 支付/下单/订单/退款
- debug: 调试/健康检查/环境信息/测试接口
- user: 用户业务接口（profile/消息/收藏等）
- other: 无法归类的

输出 JSON：
{
  "attackSurface": {"auth": ["/api/login", "/api/token/refresh"], "upload": ["/api/upload"], ...},
  "summary": "一句话总结该站点的攻击面特征（50字内）",
  "recommendations": ["渗透测试建议1", "建议2"]
}

要求：
1. 每个接口只归入一个最贴切的组
2. 保留原始路径（含 {id} 模板）
3. 组不存在则为空数组或不出现该键
4. recommendations 最多 5 条

只输出 JSON。`;

	const user = JSON.stringify({
		url: input.url,
		jsApis: input.jsApis.slice(0, 150),
	});
	return { system, user };
}

export function parseAttackSurfaceResponse(content: string): {
	attackSurface: Record<string, string[]>;
	summary: string;
	recommendations: string[];
	parseError: boolean;
} {
	const fallback = { attackSurface: {}, summary: '', recommendations: [], parseError: true };
	let obj: { attackSurface?: unknown; summary?: unknown; recommendations?: unknown };
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}
	const attackSurface: Record<string, string[]> = {};
	if (obj.attackSurface && typeof obj.attackSurface === 'object') {
		for (const [group, paths] of Object.entries(obj.attackSurface as Record<string, unknown>)) {
			if (Array.isArray(paths)) {
				attackSurface[group] = paths
					.filter((p): p is string => typeof p === 'string' && p.length > 0)
					.slice(0, 100);
			}
		}
	}
	return {
		attackSurface,
		summary: typeof obj.summary === 'string' ? obj.summary.slice(0, 200) : '',
		recommendations: Array.isArray(obj.recommendations)
			? obj.recommendations.filter((r): r is string => typeof r === 'string').slice(0, 5)
			: [],
		parseError: false,
	};
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 接口聚类攻击面地图（LLM 分析 ②）
 *
 * @returns 分析结果；失败/无接口时返回 null
 */
export async function analyzeAttackSurface(
	input: AttackSurfaceInput,
): Promise<AttackSurfaceResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	if (input.jsApis.length === 0) return null;

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
			reason: `attack_surface failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	const parsed = parseAttackSurfaceResponse(raw.choices[0].message.content);
	if (parsed.parseError) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'deny',
			reason: 'attack_surface parse failed',
			meta: { model },
		});
		return null;
	}

	const result: AttackSurfaceResult = {
		...parsed,
		fromLlm: true,
		provider,
		model,
	};

	// 落库：webapp.meta.attack_surface
	try {
		const pool = getPg();
		await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
			JSON.stringify({
				attack_surface: result.attackSurface,
				attack_surface_summary: result.summary,
				attack_surface_recommendations: result.recommendations,
				attack_surface_at: new Date().toISOString(),
			}),
			input.webappId,
		]);
	} catch {
		// 落库失败不阻塞
	}

	const groupSummary = Object.entries(result.attackSurface)
		.map(([g, p]) => `${g}:${p.length}`)
		.join(' ');
	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.webappId,
		decision: 'allow',
		reason: `attack_surface: ${groupSummary}`,
		meta: { model, decision: result, usage: raw.usage },
	});

	console.log(`[attack_surface] ${groupSummary} (${input.url})`);
	return result;
}
