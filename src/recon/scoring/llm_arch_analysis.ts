/**
 * LLM 分析 ③：技术栈架构级分析
 *
 * 在识别出"是什么技术栈"之后，进一步分析"架构怎么组织的"：
 *   - rendering: csr（客户端渲染）/ ssr（服务端渲染）/ static
 *   - apiStyle: rest / graphql / rpc / none
 *   - authMechanism: jwt / session / cookie / oauth2 / none
 *   - thirdParty: 第三方集成（CDN/分析/支付/登录）
 *   - frameworkDetail: 框架版本/组件细节
 *
 * 预算：每 webapp 1 次调用（framework 或 JS 存在才触发），meta.site_arch_analyzed_at 防重复
 * 失败：返回 null，不影响主流程
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface ArchAnalysisInput {
	webappId: string;
	url: string;
	/** HTML 关键片段（head + 前 N 字符） */
	htmlSnippet: string;
	/** 页面引用的 JS 文件名 */
	jsFiles: string[];
	/** 已识别的框架（正则或 LLM 兜底结果） */
	framework: string[];
	/** 已识别的架构（spa/mpa/ssr/static） */
	architecture: string | null;
}

export interface ArchAnalysisResult {
	rendering: 'csr' | 'ssr' | 'static' | null;
	apiStyle: 'rest' | 'graphql' | 'rpc' | 'none' | null;
	authMechanism: 'jwt' | 'session' | 'cookie' | 'oauth2' | 'none' | null;
	thirdParty: string[];
	frameworkDetail: string;
	notes: string;
	fromLlm: boolean;
	provider: string;
	model: string;
}

// =============================================================================
// Prompt 与解析
// =============================================================================

function buildPrompt(input: ArchAnalysisInput): { system: string; user: string } {
	const system = `你是 Web 应用架构分析专家。给定一个站点的 HTML 片段、JS 文件列表和已识别技术栈，分析其架构组织方式。

输出 JSON：
{
  "rendering": "csr" | "ssr" | "static" | null,
  "apiStyle": "rest" | "graphql" | "rpc" | "none" | null,
  "authMechanism": "jwt" | "session" | "cookie" | "oauth2" | "none" | null,
  "thirdParty": ["第三方集成，如 google-analytics/wechat-pay/captcha，最多5个"],
  "frameworkDetail": "框架细节（版本/UI库/状态管理，50字内）",
  "notes": "架构特征备注（100字内）"
}

判断依据：
- rendering: 有服务端注入数据（__NEXT_DATA__/window.__INITIAL_STATE__/SSR 渲染的 HTML 内容）→ ssr；根挂载点+打包 JS → csr；无 JS 动态性 → static
- apiStyle: 存在 /graphql → graphql；/api/v1 等 REST 风格 → rest；rpc/grpc-web 特征 → rpc；无接口 → none
- authMechanism: 从 HTML/JS 特征推断（JWT 关键词/token 存储/Session/Cookie 设置/oauth 跳转），无法判断 → null
- 无法判断的字段用 null，不要臆测

只输出 JSON。`;

	const user = JSON.stringify(
		{
			url: input.url,
			htmlSnippet: input.htmlSnippet.slice(0, 1500),
			jsFiles: input.jsFiles.slice(0, 20),
			detectedFramework: input.framework,
			detectedArchitecture: input.architecture,
		},
		null,
		2,
	);
	return { system, user };
}

const VALID_RENDERING = ['csr', 'ssr', 'static'] as const;
const VALID_API_STYLE = ['rest', 'graphql', 'rpc', 'none'] as const;
const VALID_AUTH = ['jwt', 'session', 'cookie', 'oauth2', 'none'] as const;

export function parseArchAnalysisResponse(content: string): {
	rendering: ArchAnalysisResult['rendering'];
	apiStyle: ArchAnalysisResult['apiStyle'];
	authMechanism: ArchAnalysisResult['authMechanism'];
	thirdParty: string[];
	frameworkDetail: string;
	notes: string;
	parseError: boolean;
} {
	const fallback = {
		rendering: null,
		apiStyle: null,
		authMechanism: null,
		thirdParty: [],
		frameworkDetail: '',
		notes: '',
		parseError: true,
	};
	let obj: {
		rendering?: unknown;
		apiStyle?: unknown;
		authMechanism?: unknown;
		thirdParty?: unknown;
		frameworkDetail?: unknown;
		notes?: unknown;
	};
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}
	const pick = <T extends readonly string[]>(v: unknown, valid: T): T[number] | null => {
		if (typeof v !== 'string') return null;
		const lower = v.toLowerCase() as T[number];
		return (valid as readonly string[]).includes(lower) ? lower : null;
	};
	return {
		rendering: pick(obj.rendering, VALID_RENDERING),
		apiStyle: pick(obj.apiStyle, VALID_API_STYLE),
		authMechanism: pick(obj.authMechanism, VALID_AUTH),
		thirdParty: Array.isArray(obj.thirdParty)
			? obj.thirdParty.filter((t): t is string => typeof t === 'string').slice(0, 5)
			: [],
		frameworkDetail:
			typeof obj.frameworkDetail === 'string' ? obj.frameworkDetail.slice(0, 200) : '',
		notes: typeof obj.notes === 'string' ? obj.notes.slice(0, 300) : '',
		parseError: false,
	};
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 技术栈架构级分析（LLM 分析 ③）
 *
 * @returns 分析结果；失败时返回 null
 */
export async function analyzeArchitecture(
	input: ArchAnalysisInput,
): Promise<ArchAnalysisResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	const { system, user } = buildPrompt(input);
	let raw;
	let errorMsg: string | null = null;
	try {
		raw = await callDeepSeek(system, user, { model, maxTokens: 1200 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'fail',
			reason: `arch_analysis failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	const parsed = parseArchAnalysisResponse(raw.choices[0].message.content);
	if (parsed.parseError) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.webappId,
			decision: 'deny',
			reason: 'arch_analysis parse failed',
			meta: { model },
		});
		return null;
	}

	const result: ArchAnalysisResult = {
		...parsed,
		fromLlm: true,
		provider,
		model,
	};

	// 落库：webapp.meta.site_arch_detail
	try {
		const pool = getPg();
		await pool.query('UPDATE webapps SET meta = meta || $1::jsonb WHERE asset_id = $2', [
			JSON.stringify({
				site_rendering: result.rendering,
				site_api_style: result.apiStyle,
				site_auth_mechanism: result.authMechanism,
				site_third_party: result.thirdParty,
				site_framework_detail: result.frameworkDetail,
				site_arch_notes: result.notes,
				site_arch_analyzed_at: new Date().toISOString(),
			}),
			input.webappId,
		]);
	} catch {
		// 落库失败不阻塞
	}

	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.webappId,
		decision: 'allow',
		reason: `arch_analysis: render=${result.rendering ?? '-'} api=${result.apiStyle ?? '-'} auth=${result.authMechanism ?? '-'}`,
		meta: { model, decision: result, usage: raw.usage },
	});

	console.log(
		`[arch_analysis] render=${result.rendering ?? '-'} api=${result.apiStyle ?? '-'} auth=${result.authMechanism ?? '-'} (${input.url})`,
	);
	return result;
}
