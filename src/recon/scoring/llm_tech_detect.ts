/**
 * 技术栈识别 LLM 兜底
 *
 * 当 single_site 模式的 analyzeSiteHtml（正则规则库）识别不到框架/语言时，
 * 把 HTML 关键片段 + 响应头 + JS 文件名喂给 LLM（DeepSeek flash）判断：
 *   框架（framework）/ 开发语言（language）/ 构建工具（buildTool）/ 架构形态（architecture）
 *
 * 设计原则：
 *   - 仅在正则结果 framework 和 language 都为空时触发（规则覆盖不到的才问 LLM，省 token）
 *   - 结果缓存到 tech_detections 表（webapp_id + provider + model UNIQUE）
 *   - LLM 失败 / 解析失败 → 返回 null，调用方保留正则结果，不阻塞流程
 *   - 全程 audit_log 留痕（调用/缓存命中/失败）
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { getPg } from '../storage/pg.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface TechDetectInput {
	webappId: string;
	url: string;
	/** 响应头（原始大小写 key） */
	headers?: Record<string, string>;
	/** HTML 关键片段（head + 前 N 字符，调用方已截断） */
	htmlSnippet: string;
	/** 页面引用的 JS 文件名/路径列表 */
	jsFiles: string[];
}

export interface TechDetectResult {
	framework: string[];
	language: string[];
	buildTool: string[];
	architecture: 'spa' | 'mpa' | 'ssr' | 'static' | null;
	reasoning: string;
	/** 是否真的走了 LLM（false = 缓存命中） */
	fromLlm: boolean;
	provider: string;
	model: string;
}

const VALID_ARCH: Array<'spa' | 'mpa' | 'ssr' | 'static'> = ['spa', 'mpa', 'ssr', 'static'];

// =============================================================================
// 缓存（PG 表 tech_detections）
// =============================================================================

async function getCached(
	webappId: string,
	provider: string,
	model: string,
): Promise<Omit<TechDetectResult, 'fromLlm' | 'provider' | 'model'> | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT framework, language, build_tool, architecture, reasoning FROM tech_detections
     WHERE webapp_id = $1 AND provider = $2 AND model = $3
     ORDER BY created_at DESC LIMIT 1`,
		[webappId, provider, model],
	);
	if (rows.length === 0) return null;
	return {
		framework: rows[0].framework ?? [],
		language: rows[0].language ?? [],
		buildTool: rows[0].build_tool ?? [],
		architecture: rows[0].architecture as TechDetectResult['architecture'],
		reasoning: rows[0].reasoning ?? '',
	};
}

async function saveCache(
	webappId: string,
	provider: string,
	model: string,
	result: Omit<TechDetectResult, 'fromLlm' | 'provider' | 'model'>,
	rawResponse: unknown,
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO tech_detections (webapp_id, provider, model, framework, language, build_tool, architecture, reasoning, raw_response)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (webapp_id, provider, model) DO UPDATE
       SET framework = EXCLUDED.framework,
           language = EXCLUDED.language,
           build_tool = EXCLUDED.build_tool,
           architecture = EXCLUDED.architecture,
           reasoning = EXCLUDED.reasoning,
           raw_response = EXCLUDED.raw_response,
           created_at = now()`,
		[
			webappId,
			provider,
			model,
			result.framework,
			result.language,
			result.buildTool,
			result.architecture,
			result.reasoning,
			JSON.stringify(rawResponse ?? null),
		],
	);
}

// =============================================================================
// Prompt 拼装
// =============================================================================

function buildPrompt(input: TechDetectInput): { system: string; user: string } {
	const system = `你是一名网站技术栈识别专家。给定一个 Web 站点的 HTML 片段、HTTP 响应头和 JS 文件列表，识别它的技术栈。

输出 JSON 格式：
{
  "framework": ["前端/后端框架名，如 react/vue/angular/next/jquery/bootstrap/spring/thinkphp/wordpress，没有则为空数组"],
  "language": ["开发语言，如 php/java/csharp/nodejs/python/golang，无法确定则为空数组"],
  "buildTool": ["构建工具，如 webpack/vite/gulp/parcel/rollup，无法确定则为空数组"],
  "architecture": "spa | mpa | ssr | static | null",
  "reasoning": "简短说明判断依据（30字内）"
}

判断要点：
- architecture: spa=单页应用（根挂载点+打包JS）；mpa=多页应用（多个独立页面）；ssr=服务端渲染（next/nuxt等）；static=纯静态站；无法判断为 null
- 只基于输入内容判断，不要臆测
- framework/language/buildTool 每项最多 5 个，按确定程度排序`;
	return {
		system,
		user: JSON.stringify(
			{
				url: input.url,
				headers: input.headers ?? {},
				htmlSnippet: input.htmlSnippet.slice(0, 1500),
				jsFiles: input.jsFiles.slice(0, 20),
			},
			null,
			2,
		),
	};
}

// =============================================================================
// 解析
// =============================================================================

export function parseTechDetectResponse(content: string): {
	framework: string[];
	language: string[];
	buildTool: string[];
	architecture: TechDetectResult['architecture'];
	reasoning: string;
} {
	const fallback = {
		framework: [],
		language: [],
		buildTool: [],
		architecture: null,
		reasoning: '解析失败',
	};
	try {
		const obj = JSON.parse(extractJsonContent(content)) as {
			framework?: unknown;
			language?: unknown;
			buildTool?: unknown;
			architecture?: unknown;
			reasoning?: unknown;
		};
		const norm = (v: unknown): string[] => {
			if (!Array.isArray(v)) return [];
			return v
				.filter((x): x is string => typeof x === 'string' && x.length > 0)
				.map((x) => x.toLowerCase())
				.slice(0, 5);
		};
		const arch =
			typeof obj.architecture === 'string'
				? (obj.architecture.toLowerCase() as TechDetectResult['architecture'])
				: null;
		return {
			framework: norm(obj.framework),
			language: norm(obj.language),
			buildTool: norm(obj.buildTool),
			architecture: arch && VALID_ARCH.includes(arch) ? arch : null,
			reasoning: typeof obj.reasoning === 'string' ? obj.reasoning.slice(0, 200) : '',
		};
	} catch {
		return fallback;
	}
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 技术栈 LLM 兜底识别
 *
 * @param input 输入信息
 * @param opts.forceRefresh 强制刷新缓存（默认 false）
 * @returns 识别结果；调用失败时返回 null（调用方保留正则结果）
 */
export async function detectTechByLlm(
	input: TechDetectInput,
	opts: { forceRefresh?: boolean } = {},
): Promise<TechDetectResult | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	// 1. 查缓存
	if (!opts.forceRefresh) {
		try {
			const cached = await getCached(input.webappId, provider, model);
			if (cached) {
				await auditLog({
					actor: `llm:${provider}`,
					action: 'llm_call',
					target: input.webappId,
					decision: 'info',
					reason: 'tech_detect cache hit',
					meta: { model, framework: cached.framework },
				});
				return { ...cached, fromLlm: false, provider, model };
			}
		} catch {
			// 缓存查失败不阻塞
		}
	}

	// 2. 拼 prompt 并调用
	const { system, user } = buildPrompt(input);
	let raw;
	let errorMsg: string | null = null;
	try {
		// maxTokens 给足：推理模型 reasoning 先消耗输出预算
		raw = await callDeepSeek(system, user, { model, maxTokens: 800 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	// 3. 失败 → null（调用方保留正则结果）
	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'llm_call',
			target: input.webappId,
			decision: 'fail',
			reason: `tech_detect failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	// 4. 解析
	const parsed = parseTechDetectResponse(raw.choices[0].message.content);
	const result: TechDetectResult = {
		...parsed,
		fromLlm: true,
		provider,
		model,
	};

	// 5. 审计 + 缓存
	await auditLog({
		actor: `llm:${provider}`,
		action: 'llm_call',
		target: input.webappId,
		decision: 'allow',
		reason: `tech_detect: framework=[${result.framework.join(',')}] arch=${result.architecture ?? '-'}`,
		meta: {
			model,
			framework: result.framework,
			language: result.language,
			buildTool: result.buildTool,
			architecture: result.architecture,
			reasoning: result.reasoning,
			usage: raw.usage,
		},
	});
	try {
		await saveCache(input.webappId, provider, model, parsed, raw);
	} catch {
		// 缓存写失败不阻塞
	}

	return result;
}
