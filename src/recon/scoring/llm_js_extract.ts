/**
 * JS 接口提取 LLM 增强
 *
 * 当正则提取（extractApiEndpoints）命中很少时，用 LLM（DeepSeek flash）
 * 从压缩/混淆 JS 中补充提取 API 路径。
 *
 * 触发条件（严格控成本）：
 *   - 正则结果 < 3 条
 *   - 文件大小 2KB ~ 300KB（太小没内容，太大超预算）
 *   - 内容截断前 8K 字符
 *
 * 预算控制（调用侧执行）：
 *   - 每个 webapp 最多对 LLM_JS_EXTRACT_PER_WEBAPP（默认 5）个文件跑 LLM
 *   - 会话内按 sourceJs 去重（同一文件不重复问）
 *
 * 容错：
 *   - LLM 失败 / 解析失败 → 返回 []，不影响正则结果
 *   - audit_log 全程留痕（调用/失败/预算跳过）
 */

import { auditLog } from '../gate/audit_log.js';
import { callDeepSeek, extractJsonContent } from './llm_client.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface LlmJsExtractInput {
	/** webapp 资产 ID（审计用） */
	webappId: string;
	/** 目标 URL（审计用） */
	url: string;
	/** JS 文件内容（已截断由调用方控制？不——本模块内部截断） */
	content: string;
	/** 源 JS URL/文件名 */
	sourceJs: string;
	/** 正则已提取的接口（供 LLM 参考去重） */
	ruleHits: Array<{ path: string; method: string }>;
}

export interface LlmJsEndpoint {
	path: string;
	method: string;
	params: string[];
}

export interface LlmJsExtractResult {
	endpoints: LlmJsEndpoint[];
	/** 是否走了 LLM（false = 未触发/失败） */
	fromLlm: boolean;
	reason?: string;
}

/** 会话级去重：sourceJs → 最近提取时间戳 */
const recentExtracts = new Map<string, number>();

/** 会话级预算：webappId → 已提取文件数 */
const budgetUsed = new Map<string, number>();

/**
 * 重置会话级状态（测试/新任务用）
 */
export function resetLlmJsExtractState(): void {
	recentExtracts.clear();
	budgetUsed.clear();
}

// =============================================================================
// 触发条件
// =============================================================================

export interface ShouldExtractInput {
	/** 正则提取条数 */
	ruleHitCount: number;
	/** 文件内容长度（字节） */
	contentLength: number;
	/** 每个 webapp 的文件预算（默认 5） */
	perWebappBudget?: number;
}

/**
 * 是否值得对某个 JS 文件跑 LLM 提取（确定性条件，不花钱先判断）
 */
export function shouldExtractByLlm(input: ShouldExtractInput): boolean {
	if (input.ruleHitCount >= 3) return false; // 正则已够，不花 token
	if (input.contentLength < 2_000 || input.contentLength > 300_000) return false;
	return true;
}

// =============================================================================
// Prompt 拼装与解析
// =============================================================================

function buildPrompt(input: LlmJsExtractInput): { system: string; user: string } {
	const system = `你是前端 JS 逆向分析助手。给定一段 JavaScript 代码，提取其中所有的 API 接口路径。

规则：
1. 提取 fetch('/api/...')、axios.get('/api/...')、XMLHttpRequest.open('GET','/api/...')、$.ajax({url:'...'}) 等请求的路径
2. 也提取字符串拼接生成的路径，如 '/api/v1/' + type + '/list' → /api/v1/{type}/list（把动态段替换为 {param}）
3. 路径去 query 参数（query 参数名提取到 params 数组）
4. 不提取静态资源路径（.js/.css/.png/.svg/.woff 等）
5. 路径统一格式：以 / 开头，数字段替换为 {id}，如 /api/users/123 → /api/users/{id}

输出 JSON：
{"endpoints": [{"path": "/api/v1/login", "method": "POST", "params": []}]}

最多返回 30 个接口，按出现顺序排列。没有则返回 {"endpoints": []}。`;

	const user = JSON.stringify({
		sourceFile: input.sourceJs,
		jsContent: input.content.slice(0, 8_000),
		alreadyFound: input.ruleHits.slice(0, 20),
	});
	return { system, user };
}

export function parseLlmJsEndpoints(content: string): LlmJsEndpoint[] {
	try {
		const obj = JSON.parse(extractJsonContent(content)) as { endpoints?: unknown };
		if (!Array.isArray(obj.endpoints)) return [];
		const out: LlmJsEndpoint[] = [];
		for (const ep of obj.endpoints) {
			if (!ep || typeof ep !== 'object') continue;
			const e = ep as { path?: unknown; method?: unknown; params?: unknown };
			if (typeof e.path !== 'string' || !e.path.startsWith('/')) continue;
			if (!/\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|map)(\?|$)/i.test(e.path)) {
				out.push({
					path: e.path.slice(0, 500),
					method: typeof e.method === 'string' && e.method ? e.method.toUpperCase() : 'GET',
					params: Array.isArray(e.params)
						? e.params.filter((p): p is string => typeof p === 'string').slice(0, 10)
						: [],
				});
			}
		}
		return out.slice(0, 30);
	} catch {
		return [];
	}
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 对单个 JS 文件做 LLM 接口提取（含预算与去重控制）
 *
 * @returns 提取结果；未触发/失败时 endpoints=[] + fromLlm=false
 */
export async function extractApisByLlm(
	input: LlmJsExtractInput,
	opts: { perWebappBudget?: number } = {},
): Promise<LlmJsExtractResult> {
	const budget = opts.perWebappBudget ?? 5;

	// 0. 会话级去重（同一文件一次扫描内只问一次）
	const lastTs = recentExtracts.get(input.sourceJs);
	if (lastTs && Date.now() - lastTs < 24 * 60 * 60 * 1000) {
		return { endpoints: [], fromLlm: false, reason: 'session dedup' };
	}

	// 1. 预算检查
	const used = budgetUsed.get(input.webappId) ?? 0;
	if (used >= budget) {
		return { endpoints: [], fromLlm: false, reason: `budget exceeded (${used}/${budget})` };
	}

	// 2. 触发条件
	if (
		!shouldExtractByLlm({
			ruleHitCount: input.ruleHits.length,
			contentLength: input.content.length,
		})
	) {
		return { endpoints: [], fromLlm: false, reason: 'trigger condition not met' };
	}

	// 3. 调用
	const { system, user } = buildPrompt(input);
	let raw;
	let errorMsg: string | null = null;
	try {
		// maxTokens 给足：推理模型 reasoning 先消耗输出预算
		raw = await callDeepSeek(system, user, { maxTokens: 2000 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: 'llm:deepseek',
			action: 'llm_call',
			target: input.webappId,
			decision: 'fail',
			reason: `js_extract failed: ${errorMsg ?? `empty response (finish=${raw?.choices?.[0]?.finish_reason ?? '?'})`} (${input.sourceJs})`,
			meta: { url: input.url, sourceJs: input.sourceJs },
		});
		return { endpoints: [], fromLlm: false, reason: `llm failed: ${errorMsg ?? 'empty'}` };
	}

	// 4. 解析 + 记账
	const endpoints = parseLlmJsEndpoints(raw.choices[0].message.content);
	recentExtracts.set(input.sourceJs, Date.now());
	budgetUsed.set(input.webappId, used + 1);

	await auditLog({
		actor: 'llm:deepseek',
		action: 'llm_call',
		target: input.webappId,
		decision: 'allow',
		reason: `js_extract: ${endpoints.length} endpoints from ${input.sourceJs}`,
		meta: {
			url: input.url,
			sourceJs: input.sourceJs,
			endpointCount: endpoints.length,
			usage: raw.usage,
			budgetUsed: used + 1,
		},
	});

	return { endpoints, fromLlm: true };
}
