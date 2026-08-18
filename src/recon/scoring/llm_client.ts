/**
 * 共享 DeepSeek API 客户端（OpenAI 兼容）
 *
 * 从 llm_classifier.ts 抽取，供所有 LLM 兜底环节复用：
 *   - llm_classifier（角色分类兜底）
 *   - llm_tech_detect（技术栈识别兜底）
 *   - llm_js_extract（JS 接口提取增强）
 *   - source_audit（源码审计）
 *
 * 统一约定：
 *   - JSON mode（response_format: json_object）
 *   - temperature 0.1（确定性优先）
 *   - 超时 30s，失败抛错由调用方兜底
 *   - 所有调用由调用方负责审计（audit_log）与缓存
 */

import { getConfig } from '../config.js';

export interface DeepSeekResponse {
	id: string;
	choices: Array<{
		message: { role: string; content: string };
		finish_reason: string;
	}>;
	usage: { prompt_tokens: number; completion_tokens: number; total_tokens: number };
}

export interface DeepSeekCallOptions {
	/** 模型名（默认取 config.llm.flashModel） */
	model?: string;
	/** 超时（毫秒，默认 30s） */
	timeoutMs?: number;
	/** 最大输出 token（默认 300） */
	maxTokens?: number;
	/** 是否要求 JSON 输出（默认 true） */
	jsonMode?: boolean;
}

/**
 * 调用 DeepSeek Chat Completions API
 *
 * @param systemPrompt 系统提示词
 * @param userPrompt 用户提示词
 * @returns DeepSeek 响应（含 choices/usage）
 * @throws 网络错误 / 非 2xx 状态
 */
export async function callDeepSeek(
	systemPrompt: string,
	userPrompt: string,
	opts: DeepSeekCallOptions = {},
): Promise<DeepSeekResponse> {
	const cfg = getConfig().llm;
	if (!cfg.apiKey) {
		// 未配置 DEEPSEEK_API_KEY：抛明确错误，由上层 try/catch 降级为纯规则
		throw new Error('DEEPSEEK_API_KEY 未配置，LLM 环节降级为纯规则（收集不受影响）');
	}
	const model = opts.model ?? cfg.flashModel;
	const timeoutMs = opts.timeoutMs ?? 30_000;
	const maxTokens = opts.maxTokens ?? 300;
	const jsonMode = opts.jsonMode !== false;

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await fetch(`${cfg.baseUrl}/v1/chat/completions`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${cfg.apiKey}`,
			},
			body: JSON.stringify({
				model,
				messages: [
					{ role: 'system', content: systemPrompt },
					{ role: 'user', content: userPrompt },
				],
				temperature: 0.1,
				max_tokens: maxTokens,
				...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
			}),
			signal: controller.signal,
		});
		if (!resp.ok) {
			const text = await resp.text();
			throw new Error(`DeepSeek API ${resp.status}: ${text.slice(0, 500)}`);
		}
		return (await resp.json()) as DeepSeekResponse;
	} finally {
		clearTimeout(timer);
	}
}

/**
 * 从 LLM 响应中提取 JSON 内容（处理代码块包裹等边界情况）
 *
 * 部分模型会输出 ```json ... ``` 包裹的 JSON，这里做兼容提取。
 */
export function extractJsonContent(content: string): string {
	const trimmed = content.trim();
	// 去掉 ```json 代码块包裹
	const fenceMatch = trimmed.match(/^```(?:json)?\s*([\s\S]*?)```\s*$/);
	if (fenceMatch) return fenceMatch[1].trim();
	return trimmed;
}
