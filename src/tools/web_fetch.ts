/**
 * ck-finder 自定义工具集：全部通过 pi-agent-core 的 AgentTool 注册。
 * 铁律：工具出数据，模型出决策。工具只负责确定性执行与结构化输出。
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';

const webFetchParams = Type.Object({
	url: Type.String({ description: '完整 URL，如 https://example.com/admin' }),
	method: Type.Optional(Type.String({ description: 'HTTP 方法，默认 GET' })),
	timeoutMs: Type.Optional(
		Type.Integer({
			description: '超时毫秒，默认 15000',
			minimum: 1000,
			maximum: 60000,
		}),
	),
});

interface WebFetchDetails {
	url: string;
	status: number;
	contentType: string;
	length: number;
	truncated: boolean;
}

/**
 * 抓取单个 URL 内容（用于访问目标 Web 页面/接口）。
 * 输出上限 512KB，超出截断并标记 truncated，防止撑爆 Agent 上下文。
 */
export const webFetchTool: AgentTool<typeof webFetchParams, WebFetchDetails> = {
	name: 'web_fetch',
	label: 'Fetch URL',
	description:
		'抓取一个 HTTP(S) URL 并返回响应文本（状态码/响应头/正文前 512KB）。用于侦察目标 Web 页面、接口响应、JS 文件内容。',
	parameters: webFetchParams,
	execute: async (
		_toolCallId,
		params,
		signal,
		onUpdate,
	): Promise<AgentToolResult<WebFetchDetails>> => {
		const timeoutMs = params.timeoutMs ?? 15_000;
		onUpdate?.({
			content: [{ type: 'text', text: `Fetching ${params.url} ...` }],
			details: {
				url: params.url,
				status: 0,
				contentType: '',
				length: 0,
				truncated: false,
			},
		});
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		if (signal) {
			if (signal.aborted) controller.abort();
			else
				signal.addEventListener('abort', () => controller.abort(), {
					once: true,
				});
		}
		try {
			const response = await fetch(params.url, {
				method: params.method ?? 'GET',
				signal: controller.signal,
				redirect: 'follow',
				headers: {
					'user-agent': 'ck-finder/0.1 (+authorized security testing)',
					accept: 'text/html,application/json,application/javascript,*/*;q=0.8',
				},
			});
			const contentType = response.headers.get('content-type') ?? '';
			const isText =
				contentType.includes('text/') ||
				contentType.includes('json') ||
				contentType.includes('javascript') ||
				contentType.includes('xml') ||
				contentType.includes('x-www-form-urlencoded');
			if (!isText) {
				return {
					content: [
						{
							type: 'text',
							text: `响应类型 ${contentType} 非文本，跳过正文（状态码 ${response.status}）`,
						},
					],
					details: {
						url: params.url,
						status: response.status,
						contentType,
						length: 0,
						truncated: false,
					},
				};
			}
			const text = await response.text();
			const truncated = text.length > 524_288;
			const body = truncated
				? `${text.slice(0, 524_288)}\n...[截断，共 ${text.length} 字符]`
				: text;
			const headers = Object.fromEntries(response.headers.entries());
			return {
				content: [
					{
						type: 'text',
						text: `状态码: ${response.status}\n响应头: ${JSON.stringify(headers)}\n\n${body}`,
					},
				],
				details: {
					url: params.url,
					status: response.status,
					contentType,
					length: text.length,
					truncated,
				},
			};
		} catch (error) {
			const reason = error instanceof Error ? error.message : String(error);
			throw new Error(`web_fetch 失败 ${params.url}: ${reason}`);
		} finally {
			clearTimeout(timer);
		}
	},
};
