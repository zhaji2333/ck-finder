/**
 * http_req：手工 HTTP 重放工具（M3 核心）
 *
 * 用途：IDOR / 越权 / 逻辑漏洞 / 认证绕过等「手工验证」场景（AGENTS SKILLS 落地关键）。
 * 与 web_fetch（侦察抓取）的区别：完整方法/头/体/cookie 控制 + 记录 raw_request/raw_response 原文，
 * 供 finding_submit 复用证据。
 *
 * 受 Scope Gate 约束（security/gate.ts NETWORK_TOOLS 已含 http_req）。
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';

export interface HttpReqDetails {
	status: number;
	contentType: string;
	length: number;
	durationMs: number;
	rawRequest: string;
	rawResponse: string;
}

const httpReqParams = Type.Object({
	url: Type.String({
		description: '完整请求 URL，如 http://192.0.2.10:8080/vul/sqli/sqli.php',
	}),
	method: Type.Optional(
		Type.Union(
			[
				Type.Literal('GET'),
				Type.Literal('POST'),
				Type.Literal('PUT'),
				Type.Literal('DELETE'),
				Type.Literal('HEAD'),
				Type.Literal('OPTIONS'),
				Type.Literal('PATCH'),
			],
			{ description: 'HTTP 方法，默认 GET' },
		),
	),
	headers: Type.Optional(
		Type.Record(Type.String(), Type.String(), {
			description: '请求头（键值对），如 {"Content-Type": "application/x-www-form-urlencoded"}',
		}),
	),
	body: Type.Optional(
		Type.String({ description: '请求体（POST/PUT 用），如 name=admin&pass=123456' }),
	),
	files: Type.Optional(
		Type.Array(
			Type.Object({
				field: Type.String({ description: '表单字段名，如 file / upload' }),
				filename: Type.String({ description: '上传文件名，如 test.php' }),
				contentType: Type.Optional(
					Type.String({ description: '文件 MIME，默认 application/octet-stream' }),
				),
				content: Type.String({ description: '文件内容' }),
			}),
			{ description: 'multipart/form-data 文件上传（数组，可传多个文件）' },
		),
	),
	cookie: Type.Optional(
		Type.String({ description: 'Cookie 字符串，如 PHPSESSID=abc123（登录后会话保持用）' }),
	),
	followRedirects: Type.Optional(Type.Boolean({ description: '是否跟随重定向，默认 true' })),
	timeoutMs: Type.Optional(
		Type.Integer({ description: '超时毫秒，默认 15000', minimum: 1000, maximum: 60000 }),
	),
});

/** 构造 raw_request 原文（HTTP 标准格式） */
function buildRawRequest(
	method: string,
	url: string,
	headers: Record<string, string>,
	body: string,
): string {
	const u = new URL(url);
	const path = u.pathname + u.search;
	const headerLines = [`${method} ${path} HTTP/1.1`, `Host: ${u.host}`];
	for (const [k, v] of Object.entries(headers)) {
		headerLines.push(`${k}: ${v}`);
	}
	if (body) {
		headerLines.push(`Content-Length: ${Buffer.byteLength(body)}`);
	}
	return `${headerLines.join('\r\n')}\r\n\r\n${body}`;
}

/** 构造 multipart/form-data body（文件上传） */
function buildMultipartBody(
	files: Array<{ field: string; filename: string; contentType?: string; content: string }>,
): {
	body: string;
	contentType: string;
} {
	const boundary = `----ckfinder${Date.now()}${Math.random().toString(36).slice(2)}`;
	const parts: string[] = [];
	for (const f of files) {
		parts.push(
			`--${boundary}\r\n` +
				`Content-Disposition: form-data; name="${f.field}"; filename="${f.filename}"\r\n` +
				`Content-Type: ${f.contentType ?? 'application/octet-stream'}\r\n\r\n` +
				`${f.content}\r\n`,
		);
	}
	parts.push(`--${boundary}--\r\n`);
	return { body: parts.join(''), contentType: `multipart/form-data; boundary=${boundary}` };
}

/** 截断大文本（防撑爆上下文/审计） */
function truncate(s: string, max = 64 * 1024): { text: string; truncated: boolean } {
	if (s.length <= max) return { text: s, truncated: false };
	return { text: `${s.slice(0, max)}\n...[截断，共 ${s.length} 字符]`, truncated: true };
}

export const httpReqTool: AgentTool<typeof httpReqParams, HttpReqDetails> = {
	name: 'http_req',
	label: '手工 HTTP 重放',
	description:
		'发送一个手工构造的 HTTP 请求（完整控制方法/头/体/Cookie/文件上传），返回状态码/响应头/正文，并记录 raw_request/raw_response 原文供漏洞证据复用。\n' +
		'用于验证：IDOR/越权（替换 id 测不同用户资源）、未授权访问（去 cookie 重放）、逻辑漏洞（改金额/状态参数）、认证绕过（对比不同头/参数组合）、文件上传（files 传 multipart）。\n' +
		'结合 skill_load 加载对应技能后使用。受授权范围约束，越权目标会被拦截。',
	parameters: httpReqParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<HttpReqDetails>> => {
		const method = params.method ?? 'GET';
		const timeoutMs = params.timeoutMs ?? 15_000;
		let body = params.body ?? '';
		const headers: Record<string, string> = {
			'user-agent': 'ck-finder/0.3 (+authorized security testing)',
			...params.headers,
		};
		if (params.cookie) headers.cookie = params.cookie;
		// multipart 文件上传优先
		if (params.files && params.files.length > 0) {
			const mp = buildMultipartBody(params.files);
			body = mp.body;
			headers['content-type'] = mp.contentType;
		} else if (body && !headers['content-type'] && !headers['Content-Type']) {
			headers['content-type'] = 'application/x-www-form-urlencoded';
		}

		const rawRequest = buildRawRequest(method, params.url, headers, body);

		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), timeoutMs);
		const startAt = Date.now();
		try {
			const response = await fetch(params.url, {
				method,
				headers,
				body: body || undefined,
				signal: controller.signal,
				redirect: params.followRedirects === false ? 'manual' : 'follow',
			});
			const contentType = response.headers.get('content-type') ?? '';
			const text = await response.text();
			const durationMs = Date.now() - startAt;

			// raw_response（HTTP 标准格式：状态行 + 头 + 正文）
			const respHeaders = Object.entries(Object.fromEntries(response.headers.entries()))
				.map(([k, v]) => `${k}: ${v}`)
				.join('\r\n');
			const rawResponse = `HTTP/1.1 ${response.status} ${response.statusText}\r\n${respHeaders}\r\n\r\n${text}`;

			const truncated = truncate(text);
			return {
				content: [
					{
						type: 'text',
						text: `状态码: ${response.status} ${response.statusText}\n耗时: ${durationMs}ms\nContent-Type: ${contentType}\n\n响应头:\n${respHeaders}\n\n响应体:\n${truncated.text}`,
					},
				],
				details: {
					status: response.status,
					contentType,
					length: text.length,
					durationMs,
					rawRequest,
					rawResponse,
				},
			};
		} catch (err) {
			const reason = err instanceof Error ? err.message : String(err);
			if (err instanceof DOMException && err.name === 'AbortError') {
				throw new Error(`http_req 超时(${timeoutMs}ms): ${params.url}`);
			}
			throw new Error(`http_req 失败 ${params.url}: ${reason}`);
		} finally {
			clearTimeout(timer);
		}
	},
};
