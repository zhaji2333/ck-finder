/**
 * B 轨：把 ck-recon 工具注册为 Pi defineTool
 *
 * 两种使用方式：
 *
 * 1. SDK 编程式（推荐）：在 createAgentSession 时传入 customTools
 *    ```ts
 *    import { createAgentSession } from '@earendil-works/pi-coding-agent';
 *    import { reconTools } from 'ck-recon/tools/pi';
 *    const { session } = await createAgentSession({
 *      customTools: reconTools,
 *      tools: [],  // 禁用内置工具
 *    });
 *    ```
 *
 * 2. Pi CLI 扩展式：把本模块作为 extension 加载
 *    ```ts
 *    // .pi/extensions/recon.ts
 *    import { registerReconTools } from 'ck-recon/tools/pi';
 *    export default (pi) => registerReconTools(pi);
 *    ```
 *
 * 每个工具的 execute 内部调用 A 轨适配器（src/tools/*.ts），
 * 工具实际执行走统一执行器（execTool），自动获得超时/限速/缓存/审计。
 */

import { Type } from '@earendil-works/pi-ai';
import {
	type ExtensionAPI,
	type ToolDefinition,
	defineTool,
} from '@earendil-works/pi-coding-agent';
import { runDnsx } from './dnsx.js';
import { runHttpx } from './httpx.js';
import { runNmap } from './nmap.js';
import { runSubfinder } from './subfinder.js';

/**
 * subfinder 工具定义（Pi defineTool 格式）
 */
export const subfinderTool = defineTool({
	name: 'subfinder',
	label: 'Subfinder',
	description:
		'子域发现工具（被动源）。输入一个域名，返回该域名的子域列表。' +
		'不直接触碰目标，数据来自公开被动源（crtsh、SecurityTrails 等）。',
	promptSnippet: 'subfinder <domain> - 获取子域列表',
	parameters: Type.Object({
		domain: Type.String({ description: '目标域名（如 example.com）' }),
		timeoutMs: Type.Optional(Type.Integer({ description: '超时毫秒数，默认 5 分钟' })),
		useCache: Type.Optional(Type.Boolean({ description: '是否启用 L2 缓存，默认 true' })),
	}),
	async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
		const records = await runSubfinder({
			domain: params.domain,
			timeoutMs: params.timeoutMs,
			useCache: params.useCache,
		});
		return {
			content: [
				{
					type: 'text',
					text: `找到 ${records.length} 个子域：\n${records.map((r) => `- ${r.host} (source: ${r.source ?? 'unknown'})`).join('\n')}`,
				},
			],
			details: { count: records.length, hosts: records.map((r) => r.host) },
		};
	},
});

/**
 * dnsx 工具定义
 */
export const dnsxTool = defineTool({
	name: 'dnsx',
	label: 'Dnsx',
	description:
		'DNS 解析工具。输入域名或域名列表，返回 A/AAAA/CNAME 等记录。' +
		'用于验证子域存活、获取 IP、识别 CNAME 链（CDN 检测关键）。',
	promptSnippet: 'dnsx <domain|domains> - DNS 解析',
	parameters: Type.Object({
		domain: Type.Optional(Type.String({ description: '单个域名' })),
		domains: Type.Optional(Type.Array(Type.String(), { description: '域名列表（优先于 domain）' })),
		recordTypes: Type.Optional(
			Type.Array(
				Type.Union([
					Type.Literal('a'),
					Type.Literal('aaaa'),
					Type.Literal('cname'),
					Type.Literal('ns'),
					Type.Literal('mx'),
					Type.Literal('txt'),
				]),
			),
		),
		timeoutMs: Type.Optional(Type.Integer({ description: '超时毫秒数，默认 3 分钟' })),
	}),
	async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
		const records = await runDnsx({
			domain: params.domain,
			domains: params.domains,
			recordTypes: params.recordTypes as
				| ('a' | 'aaaa' | 'cname' | 'ns' | 'mx' | 'txt')[]
				| undefined,
			timeoutMs: params.timeoutMs,
		});
		return {
			content: [
				{
					type: 'text',
					text: `解析到 ${records.length} 条记录：\n${records
						.map(
							(r) => `- ${r.host}: A=${(r.a ?? []).join(',')} CNAME=${(r.cname ?? []).join(',')}`,
						)
						.join('\n')}`,
				},
			],
			details: { count: records.length, records },
		};
	},
});

/**
 * nmap 工具定义
 */
export const nmapTool = defineTool({
	name: 'nmap',
	label: 'Nmap',
	description:
		'端口扫描 + 服务版本探测工具（主动）。输入 IP/域名/CIDR，返回开放端口与服务版本。' +
		'注意：主动工具，会直接请求目标，受 Scope Gate 控制。',
	promptSnippet: 'nmap <target> -p <ports> - 端口扫描',
	parameters: Type.Object({
		target: Type.String({ description: '目标 IP/域名/CIDR' }),
		ports: Type.Optional(
			Type.String({ description: '端口范围，如 "1-1000"、"80,443,8080"，默认 top 1000' }),
		),
		timing: Type.Optional(
			Type.Union([
				Type.Literal('T0'),
				Type.Literal('T1'),
				Type.Literal('T2'),
				Type.Literal('T3'),
				Type.Literal('T4'),
				Type.Literal('T5'),
			]),
		),
		serviceVersion: Type.Optional(
			Type.Boolean({ description: '是否启用服务版本探测 -sV，默认 true' }),
		),
		timeoutMs: Type.Optional(Type.Integer({ description: '超时毫秒数，默认 30 分钟' })),
	}),
	async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
		const records = await runNmap({
			target: params.target,
			ports: params.ports,
			timing: params.timing as 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5' | undefined,
			serviceVersion: params.serviceVersion,
			timeoutMs: params.timeoutMs,
		});
		return {
			content: [
				{
					type: 'text',
					text: `扫描到 ${records.length} 个开放端口：\n${records
						.map((r) => `- ${r.ip}:${r.port}/${r.protocol} ${r.service ?? ''} ${r.version ?? ''}`)
						.join('\n')}`,
				},
			],
			details: { count: records.length, records },
		};
	},
});

/**
 * httpx 工具定义
 */
export const httpxTool = defineTool({
	name: 'httpx',
	label: 'Httpx',
	description:
		'存活 URL 探测工具（主动）。输入 URL 或 URL 列表，返回 status/title/tech/webserver 等。' +
		'是 webapp 资产发现的核心工具，httpx 探测出存活的 URL 后入库为 webapp 资产。',
	promptSnippet: 'httpx <url|urls> - 存活探测 + 指纹',
	parameters: Type.Object({
		url: Type.Optional(Type.String({ description: '单个 URL' })),
		urls: Type.Optional(Type.Array(Type.String(), { description: 'URL 列表（优先于 url）' })),
		followRedirects: Type.Optional(Type.Boolean({ description: '是否跟随重定向，默认 true' })),
		techDetect: Type.Optional(Type.Boolean({ description: '是否检测技术栈，默认 true' })),
		timeoutMs: Type.Optional(Type.Integer({ description: '超时毫秒数，默认 10 分钟' })),
	}),
	async execute(_toolCallId, params, _signal, _onUpdate, _ctx) {
		const records = await runHttpx({
			url: params.url,
			urls: params.urls,
			followRedirects: params.followRedirects,
			techDetect: params.techDetect,
			timeoutMs: params.timeoutMs,
		});
		return {
			content: [
				{
					type: 'text',
					text: `探测到 ${records.length} 个存活 webapp：\n${records
						.map(
							(r) =>
								`- ${r.url} [${r.status_code ?? '?'}] "${r.title ?? ''}" tech=${(Array.isArray(r.tech) ? r.tech : []).join(',')}`,
						)
						.join('\n')}`,
				},
			],
			details: { count: records.length, records },
		};
	},
});

/**
 * 所有 ck-recon 工具的数组（SDK 编程式使用）
 */
export const reconTools: ToolDefinition[] = [subfinderTool, dnsxTool, nmapTool, httpxTool];

/**
 * Pi CLI 扩展式注册入口
 *
 * 用法：
 *   // .pi/extensions/recon.ts
 *   import { registerReconTools } from 'ck-recon/tools/pi';
 *   export default (pi) => registerReconTools(pi);
 */
export function registerReconTools(pi: ExtensionAPI): void {
	for (const tool of reconTools) {
		pi.registerTool(tool);
	}
}
