/**
 * M3 验证工具 pi 包装：nuclei_scan / sqlmap_run
 *
 * 底层复用收集引擎 execTool 适配器（src/recon/tools/nuclei.ts / sqlmap.ts）。
 * 目标校验由 ck-finder Scope Gate（security/gate.ts）负责。
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';
import { runNuclei } from '../recon/tools/nuclei.js';
import { type SqlmapInjection, runSqlmap } from '../recon/tools/sqlmap.js';

// ---------------------------------------------------------------------------
// nuclei_scan
// ---------------------------------------------------------------------------

export interface NucleiScanDetails {
	hits: number;
	bySeverity: Record<string, number>;
}

const nucleiParams = Type.Object({
	target: Type.String({
		description: '目标 URL（单站扫描），如 http://192.0.2.10:8080/',
	}),
	tags: Type.Optional(
		Type.String({
			description: '模板标签过滤（逗号分隔），如 sqli,lfi,ssrf,rce,xss,upload,idor,traversal',
		}),
	),
	templates: Type.Optional(Type.String({ description: '指定模板路径/ID（如 cves/2021/）' })),
	timeoutMs: Type.Optional(
		Type.Integer({ description: '超时毫秒，默认 10 分钟', minimum: 60_000, maximum: 30 * 60_000 }),
	),
});

export const nucleiScanTool: AgentTool<typeof nucleiParams, NucleiScanDetails> = {
	name: 'nuclei_scan',
	label: 'Nuclei 漏洞扫描',
	description:
		'用 nuclei 模板对目标做漏洞扫描（SQLi/LFI/SSRF/RCE/上传/XSS/IDOR/目录遍历/反序列化/XXE 等常用标签）。\n' +
		'返回命中列表（模板/严重程度/匹配 URL/提取结果）。命中后结合 skill_load + http_req 手工验证，再 finding_submit。\n' +
		'受授权范围约束，越权目标会被拦截。',
	parameters: nucleiParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<NucleiScanDetails>> => {
		const templateArgs: string[] = [];
		if (params.templates) {
			templateArgs.push('-t', params.templates);
		}
		const hits = await runNuclei({
			target: params.target,
			templateArgs,
			severity: 'low,medium,high,critical',
			timeoutMs: params.timeoutMs,
		});
		// 按严重程度聚合
		const bySeverity: Record<string, number> = {};
		for (const h of hits) {
			const sev = h.info?.severity ?? 'unknown';
			bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
		}
		const hitText = hits
			.slice(0, 20)
			.map(
				(h) =>
					`  [${h.info?.severity ?? '?'}] ${h['template-id'] ?? h.template ?? '?'} ${h['matched-at'] ?? ''}${h.info?.name ? ` ${h.info.name}` : ''}`,
			)
			.join('\n');
		return {
			content: [
				{
					type: 'text',
					text:
						hits.length > 0
							? `nuclei 命中 ${hits.length} 条（严重度: ${JSON.stringify(bySeverity)}）:\n${hitText}`
							: 'nuclei 扫描完成，未命中漏洞模板',
				},
			],
			details: { hits: hits.length, bySeverity },
		};
	},
};

// ---------------------------------------------------------------------------
// sqlmap_run
// ---------------------------------------------------------------------------

export interface SqlmapRunDetails {
	injections: SqlmapInjection[];
}

const sqlmapParams = Type.Object({
	url: Type.String({
		description: '待测 URL（含注入点参数），如 http://192.0.2.10:8080/vul/sqli/sqli.php?id=1',
	}),
	param: Type.Optional(Type.String({ description: '指定测试参数（如 id），不指定则全参数探测' })),
	data: Type.Optional(
		Type.String({ description: 'POST 数据串（如 name=admin&id=1），配合 POST 注入' }),
	),
	cookie: Type.Optional(Type.String({ description: '会话 Cookie（登录态注入测试）' })),
	timeoutMs: Type.Optional(
		Type.Integer({ description: '超时毫秒，默认 15 分钟', minimum: 60_000, maximum: 30 * 60_000 }),
	),
});

export const sqlmapRunTool: AgentTool<typeof sqlmapParams, SqlmapRunDetails> = {
	name: 'sqlmap_run',
	label: 'SQLMap 注入验证',
	description:
		'用 sqlmap 对 URL 做 SQL 注入验证（--batch --level 1 --risk 1 轻量模式，不重参数）。\n' +
		'返回注入结论（参数/类型/DBMS/Payload）。确认注入后结合 http_req 手工复现，再 finding_submit。\n' +
		'仅建议对 recon/skill 分析出的明确注入点使用。受授权范围约束。',
	parameters: sqlmapParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<SqlmapRunDetails>> => {
		const extraArgs: string[] = [];
		if (params.data) extraArgs.push('--data', params.data);
		if (params.cookie) extraArgs.push('--cookie', params.cookie);

		const injections = await runSqlmap({
			url: params.url,
			param: params.param,
			extraArgs,
			timeoutMs: params.timeoutMs,
		});

		const injectionText = injections
			.map(
				(i) =>
					`  - ${i.parameter} [${i.technique}] ${i.title}${i.dbms ? ` DBMS=${i.dbms}` : ''}\n    Payload: ${i.payload.slice(0, 120)}`,
			)
			.join('\n');
		return {
			content: [
				{
					type: 'text',
					text:
						injections.length > 0
							? `sqlmap 确认 ${injections.length} 处注入:\n${injectionText}`
							: 'sqlmap 扫描完成，未发现注入（或目标不可注入）',
				},
			],
			details: { injections },
		};
	},
};
