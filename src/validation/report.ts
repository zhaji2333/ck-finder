/**
 * 报告模板（M4.7）：把 validation_findings 渲染成可提交的 Markdown 漏洞报告
 *
 * 结构（AutoHunter 报告 + AGENTS 输出格式）：
 *   结论摘要（漏洞名称/等级/影响/可利用性/修复）→ 复现 POC → 根因 → 修复建议 → 证据
 *
 * 证据五件套（poc/raw_request/raw_response/kill_chain/self_check）全部渲染，
 * 其中 POC 直接可复现（curl 命令 / 请求序列）。
 */
import type { ValidationFinding } from './finding_store.js';

/** 严重度 → 中文标签 */
const SEVERITY_CN: Record<string, string> = {
	critical: '严重',
	high: '高危',
	medium: '中危',
	low: '低危',
	info: '信息',
};

/** 漏洞类型 → 中文标签 */
const VULN_TYPE_CN: Record<string, string> = {
	injection: '注入类',
	xss: 'XSS',
	broken_access: '访问控制/越权',
	idor: '水平越权(IDOR)',
	file_upload: '文件上传',
	path_traversal: '路径穿越/文件包含',
	ssrf: 'SSRF',
	deserialization: '反序列化',
	xxe: 'XXE',
	info_disclosure: '信息泄露',
	auth: '认证缺陷/弱口令',
	redirect: '开放重定向',
	other: '其他',
};

function severityCn(s: string): string {
	return SEVERITY_CN[s] ?? s;
}

function vulnTypeCn(t: string): string {
	return VULN_TYPE_CN[t] ?? t;
}

/** 渲染单个 finding 为 Markdown 报告（含复现 POC） */
export function renderFindingReport(f: ValidationFinding): string {
	const ev = f.evidence;
	const sc = ev.self_check;
	const lines: string[] = [];

	lines.push(`## ${f.vulnName}`);
	lines.push('');
	lines.push(
		`> **等级**: ${severityCn(f.severity)}（${f.severity}） · **类型**: ${vulnTypeCn(String(f.vulnType))} · **状态**: ${f.reviewStatus}`,
	);
	lines.push(`> **目标**: ${f.url}`);
	lines.push('');

	// 结论摘要
	lines.push('### 结论摘要');
	lines.push(`- **漏洞名称**: ${f.vulnName}`);
	lines.push(`- **漏洞等级**: ${severityCn(f.severity)}`);
	lines.push(`- **影响范围**: ${sc.impact}`);
	lines.push(`- **可利用性判断**: ${sc.reproducible ? '可稳定复现' : '待确认复现'}`);
	lines.push(`- **修复优先级**: ${sc.priority}`);
	lines.push('');

	// 复现 POC（核心）
	lines.push('### 复现 POC');
	lines.push('```');
	lines.push(ev.poc);
	lines.push('```');
	lines.push('');

	// 复现步骤（kill_chain）
	lines.push('### 攻击链（成因 → 触发 → 影响）');
	if (ev.kill_chain.chain.length > 0) {
		for (let i = 0; i < ev.kill_chain.chain.length; i++) {
			const step = ev.kill_chain.chain[i]!;
			lines.push(`${i + 1}. **${step.step}**: ${step.detail}`);
		}
	}
	lines.push(`> 总结: ${ev.kill_chain.summary}`);
	lines.push('');

	// 原始请求/响应
	lines.push('### 原始请求（Raw Request）');
	lines.push('```http');
	lines.push(ev.raw_request);
	lines.push('```');
	lines.push('');
	lines.push('### 原始响应（Raw Response）');
	lines.push('```http');
	lines.push(ev.raw_response.slice(0, 2000));
	lines.push('```');
	lines.push('');

	// 自我复核
	lines.push('### 自我复核');
	lines.push(`- **是否可稳定复现**: ${sc.reproducible ? '是' : '否'}`);
	lines.push(`- **利用前置条件**: ${sc.prerequisites}`);
	lines.push(`- **影响面**: ${sc.impact}`);
	lines.push(`- **修复优先级**: ${sc.priority}`);
	lines.push('');

	return lines.join('\n');
}

/** 渲染多个 finding 为一份完整报告（含总览 + 各漏洞详情） */
export function renderReport(findings: ValidationFinding[], title = '渗透测试漏洞报告'): string {
	const lines: string[] = [];
	lines.push(`# ${title}`);
	lines.push('');
	lines.push(`> 生成时间: ${new Date().toISOString()} · 漏洞总数: ${findings.length}`);
	lines.push('');

	// 总览表
	lines.push('## 漏洞总览');
	lines.push('');
	lines.push('| # | 等级 | 漏洞名称 | 目标 |');
	lines.push('|---|------|---------|------|');
	findings.forEach((f, i) => {
		lines.push(`| ${i + 1} | ${severityCn(f.severity)} | ${f.vulnName} | ${f.url} |`);
	});
	lines.push('');
	lines.push('---');
	lines.push('');

	// 各漏洞详情
	for (const f of findings) {
		lines.push(renderFindingReport(f));
		lines.push('---');
		lines.push('');
	}

	return lines.join('\n');
}

/** 导出报告到文件 */
export async function exportReport(
	findings: ValidationFinding[],
	outPath: string,
	title?: string,
): Promise<string> {
	const { writeFileSync } = await import('node:fs');
	const md = renderReport(findings, title);
	writeFileSync(outPath, md, 'utf8');
	return md;
}
