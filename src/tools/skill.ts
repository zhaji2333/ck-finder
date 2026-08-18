/**
 * skill_load 工具：worker 按需读取专项挖掘技能（AGENTS.md 技能调度中心）
 *
 * 技能库位于仓库 skills/<name>/SKILL.md（14 个，白名单）。
 * 命中 AGENTS 总纲第 4 节路由表的触发信号时，worker 先 skill_load 对应技能，
 * 按其手册执行深度挖掘，而不是停留在通用测试。
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';

/** 技能白名单（与 skills/ 目录一一对应，防任意路径读取） */
export const SKILL_NAMES = [
	'ai-llm-agent-security',
	'api-protocol-security',
	'auth-access-control',
	'business-logic-race',
	'cloud-infra-supply-chain',
	'deserialization-xxe',
	'file-handling',
	'injection-vulns',
	'mobile-iot-device-security',
	'recon-js-analysis',
	'source-code-audit',
	'ssrf-internal-network',
	'waf-bypass-techniques',
	'xss-frontend-security',
] as const;

export type SkillName = (typeof SKILL_NAMES)[number];

export const SKILL_INDEX: Record<SkillName, string> = {
	'ai-llm-agent-security':
		'LLM/Chatbot/Agent/RAG 安全：提示词注入、越狱、RAG 投毒、工具滥用致 RCE/SSRF',
	'api-protocol-security': 'API 安全：REST/GraphQL/gRPC、BOLA、HTTP 走私、协议层漏洞',
	'auth-access-control': '认证授权与越权：认证绕过、JWT、IDOR、垂直/水平越权、多租户隔离',
	'business-logic-race': '业务逻辑与竞态：支付/订单/退款/优惠券、状态机、并发重放',
	'cloud-infra-supply-chain': '云/容器/供应链：云配置错误、未授权中间件、依赖 CVE、信息泄露',
	'deserialization-xxe': '反序列化与 XXE：RCE、原型污染、ysoserial/phpggc 利用',
	'file-handling': '文件与路径：任意上传 getshell、路径穿越、Zip Slip、CSV/公式注入',
	'injection-vulns': '注入类：SQL/NoSQL/命令/SSTI/表达式注入、Fuzz 与绕过',
	'mobile-iot-device-security': '移动端/IoT：APK/IPA 逆向、WebView/DeepLink、固件安全',
	'recon-js-analysis': '资产测绘与 JS 分析：webpack/source map 还原、API 与密钥提取、历史资产',
	'source-code-audit': '源码审计：输入点→传播链→Sink、跨语言危险函数速查',
	'ssrf-internal-network': 'SSRF：URL 抓取/代理/webhook、云元数据、内网资产、DNS 重绑定',
	'waf-bypass-techniques': 'WAF/过滤绕过：编码/变形/逻辑/协议层、换入口、组合利用',
	'xss-frontend-security': 'XSS 与前端：反射/存储/DOM XSS、CSRF、CORS、Clickjacking',
};

export interface SkillLoadDetails {
	skill: SkillName;
	lines: number;
}

const skillParams = Type.Object({
	skill: Type.String({
		description: `技能名（白名单）：${SKILL_NAMES.join(' / ')}。命中 AGENTS 技能调度路由表时调用`,
	}),
});

function readSkill(skill: string): { path: string; content: string } {
	if (!(SKILL_NAMES as readonly string[]).includes(skill)) {
		throw new Error(`未知技能 "${skill}"。可用技能: ${SKILL_NAMES.join(', ')}`);
	}
	const path = join(process.cwd(), 'skills', skill, 'SKILL.md');
	return { path, content: readFileSync(path, 'utf8') };
}

export const skillLoadTool: AgentTool<typeof skillParams, SkillLoadDetails> = {
	name: 'skill_load',
	label: '加载专项挖掘技能',
	description:
		'按名称加载专项漏洞挖掘技能手册（SKILL.md 全文）。当目标命中 AGENTS 总纲技能调度路由表的触发信号时调用——例如：参数拼接 SQL 用 injection-vulns；登录/越权用 auth-access-control；JS/接口提取用 recon-js-analysis；上传下载用 file-handling；SSRF 用 ssrf-internal-network。加载后按手册步骤深度挖掘。',
	parameters: skillParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<SkillLoadDetails>> => {
		const { content, path } = readSkill(params.skill);
		const lines = content.split('\n').length;
		return {
			content: [
				{
					type: 'text',
					text: `# 技能：${params.skill}（${lines} 行，来自 ${path}）\n\n${content}`,
				},
			],
			details: { skill: params.skill as SkillName, lines },
		};
	},
};
