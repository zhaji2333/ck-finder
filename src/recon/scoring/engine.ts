/**
 * M2.2 评分引擎
 *
 * 把 webapp 资产打分为 0-100，输出 score + score_breakdown（每条加减分项的证据）。
 *
 * 评分模型：
 *   基础分 = 角色权重分（admin=85, backend=80, api=75, dev=70, business=65, middleware=60, static=30, unknown=40）
 *   加分项：
 *     + 有登录页        +10  （登录入口意味着可能有身份认证攻击面）
 *     + 有已知指纹       +5   （指纹命中说明特征明确，可能有针对性漏洞）
 *     + 有暴露的 admin 路径 +5
 *   减分项：
 *     - CDN+WAF 双重防护 -15  （攻击成本高）
 *     - 仅 CDN            -5
 *     - 仅 WAF            -5
 *     - 静态站且无登录     -20 （剪枝候选）
 *
 * 最终分数 clamp 到 [0, 100]。
 *
 * 输出格式：
 *   { score: 75, role: 'admin', breakdown: [{ name, delta, reason }, ...] }
 *
 * 评分本身不走 LLM，规则固定。LLM 仅在角色分类时兜底（见 llm_classifier.ts）。
 */

import type { AssetRole } from './roles.js';

// =============================================================================
// 角色权重表
// =============================================================================

const ROLE_BASE_SCORE: Record<AssetRole, number> = {
	admin: 85, // 管理后台优先级最高
	backend: 80, // CMS/框架后台
	api: 75, // API 接口
	dev: 70, // 开发设施（通常有未授权访问）
	business: 65, // 业务系统
	middleware: 60, // 中间件默认页/管理
	unknown: 40, // 未知角色
	static: 30, // 静态站基础分低
};

// =============================================================================
// 评分输入 / 输出
// =============================================================================

export interface ScoreInput {
	/** 资产角色（来自 roles.ts matchRole） */
	role: AssetRole;
	/** 角色匹配置信度 */
	roleConfidence: number;
	/** 是否有登录页 */
	loginPage: boolean;
	/** 命中指纹数量 */
	fingerprintCount: number;
	/** 是否暴露 admin 路径（path 含 admin/manage 等） */
	hasAdminPath: boolean;
	/** 是否使用 CDN */
	cdn: boolean;
	/** 是否使用 WAF */
	waf: boolean;
	/** 命中已知漏洞组件 hint 数（fastjson/shiro/struts/老版本等，来自 matchVulnHints） */
	vulnHintCount?: number;
	/** 命中的指纹名（用于 CMS/开发设施识别） */
	fingerprints?: string[];
	/** httpx 检测的 tech */
	tech?: string[];
	/** 单站分析识别的架构（spa/mpa/ssr/static） */
	siteArchitecture?: string | null;
	/** 终评证据：JS 接口数 */
	jsApiCount?: number;
	/** 终评证据：页面分类中高价值角色端点数（login/admin/upload/export） */
	highValueEndpointCount?: number;
	/** 终评证据：敏感发现数（secret/sensitive_path/sourcemap） */
	findingCount?: number;
	/** 终评证据：sourcemap 可用 */
	sourceAvailable?: boolean;
	/** 终评证据：是否已有深挖产物（deep_scan_done） */
	deepScanned?: boolean;
}

export interface ScoreBreakdownItem {
	/** 加减分项名称 */
	name: string;
	/** 加减分值（正数加分，负数减分） */
	delta: number;
	/** 证据说明 */
	reason: string;
}

export interface ScoreResult {
	/** 最终评分 [0, 100] */
	score: number;
	/** 资产角色 */
	role: AssetRole;
	/** 是否难以攻击（CDN+WAF 双重防护） */
	hardToAttack: boolean;
	/** 评分明细 */
	breakdown: ScoreBreakdownItem[];
}

// =============================================================================
// 评分引擎
// =============================================================================

/**
 * 对单个 webapp 计算评分
 *
 * 评分流程：
 * 1. 取角色基础分
 * 2. 应用加分项（登录页/指纹/admin 路径）
 * 3. 应用减分项（CDN/WAF 防护）
 * 4. clamp 到 [0, 100]
 *
 * @returns 评分结果（含明细）
 */
export function scoreWebapp(input: ScoreInput): ScoreResult {
	const breakdown: ScoreBreakdownItem[] = [];

	// 1. 基础分
	const base = ROLE_BASE_SCORE[input.role];
	breakdown.push({
		name: 'base',
		delta: base,
		reason: `角色="${input.role}" 基础分`,
	});

	// 角色置信度低时小幅减分（让 LLM 兜底后能修正）
	if (input.roleConfidence < 0.6) {
		breakdown.push({
			name: 'low_confidence',
			delta: -5,
			reason: `角色置信度低 (${input.roleConfidence.toFixed(2)} < 0.6)`,
		});
	}

	// 2. 加分项
	if (input.loginPage) {
		breakdown.push({
			name: 'login_page',
			delta: 10,
			reason: '有登录页，存在身份认证攻击面',
		});
	}

	if (input.fingerprintCount > 0) {
		breakdown.push({
			name: 'fingerprint_hit',
			delta: 5,
			reason: `命中 ${input.fingerprintCount} 个指纹，特征明确`,
		});
	}

	if (input.hasAdminPath) {
		breakdown.push({
			name: 'admin_path',
			delta: 5,
			reason: '路径含 admin/manage 等关键词',
		});
	}

	// 3. 减分项：防护措施
	const hardToAttack = input.cdn && input.waf;
	if (hardToAttack) {
		breakdown.push({
			name: 'cdn_waf',
			delta: -15,
			reason: 'CDN + WAF 双重防护，攻击成本高',
		});
	} else if (input.cdn) {
		breakdown.push({
			name: 'cdn_only',
			delta: -5,
			reason: 'CDN 防护',
		});
	} else if (input.waf) {
		breakdown.push({
			name: 'waf_only',
			delta: -5,
			reason: 'WAF 防护',
		});
	}

	// 4. 静态站特判：如果角色是 static 且无登录，进一步减分
	if (input.role === 'static' && !input.loginPage) {
		breakdown.push({
			name: 'static_no_login',
			delta: -20,
			reason: '静态站无登录页，攻击面有限',
		});
	}

	// 5. 技术栈上下文规则（确定性，全部可审计）
	const signals = [
		...(input.fingerprints ?? []).map((f) => f.toLowerCase()),
		...(input.tech ?? []).map((t) => t.toLowerCase()),
	].join(' ');

	// 5.1 已知漏洞组件（vuln_hints 命中）→ 攻击面明确
	if ((input.vulnHintCount ?? 0) > 0) {
		breakdown.push({
			name: 'vuln_component',
			delta: 8,
			reason: `命中 ${input.vulnHintCount} 个已知漏洞组件 hint`,
		});
	}

	// 5.2 CMS 指纹（老牌 CMS，通用补丁快、Nday 稀缺，价值降低）
	const isCms =
		/(^|\s)(wordpress|drupal|joomla|discuz|thinkphp|phpcms|dedecms|empirecms|typecho)(\s|$)/.test(
			signals,
		);
	if (isCms) {
		breakdown.push({
			name: 'cms_known',
			delta: 2,
			reason: 'CMS 指纹（wordpress/thinkphp/discuz 等），Nday 稀缺、补丁快，价值降低',
		});
	}

	// 5.2b 现代前端框架（webpack/vite 打包，sourcemap 可能泄漏 → 源码可还原）
	const isModernFrontend = /(^|\s)(react|vue|angular|next|nuxt|webpack|vite|node\.js)(\s|$)/.test(
		signals,
	);
	if (isModernFrontend) {
		breakdown.push({
			name: 'modern_frontend',
			delta: 6,
			reason: '现代前端框架（webpack/vite 打包），sourcemap 可能泄漏、源码可还原',
		});
	}

	// 5.3 开发设施指纹（常有无鉴权入口）
	const isDevTool =
		/(^|\s)(jenkins|gitlab|grafana|nacos|swagger|spring-actuator|actuator|phpmyadmin|tomcat|weblogic|kibana|elasticsearch|jupyter|portainer|sonarqube)(\s|$)/.test(
			signals,
		);
	if (isDevTool) {
		breakdown.push({
			name: 'dev_tool',
			delta: 5,
			reason: '开发设施指纹（jenkins/gitlab/grafana/actuator 等），常有未授权入口',
		});
	}

	// 5.4 纯 SPA 客户端（无服务端角色）→ 攻击面转移到 JS/API，自身降权
	const isPureSpa =
		input.siteArchitecture === 'spa' &&
		!['api', 'backend', 'admin', 'dev', 'middleware'].includes(input.role) &&
		!/(^|\/)(api|graphql)(\/|$)/.test(signals);
	if (isPureSpa) {
		breakdown.push({
			name: 'spa_client_only',
			delta: -5,
			reason: '纯 SPA 前端（无服务端逻辑），攻击面在 JS/接口层',
		});
	}

	// 5.5 终评证据项（deep-scan 后才有；初评传 0 不触发）
	const hasDeepEvidence = input.deepScanned === true;

	// 5.5.1 JS 接口证据：有真实接口 → 攻击面明确
	const jsApiCount = input.jsApiCount ?? 0;
	if (hasDeepEvidence && jsApiCount >= 10) {
		breakdown.push({
			name: 'js_api_rich',
			delta: 5,
			reason: `JS 提取 ${jsApiCount} 个接口，攻击面明确`,
		});
	} else if (hasDeepEvidence && jsApiCount >= 3) {
		breakdown.push({ name: 'js_api_ok', delta: 3, reason: `JS 提取 ${jsApiCount} 个接口` });
	}

	// 5.5.2 页面分类证据：存在登录/后台/上传/导出端点 → 高价值入口
	const hvEndpointCount = input.highValueEndpointCount ?? 0;
	if (hasDeepEvidence && hvEndpointCount > 0) {
		breakdown.push({
			name: 'high_value_endpoints',
			delta: 5,
			reason: `页面分类发现 ${hvEndpointCount} 个高价值入口（登录/后台/上传/导出）`,
		});
	}

	// 5.5.3 敏感发现证据：密钥/敏感路径/sourcemap → 真实风险面
	const findingCount = input.findingCount ?? 0;
	if (hasDeepEvidence && findingCount > 0) {
		breakdown.push({
			name: 'findings_evidence',
			delta: 5,
			reason: `发现 ${findingCount} 条敏感信息（密钥/敏感路径/sourcemap）`,
		});
	}

	// 5.5.4 sourcemap 可用 → 源码可还原
	if (hasDeepEvidence && input.sourceAvailable === true) {
		breakdown.push({ name: 'sourcemap_available', delta: 5, reason: 'sourcemap 暴露，源码可还原' });
	}

	// 5.5.5 内容站降级：深挖后仍无接口/无高价值入口 → 展示型站
	//     只看硬证据（接口数 + 高价值入口），不被误报 findings 影响
	if (hasDeepEvidence && jsApiCount === 0 && hvEndpointCount === 0) {
		const isContentCms = isCms && !input.loginPage;
		if (input.siteArchitecture === 'static' || isContentCms) {
			breakdown.push({
				name: 'content_site_low_value',
				delta: -15,
				reason: `深挖后无接口/无高价值入口（${isContentCms ? 'CMS 内容站' : '静态站'}），展示型低价值`,
			});
		}
	}

	// 6. 求和 + clamp
	let score = breakdown.reduce((acc, item) => acc + item.delta, 0);
	if (score < 0) score = 0;
	if (score > 100) score = 100;

	return {
		score,
		role: input.role,
		hardToAttack,
		breakdown,
	};
}

/**
 * 批量评分
 */
export function scoreWebapps(inputs: ScoreInput[]): ScoreResult[] {
	return inputs.map(scoreWebapp);
}
