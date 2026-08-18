/**
 * playbook 打法路由（M4.7，借鉴 AutoHunter playbook_router.py）
 *
 * 核心思想：**每个有信号的目标都值得挖，评分只决定优先级与打法，不决定挖不挖**。
 *
 * 从 webapp 元数据抽信号（cve_hints / 组件 / 角色 / 深挖建议 / 登录页）→ 路线打分 →
 * 返回打法（route_id + 意图类型建议 + 挖掘强度）。
 *
 * 路线（参考 AutoHunter 10 路线，收敛到 ck-finder 可执行的 6 类）：
 *   component_exposure   已知组件 CVE 验证（cve_hints 命中，最高优先）
 *   spa_js_api           前端框架 → JS 分析
 *   api_authorization    角色=api → 接口授权边界
 *   auth_gateway         登录页 → 认证/弱口令
 *   upload_business      上传/导出词 → 文件与业务逻辑
 *   generic_admin        兜底：通用后台/接口验证
 *   static_low_value     低价值静态 → 快速收敛（不浪费深挖）
 */
import type { WebappQueryRow } from '../recon/storage/models/query.js';

// ---------------------------------------------------------------------------
// 路线定义
// ---------------------------------------------------------------------------

export interface RouteDefinition {
	id: string;
	/** 基础分（兜底权重） */
	base: number;
	/** 信号 → 加分 */
	tags: Array<{ tag: string; weight: number }>;
	/** 意图类型建议 */
	intentType: string;
	/** 挖掘强度：deep（重）/ normal（常规）/ quick（快速收敛） */
	intensity: 'deep' | 'normal' | 'quick';
	/** 路线一句话打法 */
	tactic: string;
}

export const ROUTES: RouteDefinition[] = [
	{
		id: 'component_exposure',
		base: 20,
		tags: [
			{ tag: 'cve_hints', weight: 30 },
			{ tag: 'known_component', weight: 15 },
		],
		intentType: 'verify_component',
		intensity: 'deep',
		tactic: '验证已知组件漏洞（cve_hints 命中）——重点测对应 CVE 的 PoC 面',
	},
	{
		id: 'spa_js_api',
		base: 10,
		tags: [
			{ tag: 'modern_frontend', weight: 18 },
			{ tag: 'spa', weight: 12 },
		],
		intentType: 'recon_js',
		intensity: 'deep',
		tactic: '前端框架站——扒 JS 找接口/密钥/签名逻辑（最高频破局点）',
	},
	{
		id: 'api_authorization',
		base: 8,
		tags: [
			{ tag: 'api_role', weight: 16 },
			{ tag: 'swagger', weight: 10 },
		],
		intentType: 'recon_api',
		intensity: 'deep',
		tactic: 'API 角色——测接口授权边界（未授权访问/IDOR）',
	},
	{
		id: 'auth_gateway',
		base: 5,
		tags: [
			{ tag: 'login_page', weight: 12 },
			{ tag: 'sso', weight: 8 },
		],
		intentType: 'recon_auth',
		intensity: 'normal',
		tactic: '登录页——认证绕过/弱口令/会话安全',
	},
	{
		id: 'upload_business',
		base: 3,
		tags: [
			{ tag: 'upload', weight: 10 },
			{ tag: 'export', weight: 8 },
			{ tag: 'business', weight: 6 },
		],
		intentType: 'recon_business',
		intensity: 'normal',
		tactic: '上传/导出/业务词——文件处理与业务逻辑漏洞',
	},
	{
		id: 'generic_admin',
		base: 1,
		tags: [{ tag: 'admin', weight: 5 }],
		intentType: 'recon_asset',
		intensity: 'normal',
		tactic: '通用后台/接口——常规路径与未授权点验证',
	},
	{
		id: 'static_low_value',
		base: -20,
		tags: [{ tag: 'static', weight: -15 }],
		intentType: 'recon_quick',
		intensity: 'quick',
		tactic: '低价值静态站——快速确认无交互点后收敛，不浪费深挖',
	},
];

// ---------------------------------------------------------------------------
// 信号抽取（从 webapp 元数据）
// ---------------------------------------------------------------------------

export interface WebappSignals {
	tags: string[];
	cveHints: number;
	/** cve 严重度列表（critical/high/medium/low）——按 severity 加权优先级 */
	cveSeverities: string[];
	detail: string[];
}

/** 抽取 webapp 信号（零网络，纯元数据） */
export function extractWebappSignals(w: WebappQueryRow): WebappSignals {
	const tags: string[] = [];
	const detail: string[] = [];
	const cveSeverities: string[] = [];
	const meta = w.meta ?? {};

	// cve_hints（最高信号）
	const cveHints = Array.isArray(meta.cve_hints) ? (meta.cve_hints as unknown[]) : [];
	if (cveHints.length > 0) {
		tags.push('cve_hints');
		for (const c of cveHints) {
			const sev = String((c as { severity?: string }).severity ?? '').toLowerCase();
			if (['critical', 'high', 'medium', 'low'].includes(sev)) cveSeverities.push(sev);
			else cveSeverities.push('medium');
		}
		detail.push(
			`已知组件漏洞 ${cveHints.length} 条: ${cveHints.map((c) => (c as { component?: string; cve?: string }).component ?? (c as { cve?: string }).cve ?? '').join(', ')}`,
		);
	}

	// 技术栈
	const tech = (w.tech ?? []).map((t) => String(t).toLowerCase());
	const modernFront = ['react', 'vue', 'angular', 'next.js', 'nuxt', 'webpack', 'spa'];
	if (tech.some((t) => modernFront.some((m) => t.includes(m)))) {
		tags.push('modern_frontend');
		detail.push(`现代前端框架: ${tech.join(', ')}`);
	}
	const knownComps = [
		'struts',
		'log4j',
		'shiro',
		'spring',
		'thinkphp',
		'weblogic',
		'fastjson',
		'druid',
		'nacos',
	];
	if (tech.some((t) => knownComps.some((k) => t.includes(k)))) {
		tags.push('known_component');
		detail.push(`已知组件: ${tech.join(', ')}`);
	}
	if (tech.some((t) => t.includes('spa') || t.includes('javascript'))) tags.push('spa');

	// 角色
	const role = String(w.role ?? '').toLowerCase();
	if (role === 'api') {
		tags.push('api_role');
		detail.push('角色=api');
	}
	if (['admin', 'backend', 'dev'].includes(role)) {
		tags.push('admin');
		detail.push(`角色=${w.role}`);
	}
	if (role === 'static' || (role === 'business' && (w.score ?? 0) < 40)) tags.push('static');

	// 登录页
	if (w.loginPage) {
		tags.push('login_page');
		detail.push('有登录页');
	}
	if (tech.some((t) => t.includes('sso') || t.includes('cas'))) tags.push('sso');

	// 深挖建议（task_gate.suggested_next 在 meta 无直接字段，用 task_level 判断深度）
	const taskLevel = String(meta.task_level ?? 'L0');
	if (['L2', 'L3'].includes(taskLevel)) {
		tags.push('deep_suggested');
		detail.push(`建议深挖 L${taskLevel}`);
	}

	// URL 关键词
	const url = w.url.toLowerCase();
	if (/upload|import/.test(url)) tags.push('upload');
	if (/export|download/.test(url)) tags.push('export');
	if (/admin|manage|console|backstage/.test(url)) tags.push('admin');
	if (/swagger|api-docs|openapi/.test(url)) tags.push('swagger');

	return { tags, cveHints: cveHints.length, cveSeverities, detail };
}

// ---------------------------------------------------------------------------
// 路线打分
// ---------------------------------------------------------------------------

export interface RoutePlan {
	route: RouteDefinition;
	score: number;
	matchedTags: string[];
}

/** 目标路由：信号 → 路线打分，返回最优路线（AutoHunter route_target 思想） */
export function routeWebapp(w: WebappQueryRow): RoutePlan {
	const signals = extractWebappSignals(w);
	let best: RoutePlan | null = null;

	for (const route of ROUTES) {
		let score = route.base;
		const matchedTags: string[] = [];
		for (const { tag, weight } of route.tags) {
			if (signals.tags.includes(tag)) {
				score += weight;
				matchedTags.push(tag);
			}
		}
		if (!best || score > best.score) {
			best = { route, score, matchedTags };
		}
	}
	if (!best) {
		best = { route: ROUTES[5]!, score: ROUTES[5]?.base, matchedTags: [] }; // generic_admin 兜底
	}

	// static_low_value 只在无强信号时胜出（防误杀低分但有 cve 的目标）
	if (best.route.id === 'static_low_value' && signals.cveHints > 0) {
		best = { route: ROUTES[0]!, score: best.score + 30, matchedTags: ['cve_hints'] }; // 强制转 component_exposure
	}
	return best;
}

// ---------------------------------------------------------------------------
// 候选选取（双通道：评分 + 信号）
// ---------------------------------------------------------------------------

export interface PlannerTarget extends WebappQueryRow {
	/** 综合优先级分（评分 + 信号加分），planner 用它排序 */
	priorityScore: number;
	routeId: string;
	routeTactic: string;
	routeIntensity: string;
	signals: WebappSignals;
}

/** 目标是否有强信号（cve/组件/API/登录/深挖建议）——低分但高信号也要挖 */
export function hasStrongSignal(w: WebappQueryRow): boolean {
	const signals = extractWebappSignals(w);
	return (
		signals.cveHints > 0 ||
		signals.tags.includes('known_component') ||
		signals.tags.includes('api_role') ||
		signals.tags.includes('modern_frontend') ||
		signals.tags.includes('login_page') ||
		signals.tags.includes('deep_suggested') ||
		signals.tags.includes('swagger')
	);
}

/** 综合优先级分：评分 + 信号加成（AutoHunter priority_score 思想；已知组件漏洞按 severity 加权） */
export function priorityScoreOf(w: WebappQueryRow, signals: WebappSignals): number {
	let score = w.score ?? 0;
	// 已知组件漏洞：critical RCE 是最高优先（AutoHunter「信号决定优先级」——低分高危也排前）
	let hasCritical = false;
	for (const sev of signals.cveSeverities) {
		score += sev === 'critical' ? 100 : sev === 'high' ? 50 : sev === 'medium' ? 30 : 15;
		if (sev === 'critical') hasCritical = true;
	}
	// critical 已知漏洞强制置顶（AutoHunter deepen +100 思想：压过普通高分与 high cve）
	if (hasCritical) score += 60;
	if (signals.tags.includes('known_component')) score += 15;
	if (signals.tags.includes('api_role')) score += 10;
	if (signals.tags.includes('modern_frontend')) score += 8;
	if (signals.tags.includes('deep_suggested')) score += 6;
	if (signals.tags.includes('login_page')) score += 4;
	if (signals.tags.includes('swagger')) score += 4;
	return score;
}

/** 构建 planner 目标候选：高评分（≥60）+ 低分但强信号（AutoHunter「可达即挖」） */
export function buildPlannerTargets(webapps: WebappQueryRow[]): PlannerTarget[] {
	const targets: PlannerTarget[] = [];
	for (const w of webapps) {
		const signals = extractWebappSignals(w);
		// 双通道：评分≥60 或 强信号（低分不因评分被排除）
		if ((w.score ?? 0) >= 60 || hasStrongSignal(w)) {
			const route = routeWebapp(w);
			targets.push({
				...w,
				priorityScore: priorityScoreOf(w, signals),
				routeId: route.route.id,
				routeTactic: route.route.tactic,
				routeIntensity: route.route.intensity,
				signals,
			});
		}
	}
	// 按优先级分排序（评分 + 信号加成）
	return targets.sort((a, b) => b.priorityScore - a.priorityScore);
}

/** 确定性意图模板：按 routeId 生成标准挖洞意图（AutoHunter「目标必挖，打法路由」） */
export function routeIntentTemplate(t: PlannerTarget): { intentType: string; description: string } {
	const cveInfo =
		t.signals.cveHints > 0
			? `（已知组件漏洞 ${t.signals.cveHints} 条: ${(t.signals.detail[0] ?? '').replace(/^已知组件漏洞 \d+ 条: /, '')}）`
			: '';
	switch (t.routeId) {
		case 'component_exposure':
			return {
				intentType: 'verify',
				description: `验证 ${t.url} 的已知组件漏洞${cveInfo}。skill_load 注入/反序列化/WAF 技能，http_req/nuclei_scan 针对性 PoC 验证，只做存在性证明（红线 R1-R5 禁改删/脱库）。`,
			};
		case 'spa_js_api':
			return {
				intentType: 'recon_js',
				description: `扒 ${t.url} 的 JS（sourcemap/接口/密钥/签名逻辑），recon-js-analysis 技能，提取高价值接口后用 http_req 验证。`,
			};
		case 'api_authorization':
			return {
				intentType: 'recon_api',
				description: `测 ${t.url} 的 API 授权边界（未授权访问/IDOR/BOLA），auth-access-control + api-protocol-security 技能，只读验证。`,
			};
		case 'auth_gateway':
			return {
				intentType: 'recon_auth',
				description: `测 ${t.url} 的认证安全（绕过/弱口令/会话），auth-access-control 技能；弱口令用 auth_brute（授权护栏内）。`,
			};
		case 'upload_business':
			return {
				intentType: 'recon_business',
				description: `测 ${t.url} 的上传/导出/业务逻辑，file-handling + business-logic-race 技能，只读验证不落数据。`,
			};
		default:
			return {
				intentType: 'recon_asset',
				description: `常规验证 ${t.url}（未授权路径/敏感端点/管理后台），recon-js-analysis + api-protocol-security 技能。`,
			};
	}
}

/**
 * 通用攻击面遍历意图（AutoHunter「每目标挖到底」思想，通用方法论非靶场清单）
 *
 * 两阶段执行（重要）：
 *   阶段1 快速探测：全部攻击面过一遍，找出「有入口」的（表单/参数/URL可控），coverage fact 标记
 *   阶段2 深挖验证：对每个有入口的攻击面，skill_load + http_req 验证到能提交 finding（证据五件套）
 * 攻击面类型来自 AGENTS 技能路由表（通用方法论），对任何目标适用，不写死靶场路径。
 */
export function buildAttackSurfaceIntent(url: string): {
	intentType: string;
	description: string;
} {
	return {
		intentType: 'recon_full',
		description: `对 ${url} 做系统性攻击面遍历（两阶段，只读实证红线 R1-R5）：
【阶段1 快速探测】逐类探测攻击面，用 graph_store_fact 记 coverage 事实（factType=coverage，summary 标注 [类名] 有入口/无入口）：
1) 注入类：搜索/排序/导出/登录参数（injection-vulns）
2) 认证授权：登录/注册/找回密码/JWT/IDOR/越权（auth-access-control）
3) 文件处理：上传/下载/导入/路径穿越/LFI（file-handling）
4) SSRF：URL可控抓取/代理/回调/图片预览（ssrf-internal-network）
5) XSS：评论/搜索/富文本/DOM（xss-frontend-security）
6) 反序列化/XXE：XML/SOAP/JSON 解析（deserialization-xxe）
7) API面：REST/GraphQL/Swagger/调试端点（api-protocol-security）
8) 信息泄露：.git/.env/备份/错误栈（cloud-infra-supply-chain）

【阶段2 深挖验证】对每个「有入口」的攻击面，**必须验证并提交 finding**：
- ⚠️ 确认漏洞入口后必须 finding_submit（证据五件套），不能只记 fact
- skill_load 对应技能 → http_req 构造 payload → 响应差异/盲注时间差/回连确认 → finding_submit
- 注入类：报错/时间盲/布尔差异坐实；SSRF：回连/响应差异；XXE：外部实体读取/报错；文件：读敏感文件内容；上传：存活性验证
- 每确认一个漏洞就 finding_submit 一个

纪律：8 类全部探测完才结束；「有入口的确认漏洞」必须提交 finding，严禁只记 fact 就当 done。`,
	};
}
