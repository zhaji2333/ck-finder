/**
 * M2.1 资产角色规则
 *
 * 把 webapp 分类为 7 种角色（webapps.role CHECK 约束）：
 *   admin      管理系统（admin/manage/console/dashboard/backend/system）
 *   backend    后台（cms/wp-admin/admin.php 等已知后台路径）
 *   business   业务系统（业务词、login、shop、order、user）
 *   api        API 接口（api/swagger/graphql/json）
 *   dev        开发设施（jenkins/gitlab/gitea/jupyter/dev/test/staging）
 *   middleware 中间件（nginx/apache 默认页、tomcat、weblogic、phpmyadmin）
 *   static     静态站（无登录、无动态路径、纯静态文件）
 *   unknown    兜底
 *
 * 规则结构：
 *   每条规则匹配 webapp 的某些字段（host/path/title/tech/webserver/status_code/body_hash），
 *   命中后给出 role + confidence（0-1）+ 命中证据。
 *
 * 多条规则命中时取 confidence 最高的（同分时按优先级 admin > backend > api > dev > middleware > business > static）。
 *
 * 不走 LLM，规则命中率应该 > 80%。
 */

/** 资产角色（与 webapps.role CHECK 约束一致） */
export type AssetRole =
	| 'admin'
	| 'backend'
	| 'business'
	| 'api'
	| 'dev'
	| 'middleware'
	| 'static'
	| 'unknown';

/** 单条规则匹配的输入字段（来自 webapp + 探测扩展字段） */
export interface RoleMatchInput {
	/** URL 主机名（小写，如 admin.example.com） */
	host: string;
	/** URL 路径（小写，如 /wp-admin/） */
	path: string;
	/** 页面标题（保留原大小写） */
	title?: string | null;
	/** 技术栈数组（小写，如 ['nginx', 'jenkins']） */
	tech: string[];
	/** Web 服务器（如 nginx、Apache） */
	webserver?: string | null;
	/** HTTP 状态码 */
	statusCode?: number | null;
	/** 是否有登录页（前置探测结果，本规则引擎不计算） */
	loginPage?: boolean;
	/** 命中的指纹名数组（来自 finger.yaml 指纹库） */
	fingerprints?: string[];
}

/** 规则命中结果 */
export interface RoleMatchResult {
	role: AssetRole;
	/** 置信度 0-1 */
	confidence: number;
	/** 命中规则 ID */
	ruleId: string;
	/** 命中证据（人类可读） */
	evidence: string;
}

/** 角色规则定义 */
export interface RoleRule {
	/** 规则 ID（唯一） */
	id: string;
	/** 命中后赋的角色 */
	role: AssetRole;
	/** 置信度（0-1，规则越明确越高） */
	confidence: number;
	/**
	 * 匹配函数：返回 true 表示命中
	 * 内联函数方便单测，避免正则预编译放在模块顶层
	 */
	match: (input: RoleMatchInput) => boolean;
	/** 命中证据描述（可含 ${field} 占位） */
	describe: (input: RoleMatchInput) => string;
}

// =============================================================================
// 指纹产品名 → 角色 映射表
// =============================================================================
//
// finger.yaml 的指纹名比较自由（如 "Jenkins"、"Apache-Shiro"、"WordPress-Elementor"），
// 这里用关键词匹配的方式做角色分类。
//
// 每个角色维护一组关键词，指纹名含任一关键词即归为该角色。
// 优先级：admin > backend > api > dev > middleware > business > static（同 ROLE_PRIORITY）
//

interface FpRoleMap {
	/** 角色关键词列表（指纹名小写包含任一关键词） */
	keywords: string[];
	role: AssetRole;
	confidence: number;
}

const FINGERPRINT_ROLE_MAP: FpRoleMap[] = [
	// admin（管理系统指纹）
	{
		role: 'admin',
		confidence: 0.85,
		keywords: [
			'admin',
			'console',
			'dashboard',
			'manage',
			'manager',
			'control',
			'panel',
			'后台',
			'管理',
		],
	},

	// backend（已知 CMS / 框架后台）
	{
		role: 'backend',
		confidence: 0.88,
		keywords: [
			'wordpress',
			'drupal',
			'joomla',
			'discuz',
			'dedecms',
			'phpcms',
			'developelement',
			'eyou',
		],
	},

	// api（接口服务）
	{
		role: 'api',
		confidence: 0.85,
		keywords: [
			'swagger',
			'openapi',
			'graphql',
			'api-docs',
			'spring-cloud',
			'eureka',
			'consul',
			'nacos',
			'gateway',
			'zuul',
		],
	},

	// dev（开发设施）
	{
		role: 'dev',
		confidence: 0.93,
		keywords: [
			'jenkins',
			'gitlab',
			'gitea',
			'gogs',
			'sonar',
			'nexus',
			'harbor',
			'grafana',
			'kibana',
			'jupyter',
			'kubernetes',
			'k8s',
			'rancher',
			'drone',
			'gogs',
			'phpmyadmin',
			'adminer',
			'redis',
			'memcached',
		],
	},

	// middleware（中间件）
	{
		role: 'middleware',
		confidence: 0.88,
		keywords: [
			'tomcat',
			'weblogic',
			'jboss',
			'wildfly',
			'iis',
			'apache-nginx',
			'nginx-ui',
			'apache-shiro',
			'shiro',
			'fastjson',
			'struts',
			'log4j',
			'spring-boot-actuator',
			'actuator',
			'solr',
			'elasticsearch',
			'zabbix',
			'prometheus',
			'nacos',
		],
	},

	// business（业务系统关键词较泛，confidence 略低）
	{
		role: 'business',
		confidence: 0.65,
		keywords: [
			'shop',
			'store',
			'mall',
			'order',
			'pay',
			'crm',
			'erp',
			'oa',
			'portal',
			'system',
			'平台',
			'系统',
			'商城',
		],
	},
];

/**
 * 根据指纹名列表推断角色
 *
 * @returns role + confidence + evidence，未匹配返回 null
 */
function matchRoleByFingerprint(fps: string[]): RoleMatchResult | null {
	if (!fps || fps.length === 0) return null;
	const lowerFps = fps.map((f) => f.toLowerCase());
	for (const m of FINGERPRINT_ROLE_MAP) {
		for (const fp of lowerFps) {
			for (const kw of m.keywords) {
				if (fp.includes(kw)) {
					return {
						role: m.role,
						confidence: m.confidence,
						ruleId: `fingerprint:${fp}`,
						evidence: `指纹 "${fp}" 含关键词 "${kw}" → ${m.role}`,
					};
				}
			}
		}
	}
	return null;
}

function includesCI(haystack: string | undefined | null, needle: string): boolean {
	if (!haystack) return false;
	return haystack.toLowerCase().includes(needle.toLowerCase());
}

/** tech 数组中是否包含任一关键词（tech 字段是离散值，用相等而非 contains） */
function techIncludesAny(tech: string[], keywords: string[]): boolean {
	const lowerKeywords = keywords.map((k) => k.toLowerCase());
	return tech.some((t) => lowerKeywords.includes(t.toLowerCase()));
}

function hostMatch(host: string, pattern: RegExp): boolean {
	return pattern.test(host.toLowerCase());
}

function pathMatch(path: string, pattern: RegExp): boolean {
	return pattern.test(path.toLowerCase());
}

// =============================================================================
// 规则表
// =============================================================================

export const ROLE_RULES: RoleRule[] = [
	// ---------------- admin（管理系统） ----------------
	{
		id: 'admin-host-prefix',
		role: 'admin',
		confidence: 0.92,
		match: (i) => hostMatch(i.host, /^admin\.|\.admin\.|admin-\d|manage\.|console\.|dashboard\./),
		describe: (i) => `host="${i.host}" 命中 admin/manage/console/dashboard 前缀`,
	},
	{
		id: 'admin-path-segment',
		role: 'admin',
		confidence: 0.85,
		match: (i) =>
			pathMatch(
				i.path,
				/(^|\/)(admin|manage|console|dashboard|backend|sysadmin|cp\/|controlpanel)(\/|$)/,
			),
		describe: (i) => `path="${i.path}" 含 admin 等管理路径段`,
	},
	{
		id: 'admin-title',
		role: 'admin',
		confidence: 0.78,
		match: (i) =>
			includesCI(i.title, '管理后台') ||
			includesCI(i.title, '管理系统') ||
			includesCI(i.title, 'Admin Panel') ||
			includesCI(i.title, '管理控制台'),
		describe: (i) => `title="${i.title}" 含管理后台关键词`,
	},

	// ---------------- backend（已知后台框架） ----------------
	{
		id: 'backend-wp-admin',
		role: 'backend',
		confidence: 0.9,
		match: (i) =>
			pathMatch(i.path, /\/wp-admin\/|\/wp-login\.php/) || includesCI(i.title, 'wordpress'),
		describe: () => 'WordPress 后台 (wp-admin)',
	},
	{
		id: 'backend-cms',
		role: 'backend',
		confidence: 0.85,
		match: (i) =>
			pathMatch(i.path, /\/dede\/|\/phpcms\/|\/帝国\/|\/eyou\/|\/admin\.php/) ||
			techIncludesAny(i.tech, ['dedecms', 'phpcms', 'discuz', 'drupal', 'joomla']),
		describe: (i) => `CMS 后台 (tech=${i.tech.join(',')})`,
	},
	{
		id: 'backend-admin-login',
		role: 'backend',
		confidence: 0.72,
		match: (i) =>
			pathMatch(i.path, /\/admin\.php|\/login\.php.*redirect=admin|\/manager\/html/) &&
			!!i.loginPage,
		describe: (i) => `后台登录入口 path="${i.path}"`,
	},

	// ---------------- api（接口服务） ----------------
	{
		id: 'api-host-prefix',
		role: 'api',
		confidence: 0.9,
		match: (i) => hostMatch(i.host, /^api\.|\.api\.|api-\d|gateway\.|svc\.|service\.|rpc\./),
		describe: (i) => `host="${i.host}" 命中 api/gateway/service 前缀`,
	},
	{
		id: 'api-path-segment',
		role: 'api',
		confidence: 0.85,
		match: (i) => pathMatch(i.path, /(^|\/)(api|graphql|gql)(\/|$)|\/v\d+\/|\/rest\/|\/rpc\//),
		describe: (i) => `path="${i.path}" 含 api/graphql/v{N} 路径`,
	},
	{
		id: 'api-swagger',
		role: 'api',
		confidence: 0.95,
		match: (i) =>
			pathMatch(i.path, /\/swagger|\/api-docs|\/openapi/) ||
			techIncludesAny(i.tech, ['swagger', 'openapi', 'graphql']),
		describe: () => 'API 文档 (swagger/openapi)',
	},
	{
		id: 'api-content-type-json',
		role: 'api',
		confidence: 0.7,
		match: (i) => pathMatch(i.path, /\.json$/i) && (i.statusCode === 200 || i.statusCode === 401),
		describe: () => 'JSON 响应 endpoint',
	},

	// ---------------- dev（开发设施） ----------------
	{
		id: 'dev-known-services',
		role: 'dev',
		confidence: 0.93,
		match: (i) =>
			hostMatch(
				i.host,
				/^(jenkins|gitlab|gitea|gogs|sonar|nexus|harbor|grafana|kibana|prometheus|jupyter|kubernetes|k8s)\./,
			) ||
			techIncludesAny(i.tech, [
				'jenkins',
				'gitlab',
				'gitea',
				'gogs',
				'sonarqube',
				'nexus',
				'harbor',
				'grafana',
				'kibana',
				'jupyter',
			]),
		describe: (i) => `DevOps 服务 (tech=${i.tech.join(',')})`,
	},
	{
		id: 'dev-env-host',
		role: 'dev',
		confidence: 0.82,
		match: (i) => hostMatch(i.host, /^(dev|test|stage|staging|qa|pre|sandbox|local)\./),
		describe: (i) => `host="${i.host}" 命中开发/测试环境前缀`,
	},

	// ---------------- middleware（中间件默认页/管理） ----------------
	{
		id: 'middleware-tomcat',
		role: 'middleware',
		confidence: 0.88,
		match: (i) => techIncludesAny(i.tech, ['tomcat']) || includesCI(i.title, 'Apache Tomcat'),
		describe: () => 'Tomcat 默认页/管理',
	},
	{
		id: 'middleware-weblogic',
		role: 'middleware',
		confidence: 0.88,
		match: (i) =>
			techIncludesAny(i.tech, ['weblogic']) || pathMatch(i.path, /\/console\/app\/Security$/),
		describe: () => 'WebLogic 管理控制台',
	},
	{
		id: 'middleware-phpmyadmin',
		role: 'middleware',
		confidence: 0.9,
		match: (i) => pathMatch(i.path, /\/phpmyadmin\//i) || techIncludesAny(i.tech, ['phpmyadmin']),
		describe: () => 'phpMyAdmin',
	},
	{
		id: 'middleware-default-page',
		role: 'middleware',
		confidence: 0.6,
		match: (i) =>
			includesCI(i.title, 'Test Page') ||
			includesCI(i.title, 'Default Page') ||
			includesCI(i.title, 'Apache2 Ubuntu') ||
			includesCI(i.title, 'Welcome to nginx'),
		describe: (i) => `Web 服务器默认页 title="${i.title}"`,
	},

	// ---------------- business（业务系统） ----------------
	{
		id: 'business-host-prefix',
		role: 'business',
		confidence: 0.78,
		match: (i) =>
			hostMatch(
				i.host,
				/^(www|app|shop|store|order|pay|user|member|account|portal|my|crm|erp|oa)\./,
			),
		describe: (i) => `host="${i.host}" 命中业务前缀`,
	},
	{
		id: 'business-login',
		role: 'business',
		confidence: 0.65,
		match: (i) => !!i.loginPage && pathMatch(i.path, /\/login|\/signin|\/auth|\/sso/i),
		describe: (i) => `业务系统登录入口 path="${i.path}"`,
	},
	{
		id: 'business-title-keyword',
		role: 'business',
		confidence: 0.6,
		match: (i) =>
			includesCI(i.title, '平台') ||
			includesCI(i.title, '系统') ||
			includesCI(i.title, '商城') ||
			includesCI(i.title, '登录') ||
			includesCI(i.title, 'Portal'),
		describe: (i) => `title="${i.title}" 含业务系统关键词`,
	},

	// ---------------- static（静态站） ----------------
	{
		id: 'static-no-login-low-score',
		role: 'static',
		confidence: 0.55,
		// 兜底静态站：根路径 + 无登录 + 200 + 无业务关键词
		match: (i) =>
			(i.path === '/' || i.path === '/index.html') &&
			!i.loginPage &&
			(i.statusCode === 200 || i.statusCode === 301 || i.statusCode === 302) &&
			!includesCI(i.title, '登录') &&
			!includesCI(i.title, '管理') &&
			!includesCI(i.title, '系统'),
		describe: () => '根路径无登录无业务关键词，疑似静态站',
	},
];

// =============================================================================
// 角色优先级（同 confidence 时用）
// =============================================================================

const ROLE_PRIORITY: Record<AssetRole, number> = {
	admin: 1,
	backend: 2,
	api: 3,
	dev: 4,
	middleware: 5,
	business: 6,
	static: 7,
	unknown: 8,
};

// =============================================================================
// 角色匹配引擎
// =============================================================================

/**
 * 对单个 webapp 执行角色规则匹配
 *
 * 算法：
 * 1. **优先**用指纹产品名匹配（matchRoleByFingerprint）
 *    - 指纹识别是强信号，confidence 通常 >= 0.85
 *    - 命中即返回，不再跑后续规则
 * 2. 指纹未命中 → 遍历 ROLE_RULES 规则表
 * 3. 收集所有命中，取 confidence 最高的（同分按 ROLE_PRIORITY 排序）
 * 4. 全部未命中返回 { role: 'unknown', confidence: 0 }
 *
 * @returns 角色匹配结果（含证据）
 */
export function matchRole(input: RoleMatchInput): RoleMatchResult {
	// 1. 优先用指纹识别
	if (input.fingerprints && input.fingerprints.length > 0) {
		const fpHit = matchRoleByFingerprint(input.fingerprints);
		if (fpHit) return fpHit;
	}

	// 2. 跑 URL/title/tech 规则
	const hits: RoleMatchResult[] = [];
	for (const rule of ROLE_RULES) {
		try {
			if (rule.match(input)) {
				hits.push({
					role: rule.role,
					confidence: rule.confidence,
					ruleId: rule.id,
					evidence: rule.describe(input),
				});
			}
		} catch {
			// 规则异常不阻塞，跳过
		}
	}

	if (hits.length === 0) {
		return {
			role: 'unknown',
			confidence: 0,
			ruleId: 'fallback-unknown',
			evidence: '无规则命中',
		};
	}

	// 排序：confidence 降序，同分按 ROLE_PRIORITY 升序
	hits.sort((a, b) => {
		if (b.confidence !== a.confidence) return b.confidence - a.confidence;
		return ROLE_PRIORITY[a.role] - ROLE_PRIORITY[b.role];
	});

	return hits[0];
}

/**
 * 批量角色匹配（用于扫描后批量评分）
 */
export function matchRoles(inputs: RoleMatchInput[]): RoleMatchResult[] {
	return inputs.map(matchRole);
}
