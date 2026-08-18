/**
 * M2.3 已知漏洞组件被动关联
 *
 * 输入：webapp 的指纹名 + tech + title + body_preview
 * 输出：命中的 CVE hint 列表（不验证，仅作为后续 DAST/POC 的提示）
 *
 * 设计：
 * - 内置已知漏洞组件表（VULN_SIGNATURES）
 * - 每条记录含：组件名关键词 + 漏洞类型 + CVE 编号 + 严重性 + 简介 + 推荐下一步
 * - 匹配方式：指纹名/tech/title/body 包含关键词即命中
 *
 * 不走 LLM，纯规则。
 */

// =============================================================================
// 类型定义
// =============================================================================

export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface VulnHint {
	/** 组件名 */
	component: string;
	/** 漏洞类型（如 RCE / 反序列化 / SSTI） */
	type: string;
	/** CVE 编号 */
	cve: string;
	/** 严重性 */
	severity: VulnSeverity;
	/** 简介说明 */
	description: string;
	/** 推荐下一步（如 "尝试 shiro-550 利用"） */
	suggestedNext: string;
	/** 命中证据 */
	evidence: string;
}

export interface VulnMatchInput {
	/** 命中的指纹名列表 */
	fingerprints: string[];
	/** tech 字段（如 ['Nginx', 'Apache-Shiro']） */
	tech: string[];
	/** 页面标题 */
	title?: string | null;
	/** body preview（httpx -bp 4096） */
	body?: string | null;
	/** 完整 header 拼接字符串 */
	header?: string | null;
}

// =============================================================================
// 漏洞组件表（人工维护，按需扩充）
// =============================================================================
//
// 匹配逻辑：
// - keyword 数组中任一关键词出现在 fingerprints/tech/title/body/header 即命中
// - keyword 用小写匹配
//

interface VulnSignature {
	/** 组件名（用于 VulnHint.component） */
	component: string;
	/** 匹配关键词（小写，命中任一即匹配） */
	keywords: string[];
	type: string;
	cve: string;
	severity: VulnSeverity;
	description: string;
	suggestedNext: string;
}

const VULN_SIGNATURES: VulnSignature[] = [
	// ---------------- Apache Shiro ----------------
	{
		component: 'Apache Shiro',
		keywords: ['shiro', 'rememberme', 'remember-me'],
		type: '反序列化 RCE',
		cve: 'CVE-2016-4437 (Shiro-550)',
		severity: 'critical',
		description: 'Shiro 默认密钥固定，rememberMe Cookie 可构造序列化 payload 触发 RCE',
		suggestedNext: '尝试 shiro-550 利用：检测默认密钥 + 构造 rememberMe Cookie',
	},
	{
		component: 'Apache Shiro',
		keywords: ['shiro'],
		type: '身份认证绕过',
		cve: 'CVE-2022-32532',
		severity: 'high',
		description: 'Shiro RegExPatternMatcher 路径匹配绕过',
		suggestedNext: '路径绕过测试',
	},

	// ---------------- Fastjson ----------------
	{
		component: 'Fastjson',
		keywords: ['fastjson'],
		type: '反序列化 RCE',
		cve: 'CVE-2022-25845',
		severity: 'critical',
		description: 'Fastjson autotype 绕过，可触发 JNDI 注入 RCE',
		suggestedNext: '尝试 fastjson autotype 利用 + JNDI 外带',
	},

	// ---------------- Struts2 ----------------
	{
		component: 'Apache Struts2',
		keywords: ['struts', 'struts2'],
		type: 'OGNL RCE',
		cve: 'CVE-2017-5638 (S2-045) / CVE-2020-17530 (S2-061)',
		severity: 'critical',
		description: 'Struts2 OGNL 表达式注入，常见 S2-045/S2-046/S2-057/S2-061',
		suggestedNext: '尝试 S2-045 / S2-061 利用：Content-Type 注入 OGNL',
	},

	// ---------------- Log4j ----------------
	{
		component: 'Apache Log4j',
		keywords: ['log4j', 'log4shell'],
		type: 'JNDI 注入 RCE',
		cve: 'CVE-2021-44228 (Log4Shell)',
		severity: 'critical',
		description: 'Log4j 2.x JNDI 注入，影响极广',
		suggestedNext: '尝试 log4shell 利用：header/body 注入 ${jndi:ldap://...}',
	},

	// ---------------- Spring ----------------
	{
		component: 'Spring Framework',
		keywords: ['spring-boot-actuator', 'actuator'],
		type: '未授权访问 / RCE',
		cve: 'CVE-2022-22965 (Spring4Shell) / Actuator 未授权',
		severity: 'high',
		description: 'Spring Boot Actuator 暴露，可能有 /env /heapdump /jolokia 未授权',
		suggestedNext: '尝试 /actuator/heapdump /actuator/env 未授权访问',
	},
	{
		component: 'Spring Cloud Function',
		keywords: ['spring-cloud-function'],
		type: 'SpEL RCE',
		cve: 'CVE-2022-22963',
		severity: 'critical',
		description: 'spring-cloud-function SpEL 注入 RCE',
		suggestedNext: '尝试 spring-cloud-function SpEL 注入',
	},

	// ---------------- WebLogic ----------------
	{
		component: 'Oracle WebLogic',
		keywords: ['weblogic'],
		type: '反序列化 RCE',
		cve: 'CVE-2017-10271 / CVE-2020-14882',
		severity: 'critical',
		description: 'WebLogic XMLDecoder 反序列化 + 管理控制台未授权 RCE',
		suggestedNext: '尝试 /console /_async /wls-wsat 利用',
	},

	// ---------------- Tomcat ----------------
	{
		component: 'Apache Tomcat',
		keywords: ['tomcat'],
		type: '弱口令 / PUT 上传',
		cve: 'CVE-2017-12615 (PUT) / Tomcat Manager 弱口令',
		severity: 'high',
		description: 'Tomcat Manager 弱口令部署 WAR；PUT 方法上传 JSP',
		suggestedNext: '尝试 /manager/html 弱口令 + PUT 上传',
	},

	// ---------------- Jenkins ----------------
	{
		component: 'Jenkins',
		keywords: ['jenkins', 'hudson'],
		type: '未授权 / Groovy RCE',
		cve: 'CVE-2019-1003000 / Jenkins 未授权',
		severity: 'critical',
		description: 'Jenkins Script Console 未授权执行 Groovy 脚本',
		suggestedNext: '尝试 /script /asynchPeople/ 未授权访问',
	},

	// ---------------- GitLab ----------------
	{
		component: 'GitLab',
		keywords: ['gitlab'],
		type: 'SSRF / RCE',
		cve: 'CVE-2021-22201 / CVE-2021-22214',
		severity: 'high',
		description: 'GitLab GraphQL SSRF + CI/CD Runner RCE',
		suggestedNext: '尝试 /api/v4 /-/graphql 探测',
	},

	// ---------------- Nexus ----------------
	{
		component: 'Sonatype Nexus',
		keywords: ['nexus'],
		type: '未授权 / RCE',
		cve: 'CVE-2020-3650 / Nexus Repository Manager 未授权',
		severity: 'high',
		description: 'Nexus Repository Manager 未授权 + EL 表达式注入',
		suggestedNext: '尝试 /service/rest/ 未授权访问',
	},

	// ---------------- phpMyAdmin ----------------
	{
		component: 'phpMyAdmin',
		keywords: ['phpmyadmin'],
		type: '弱口令 / SQL 注入',
		cve: 'CVE-2018-12613 / phpMyAdmin 弱口令',
		severity: 'high',
		description: 'phpMyAdmin 弱口令可直连数据库；老版本 LFI',
		suggestedNext: '尝试 root/root 弱口令 + LFI 利用',
	},

	// ---------------- Elasticsearch ----------------
	{
		component: 'Elasticsearch',
		keywords: ['elasticsearch'],
		type: '未授权访问',
		cve: 'CVE-2015-1427 / Elasticsearch 未授权',
		severity: 'critical',
		description: 'Elasticsearch 默认 9200 端口无认证，可读所有索引',
		suggestedNext: '尝试 /_cat/indices /_search 未授权访问',
	},

	// ---------------- Solr ----------------
	{
		component: 'Apache Solr',
		keywords: ['solr'],
		type: 'RCE',
		cve: 'CVE-2019-0193 / CVE-2021-27905',
		severity: 'critical',
		description: 'Solr DataImportHandler RCE + 远程流读取',
		suggestedNext: '尝试 /solr/admin/ /solr/{core}/dataimport 利用',
	},

	// ---------------- Zabbix ----------------
	{
		component: 'Zabbix',
		keywords: ['zabbix'],
		type: '未授权 / SQL 注入',
		cve: 'CVE-2017-2824 / Zabbix Guest 未授权',
		severity: 'high',
		description: 'Zabbix Guest 账户未授权查看 + JS RPC SQL 注入',
		suggestedNext: '尝试 /zabbix.php Guest 登录 + latest.php',
	},

	// ---------------- Nacos ----------------
	{
		component: 'Alibaba Nacos',
		keywords: ['nacos'],
		type: '未授权 / 默认口令',
		cve: 'CVE-2021-29441',
		severity: 'critical',
		description: 'Nacos 默认口令 nacos/nacos + 用户认证绕过',
		suggestedNext: '尝试 /nacos/v1/auth/users/login nacos/nacos + 认证绕过',
	},
];

// =============================================================================
// 匹配引擎
// =============================================================================

/**
 * 对单个 webapp 做漏洞组件关联
 *
 * @returns 命中的漏洞 hint 列表
 */
export function matchVulnHints(input: VulnMatchInput): VulnHint[] {
	// 收集所有可匹配字符串（全部小写）
	const haystacks: string[] = [];
	haystacks.push(...(input.fingerprints ?? []).map((s) => s.toLowerCase()));
	haystacks.push(...(input.tech ?? []).map((s) => s.toLowerCase()));
	if (input.title) haystacks.push(input.title.toLowerCase());
	if (input.body) haystacks.push(input.body.toLowerCase());
	if (input.header) haystacks.push(input.header.toLowerCase());

	const results: VulnHint[] = [];
	const seen = new Set<string>(); // 去重（同一 CVE 不重复输出）

	for (const sig of VULN_SIGNATURES) {
		const lowerKeywords = sig.keywords.map((k) => k.toLowerCase());
		for (const haystack of haystacks) {
			for (const kw of lowerKeywords) {
				if (haystack.includes(kw)) {
					const key = `${sig.component}:${sig.cve}`;
					if (seen.has(key)) break;
					seen.add(key);
					results.push({
						component: sig.component,
						type: sig.type,
						cve: sig.cve,
						severity: sig.severity,
						description: sig.description,
						suggestedNext: sig.suggestedNext,
						evidence: `命中关键词 "${kw}"（在 "${haystack.slice(0, 80)}"）`,
					});
					break; // 同一签名命中一次即可
				}
			}
		}
	}
	return results;
}
