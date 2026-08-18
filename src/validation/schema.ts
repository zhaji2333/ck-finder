/**
 * finding 强制证据 schema（M3）
 *
 * 每个漏洞 finding 必须携带完整证据链（AutoHunter submit_finding 同款设计）：
 *   poc           复现步骤/Payload
 *   raw_request   原始请求原文
 *   raw_response  原始响应原文
 *   kill_chain    攻击链（漏洞成因 → 触发 → 影响）
 *   self_check    自我复核（可复现性/前置条件/影响/危害/优先级）
 *
 * 双保险：代码层 validateEvidence() 拒收 + DB CHECK（008 迁移）。
 */

/** 强制证据类型 */
export interface KillChainStep {
	step: string;
	detail: string;
}

export interface SelfCheck {
	/** 是否可稳定复现 */
	reproducible: boolean;
	/** 利用前置条件（登录态/角色/网络位置/版本） */
	prerequisites: string;
	/** 影响面（数据泄露/资金/提权/横向/持久化） */
	impact: string;
	/** 危害等级复核 */
	severity: string;
	/** 修复优先级 P0/P1/P2 */
	priority: string;
}

export interface FindingEvidence {
	poc: string;
	raw_request: string;
	raw_response: string;
	kill_chain: {
		chain: KillChainStep[];
		summary: string;
	};
	self_check: SelfCheck;
}

/** OWASP 漏洞分类（AGENTS 技能路由对应） */
export const VULN_TYPES = [
	'injection', // SQL/NoSQL/命令/SSTI（injection-vulns）
	'xss', // 反射/存储/DOM XSS（xss-frontend-security）
	'broken_access', // 认证/越权/IDOR（auth-access-control）
	'idor', // 水平越权（auth-access-control）
	'file_upload', // 文件上传（file-handling）
	'path_traversal', // 目录遍历/LFI（file-handling）
	'ssrf', // SSRF（ssrf-internal-network）
	'deserialization', // 反序列化（deserialization-xxe）
	'xxe', // XXE（deserialization-xxe）
	'info_disclosure', // 信息泄露（cloud-infra-supply-chain）
	'auth', // 弱口令/认证缺陷（auth-access-control）
	'redirect', // 开放重定向
	'other',
] as const;

export type VulnType = (typeof VULN_TYPES)[number];

/** 清洗字符串中的控制字符（PG JSONB 不接受 \u0000；保留 \n\t\r）。nuclei 等工具输出可能含空字节 */
export function sanitizeJsonString(s: string): string {
	return s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '');
}

/** 校验证据：缺任一必填字段抛错（拒收）。返回规范化后的证据。 */
export function validateEvidence(e: unknown): FindingEvidence {
	if (!e || typeof e !== 'object') {
		throw new Error(
			'evidence 必须为对象（poc/raw_request/raw_response/kill_chain/self_check 五件套）',
		);
	}
	const r = e as Record<string, unknown>;

	const requireString = (key: string): string => {
		const v = r[key];
		if (typeof v !== 'string' || v.trim() === '') {
			throw new Error(`evidence 缺少必填字段: ${key}（须为非空字符串）`);
		}
		return sanitizeJsonString(v);
	};
	const poc = requireString('poc');
	const rawRequest = requireString('raw_request');
	const rawResponse = requireString('raw_response');

	// kill_chain
	const kc = r.kill_chain;
	if (!kc || typeof kc !== 'object') {
		throw new Error('evidence 缺少必填字段: kill_chain');
	}
	const kcObj = kc as Record<string, unknown>;
	const chain = Array.isArray(kcObj.chain) ? kcObj.chain : [];
	if (chain.length === 0) {
		throw new Error('kill_chain.chain 必须至少 1 步（成因→触发→影响）');
	}
	if (typeof kcObj.summary !== 'string' || String(kcObj.summary).trim() === '') {
		throw new Error('kill_chain 缺少必填字段: summary');
	}
	const kcSummary = sanitizeJsonString(String(kcObj.summary));

	// self_check
	const sc = r.self_check;
	if (!sc || typeof sc !== 'object') {
		throw new Error('evidence 缺少必填字段: self_check');
	}
	const scObj = sc as Record<string, unknown>;
	for (const key of ['reproducible', 'prerequisites', 'impact', 'severity', 'priority']) {
		if (scObj[key] === undefined || scObj[key] === null || scObj[key] === '') {
			throw new Error(`self_check 缺少必填字段: ${key}`);
		}
	}

	return {
		poc,
		raw_request: rawRequest,
		raw_response: rawResponse,
		kill_chain: {
			chain: chain as KillChainStep[],
			summary: kcSummary,
		},
		self_check: {
			reproducible: Boolean(scObj.reproducible),
			prerequisites: sanitizeJsonString(String(scObj.prerequisites)),
			impact: sanitizeJsonString(String(scObj.impact)),
			severity: sanitizeJsonString(String(scObj.severity)),
			priority: sanitizeJsonString(String(scObj.priority)),
		},
	};
}

/** 创建一份合法的证据（供工具内部构造 finding 时兜底使用） */
export function buildEvidence(input: {
	poc: string;
	rawRequest: string;
	rawResponse: string;
	killChainSteps: KillChainStep[];
	killChainSummary: string;
	selfCheck: SelfCheck;
}): FindingEvidence {
	const ev: FindingEvidence = {
		poc: input.poc,
		raw_request: input.rawRequest,
		raw_response: input.rawResponse,
		kill_chain: { chain: input.killChainSteps, summary: input.killChainSummary },
		self_check: input.selfCheck,
	};
	return validateEvidence(ev);
}
