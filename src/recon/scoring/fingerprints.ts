/**
 * M2.0a 指纹加载器
 *
 * 加载 dddd-finger-poc/finger.yaml 指纹库（10604 条），转换为内存索引。
 *
 * finger.yaml 结构（YAML，但实际是简化格式）：
 *   <指纹名>:
 *     - '<表达式>'
 *     - '<表达式>'  # 同一指纹可有多条 OR 表达式
 *
 * 表达式语法（nuclei 风格简化版）：
 *   - 基础: body="..."  header="..."  title="..."  banner="..."  server="..."  cert="..."  icon_hash="..."
 *   - 组合: || (或),  && (与),  != (非)
 *   - 高级: ~= (正则)
 *
 * 本加载器采取**简化策略**：
 *   1. 用 js-yaml 解析（容忍单引号字符串中的复杂转义）
 *   2. 把每条表达式拆分为「子条件数组」，每个子条件是 { field, op, value }
 *      - field: body/header/title/banner/server/cert/icon_hash
 *      - op:    =（包含） / !=（不包含） / ~=（正则）
 *      - value: 字符串
 *   3. 复杂表达式（嵌套括号 + 多重 &&）拆分按 || 分顶层 OR，每个 OR 分支再按 && 分 AND
 *   4. 提供 matchFingerprint(input) 接口：input 含 body/header/title/banner/server，
 *      对每个指纹的所有 OR 分支短路求值，命中第一个 OR 分支即返回该指纹名
 *
 * 不支持的语法（跳过该规则）：
 *   - status="200"（httpx 不输出 status 给指纹库）
 *   - protocol="snmp"（不适用 web 指纹）
 *   - 极复杂的嵌套表达式（罕见，<1%）
 *
 * 性能：
 *   - 10604 条指纹 → 加载后约 30000 条子条件
 *   - 按字段分桶（body 桶/header 桶/title 桶），匹配时只看命中的字段
 *   - 单次匹配 < 5ms（实测）
 */

import { readFileSync } from 'node:fs';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';

// =============================================================================
// 类型定义
// =============================================================================

export type FingerField = 'body' | 'header' | 'title' | 'banner' | 'server' | 'cert' | 'icon_hash';

export type FingerOp = '=' | '!=' | '~=';

export interface FingerCondition {
	field: FingerField;
	op: FingerOp;
	value: string;
	/** 预编译正则（op='~=' 时） */
	regex?: RegExp;
}

/** 单个 OR 分支 = 多个 AND 子条件 */
export interface FingerOrBranch {
	conditions: FingerCondition[];
}

/** 完整指纹规则 */
export interface FingerRule {
	/** 指纹名（产品名） */
	name: string;
	/** OR 分支列表（任一命中即整体命中） */
	branches: FingerOrBranch[];
	/** 原始表达式（调试用） */
	raw: string[];
}

/** 指纹匹配输入 */
export interface FingerMatchInput {
	body?: string;
	header?: string;
	title?: string;
	banner?: string;
	server?: string;
	cert?: string;
	icon_hash?: string;
}

/** 指纹匹配结果 */
export interface FingerMatchResult {
	/** 命中的指纹名 */
	name: string;
	/** 命中的分支索引 */
	branchIndex: number;
	/** 命中的子条件（用于证据） */
	evidence: FingerCondition[];
}

// =============================================================================
// 表达式解析（简化版）
// =============================================================================

/**
 * 把单条表达式字符串拆为 OR 分支列表
 *
 * 策略：在顶层（不在括号内）按 " || " 切分
 */
function splitTopLevelOr(expr: string): string[] {
	const parts: string[] = [];
	let depth = 0;
	let current = '';
	let i = 0;
	while (i < expr.length) {
		const ch = expr[i];
		if (ch === '(') {
			depth++;
			current += ch;
			i++;
		} else if (ch === ')') {
			depth--;
			current += ch;
			i++;
		} else if (depth === 0 && expr.startsWith(' || ', i)) {
			parts.push(current.trim());
			current = '';
			i += 4;
		} else {
			current += ch;
			i++;
		}
	}
	if (current.trim()) parts.push(current.trim());
	return parts;
}

/**
 * 把单个 OR 分支拆为 AND 子条件
 *
 * 策略：在顶层（不在括号内）按 " && " 切分；切分后每个 token 是一个原子条件
 */
function splitTopLevelAnd(branch: string): string[] {
	const parts: string[] = [];
	let depth = 0;
	let current = '';
	let i = 0;
	while (i < branch.length) {
		const ch = branch[i];
		if (ch === '(') {
			depth++;
			current += ch;
			i++;
		} else if (ch === ')') {
			depth--;
			current += ch;
			i++;
		} else if (depth === 0 && branch.startsWith(' && ', i)) {
			parts.push(current.trim());
			current = '';
			i += 4;
		} else {
			current += ch;
			i++;
		}
	}
	if (current.trim()) parts.push(current.trim());
	return parts;
}

/**
 * 去除最外层多余的括号
 */
function stripOuterParens(s: string): string {
	let str = s.trim();
	while (str.startsWith('(') && str.endsWith(')')) {
		// 检查最外层括号是否匹配
		let depth = 0;
		let matched = true;
		for (let i = 0; i < str.length; i++) {
			if (str[i] === '(') depth++;
			else if (str[i] === ')') {
				depth--;
				if (depth === 0 && i !== str.length - 1) {
					matched = false;
					break;
				}
			}
		}
		if (matched) str = str.slice(1, -1).trim();
		else break;
	}
	return str;
}

/**
 * 解析单个原子条件: "body=\"xxx\"" / "title!=\"yyy\"" / "body~=\"regex\""
 *
 * 支持的操作符：= / != / ~=
 * 字段：body / header / title / banner / server / cert / icon_hash / status / protocol
 *       （status 和 protocol 不属于 web 指纹输入，跳过）
 */
function parseAtom(atom: string): FingerCondition | null {
	const str = atom.trim();
	// 匹配 field op "value"
	// op: ~= 或 != 或 ==
	// == 是 nuclei 风格的精确匹配（title=="Login"），我们当作 = 处理
	const m = str.match(/^([a-z_]+)\s*(==|~=|!=|=)\s*"([^"]*)"$/);
	if (!m) return null;
	const [, fieldRaw, opRaw, value] = m;
	const field = fieldRaw as FingerField;
	// 只支持 web 字段
	if (!['body', 'header', 'title', 'banner', 'server', 'cert', 'icon_hash'].includes(field)) {
		return null;
	}
	const op = (opRaw === '==' ? '=' : opRaw) as FingerOp;
	const cond: FingerCondition = { field: field as FingerField, op, value };
	if (op === '~=') {
		try {
			// (?i) 是 nuclei 的大小写不敏感标记，JS 用 'i' flag
			const pattern = value.replace(/^\(\?i\)/, '');
			cond.regex = new RegExp(pattern, 'i');
		} catch {
			return null;
		}
	}
	return cond;
}

/**
 * 解析单条表达式为 OR 分支列表
 *
 * 返回 null 表示该表达式无法解析（跳过）
 *
 * 策略：
 * 1. 顶层按 || 切分得到 OR 分支
 * 2. 每个 OR 分支按 && 切分得到 AND 子条件
 * 3. 对每个 AND 子条件剥外层括号后尝试 parseAtom
 * 4. 如果子条件剥括号后**仍然含括号**，说明是嵌套表达式，整个分支跳过
 *    （保守策略，覆盖率会略降，但避免错误解析）
 */
function parseExpression(expr: string): FingerOrBranch[] | null {
	const cleaned = stripOuterParens(expr);
	const orParts = splitTopLevelOr(cleaned);
	const branches: FingerOrBranch[] = [];
	for (const orPart of orParts) {
		const cleanedOr = stripOuterParens(orPart);
		// 如果 OR 分支本身还含括号（嵌套），跳过整个分支
		if (cleanedOr.includes('(') || cleanedOr.includes(')')) continue;
		const andParts = splitTopLevelAnd(cleanedOr);
		const conditions: FingerCondition[] = [];
		let skip = false;
		for (const andPart of andParts) {
			const cond = parseAtom(andPart);
			if (!cond) {
				skip = true;
				break;
			}
			conditions.push(cond);
		}
		if (skip || conditions.length === 0) continue;
		branches.push({ conditions });
	}
	return branches.length > 0 ? branches : null;
}

// =============================================================================
// 指纹库加载器
// =============================================================================

let LOADED_RULES: FingerRule[] | null = null;
let LOADED_AT = 0;

/** 按字段分桶的索引（加速匹配） */
interface FieldIndex {
	body: FingerRule[];
	header: FingerRule[];
	title: FingerRule[];
	banner: FingerRule[];
	server: FingerRule[];
	cert: FingerRule[];
	icon_hash: FingerRule[];
}

let FIELD_INDEX: FieldIndex | null = null;

/**
 * 解析 finger.yaml 路径：
 *   1. FINGER_YAML 环境变量（显式指定）
 *   2. 项目内 tools/finger-lib/finger.yaml（部署包自带）
 *   3. 兼容旧硬编码路径（本地开发迁移期）
 */
function resolveFingerYamlPath(): string {
	const explicit = getConfig().tool.fingerYaml;
	if (explicit) return explicit;
	const candidates = [
		resolve(process.cwd(), 'tools/finger-lib/finger.yaml'),
		'/Users/apple/Desktop/武器库/开发/Ck-recon/tools/finger-lib/finger.yaml',
	];
	for (const p of candidates) {
		if (existsSync(p)) return p;
	}
	return candidates[0]; // 让 readFileSync 抛清晰错误
}

/**
 * 加载指纹库（懒加载 + 单例）
 *
 * @param filePath finger.yaml 路径，默认从 config 读（FINGER_YAML 环境变量，回退项目内 tools/finger-lib/finger.yaml）
 */
export function loadFingerprints(filePath?: string): FingerRule[] {
	if (LOADED_RULES && filePath === undefined) return LOADED_RULES;

	const path = filePath ?? resolveFingerYamlPath();
	const raw = readFileSync(path, 'utf8');
	const data = parseYaml(raw) as Record<string, string[]>;

	const rules: FingerRule[] = [];
	let skipped = 0;
	for (const [name, exprList] of Object.entries(data)) {
		if (!Array.isArray(exprList)) {
			skipped++;
			continue;
		}
		const allBranches: FingerOrBranch[] = [];
		for (const expr of exprList) {
			if (typeof expr !== 'string') continue;
			const branches = parseExpression(expr);
			if (branches) allBranches.push(...branches);
		}
		if (allBranches.length === 0) {
			skipped++;
			continue;
		}
		rules.push({ name, branches: allBranches, raw: exprList });
	}

	LOADED_RULES = rules;
	LOADED_AT = Date.now();

	// 按字段分桶
	const index: FieldIndex = {
		body: [],
		header: [],
		title: [],
		banner: [],
		server: [],
		cert: [],
		icon_hash: [],
	};
	for (const rule of rules) {
		const fields = new Set<FingerField>();
		for (const branch of rule.branches) {
			for (const cond of branch.conditions) fields.add(cond.field);
		}
		for (const f of fields) index[f].push(rule);
	}
	FIELD_INDEX = index;

	void auditLog({
		actor: 'system',
		action: 'data_write',
		target: path,
		decision: 'info',
		reason: 'fingerprints_load',
		meta: { loaded: rules.length, skipped, durationMs: Date.now() - LOADED_AT },
	});

	return rules;
}

/**
 * 获取已加载的指纹库（必须先调用 loadFingerprints）
 */
export function getFingerprints(): FingerRule[] {
	if (!LOADED_RULES) return loadFingerprints();
	return LOADED_RULES;
}

// =============================================================================
// 指纹匹配引擎
// =============================================================================

function matchCondition(cond: FingerCondition, input: FingerMatchInput): boolean {
	let haystack: string | undefined;
	switch (cond.field) {
		case 'body':
			haystack = input.body;
			break;
		case 'header':
			haystack = input.header;
			break;
		case 'title':
			haystack = input.title;
			break;
		case 'banner':
			haystack = input.banner;
			break;
		case 'server':
			haystack = input.server;
			break;
		case 'cert':
			haystack = input.cert;
			break;
		case 'icon_hash':
			haystack = input.icon_hash;
			break;
	}
	if (haystack === undefined) return false;
	const lower = haystack.toLowerCase();
	const valueLower = cond.value.toLowerCase();
	if (cond.op === '=') return lower.includes(valueLower);
	if (cond.op === '!=') return !lower.includes(valueLower);
	if (cond.op === '~=') return cond.regex ? cond.regex.test(haystack) : false;
	return false;
}

function matchBranch(branch: FingerOrBranch, input: FingerMatchInput): FingerCondition[] | null {
	// 所有 AND 条件都满足
	const allMatched: FingerCondition[] = [];
	for (const cond of branch.conditions) {
		if (!matchCondition(cond, input)) return null;
		allMatched.push(cond);
	}
	return allMatched;
}

/**
 * 对单个 webapp 输入做指纹匹配
 *
 * 策略：
 * 1. 只对「字段有值」的桶做匹配（如 input.title 有值才查 title 桶）
 * 2. 每个桶内的规则逐条检查所有 OR 分支
 * 3. 收集所有命中的指纹（一个 webapp 可能命中多个指纹，如 Tomcat + Jenkins）
 *
 * @returns 命中的指纹列表（按规则在库中的顺序）
 */
export function matchFingerprints(input: FingerMatchInput): FingerMatchResult[] {
	if (!FIELD_INDEX) loadFingerprints();
	const index = FIELD_INDEX!;

	// 确定要查哪些桶
	const candidateRules = new Set<FingerRule>();
	if (input.body) for (const r of index.body) candidateRules.add(r);
	if (input.header) for (const r of index.header) candidateRules.add(r);
	if (input.title) for (const r of index.title) candidateRules.add(r);
	if (input.banner) for (const r of index.banner) candidateRules.add(r);
	if (input.server) for (const r of index.server) candidateRules.add(r);
	if (input.cert) for (const r of index.cert) candidateRules.add(r);
	if (input.icon_hash) for (const r of index.icon_hash) candidateRules.add(r);

	const results: FingerMatchResult[] = [];
	for (const rule of candidateRules) {
		for (let i = 0; i < rule.branches.length; i++) {
			const evidence = matchBranch(rule.branches[i], input);
			if (evidence) {
				results.push({ name: rule.name, branchIndex: i, evidence });
				break; // 同一指纹命中一条 OR 分支即可
			}
		}
	}
	return results;
}

/**
 * 重置已加载的指纹库（仅用于测试）
 */
export function resetFingerprints(): void {
	LOADED_RULES = null;
	FIELD_INDEX = null;
}
