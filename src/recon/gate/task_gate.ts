/**
 * M2.5 任务门控
 *
 * 根据评分给 webapp 标记后续任务的执行级别（L0/L1/L2/L3），
 * 输出 suggested_next 数组，pipeline 按这个数组决定要跑哪些后续任务。
 *
 * 级别定义：
 *   L0  剪枝      score < 40  → 不跑任何后续任务（suggested_next = []）
 *   L1  基础侦察  40 ≤ score < 60 → dirscan + history_url
 *   L2  深度挖掘  60 ≤ score < 85 → + jsmining + source_collect
 *   L3  攻击靶心  score ≥ 85 → 全套（DAST 强度提升，但 DAST 不在本模块控制）
 *
 * 特殊规则：
 * - score<60 且 role=static → 强制降级为 L0（剪枝静态站）
 * - hard_to_attack=true（CDN+WAF）→ 不影响评分，但 suggested_next 仅保留被动 history_url
 * - 命中 CVE hint → 至少 L2（保证漏洞组件被深挖）
 * - 技术栈画像调整（adjustByTechProfile）：SPA/CMS/API/源码可用 等特征改变任务组合
 *
 * suggested_next 字段（与 webapps.suggested_next CHECK 约束一致）：
 *   'dirscan' | 'jsmining' | 'history_url' | 'source_collect'
 */

import type { AssetRole } from '../scoring/roles.js';

// =============================================================================
// 类型定义
// =============================================================================

export type TaskLevel = 'L0' | 'L1' | 'L2' | 'L3';

export type SuggestedNext = 'dirscan' | 'jsmining' | 'history_url' | 'source_collect';

export interface TaskGateInput {
	score: number;
	role: AssetRole;
	hardToAttack: boolean;
	/** 命中的漏洞 hint 数量 */
	vulnHintCount: number;
}

export interface TaskGateResult {
	level: TaskLevel;
	suggestedNext: SuggestedNext[];
	/** 门控理由（用于审计/调试） */
	reason: string;
}

// =============================================================================
// 门控引擎
// =============================================================================

/**
 * 计算任务门控
 */
export function computeTaskGate(input: TaskGateInput): TaskGateResult {
	const { score, role, hardToAttack, vulnHintCount } = input;

	// 1. 计算基础 level
	let level: TaskLevel;
	if (score < 40) level = 'L0';
	else if (score < 60) level = 'L1';
	else if (score < 85) level = 'L2';
	else level = 'L3';

	let reason = `score=${score} → ${level}`;

	// 2. 静态站剪枝：score<60 且 role=static → L0
	if (level !== 'L0' && role === 'static' && score < 60) {
		level = 'L0';
		reason += '; static + score<60 强制剪枝 → L0';
	}

	// 3. 命中 CVE hint → 至少 L2
	if (vulnHintCount > 0 && level === 'L1') {
		level = 'L2';
		reason += `; 命中 ${vulnHintCount} 个 CVE hint 提升 → L2`;
	}

	// 4. 计算 suggested_next
	let suggestedNext: SuggestedNext[];
	switch (level) {
		case 'L0':
			suggestedNext = [];
			break;
		case 'L1':
			suggestedNext = ['dirscan', 'history_url'];
			break;
		case 'L2':
			suggestedNext = ['dirscan', 'jsmining', 'history_url', 'source_collect'];
			break;
		case 'L3':
			suggestedNext = ['dirscan', 'jsmining', 'history_url', 'source_collect'];
			break;
	}

	// 5. CDN+WAF 双重防护 → 减半（只跑 history_url + github_search，不跑主动 dirscan）
	if (hardToAttack && level !== 'L0') {
		suggestedNext = suggestedNext.filter((t) => t === 'history_url');
		reason += '; CDN+WAF 双重防护，仅保留被动任务';
	}

	return { level, suggestedNext, reason };
}

/**
 * 批量计算任务门控
 */
export function computeTaskGates(inputs: TaskGateInput[]): TaskGateResult[] {
	return inputs.map(computeTaskGate);
}

// =============================================================================
// 技术栈画像调整（动态规划）
// =============================================================================

/**
 * webapp 的技术栈画像（来自指纹/httpx tech/单站分析 meta）
 */
export interface TechProfile {
	/** 指纹库命中的指纹名（wordpress/thinkphp/vue 等） */
	fingerprints: string[];
	/** httpx 检测的 tech（nginx/cloudflare 等） */
	tech: string[];
	/** 单站分析识别的框架（site_framework） */
	framework: string[];
	/** 单站分析识别的架构（spa/mpa/ssr/static） */
	architecture: string | null;
	/** 是否检测到 webpack 指纹 */
	webpackDetected: boolean;
	/** 是否发现 sourcemap（源码可还原） */
	sourceAvailable: boolean;
	/** 角色是否为 api / 路径是否含 /api */
	isApi: boolean;
}

/**
 * 根据技术栈画像调整 suggested_next（确定性规则，不走 LLM）
 *
 * 目标：CMS 站、SPA 站、API 站跑不同的深挖组合，而不是所有站一刀切。
 *
 * 规则（全部追加进 reason，可审计）：
 *   - SPA（vue/react/angular/webpack/vite）→ 保证 jsmining + source_collect（L1 也至少 jsmining）
 *   - CMS（wordpress/thinkphp/drupal/discuz 等）→ 保证 dirscan + history_url
 *   - sourcemap 可用 → 强制 source_collect（高价值）
 *   - API 站 → 保证 jsmining（接口提取是核心）
 *   - 纯静态（architecture=static 且无指纹）→ 若 L1 降为 L0（剪枝）
 */
export function adjustByTechProfile(gate: TaskGateResult, profile: TechProfile): TaskGateResult {
	if (gate.level === 'L0' || gate.suggestedNext.length === 0) return gate;

	const next = new Set<SuggestedNext>(gate.suggestedNext);
	const reasons: string[] = [];

	const allSignals = [
		...profile.fingerprints.map((f) => f.toLowerCase()),
		...profile.tech.map((t) => t.toLowerCase()),
		...profile.framework.map((f) => f.toLowerCase()),
	].join(' ');

	// 1. SPA / webpack / vite → JS 与源码是核心攻击面
	const isSpa =
		profile.architecture === 'spa' ||
		/(^|\s)(vue|react|angular|webpack|vite|next|nuxt)(\s|$)/.test(allSignals);
	if (isSpa) {
		if (!next.has('jsmining')) {
			next.add('jsmining');
			reasons.push('SPA 技术栈 → 补 jsmining');
		}
		if (!next.has('source_collect')) {
			next.add('source_collect');
			reasons.push('SPA 技术栈 → 补 source_collect');
		}
	}

	// 2. CMS → 后台路径与已知组件是核心
	const isCms =
		/(^|\s)(wordpress|drupal|joomla|discuz|thinkphp|phpcms|dedecms|empirecms|typecho|ghost)(\s|$)/.test(
			allSignals,
		);
	if (isCms) {
		if (!next.has('dirscan')) {
			next.add('dirscan');
			reasons.push('CMS 技术栈 → 补 dirscan（后台路径）');
		}
		if (!next.has('history_url')) {
			next.add('history_url');
			reasons.push('CMS 技术栈 → 补 history_url');
		}
	}

	// 3. sourcemap 可用 → 源码还原优先
	if (profile.sourceAvailable && !next.has('source_collect')) {
		next.add('source_collect');
		reasons.push('sourcemap 可用 → 强制 source_collect');
	}

	// 4. API 站 → 接口提取优先
	if ((profile.isApi || profile.architecture === 'api') && !next.has('jsmining')) {
		next.add('jsmining');
		reasons.push('API 站 → 补 jsmining');
	}

	// 5. 纯静态站（无任何技术信号）→ L1 剪枝
	if (
		profile.architecture === 'static' &&
		!isSpa &&
		!isCms &&
		next.size > 0 &&
		gate.level === 'L1'
	) {
		gate = { ...gate, level: 'L0', suggestedNext: [], reason: `${gate.reason}; 纯静态站剪枝 → L0` };
		return gate;
	}

	if (reasons.length === 0) return gate;

	const ALL_TASKS: SuggestedNext[] = ['dirscan', 'jsmining', 'history_url', 'source_collect'];
	const ordered = ALL_TASKS.filter((t) => next.has(t));
	return {
		...gate,
		suggestedNext: ordered,
		reason: `${gate.reason}; ${reasons.join('，')}`,
	};
}
