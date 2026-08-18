/**
 * 决策点 1：侦察策略规划器（LLM Planner）
 *
 * 混合架构：确定性管道执行，LLM 决定"这一轮收集怎么打"。
 * 种子进来后、管道执行前，LLM 输出一个策略参数包：
 *   - mode: site（单站）/ full（全量）
 *   - options: skipNmap / maxSubdomains / ports 等参数微调
 *   - deepScanLevel: none/l1/l2/l3（扫描后深挖力度）
 *
 * 设计原则：
 *   - **范围护栏**：LLM 只能缩小范围、不能放大
 *     · URL 种子 → mode 只能 site（护栏强制，防止 LLM 把单站放大成域名测绘）
 *     · maxSubdomains clamp 到 [50, 2000]
 *     · 违规建议 → 记录审计 + 采用护栏值
 *   - 缓存：planner_decisions 表（seed_type+seed_value+model UNIQUE）
 *   - 失败 / 解析失败 → 返回 null，调用方用默认策略，不阻塞扫描
 *   - 全程 audit_log 留痕（决策内容/护栏修正/失败）
 */

import { getConfig } from '../config.js';
import { auditLog } from '../gate/audit_log.js';
import { callDeepSeek, extractJsonContent } from '../scoring/llm_client.js';
import type { Seed, SeedType } from '../seeds/types.js';
import { getPg } from '../storage/pg.js';

// =============================================================================
// 类型定义
// =============================================================================

export interface PlannerInput {
	seed: Seed;
	/** 默认约束（用户显式传入的参数优先于 LLM 建议） */
	defaults: {
		maxSubdomains: number;
		maxCompanyDomains: number;
		skipNmap: boolean;
		skipHttpx: boolean;
	};
	/** 该种子是否有历史扫描记录（提示用） */
	hasHistory: boolean;
}

export interface PlannerDecision {
	/** 建议的收集模式；null = 维持默认（auto） */
	mode: 'site' | 'full' | null;
	/** 参数微调（全部可空 = 维持默认） */
	options: {
		skipNmap?: boolean;
		skipOneForAll?: boolean;
		maxSubdomains?: number;
		ports?: string;
	};
	/** 扫描完成后深挖力度：none = 不深挖，l1/l2/l3 = 对应级别任务 */
	deepScanLevel: 'none' | 'l1' | 'l2' | 'l3';
	reasoning: string;
	/** 护栏修正记录（audit 用） */
	guardNotes: string[];
	/** 是否真的走了 LLM（false = 缓存命中） */
	fromLlm: boolean;
	provider: string;
	model: string;
}

/** 深挖级别 → suggested_next 任务组合（与 task_gate 语义一致） */
export const DEEP_SCAN_LEVEL_TASKS: Record<string, string[]> = {
	none: [],
	l1: ['dirscan', 'history_url'],
	l2: ['dirscan', 'jsmining', 'history_url', 'source_collect'],
	l3: ['dirscan', 'jsmining', 'history_url', 'source_collect'],
};

// =============================================================================
// 缓存（PG 表 planner_decisions）
// =============================================================================

async function getCached(
	seedType: SeedType,
	seedValue: string,
	provider: string,
	model: string,
): Promise<PlannerDecision | null> {
	const pool = getPg();
	const { rows } = await pool.query(
		`SELECT decision, reasoning FROM planner_decisions
     WHERE seed_type = $1 AND seed_value = $2 AND provider = $3 AND model = $4
     ORDER BY created_at DESC LIMIT 1`,
		[seedType, seedValue, provider, model],
	);
	if (rows.length === 0) return null;
	const d = rows[0].decision;
	return {
		mode: d.mode ?? null,
		options: d.options ?? {},
		deepScanLevel: d.deepScanLevel ?? 'none',
		reasoning: rows[0].reasoning ?? '',
		guardNotes: d.guardNotes ?? [],
		fromLlm: false,
		provider,
		model,
	};
}

async function saveCache(
	seedType: SeedType,
	seedValue: string,
	provider: string,
	model: string,
	decision: Omit<PlannerDecision, 'fromLlm' | 'provider' | 'model'>,
	rawResponse: unknown,
): Promise<void> {
	const pool = getPg();
	await pool.query(
		`INSERT INTO planner_decisions (seed_type, seed_value, provider, model, decision, reasoning, raw_response)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (seed_type, seed_value, provider, model) DO UPDATE
       SET decision = EXCLUDED.decision,
           reasoning = EXCLUDED.reasoning,
           raw_response = EXCLUDED.raw_response,
           created_at = now()`,
		[
			seedType,
			seedValue,
			provider,
			model,
			JSON.stringify({
				mode: decision.mode,
				options: decision.options,
				deepScanLevel: decision.deepScanLevel,
				guardNotes: decision.guardNotes,
			}),
			decision.reasoning,
			JSON.stringify(rawResponse ?? null),
		],
	);
}

// =============================================================================
// Prompt 拼装
// =============================================================================

function buildPrompt(input: PlannerInput): { system: string; user: string } {
	const system = `你是一名网络侦察规划专家。给定一个信息收集种子，规划收集策略。

背景：ck-recon 是纯信息收集系统（不做漏洞验证）。确定性管道负责执行：
- URL 种子 → 单站模式（只收集这个站：框架/语言/接口/JS/webpack，不枚举子域/端口）
- 域名种子 → 全量模式（subfinder+oneforall 子域 → dnsx → nmap → httpx → 评分）
- 公司名 → ICP 反查域名 → 全量模式
- IP/CIDR → nmap → httpx

你的任务：输出策略参数包（不是执行计划，管道自己会执行）：
{
  "mode": "site" | "full" | null,
  "options": {
    "skipNmap": true | false,
    "skipOneForAll": true | false,
    "maxSubdomains": 数字,
    "ports": "80,443,8080" 或 null
  },
  "deepScanLevel": "none" | "l1" | "l2" | "l3",
  "reasoning": "简短理由（30字内）"
}

决策原则：
1. URL 种子：mode 必须为 null 或 "site"（系统强制单站，不要建议 full）
2. 域名种子：普通业务域名建议 full；已知是小站/个人站可建议 site 或 null
3. skipNmap：CDN 防护明显/只需快速摸底时可建议 true（跳过最慢环节）
4. skipOneForAll：子域已够多或目标明确时建议 true（OneForAll 爆破较慢）
5. maxSubdomains：大目标（大厂/金融）可建议 300-800，普通目标 100-300，小目标不填
6. ports：Web 应用站建议 "80,443,8080-8090"；API 服务可 "80,443,3000,5000"；不明确就 null
7. deepScanLevel：管理后台/API 站/高价值目标 l2-l3；普通业务站 l1；纯静态 l0 不需要深挖用 "none"
8. 不确定的参数留空（null/false），让默认值接管

只输出 JSON。`;

	const user = JSON.stringify(
		{
			seed: input.seed.value,
			seedType: input.seed.seedType,
			parsed: input.seed.parsed,
			defaults: input.defaults,
			hasHistory: input.hasHistory,
			availableTools: [
				'subfinder',
				'oneforall',
				'dnsx',
				'nmap',
				'httpx',
				'dirsearch',
				'katana',
				'gau',
				'waybackurls',
				'fofa',
				'icp_adapter',
			],
		},
		null,
		2,
	);
	return { system, user };
}

// =============================================================================
// 解析 + 范围护栏
// =============================================================================

export function parsePlannerDecision(
	content: string,
	input: PlannerInput,
): { decision: Omit<PlannerDecision, 'fromLlm' | 'provider' | 'model'>; parseError: boolean } {
	const fallback = {
		decision: {
			mode: null as 'site' | 'full' | null,
			options: {} as PlannerDecision['options'],
			deepScanLevel: 'none' as PlannerDecision['deepScanLevel'],
			reasoning: '',
			guardNotes: [] as string[],
		},
		parseError: true,
	};
	let obj: {
		mode?: unknown;
		options?: unknown;
		deepScanLevel?: unknown;
		reasoning?: unknown;
	};
	try {
		obj = JSON.parse(extractJsonContent(content));
	} catch {
		return fallback;
	}

	const guardNotes: string[] = [];

	// ---- mode（范围护栏：URL 种子只能 site）----
	let mode: 'site' | 'full' | null = null;
	if (obj.mode === 'site' || obj.mode === 'full') {
		if (input.seed.seedType === 'url' && obj.mode === 'full') {
			guardNotes.push('URL 种子建议 full 被护栏拦截 → site（单站模式不可放大）');
			mode = 'site';
		} else {
			mode = obj.mode;
		}
	}

	// ---- options ----
	const opts =
		obj.options && typeof obj.options === 'object' ? (obj.options as Record<string, unknown>) : {};
	const options: PlannerDecision['options'] = {};
	if (typeof opts.skipNmap === 'boolean') options.skipNmap = opts.skipNmap;
	if (typeof opts.skipOneForAll === 'boolean') options.skipOneForAll = opts.skipOneForAll;
	if (typeof opts.maxSubdomains === 'number' && Number.isFinite(opts.maxSubdomains)) {
		const clamped = Math.max(50, Math.min(2000, Math.round(opts.maxSubdomains)));
		if (clamped !== opts.maxSubdomains) {
			guardNotes.push(`maxSubdomains ${opts.maxSubdomains} 越界 → clamp 到 ${clamped}`);
		}
		options.maxSubdomains = clamped;
	}
	if (typeof opts.ports === 'string' && /^[\d,\- ]+$/.test(opts.ports)) {
		options.ports = opts.ports.trim();
	}

	// ---- deepScanLevel ----
	let deepScanLevel: PlannerDecision['deepScanLevel'] = 'none';
	if (obj.deepScanLevel === 'l1' || obj.deepScanLevel === 'l2' || obj.deepScanLevel === 'l3') {
		deepScanLevel = obj.deepScanLevel;
	}

	return {
		decision: {
			mode,
			options,
			deepScanLevel,
			reasoning: typeof obj.reasoning === 'string' ? obj.reasoning.slice(0, 200) : '',
			guardNotes,
		},
		parseError: false,
	};
}

// =============================================================================
// 主入口
// =============================================================================

/**
 * 生成侦察策略（决策点 1）
 *
 * @returns 策略决策；失败/关闭时返回 null（调用方用默认策略）
 */
export async function planRecon(
	input: PlannerInput,
	opts: { forceRefresh?: boolean } = {},
): Promise<PlannerDecision | null> {
	const cfg = getConfig().llm;
	const provider = 'deepseek';
	const model = cfg.flashModel;

	// 1. 查缓存
	if (!opts.forceRefresh) {
		try {
			const cached = await getCached(input.seed.seedType, input.seed.valueNorm, provider, model);
			if (cached) {
				await auditLog({
					actor: `llm:${provider}`,
					action: 'agent_decision',
					target: input.seed.valueNorm,
					decision: 'info',
					reason: `planner cache hit: mode=${cached.mode ?? 'auto'} deep=${cached.deepScanLevel}`,
					meta: { model, decision: cached },
				});
				return cached;
			}
		} catch {
			// 缓存查失败不阻塞
		}
	}

	// 2. 拼 prompt 并调用
	const { system, user } = buildPrompt(input);
	let raw;
	let errorMsg: string | null = null;
	try {
		raw = await callDeepSeek(system, user, { model, maxTokens: 1200 });
	} catch (err) {
		errorMsg = err instanceof Error ? err.message : String(err);
	}

	if (!raw || !raw.choices?.[0]?.message?.content) {
		await auditLog({
			actor: `llm:${provider}`,
			action: 'agent_decision',
			target: input.seed.valueNorm,
			decision: 'fail',
			reason: `planner failed: ${errorMsg ?? 'empty response'}`,
			meta: { model },
		});
		return null;
	}

	// 3. 解析 + 护栏
	const { decision, parseError } = parsePlannerDecision(raw.choices[0].message.content, input);
	const result: PlannerDecision = {
		...decision,
		fromLlm: true,
		provider,
		model,
	};

	// 4. 审计 + 缓存
	await auditLog({
		actor: `llm:${provider}`,
		action: 'agent_decision',
		target: input.seed.valueNorm,
		decision: parseError ? 'deny' : 'allow',
		reason: `planner: mode=${result.mode ?? 'auto'} deep=${result.deepScanLevel}${result.guardNotes.length > 0 ? ` | 护栏: ${result.guardNotes.join('; ')}` : ''}`,
		meta: {
			model,
			decision: result,
			parseError,
			usage: raw.usage,
		},
	});
	try {
		await saveCache(input.seed.seedType, input.seed.valueNorm, provider, model, decision, raw);
	} catch {
		// 缓存写失败不阻塞
	}

	if (parseError) return null;
	return result;
}
