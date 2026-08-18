/**
 * LLM 运行时：基于 pi-ai 的 createModels + 自定义 DeepSeek provider（Chat Completions）。
 *
 * M5.3 端点池：支持多 provider（CKFINDER_LLM_POOL）负载均衡 + 失败熔断。
 *   - 默认单端点：DEEPSEEK_BASE_URL / DEEPSEEK_API_KEY
 *   - 端点池：CKFINDER_LLM_POOL JSON 数组，每项 { name, baseUrl, apiKey, model, weight }
 *   - 失败熔断：provider 连续失败后冷却，切换到下一可用端点
 */
import {
	type Model,
	type MutableModels,
	createModels,
	createProvider,
} from '@earendil-works/pi-ai';
import { openAICompletionsApi } from '@earendil-works/pi-ai/api/openai-completions.lazy';
import { getConfig } from '../recon/config.js';

/** 注册模型（1M 上下文，模型 id = API 需要的名称） */
function buildModel(modelId: string, baseUrl: string): Model<'openai-completions'> {
	return {
		id: modelId,
		name: 'DeepSeek V4 Flash',
		api: 'openai-completions',
		provider: 'deepseek',
		baseUrl,
		reasoning: true,
		input: ['text'],
		cost: { input: 0.14, output: 0.28, cacheRead: 0.0028, cacheWrite: 0 },
		contextWindow: 1_000_000, // 用户 API：1M 上下文
		maxTokens: 384_000,
		compat: {
			supportsStore: false,
			supportsDeveloperRole: false,
			maxTokensField: 'max_tokens',
			requiresReasoningContentOnAssistantMessages: true,
			thinkingFormat: 'deepseek',
		},
		thinkingLevelMap: {
			minimal: null,
			low: 'low',
			medium: null,
			high: 'high',
			max: 'max',
		},
	};
}

/** 熔断状态（进程内） */
const providerCooldown = new Map<string, number>(); // providerId -> cooldownUntil timestamp
const providerFailCount = new Map<string, number>(); // providerId -> 连续失败次数

const FAIL_THRESHOLD = 3;
const COOLDOWN_MS = 60_000;

/** provider 是否可用（未熔断） */
export function isProviderAvailable(providerId: string): boolean {
	const until = providerCooldown.get(providerId);
	return !until || Date.now() > until;
}

/** 标记 provider 失败（连续失败达阈值则熔断） */
export function markProviderFailure(providerId: string): void {
	const n = (providerFailCount.get(providerId) ?? 0) + 1;
	providerFailCount.set(providerId, n);
	if (n >= FAIL_THRESHOLD) {
		providerCooldown.set(providerId, Date.now() + COOLDOWN_MS);
		providerFailCount.set(providerId, 0);
		console.warn(
			`[llm] provider ${providerId} 连续失败 ${FAIL_THRESHOLD} 次，熔断 ${COOLDOWN_MS / 1000}s`,
		);
	}
}

/** 标记 provider 成功（重置失败计数） */
export function markProviderSuccess(providerId: string): void {
	providerFailCount.set(providerId, 0);
}

/** 创建包含 DeepSeek provider(s) 的模型注册表（端点池 + 熔断）。 */
export function createDeepSeekModels(): MutableModels {
	const cfg = getConfig().llm;
	const models = createModels();

	// 端点列表：优先 CKFINDER_LLM_POOL，否则单端点
	const endpoints =
		getConfig().agent.llmPool.length > 0
			? getConfig().agent.llmPool.map((p) => ({
					name: p.name,
					baseUrl: p.baseUrl,
					apiKey: p.apiKey,
					model: p.model,
					weight: p.weight ?? 1,
				}))
				: [
						{
							name: 'deepseek',
							baseUrl: cfg.baseUrl,
							apiKey: cfg.apiKey,
							// 单端点模型 id 跟随配置（CKFINDER_MODEL > DEEPSEEK_FLASH_MODEL），
							// 使指挥台「设置」修改模型后即时生效（不再是硬编码 deepseek-v4-flash）。
							model:
								getConfig().agent.model ||
								cfg.flashModel ||
								'deepseek-v4-flash',
							weight: 1,
						},
					];

	for (const ep of endpoints) {
		const providerId = ep.name;
		models.setProvider(
			createProvider({
				id: providerId,
				name: ep.name,
				baseUrl: ep.baseUrl,
				auth: {
					apiKey: {
						name: `${ep.name} API key`,
						resolve: async () => {
							if (!ep.apiKey) return undefined;
							return { auth: { apiKey: ep.apiKey }, source: 'config' };
						},
					},
				},
				models: [buildModel(ep.model, ep.baseUrl)],
				api: openAICompletionsApi(),
			}),
		);
	}
	return models;
}

/** 解析可用模型：优先指定 id（跳过熔断 provider），回退到第一个可用端点。 */
export function resolveDeepSeekModel(
	models: MutableModels,
	preferredId: string,
): NonNullable<ReturnType<MutableModels['getModel']>> {
	// 端点池：按可用性选（跳过熔断的 provider）
	const providers = models.getProviders();
	for (const p of providers) {
		if (!isProviderAvailable(p.id)) continue;
		const m = models.getModel(p.id, preferredId);
		if (m) return m;
	}
	// 兜底：任意可用 provider 的第一个模型
	for (const p of providers) {
		if (!isProviderAvailable(p.id)) continue;
		const any = models.getModel(p.id, models.getModels(p.id)[0]?.id ?? '');
		if (any) return any;
	}
	throw new Error(
		'所有 LLM provider 均不可用（熔断或无模型）。请检查 .env 的 DEEPSEEK_* / CKFINDER_LLM_POOL',
	);
}
