/**
 * 探索图工具（M2）：planner / worker 的终态工具
 *
 * - exploration_submit（planner）：把意图写图并加入 frontier（终态，一轮只产意图）
 * - graph_store_fact（worker）：把确定性发现落图（summary 摘要进上下文，raw_json 落盘）
 * - task_result_submit（worker）：标记意图完成 + 摘要（终态）
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';
import type { ExplorationStore } from '../graph/store.js';

// ---------------------------------------------------------------------------
// exploration_submit —— planner 终态工具
// ---------------------------------------------------------------------------

const explorationSubmitParams = Type.Object({
	seedId: Type.String({ description: '收集任务（种子）ID，UUID' }),
	intentType: Type.String({
		description:
			'意图类型：recon_js（JS/接口/密钥分析）/ recon_endpoint（端点枚举）/ recon_asset（资产深挖）/ verify（验证，M3 起）/ other',
	}),
	description: Type.String({
		description: '意图描述（给 worker 的任务说明，含目标 URL、要做什么、关注什么）',
	}),
	assetId: Type.Optional(
		Type.String({
			description: '锚点资产 ID（webapp 的 assetId，来自 recon_assets/recon_asset_detail）',
		}),
	),
	priority: Type.Optional(
		Type.Integer({ description: '优先级 1-9（1 最高），默认 5', minimum: 1, maximum: 9 }),
	),
});

export interface ExplorationSubmitDetails {
	intentId: string;
}

/** 创建 planner 意图工具（依赖 store + scope 校验） */
export function createExplorationSubmit(
	store: ExplorationStore,
	scope: string[],
): AgentTool<typeof explorationSubmitParams, ExplorationSubmitDetails> {
	return {
		name: 'exploration_submit',
		label: '提交探索意图',
		description:
			'【终态工具，每轮只能调用一次】把你规划的一条侦察意图写入探索图。调用后本轮规划结束。意图会被分派给 worker 执行。意图描述要具体：目标 URL/资产、要确认的问题、关注点。',
		parameters: explorationSubmitParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<ExplorationSubmitDetails>> => {
			// 锚点资产必须存在（防锚到不存在的资产）
			if (params.assetId) {
				const exists = await store.assetExists(params.assetId);
				if (!exists) {
					throw new Error(`锚点资产不存在: ${params.assetId}`);
				}
			}
			const intent = await store.createIntent({
				seedId: params.seedId,
				intentType: params.intentType,
				description: params.description,
				priority: params.priority,
				assetId: params.assetId,
				scopeAnchor: scope.join(',') || params.seedId,
				depth: 0,
			});
			await store.logActivity(
				params.seedId,
				'intent_created',
				`意图创建: [${intent.intentType}] ${intent.description}`,
				{ intentId: intent.id },
			);
			return {
				content: [
					{
						type: 'text',
						text: `意图已提交: ${intent.id}\n类型: ${intent.intentType}\n描述: ${intent.description}\n状态: pending（将由 worker 执行）`,
					},
				],
				details: { intentId: intent.id },
				terminate: true,
			};
		},
	};
}

// ---------------------------------------------------------------------------
// graph_store_fact —— worker 落图
// ---------------------------------------------------------------------------

const storeFactParams = Type.Object({
	intentId: Type.String({ description: '当前意图 ID' }),
	seedId: Type.String({ description: '收集任务（种子）ID' }),
	factType: Type.String({
		description:
			'事实类型：tech（技术栈）/ endpoint（端点）/ js_api（JS接口）/ param（参数）/ secret（密钥线索）/ info（其他情报）',
	}),
	summary: Type.String({ description: '事实摘要（150 字内，Agent 后续可直接引用）' }),
	assetId: Type.Optional(Type.String({ description: '关联资产 ID（可选）' })),
	rawJson: Type.Optional(Type.String({ description: '原始数据 JSON 字符串（落盘备查，可不填）' })),
});

export interface StoreFactDetails {
	factId: string;
}

export function createStoreFact(
	store: ExplorationStore,
): AgentTool<typeof storeFactParams, StoreFactDetails> {
	return {
		name: 'graph_store_fact',
		label: '存入探索事实',
		description:
			'把确认的侦察发现写入探索图（确定性数据，带资产锚点）。每次发现后调用，形成跨意图共享的知识。summary 要精炼。',
		parameters: storeFactParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<StoreFactDetails>> => {
			let raw: unknown;
			try {
				raw = params.rawJson ? JSON.parse(params.rawJson) : undefined;
			} catch {
				throw new Error('rawJson 不是合法 JSON');
			}
			const fact = await store.insertFact({
				intentId: params.intentId,
				seedId: params.seedId,
				assetId: params.assetId,
				factType: params.factType,
				summary: params.summary,
				rawJson: raw,
			});
			return {
				content: [{ type: 'text', text: `事实已存储: ${fact.id} (${fact.factType})` }],
				details: { factId: fact.id },
			};
		},
	};
}

// ---------------------------------------------------------------------------
// task_result_submit —— worker 终态工具
// ---------------------------------------------------------------------------

const taskResultParams = Type.Object({
	intentId: Type.String({ description: '当前意图 ID' }),
	seedId: Type.String({ description: '收集任务（种子）ID' }),
	summary: Type.String({ description: '执行结果摘要（做了什么、发现了什么、有无高价值线索）' }),
	status: Type.Optional(
		Type.Union([Type.Literal('done'), Type.Literal('failed')], {
			description: '执行结果，默认 done',
		}),
	),
	deepenLead: Type.Optional(
		Type.String({
			description:
				'深挖交棒：找到突破口但没打穿时，用一句话给出下一轮深挖方向（触发系统自动重派定向深挖，最多 2 次）',
		}),
	),
});

export interface TaskResultDetails {
	intentId: string;
	status: string;
}

export function createTaskResultSubmit(
	store: ExplorationStore,
): AgentTool<typeof taskResultParams, TaskResultDetails> {
	return {
		name: 'task_result_submit',
		label: '提交任务结果',
		description:
			'【终态工具，每轮只能调用一次】标记当前意图执行完成并提交结果摘要。调用后本轮 worker 结束。',
		parameters: taskResultParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<TaskResultDetails>> => {
			const status = params.status ?? 'done';
			await store.updateIntentStatus(params.intentId, status, params.summary);
			const meta: Record<string, unknown> = {
				intentId: params.intentId,
				summary: params.summary.slice(0, 200),
			};
			if (params.deepenLead) {
				meta.deepen_lead = params.deepenLead;
			}
			await store.logActivity(params.seedId, 'intent_done', `意图完成: ${status}`, meta);
			return {
				content: [
					{
						type: 'text',
						text: `意图 ${params.intentId} 已标记为 ${status}${
							params.deepenLead ? `\n深挖交棒: ${params.deepenLead}` : ''
						}`,
					},
				],
				details: { intentId: params.intentId, status },
				terminate: true,
			};
		},
	};
}
