/**
 * Agent 会话封装：基于 pi-agent-core 的 Agent 类。
 * M0 目标：跑通「目标 + 授权范围 + 工具集」的 Agent 循环，并落地审计日志。
 * 合并后：recon_* 工具进程内调用本地收集引擎（ReconProvider），不再走 HTTP。
 * M2 起在 beforeToolCall 中接入 Scope Gate 与危险动作审批。
 */
import { type WriteStream, createWriteStream } from 'node:fs';
import { Agent, type AgentEvent } from '@earendil-works/pi-agent-core';
import { createDeepSeekModels, resolveDeepSeekModel } from '../llm/provider.js';
import type { ReconProvider } from '../recon/provider.js';
import { buildTools } from '../tools/index.js';

export interface RunSessionOptions {
	/** 工作目录（agent 的 cwd，工具相对路径基于此） */
	cwd: string;
	/** 首选模型 id（如 deepseek-chat） */
	modelId: string;
	/** 授权范围（域名/IP/CIDR），M2 起接入 Scope Gate 强制校验 */
	scope: string[];
	/** 审计输出路径（JSONL，每次工具调用一行） */
	auditLogPath?: string;
	/** 收集引擎数据通道（合并后：进程内 ReconProvider）；缺省则不注册 recon 工具 */
	provider?: ReconProvider | null;
}

/** 构造系统提示词：声明角色 + 授权边界铁律 + 数据源说明。 */
function buildSystemPrompt(scope: string[], hasRecon: boolean): string {
	const scopeText =
		scope.length > 0
			? scope.map((s) => `  - ${s}`).join('\n')
			: '  - (未设置，仅允许对明确授权的目标操作)';
	const reconText = hasRecon
		? '信息收集数据由本地收集引擎提供（recon_* 只读工具，已入库的元数据，不会对目标发起新请求）。查询资产先用 recon_assets 按评分挑目标，再 recon_asset_detail 吃透单资产。'
		: '';
	return `你是 ck-finder，一个受控的渗透测试 / SRC 侦察 Agent。

铁律：
1. 只对授权范围内的目标操作。授权范围：
${scopeText}
2. 工具出数据，模型出决策。先收集信息，再下结论。
3. 不执行任何攻击性/破坏性动作（爆破、上传 webshell、删改数据等一律禁止）。
4. 大输出（>64KB）不要逐字复述，用摘要。
5. 每一步工具调用都会审计留痕。
6. 不确定时，明确说明不确定，不要编造。
${reconText}`;
}

/**
 * 创建一次 ck-finder Agent 运行。
 * 返回 agent（可直接 prompt / steer / subscribe）。
 */
export async function createRunSession(options: RunSessionOptions) {
	const models = createDeepSeekModels();
	const model = resolveDeepSeekModel(models, options.modelId);

	// 合并后：进程内 ReconProvider（本地收集引擎），构建含 recon_* 的工具集
	const provider = options.provider ?? null;
	const tools = buildTools(provider);

	const agent = new Agent({
		initialState: {
			systemPrompt: buildSystemPrompt(options.scope, provider !== null),
			model,
			thinkingLevel: 'medium',
			tools,
		},
		streamFn: models.streamSimple.bind(models),
		beforeToolCall: async () => {
			// M0/M1: 全放行（web_fetch 只读 + recon_* 只读消费）。
			// M2 在此接入 Scope Gate + 审批（recon 工具自身无越权面，验证工具需 Gate）。
			return undefined;
		},
	});

	// 审计订阅：所有工具调用写 JSONL
	let auditStream: WriteStream | undefined;
	if (options.auditLogPath) {
		auditStream = createWriteStream(options.auditLogPath, { flags: 'a' });
	}
	agent.subscribe((event: AgentEvent) => {
		if (event.type === 'tool_execution_start') {
			const line = JSON.stringify({
				ts: new Date().toISOString(),
				type: 'tool_call',
				tool: event.toolName,
				args: event.args,
				callId: event.toolCallId,
			});
			auditStream?.write(`${line}\n`);
			console.log(`[tool] ${event.toolName} ${JSON.stringify(event.args)}`);
		} else if (event.type === 'tool_execution_end') {
			const err = event.isError ? ' (error)' : '';
			console.log(`[tool-done] ${event.toolName}${err}`);
		} else if (event.type === 'agent_end') {
			console.log('[agent] run finished');
		}
	});

	return {
		agent,
		model,
		close: () => {
			auditStream?.end();
		},
	};
}
