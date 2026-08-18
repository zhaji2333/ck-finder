/**
 * 子代理 Prompt 加载器（M5.5）
 *
 * 架构文档 §3：
 *   "subagent 机制（独立进程+隔离上下文），定义 recon-planner / classifier / source-auditor 子代理"
 *
 * 设计：
 *   - 3 个 prompt 文件（.md）作为子代理的系统提示词
 *   - 加载器从 src/agents/ 目录读取 .md 文件
 *   - 运行时缓存（同一进程只读一次文件）
 *   - 提供 buildAgentMessages() 拼装 [system, user] 消息对
 *
 * 使用：
 *   import { loadAgentPrompt, buildAgentMessages } from './agents/loader.js';
 *   const systemPrompt = await loadAgentPrompt('recon-planner');
 *   const messages = buildAgentMessages('recon-planner', userInputJson);
 *
 * MVP 阶段不直接对接 Pi 的 subagent 进程机制，仅提供 prompt 加载能力。
 * 后续可扩展为：
 *   - 通过 Pi 的 createAgentSession() 启动独立子代理进程
 *   - 通过 MCP Server 暴露 invoke_agent 工具
 */

import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// =============================================================================
// 类型定义
// =============================================================================

export type AgentName = 'recon-planner' | 'classifier' | 'source-auditor';

export interface AgentMessage {
	role: 'system' | 'user';
	content: string;
}

export interface AgentDefinition {
	name: AgentName;
	description: string;
	/** 系统 prompt 文件路径（绝对） */
	promptPath: string;
	/** 推荐模型（flash=便宜/pro=强） */
	model: 'flash' | 'pro';
}

// =============================================================================
// Agent 注册表
// =============================================================================

const AGENTS: Record<AgentName, AgentDefinition> = {
	'recon-planner': {
		name: 'recon-planner',
		description: '侦察规划子代理：根据种子规划信息收集路径',
		promptPath: 'recon-planner.md',
		model: 'flash',
	},
	classifier: {
		name: 'classifier',
		description: '资产分类子代理：判断 webapp 角色和价值评分',
		promptPath: 'classifier.md',
		model: 'flash',
	},
	'source-auditor': {
		name: 'source-auditor',
		description: '源码审计子代理：审计还原后的源码，提取渗透线索',
		promptPath: 'source-auditor.md',
		model: 'pro',
	},
};

// =============================================================================
// Prompt 加载
// =============================================================================

const _promptCache = new Map<AgentName, string>();

/**
 * 获取 agents 目录的绝对路径
 *
 * 兼容两种运行模式：
 *   - tsx 源码运行：src/agents/loader.ts → 同目录的 .md 文件
 *   - 编译后 dist 运行：dist/agents/loader.js → src/agents/ 的 .md 文件
 *     （通过相对路径回溯到 src/agents）
 */
function getAgentsDir(): string {
	if (import.meta.url) {
		const currentFile = fileURLToPath(import.meta.url);
		const currentDir = dirname(currentFile);
		// 如果当前在 dist/agents/ 下，回溯到 src/agents/
		if (currentDir.includes('/dist/')) {
			return resolve(currentDir, '../../src/agents');
		}
		return currentDir;
	}
	// 兜底：用 process.cwd() 推断
	return resolve(process.cwd(), 'src/agents');
}

/**
 * 加载子代理的 prompt
 *
 * @param name 子代理名
 * @returns 系统 prompt 字符串
 */
export async function loadAgentPrompt(name: AgentName): Promise<string> {
	const cached = _promptCache.get(name);
	if (cached) return cached;

	const def = AGENTS[name];
	if (!def) {
		throw new Error(`unknown agent: ${name}`);
	}

	const agentsDir = getAgentsDir();
	const fullPath = join(agentsDir, def.promptPath);

	try {
		const content = await readFile(fullPath, 'utf8');
		_promptCache.set(name, content);
		return content;
	} catch (err) {
		throw new Error(
			`failed to load agent prompt ${name} from ${fullPath}: ${err instanceof Error ? err.message : err}`,
		);
	}
}

/**
 * 拼装子代理消息对（[system, user]）
 *
 * @param name 子代理名
 * @param userInput 用户输入（对象，会被 JSON.stringify）
 * @returns OpenAI 兼容的消息数组
 */
export async function buildAgentMessages(
	name: AgentName,
	userInput: unknown,
): Promise<AgentMessage[]> {
	const systemPrompt = await loadAgentPrompt(name);
	const userContent =
		typeof userInput === 'string' ? userInput : JSON.stringify(userInput, null, 2);

	return [
		{ role: 'system', content: systemPrompt },
		{ role: 'user', content: userContent },
	];
}

// =============================================================================
// Agent 元信息查询
// =============================================================================

/**
 * 列出所有可用子代理
 */
export function listAgents(): AgentDefinition[] {
	return Object.values(AGENTS);
}

/**
 * 获取子代理定义
 */
export function getAgentDefinition(name: AgentName): AgentDefinition {
	const def = AGENTS[name];
	if (!def) {
		throw new Error(`unknown agent: ${name}`);
	}
	return def;
}

/**
 * 清除 prompt 缓存（测试用）
 */
export function clearAgentPromptCache(): void {
	_promptCache.clear();
}
