/**
 * 工具注册表
 *
 * 管理所有已注册的 ToolDefinition，供运行时查询、CLI 列表、Pi defineTool 注册使用。
 */

import type { ToolDefinition } from './types.js';

const _registry = new Map<string, ToolDefinition>();

export function registerTool(def: ToolDefinition): void {
	_registry.set(def.name, def);
}

export function getTool(name: string): ToolDefinition | undefined {
	return _registry.get(name);
}

export function listTools(): ToolDefinition[] {
	return Array.from(_registry.values());
}

export function clearRegistry(): void {
	_registry.clear();
}
