/**
 * 工具注册中心：ck-finder 所有自定义工具汇总。
 *
 * M0：web_fetch（基础抓取）
 * M1（合并后）：+ 6 个 recon_* 消费工具（进程内调用本地收集引擎，只读）
 * M2 起：+ 验证工具（nuclei/sqlmap/http_req/...），全部过 Scope Gate 与审批门
 */
import type { AgentTool } from '@earendil-works/pi-agent-core';
import type { ReconProvider } from '../recon/provider.js';
import { createReconTools } from './recon.js';
import { webFetchTool } from './web_fetch.js';

/** 构建 ck-finder 完整工具集（依赖注入 ReconProvider，便于测试与隔离） */
export function buildTools(provider: ReconProvider | null): AgentTool[] {
	const tools: AgentTool[] = [webFetchTool];
	if (provider) {
		tools.push(...createReconTools(provider));
	}
	return tools;
}

/** 无收集引擎的默认工具集（M0 兼容 / doctor 用） */
export const ckFinderTools: AgentTool[] = [webFetchTool];

export { createReconTools } from './recon.js';
export { webFetchTool } from './web_fetch.js';
