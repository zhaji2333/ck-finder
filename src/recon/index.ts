/**
 * ck-recon 入口模块
 *
 * 双轨入口：
 * - SDK 库（import { createReconAgentSession } from 'ck-recon'）
 * - REST/MCP 服务（node dist/index.js，启动 HTTP 服务）
 *
 * 项目铁律：工具出数据，模型出决策；确定性流程不走 LLM；收集不做验证。
 */

export const VERSION = '0.1.0';

// 子模块按需导出（M1 阶段先放占位，后续里程碑逐步补充）
export * from './config.js';
