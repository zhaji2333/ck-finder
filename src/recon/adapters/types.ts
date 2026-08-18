/**
 * 适配器类型定义
 *
 * 工具适配层协议：
 *   ToolDefinition（声明） → ToolExecutor（执行） → ToolResult（结果）
 *
 * 解析器协议：
 *   每个 Parser 把工具原始输出（stdout/文件）转成结构化 ToolRecord[]
 */

/** 工具类别：被动（不触目标）/ 主动（直接请求目标） */
export type ToolMode = 'passive' | 'active';

/** 工具执行结果状态 */
export type ToolExecStatus = 'ok' | 'timeout' | 'failed' | 'canceled';

/** 工具执行的统一结果 */
export interface ToolResult<T = unknown> {
	/** 工具名 */
	tool: string;
	/** 状态 */
	status: ToolExecStatus;
	/** 退出码（null 表示被信号杀死） */
	exitCode: number | null;
	/** 执行时长（毫秒） */
	durationMs: number;
	/** 标准输出（已捕获，可能截断） */
	stdout: string;
	/** 标准错误（已捕获，可能截断） */
	stderr: string;
	/** 解析后的结构化记录（由 parser 产出） */
	records: T[];
	/** 错误信息（status != ok 时） */
	error?: string;
	/** 原始输出文件路径（如 jsonl/txt 落地文件，可选） */
	rawOutputPath?: string;
}

/** 工具执行参数 */
export interface ToolExecParams {
	/** 工具可执行文件路径或命令名（默认走 PATH 查找） */
	command: string;
	/** 命令行参数 */
	args: string[];
	/** 工作目录（默认 process.cwd()） */
	cwd?: string;
	/** 超时（毫秒，默认从 config 读） */
	timeoutMs?: number;
	/** 环境变量 */
	env?: Record<string, string>;
	/** stdin 输入（如通过管道传目标列表） */
	stdin?: string;
	/** 工具模式（被动/主动，影响限速） */
	mode?: ToolMode;
	/** 是否捕获 stdout 用于解析（默认 true） */
	captureStdout?: boolean;
	/** stdout 最大字节数（超出截断，防 OOM） */
	maxStdoutBytes?: number;
	/** 决策点3：高危动作审批标识（适配器显式声明；命中高危清单时走 LLM Judge） */
	judgeAction?: string;
}

/** 工具定义（声明式，用于注册表） */
export interface ToolDefinition {
	/** 工具名（唯一，如 subfinder/dnsx/nmap/httpx） */
	name: string;
	/** 类别 */
	mode: ToolMode;
	/** 描述 */
	description: string;
	/** 默认参数（可被调用方覆盖） */
	defaultArgs?: string[];
	/** 默认超时（毫秒） */
	defaultTimeoutMs?: number;
}

/** 输出解析器：把原始 stdout 转为结构化记录 */
export interface OutputParser<T = unknown> {
	/** 解析器名（通常等于工具名或工具+格式） */
	name: string;
	/** 输入格式：jsonl / json / plain */
	format: 'jsonl' | 'json' | 'plain';
	/** 解析函数 */
	parse(input: string): T[];
}

/** 工具执行错误 */
export class ToolExecError extends Error {
	constructor(
		message: string,
		public readonly tool: string,
		public readonly status: ToolExecStatus,
		public readonly exitCode: number | null,
		public readonly stderr?: string,
	) {
		super(message);
		this.name = 'ToolExecError';
	}
}
