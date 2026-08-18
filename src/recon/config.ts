/**
 * ck-recon 配置层
 *
 * 统一从环境变量读取配置，启动时一次性加载、校验。
 * 业务代码只读 Config 单例，不再散落 process.env 调用。
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function loadEnvFile(path: string): Record<string, string> {
	try {
		const content = readFileSync(path, 'utf8');
		const env: Record<string, string> = {};
		for (const line of content.split('\n')) {
			const trimmed = line.trim();
			if (!trimmed || trimmed.startsWith('#')) continue;
			const eqIdx = trimmed.indexOf('=');
			if (eqIdx === -1) continue;
			const key = trimmed.slice(0, eqIdx).trim();
			let value = trimmed.slice(eqIdx + 1).trim();
			// 去除可选引号
			if (
				(value.startsWith('"') && value.endsWith('"')) ||
				(value.startsWith("'") && value.endsWith("'"))
			) {
				value = value.slice(1, -1);
			}
			env[key] = value;
		}
		return env;
	} catch {
		return {};
	}
}

// 启动时加载 .env（不依赖第三方库，避免 dotenv 依赖）
const fileEnv = loadEnvFile(resolve(process.cwd(), '.env'));
for (const [k, v] of Object.entries(fileEnv)) {
	if (process.env[k] === undefined) {
		process.env[k] = v;
	}
}

function optional(key: string, fallback: string): string {
	return process.env[key] ?? fallback;
}

function int(key: string, fallback: number): number {
	const v = process.env[key];
	if (v === undefined || v === '') return fallback;
	const n = Number.parseInt(v, 10);
	if (Number.isNaN(n)) throw new Error(`[config] env ${key} not an integer: ${v}`);
	return n;
}

function bool(key: string, fallback: boolean): boolean {
	const v = process.env[key];
	if (v === undefined) return fallback;
	return v === 'true' || v === '1' || v === 'yes';
}

export interface DbConfig {
	host: string;
	port: number;
	user: string;
	password: string;
	database: string;
	poolMax: number;
}

export interface RedisConfig {
	host: string;
	port: number;
	db: number;
}

export interface LlmConfig {
	apiKey: string;
	baseUrl: string;
	flashModel: string;
	proModel: string;
	/** 技术栈识别 LLM 兜底（正则识别不到时调 flash，默认开） */
	techDetectEnabled: boolean;
	/** JS 接口提取 LLM 增强（正则命中少时调 flash，默认开） */
	jsExtractEnabled: boolean;
	/** 每个 webapp JS LLM 提取的文件预算（默认 5） */
	jsExtractPerWebapp: number;
	/** 决策点1：侦察策略规划（种子进来时 LLM 规划收集策略，默认开） */
	plannerEnabled: boolean;
	/** 决策点2：深挖任务选择 LLM 兜底（规则画像信息不足时，默认开） */
	taskSelectEnabled: boolean;
	/** 决策点3：高危动作 LLM 审批（适配器显式声明的高危调用，默认开） */
	judgeEnabled: boolean;
	/** 决策点4：停止/继续判断（扫描结果不足以判断价值时 LLM 决定是否追加深挖，默认开） */
	stopJudgeEnabled: boolean;
	/** LLM 分析驱动 Phase1：页面语义分类/攻击面地图/架构级分析（默认开） */
	analysisEnabled: boolean;
	/** 评分后自动深挖：L2/L3 评分完成后自动触发 deep-scan（默认开） */
	autoDeepScanEnabled: boolean;
	/** 自动深挖的最低任务级别（L2/L3，默认 L2） */
	autoDeepScanMinLevel: 'L1' | 'L2' | 'L3';
	/** LLM 评分复核：规则分达阈值的高分资产必须 LLM 认定（默认开） */
	scoreReviewEnabled: boolean;
	/** 评分复核触发阈值（默认 70） */
	scoreReviewThreshold: number;
}

export interface ToolExecConfig {
	timeoutSec: number;
	concurrency: number;
	activeRps: number;
	/** 工具二进制目录（gau/katana/waybackurls/wafw00f 等不在 PATH 时使用绝对路径） */
	binDir: string;
	/** dirsearch 脚本完整路径（如 /path/to/dirsearch.py） */
	dirsearchPath: string;
	/** dirsearch 用的 Python 解释器（默认 python3） */
	dirsearchPython: string;
	/** ParamSpider 项目根目录（含 paramspider/ 包，git clone 得到） */
	paramspiderDir: string;
	/** ParamSpider 用的 Python 解释器（默认 python3） */
	paramspiderPython: string;
	/** ParamSpider 代理（如 http://127.0.0.1:7897，访问 web.archive.org 用） */
	paramspiderProxy: string;
	/** 指纹库 finger.yaml 路径（FINGER_YAML，默认项目内 tools/finger-lib/finger.yaml） */
	fingerYaml: string;
}

export interface ScopeGateConfig {
	enabled: boolean;
	allowed: readonly string[];
}

export interface SourcesConfig {
	dir: string;
	maxSizeMb: number;
}

export interface ServerConfig {
	restPort: number;
	mcpPort: number;
	logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export interface FofaConfig {
	mcpCmd: string;
	mcpArgs: string;
	mcpCwd: string;
	email: string;
	key: string;
	/** 扫描流程中启用 FOFA 资产补充（默认开，配置了 email+key 即生效） */
	enabled: boolean;
}

export interface IcpConfig {
	url: string;
}

export interface GithubConfig {
	/** GitHub Personal Access Token（可选，无 token 限速 10 req/min，有 30 req/min） */
	token: string;
	/** 搜索结果数量上限（默认 50） */
	maxResults: number;
}

export interface OneForAllConfig {
	/** OneForAll 项目根目录（含 oneforall.py） */
	dir: string;
	/** Python 解释器路径（默认 python3.11） */
	python: string;
	/** 是否启用爆破模块（默认 true） */
	brute: boolean;
	/** 是否启用 HTTP 请求探测（默认 false，我们用 httpx 单独做） */
	httpProbe: boolean;
	/** 是否启用 CDN 检查（默认 false，OneForAll 自带 CDN 库较老） */
	cdnCheck: boolean;
	/** 是否启用子域接管检查（默认 false，慢） */
	takeover: boolean;
	/** 爆破并发数（默认 2000） */
	bruteConcurrency: number;
}

/** ck-finder Agent 编排层配置 */
export interface AgentConfig {
	/** Agent 执行模型 id（默认 deepseek-chat，对应 CKFINDER_MODEL） */
	model: string;
	/** 复杂判断模型 id（planner/reviewer 用，对应 CKFINDER_MODEL_PRO） */
	modelPro: string;
	/** LLM 端点池（CKFINDER_LLM_POOL，JSON 数组）——多 provider 负载均衡 + 失败熔断 */
	llmPool: ReadonlyArray<{
		name: string;
		baseUrl: string;
		apiKey: string;
		model: string;
		weight?: number;
	}>;
	/** 授权范围：逗号分隔的 domain / *.domain / ip / cidr（CKFINDER_SCOPE） */
	scope: readonly string[];
	/** 挖洞排除域名（CKFINDER_HUNT_EXCLUDE，逗号分隔）——防止误挖非本次任务的历史资产（如 lenovomm.com） */
	huntExclude: readonly string[];
	/** 登录凭据（CKFINDER_HUNT_CREDENTIALS，JSON）——按 host:port 注入登录态给挖洞 worker */
	huntCredentials: Readonly<
		Record<
			string,
			{ cookie?: string; username?: string; password?: string; authorization?: string }
		>
	>;
	/** 日志级别（CKFINDER_LOG_LEVEL） */
	logLevel: 'debug' | 'info' | 'warn' | 'error';
}

export interface Config {
	llm: LlmConfig;
	db: DbConfig;
	redis: RedisConfig;
	tool: ToolExecConfig;
	scopeGate: ScopeGateConfig;
	sources: SourcesConfig;
	server: ServerConfig;
	fofa: FofaConfig;
	icp: IcpConfig;
	github: GithubConfig;
	oneforall: OneForAllConfig;
	agent: AgentConfig;
}

function buildConfig(): Config {
	return {
		llm: {
			// 合并后：key 改为可选（LLM 环节全部 try/catch 可降级为纯规则）。
			// 未配置时收集管道降级运行，doctor/recon 自检不被 key 阻塞。
			apiKey: optional('DEEPSEEK_API_KEY', ''),
			baseUrl: optional('DEEPSEEK_BASE_URL', 'https://api.deepseek.com'),
			flashModel: optional('DEEPSEEK_FLASH_MODEL', 'deepseek-chat'),
			proModel: optional('DEEPSEEK_PRO_MODEL', 'deepseek-reasoner'),
			techDetectEnabled: optional('LLM_TECH_DETECT_ENABLED', 'true') === 'true',
			jsExtractEnabled: optional('LLM_JS_EXTRACT_ENABLED', 'true') === 'true',
			jsExtractPerWebapp: int('LLM_JS_EXTRACT_PER_WEBAPP', 5),
			plannerEnabled: optional('LLM_PLANNER_ENABLED', 'true') === 'true',
			taskSelectEnabled: optional('LLM_TASK_SELECT_ENABLED', 'true') === 'true',
			judgeEnabled: optional('LLM_JUDGE_ENABLED', 'true') === 'true',
			stopJudgeEnabled: optional('LLM_STOP_JUDGE_ENABLED', 'true') === 'true',
			analysisEnabled: optional('LLM_ANALYSIS_ENABLED', 'true') === 'true',
			autoDeepScanEnabled: optional('AUTO_DEEP_SCAN_ENABLED', 'true') === 'true',
			autoDeepScanMinLevel: optional('AUTO_DEEP_SCAN_MIN_LEVEL', 'L2') as 'L1' | 'L2' | 'L3',
			scoreReviewEnabled: optional('LLM_SCORE_REVIEW_ENABLED', 'true') === 'true',
			scoreReviewThreshold: int('LLM_SCORE_REVIEW_THRESHOLD', 70),
		},
		db: {
			host: optional('PG_HOST', '127.0.0.1'),
			port: int('PG_PORT', 5432),
			user: optional('PG_USER', 'ckrecon'),
			password: optional('PG_PASSWORD', 'ckrecon_dev'),
			database: optional('PG_DB', 'ckrecon'),
			poolMax: int('PG_POOL_MAX', 10),
		},
		redis: {
			host: optional('REDIS_HOST', '127.0.0.1'),
			port: int('REDIS_PORT', 6379),
			db: int('REDIS_DB', 0),
		},
		tool: {
			timeoutSec: int('TOOL_TIMEOUT_SEC', 600),
			concurrency: int('TOOL_CONCURRENCY', 4),
			activeRps: int('ACTIVE_RPS', 2),
			binDir: optional('TOOLS_BIN_DIR', ''),
			dirsearchPath: optional('DIRSEARCH_PATH', ''),
			dirsearchPython: optional('DIRSEARCH_PYTHON', 'python3'),
			paramspiderDir: optional('PARAMSPIDER_DIR', ''),
			paramspiderPython: optional('PARAMSPIDER_PYTHON', 'python3'),
			paramspiderProxy: optional('PARAMSPIDER_PROXY', ''),
			fingerYaml: optional('FINGER_YAML', ''),
		},
		scopeGate: {
			enabled: bool('SCOPE_GATE_ENABLED', false),
			allowed: optional('SCOPE_ALLOWED', '')
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean),
		},
		sources: {
			dir: optional('SOURCES_DIR', './sources'),
			maxSizeMb: int('SOURCE_MAX_SIZE_MB', 500),
		},
		server: {
			restPort: int('REST_PORT', 8787),
			mcpPort: int('MCP_PORT', 8788),
			logLevel: optional('LOG_LEVEL', 'info') as ServerConfig['logLevel'],
		},
		fofa: {
			mcpCmd: optional('FOFA_MCP_CMD', 'python'),
			mcpArgs: optional('FOFA_MCP_ARGS', 'mcp_server.py'),
			mcpCwd: optional('FOFA_MCP_CWD', ''),
			email: optional('FOFA_EMAIL', ''),
			key: optional('FOFA_KEY', ''),
			enabled: optional('FOFA_ENABLED', 'true') === 'true',
		},
		icp: {
			url: optional('ICP_QUERY_URL', 'http://127.0.0.1:16181'),
		},
		github: {
			token: optional('GITHUB_TOKEN', ''),
			maxResults: int('GITHUB_MAX_RESULTS', 50),
		},
		oneforall: {
			dir: optional('ONEFORALL_DIR', '/Users/apple/Desktop/武器库/开发/Ck-recon/tools/OneForAll'),
			python: optional('ONEFORALL_PYTHON', ''),
			brute: bool('ONEFORALL_BRUTE', true),
			httpProbe: bool('ONEFORALL_HTTP_PROBE', false),
			cdnCheck: bool('ONEFORALL_CDN_CHECK', false),
			takeover: bool('ONEFORALL_TAKEOVER', false),
			bruteConcurrency: int('ONEFORALL_BRUTE_CONCURRENCY', 2000),
		},
		agent: {
			model: optional('CKFINDER_MODEL', 'deepseek-v4-flash'),
			modelPro: optional('CKFINDER_MODEL_PRO', ''),
			scope: optional('CKFINDER_SCOPE', '')
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean),
			huntExclude: optional('CKFINDER_HUNT_EXCLUDE', '')
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean),
			huntCredentials: parseCredentials(process.env.CKFINDER_HUNT_CREDENTIALS ?? ''),
			llmPool: parseLlmPool(process.env.CKFINDER_LLM_POOL ?? ''),
			logLevel: optional('CKFINDER_LOG_LEVEL', 'info') as AgentConfig['logLevel'],
		},
	};
}

let _config: Config | null = null;

export function getConfig(): Config {
	if (!_config) {
		_config = buildConfig();
	}
	return _config;
}

/** 测试用：重置配置缓存 */
export function resetConfigForTest(): void {
	reloadConfig();
}

/** 运行时重载配置缓存（指挥台修改 .env 后调用，使新配置即时生效，无需重启） */
export function reloadConfig(): void {
	_config = null;
}

/** 指挥台配置字段白名单（可在 Web 界面安全编辑的 env 键 + 展示元数据） */
export interface EditableConfigField {
	key: string;
	label: string;
	group: 'llm' | 'agent' | 'scope';
	type: 'text' | 'password' | 'json' | 'boolean';
	secret?: boolean;
	placeholder?: string;
	help?: string;
}

export const EDITABLE_CONFIG_FIELDS: readonly EditableConfigField[] = [
	{
		key: 'DEEPSEEK_API_KEY',
		label: 'LLM API Key',
		group: 'llm',
		type: 'password',
		secret: true,
		help: 'DeepSeek / OpenAI 兼容端点密钥（如 sk-...）',
	},
	{
		key: 'DEEPSEEK_BASE_URL',
		label: 'LLM Base URL',
		group: 'llm',
		type: 'text',
		placeholder: 'https://api.deepseek.com/v1',
		help: 'OpenAI 兼容端点地址',
	},
	{
		key: 'CKFINDER_MODEL',
		label: '执行模型',
		group: 'llm',
		type: 'text',
		placeholder: 'deepseek-v4-flash',
		help: 'worker 执行模型 id（Agent 挖洞用）',
	},
	{
		key: 'CKFINDER_MODEL_PRO',
		label: '复杂判断模型',
		group: 'llm',
		type: 'text',
		placeholder: 'deepseek-v4-flash',
		help: 'planner/reviewer 用，留空则与执行模型相同',
	},
	{
		key: 'DEEPSEEK_FLASH_MODEL',
		label: 'Flash 模型',
		group: 'llm',
		type: 'text',
		placeholder: 'deepseek-chat',
		help: '快速/技术栈识别等轻量调用模型',
	},
	{
		key: 'DEEPSEEK_PRO_MODEL',
		label: 'Pro 模型',
		group: 'llm',
		type: 'text',
		placeholder: 'deepseek-reasoner',
		help: '复杂推理模型',
	},
	{
		key: 'CKFINDER_LLM_POOL',
		label: 'LLM 端点池',
		group: 'llm',
		type: 'json',
		placeholder: '[{"name":"a","baseUrl":"...","apiKey":"...","model":"...","weight":1}]',
		help: '多 provider 负载均衡 + 熔断，留空则用单端点（BASE_URL/API_KEY）',
	},
	{
		key: 'CKFINDER_SCOPE',
		label: '授权范围',
		group: 'scope',
		type: 'text',
		placeholder: '192.0.2.10, *.example.com',
		help: '逗号分隔：域名 / *.域名 / IP / CIDR',
	},
	{
		key: 'CKFINDER_HUNT_EXCLUDE',
		label: '挖洞排除',
		group: 'scope',
		type: 'text',
		placeholder: 'lenovomm.com',
		help: '逗号分隔，防止误挖非本次任务的历史资产',
	},
	{
		key: 'CKFINDER_HUNT_CREDENTIALS',
		label: '登录凭据',
		group: 'scope',
		type: 'json',
		placeholder: '{"host:port":{"username":"admin","password":"123456"}}',
		help: '按 host:port 注入登录态给挖洞 worker（cookie / username+password / authorization）',
	},
	{
		key: 'SCOPE_GATE_ENABLED',
		label: 'Scope Gate',
		group: 'scope',
		type: 'boolean',
		help: '强制范围校验（生产建议开启）',
	},
	{
		key: 'SCOPE_ALLOWED',
		label: 'Scope 允许列表',
		group: 'scope',
		type: 'text',
		placeholder: '192.0.2.10',
		help: 'Scope Gate 允许的域名/IP/CIDR（逗号分隔）',
	},
];

/** 解析登录凭据 JSON（CKFINDER_HUNT_CREDENTIALS：{"host:port": {"cookie": "..."}} 或 {"host:port": {"username":"admin","password":"123456"}}） */
function parseCredentials(
	raw: string,
): Record<
	string,
	{ cookie?: string; username?: string; password?: string; authorization?: string }
> {
	if (!raw.trim()) return {};
	try {
		const parsed = JSON.parse(raw) as Record<
			string,
			{ cookie?: string; username?: string; password?: string; authorization?: string }
		>;
		return parsed;
	} catch {
		console.warn('[config] CKFINDER_HUNT_CREDENTIALS JSON 解析失败，凭据未生效');
		return {};
	}
}

/** 解析 LLM 端点池 JSON（CKFINDER_LLM_POOL：[{"name":"a","baseUrl":"...","apiKey":"...","model":"...","weight":1}]） */
function parseLlmPool(
	raw: string,
): Array<{ name: string; baseUrl: string; apiKey: string; model: string; weight?: number }> {
	if (!raw.trim()) return [];
	try {
		const parsed = JSON.parse(raw) as Array<{
			name?: string;
			baseUrl?: string;
			apiKey?: string;
			model?: string;
			weight?: number;
		}>;
		return parsed
			.filter((p) => p.baseUrl && p.apiKey && p.model)
			.map((p) => ({
				name: p.name ?? 'provider',
				baseUrl: p.baseUrl!,
				apiKey: p.apiKey!,
				model: p.model!,
				weight: p.weight ?? 1,
			}));
	} catch {
		console.warn('[config] CKFINDER_LLM_POOL JSON 解析失败，端点池未生效');
		return [];
	}
}

// ---------------------------------------------------------------------------
// 运行时 Scope 管理（指挥台「添加资产」= 自动加入白名单）
//   资产范围（域名/IP/URL）落到 SCOPE_ALLOWED（.env 持久化 + 热加载），
//   Scope Gate 的 effectiveScope 会与 CKFINDER_SCOPE 取并集，从而实现「资产范围自带白名单」。
// ---------------------------------------------------------------------------

const ENV_FILE_PATH = resolve(process.cwd(), '.env');

/** .env 值引用：含空白或 # 时加双引号（loader 会剥离） */
function quoteEnvValue(value: string): string {
	if (/\s|#/.test(value)) return `"${value.replace(/"/g, '\\"')}"`;
	return value;
}

/** 更新 .env 中的单键（存在则替换，否则追加），保留注释与其它键 */
function setEnvLine(raw: string, key: string, value: string): string {
	const lines = raw.split('\n');
	let found = false;
	const next = lines.map((line) => {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) return line;
		const eq = trimmed.indexOf('=');
		if (eq === -1) return line;
		if (trimmed.slice(0, eq).trim() === key) {
			found = true;
			return `${key}=${quoteEnvValue(value)}`;
		}
		return line;
	});
	if (!found) {
		if (next.length > 0 && next[next.length - 1] !== '') next.push('');
		next.push(`${key}=${quoteEnvValue(value)}`);
	}
	return next.join('\n');
}

function readEnvRaw(): string {
	try {
		return readFileSync(ENV_FILE_PATH, 'utf8');
	} catch {
		return '';
	}
}

/** 写单键到 .env 并热加载到 process.env + 重置配置缓存 */
function persistEnv(key: string, value: string): void {
	writeFileSync(ENV_FILE_PATH, setEnvLine(readEnvRaw(), key, value), 'utf8');
	process.env[key] = value;
	reloadConfig();
}

/** 读取当前授权范围（SCOPE_ALLOWED ∪ CKFINDER_SCOPE，去重，保序） */
export function getScopeEntries(): string[] {
	const cfg = getConfig();
	return [...new Set([...cfg.scopeGate.allowed, ...cfg.agent.scope])];
}

/** 从 URL/IP/域名 提取白名单条目（URL → hostname 去端口，IP:port → IP，域名[:port] → 域名，均小写） */
export function scopeEntryFromValue(value: string): string {
	const trimmed = value.trim().toLowerCase().replace(/\/+$/, '');
	// URL → hostname（去端口/路径）
	if (/^https?:\/\//.test(trimmed)) {
		try {
			return new URL(trimmed).hostname;
		} catch {
			const m = trimmed.match(/^https?:\/\/([^/:]+)/);
			if (m) return m[1]!;
		}
	}
	// IP[:port] → IP
	const hostPort = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/);
	if (hostPort) return hostPort[1]!;
	// 域名[:port] → 域名
	const dom = trimmed.match(/^([^/:]+)/);
	return dom ? dom[1]! : trimmed;
}

/** 追加授权范围条目到 SCOPE_ALLOWED，返回最新白名单 */
export function addScopeEntry(value: string): string[] {
	const entry = scopeEntryFromValue(value);
	if (!entry) return getScopeEntries();
	const cfg = getConfig();
	const current = [...cfg.scopeGate.allowed];
	if (current.includes(entry)) return getScopeEntries();
	current.push(entry);
	persistEnv('SCOPE_ALLOWED', current.join(','));
	return getScopeEntries();
}

/** 移除授权范围条目（从 SCOPE_ALLOWED 与 CKFINDER_SCOPE 两处都删，否则并集仍会带回来），返回最新白名单 */
export function removeScopeEntry(value: string): string[] {
	const entry = scopeEntryFromValue(value);
	if (!entry) return getScopeEntries();
	const cfg = getConfig();
	const allowed = cfg.scopeGate.allowed.filter((s) => s !== entry);
	const agentScope = cfg.agent.scope.filter((s) => s !== entry);
	persistEnv('SCOPE_ALLOWED', allowed.join(','));
	persistEnv('CKFINDER_SCOPE', agentScope.join(','));
	return getScopeEntries();
}
