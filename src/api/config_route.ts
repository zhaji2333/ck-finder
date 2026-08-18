/**
 * 指挥台「设置」API（挂载到 Hono server /api/config）
 *
 * 让用户在 Web 界面安全配置 AI API Key、模型、授权范围、凭据等，
 * 写入 .env（持久化）并即时热加载到进程（无需重启）。
 *
 * - GET  /api/config           当前配置（密钥脱敏）+ 字段白名单
 * - PUT  /api/config           更新配置（body: { updates: { KEY: value } }）
 * - POST /api/config/test-llm  LLM 连通性测试（用当前配置发起一次最小对话）
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Hono } from 'hono';
import { Agent } from '@earendil-works/pi-agent-core';
import {
	EDITABLE_CONFIG_FIELDS,
	getConfig,
	reloadConfig,
	type EditableConfigField,
} from '../recon/config.js';
import { createDeepSeekModels, resolveDeepSeekModel } from '../llm/provider.js';

export const configApp = new Hono();

const ENV_PATH = resolve(process.cwd(), '.env');

/** 从 assistant content（string 或 part 数组）提取纯文本 */
function extractText(content: unknown): string {
	if (typeof content === 'string') return content;
	if (Array.isArray(content)) {
		return content
			.map((part) => {
				if (typeof part === 'string') return part;
				if (part && typeof part === 'object' && 'text' in part) {
					return String((part as { text: unknown }).text ?? '');
				}
				return '';
			})
			.filter(Boolean)
			.join('');
	}
	return JSON.stringify(content);
}

/** 脱敏：只保留尾 4 位，前面打码（密钥字段） */
function maskSecret(value: string): string {
	if (!value) return '';
	if (value.length <= 6) return '••••••';
	return `••••••${value.slice(-4)}`;
}

/** 读取 .env 原始文本（不存在返回 ''） */
function readEnvFile(): string {
	try {
		return readFileSync(ENV_PATH, 'utf8');
	} catch {
		return '';
	}
}

/** 将单值安全写入 .env（更新既有行 / 追加，保留注释与其它键） */
function writeEnvValue(raw: string, key: string, value: string): string {
	const lines = raw.split('\n');
	let found = false;
	const next = lines.map((line) => {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith('#')) return line;
		const eq = trimmed.indexOf('=');
		if (eq === -1) return line;
		if (trimmed.slice(0, eq).trim() === key) {
			found = true;
			return `${key}=${quoteEnv(value)}`;
		}
		return line;
	});
	if (!found) {
		if (next.length > 0 && next[next.length - 1] !== '') next.push('');
		next.push(`${key}=${quoteEnv(value)}`);
	}
	return next.join('\n');
}

/** .env 值引用：含空白或 # 时加双引号（loader 会剥离） */
function quoteEnv(value: string): string {
	if (/\s|#/.test(value)) return `"${value.replace(/"/g, '\\"')}"`;
	return value;
}

/** 字段当前值（密钥脱敏）+ 是否已设置 */
function fieldSnapshot(field: EditableConfigField, env: Record<string, string>) {
	const value = env[field.key] ?? '';
	return {
		...field,
		value: field.secret ? maskSecret(value) : value,
		set: value !== '' && value !== undefined,
	};
}

/** 读取当前进程 env（合并 .env 与已热加载值） */
function currentEnv(): Record<string, string> {
	return { ...process.env } as Record<string, string>;
}

configApp.get('/', (c) => {
	const env = currentEnv();
	const fields = EDITABLE_CONFIG_FIELDS.map((f) => fieldSnapshot(f, env));
	const cfg = getConfig();
	return c.json({
		fields,
		status: {
			llmConfigured: Boolean(cfg.llm.apiKey),
			llmPoolProviders: cfg.agent.llmPool.length,
			scope: cfg.agent.scope,
			scopeGateEnabled: cfg.scopeGate.enabled,
			model: cfg.agent.model,
			modelPro: cfg.agent.modelPro || cfg.agent.model,
		},
		envPath: ENV_PATH,
	});
});

configApp.put('/', async (c) => {
	const body = (await c.req.json().catch(() => ({}))) as {
		updates?: Record<string, string>;
	};
	const updates = body.updates ?? {};
	if (typeof updates !== 'object' || Object.keys(updates).length === 0) {
		return c.json({ error: 'missing updates' }, 400);
	}

	// 白名单校验：拒绝未知键，防止越权写任意 env
	const allowed = new Set(EDITABLE_CONFIG_FIELDS.map((f) => f.key));
	const unknown = Object.keys(updates).filter((k) => !allowed.has(k));
	if (unknown.length > 0) {
		return c.json({ error: `unknown config key: ${unknown.join(', ')}` }, 400);
	}

	const byKey = new Map(EDITABLE_CONFIG_FIELDS.map((f) => [f.key, f]));
	const changed: string[] = [];
	const skipped: string[] = [];
	const applied: Record<string, string> = {};

	for (const [key, value] of Object.entries(updates)) {
		const field = byKey.get(key);
		if (!field) continue;
		const rawValue = value ?? '';

		// 密钥字段：空值 / 掩码哨兵 = 保持不变
		if (field.secret && (rawValue.trim() === '' || /^[*•·]+$/.test(rawValue.trim()))) {
			skipped.push(key);
			continue;
		}
		// JSON 字段：非空时校验合法性
		if (field.type === 'json' && rawValue.trim() !== '') {
			try {
				JSON.parse(rawValue);
			} catch {
				return c.json({ error: `${key} 不是合法 JSON` }, 400);
			}
		}
		// boolean 归一化
		if (field.type === 'boolean') {
			applied[key] = rawValue === 'true' || rawValue === '1' ? 'true' : 'false';
		} else {
			applied[key] = rawValue;
		}
		changed.push(key);
	}

	if (changed.length === 0) {
		return c.json({ error: 'nothing to update', skipped });
	}

	// 1) 持久化到 .env
	let envRaw = readEnvFile();
	for (const [key, value] of Object.entries(applied)) {
		envRaw = writeEnvValue(envRaw, key, value);
	}
	writeFileSync(ENV_PATH, envRaw, 'utf8');

	// 2) 热加载到进程 env + 重置配置缓存（下一次 getConfig()/createDeepSeekModels() 读到新值）
	for (const [key, value] of Object.entries(applied)) {
		process.env[key] = value;
	}
	reloadConfig();

	return c.json({
		ok: true,
		changed,
		skipped,
		status: {
			llmConfigured: Boolean(getConfig().llm.apiKey),
			llmPoolProviders: getConfig().agent.llmPool.length,
			model: getConfig().agent.model,
		},
	});
});

/** LLM 连通性测试：用当前配置发起一次最小对话，返回模型响应片段 */
configApp.post('/test-llm', async (c) => {
	try {
		const cfg = getConfig();
		if (!cfg.llm.apiKey && cfg.agent.llmPool.length === 0) {
			return c.json({ ok: false, error: '未配置 LLM API Key' }, 400);
		}
		const models = createDeepSeekModels();
		const model = resolveDeepSeekModel(models, cfg.agent.model || 'deepseek-v4-flash');
		const agent = new Agent({
			initialState: {
				systemPrompt: '你是连通性测试助手。只需回复两个字：OK。不要调用任何工具。',
				model,
				thinkingLevel: 'minimal',
				tools: [],
			},
			streamFn: models.streamSimple.bind(models),
			beforeToolCall: async () => undefined,
		});

		let reply = '';
		let toolCalls = 0;
		agent.subscribe((event) => {
			if (event.type === 'tool_execution_start') toolCalls++;
			if (event.type === 'agent_end') {
				const msgs = event.messages as Array<{ role?: string; content?: unknown }>;
				const last = [...msgs].reverse().find((m) => m.role === 'assistant');
				if (last?.content != null) {
					reply = extractText(last.content);
				}
			}
		});

		// 超时保护（20s）：LLM 卡住不阻塞请求
		await Promise.race([
			agent.prompt('ping'),
			new Promise((_, reject) =>
				setTimeout(() => reject(new Error('test-llm timeout (20s)')), 20_000),
			),
		]);

		return c.json({
			ok: true,
			model: cfg.agent.model || 'deepseek-v4-flash',
			reply: reply.slice(0, 200),
			toolCalls,
		});
	} catch (err) {
		return c.json({
			ok: false,
			error: err instanceof Error ? err.message : String(err),
		});
	}
});
