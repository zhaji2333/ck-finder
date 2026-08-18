import { afterEach, describe, expect, it } from 'vitest';
import { execTool, execToolOrThrow } from '../../src/recon/adapters/executor.js';
import { jsonlParser, plainParser } from '../../src/recon/adapters/parsers.js';
import { resetConfigForTest } from '../../src/recon/config.js';

// 测试用配置（不连真实 PG/Redis）
process.env.PG_HOST = '127.0.0.1';
process.env.PG_PORT = '5432';
process.env.REDIS_HOST = '127.0.0.1';
process.env.REDIS_PORT = '6379';
// 跳过审计写入（避免连真实 PG）
process.env.CKRECON_AUDIT_DISABLED = '1';

afterEach(() => {
	resetConfigForTest();
});

describe('execTool', () => {
	it('执行 echo 命令成功', async () => {
		const result = await execTool({
			command: 'echo',
			args: ['hello', 'world'],
			mode: 'passive',
			timeoutMs: 5000,
		});
		expect(result.status).toBe('ok');
		expect(result.exitCode).toBe(0);
		expect(result.stdout.trim()).toBe('hello world');
		expect(result.records).toEqual([]);
	});

	it('plain parser 解析多行输出', async () => {
		const result = await execTool(
			{
				command: 'printf',
				args: ['line1\nline2\nline3\n'],
				mode: 'passive',
				timeoutMs: 5000,
			},
			plainParser('test'),
		);
		expect(result.status).toBe('ok');
		expect(result.records).toEqual(['line1', 'line2', 'line3']);
	});

	it('jsonl parser 解析 JSONL 输出', async () => {
		const result = await execTool<{ name: string }>(
			{
				command: 'printf',
				args: ['{"name":"a"}\n{"name":"b"}\n'],
				mode: 'passive',
				timeoutMs: 5000,
			},
			jsonlParser<{ name: string }>('test'),
		);
		expect(result.status).toBe('ok');
		expect(result.records).toEqual([{ name: 'a' }, { name: 'b' }]);
	});

	it('jsonl parser 跳过无效行', async () => {
		const result = await execTool<{ name: string }>(
			{
				command: 'printf',
				args: ['{"name":"a"}\ninvalid line\n{"name":"b"}\n'],
				mode: 'passive',
				timeoutMs: 5000,
			},
			jsonlParser<{ name: string }>('test'),
		);
		expect(result.records).toEqual([{ name: 'a' }, { name: 'b' }]);
	});

	it('超时触发 timeout 状态', async () => {
		const result = await execTool({
			command: 'sleep',
			args: ['10'],
			mode: 'passive',
			timeoutMs: 200,
		});
		expect(result.status).toBe('timeout');
		expect(result.error).toContain('timed out');
	});

	it('不存在的命令触发 failed 状态', async () => {
		const result = await execTool({
			command: 'nonexistent_command_xyz_12345',
			args: [],
			mode: 'passive',
			timeoutMs: 1000,
		});
		expect(result.status).toBe('failed');
		expect(result.error).toContain('spawn error');
	});

	it('非零退出码触发 failed 状态', async () => {
		const result = await execTool({
			command: 'sh',
			args: ['-c', 'exit 42'],
			mode: 'passive',
			timeoutMs: 5000,
		});
		expect(result.status).toBe('failed');
		expect(result.exitCode).toBe(42);
	});

	it('execToolOrThrow 成功不抛错', async () => {
		const result = await execToolOrThrow({
			command: 'echo',
			args: ['ok'],
			mode: 'passive',
			timeoutMs: 5000,
		});
		expect(result.status).toBe('ok');
	});

	it('execToolOrThrow 失败抛 ToolExecError', async () => {
		await expect(
			execToolOrThrow({
				command: 'sh',
				args: ['-c', 'exit 1'],
				mode: 'passive',
				timeoutMs: 5000,
			}),
		).rejects.toThrow('non-zero exit: 1');
	});

	it('stdin 管道输入', async () => {
		const result = await execTool({
			command: 'cat',
			args: [],
			mode: 'passive',
			timeoutMs: 5000,
			stdin: 'piped input',
		});
		expect(result.stdout).toBe('piped input');
	});
});
