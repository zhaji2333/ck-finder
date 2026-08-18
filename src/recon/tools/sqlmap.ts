/**
 * sqlmap 注入验证适配器（M3）
 *
 * 复用收集引擎 execTool。轻量默认：--batch --level 1 --risk 1（防误跑重参数）。
 * 目标校验由 ck-finder Scope Gate 负责（子进程层 flagMap 已补 -u/-url）。
 * 输出解析：sqlmap --batch 文本输出 → 提取注入结论（type/payload/DBMS）。
 */
import { execToolOrThrow } from '../adapters/executor.js';
import { plainParser } from '../adapters/parsers.js';

export interface SqlmapInjection {
	title: string;
	parameter: string;
	payload: string;
	technique: string;
	dbms?: string;
}

export interface SqlmapOptions {
	url: string;
	/** 指定注入参数（如 'id'），不指定则 sqlmap 全参数探测 */
	param?: string;
	/** 额外参数（如 --data、--cookie） */
	extraArgs?: string[];
	timeoutMs?: number;
}

/** 从 sqlmap 文本输出解析注入结论 */
export function parseSqlmapOutput(stdout: string): SqlmapInjection[] {
	const injections: SqlmapInjection[] = [];
	const lines = stdout.split('\n');

	// sqlmap 关键特征行：
	// "Parameter: id (GET)" / "    Type: boolean-based blind" / "    Title: ..." / "    Payload: id=..."
	let current: Partial<SqlmapInjection> | null = null;
	for (const line of lines) {
		const paramMatch = line.match(
			/Parameter:\s+(.+?)\s+\((GET|POST|URI|Cookie|Header|User-Agent|Referer)\)/i,
		);
		if (paramMatch) {
			current = { parameter: paramMatch[1] };
			continue;
		}
		const typeMatch = line.match(/Type:\s+(.+)/i);
		if (typeMatch && current) {
			current.technique = typeMatch[1].trim();
			continue;
		}
		const titleMatch = line.match(/Title:\s+(.+)/i);
		if (titleMatch && current) {
			current.title = titleMatch[1].trim();
			continue;
		}
		const payloadMatch = line.match(/Payload:\s+(.+)/i);
		if (payloadMatch && current) {
			current.payload = payloadMatch[1].trim();
		}
		const dbmsMatch = line.match(/back-end DBMS:\s+(.+)/i);
		if (dbmsMatch && current) {
			current.dbms = dbmsMatch[1].trim();
		}
		// 完成一个注入块
		if (current?.title && current.parameter && current.payload && !line.trim().startsWith('---')) {
			injections.push(current as SqlmapInjection);
			current = null;
		}
	}
	return injections;
}

/** sqlmap 注入验证（轻量） */
export async function runSqlmap(opts: SqlmapOptions): Promise<SqlmapInjection[]> {
	const args = ['-u', opts.url, '--batch', '--level', '1', '--risk', '1', '--flush-session'];
	if (opts.param) {
		args.push('-p', opts.param);
	}
	if (opts.extraArgs) {
		args.push(...opts.extraArgs);
	}

	// 安全红线 R2：禁止脱库/写文件/系统命令（guard 层拦截，fail-closed）
	const { guardToolArgs, guardAndAudit } = await import('../../security/guard.js');
	const guard = guardToolArgs('sqlmap', args);
	if (!guard.allowed) {
		await guardAndAudit('sqlmap', opts.url, guard.reason ?? '红线拦截');
		throw new Error(`sqlmap 被安全 guard 拦截: ${guard.reason}`);
	}

	const result = await execToolOrThrow<string>(
		{
			command: 'sqlmap',
			args,
			mode: 'active',
			timeoutMs: opts.timeoutMs ?? 15 * 60 * 1000,
		},
		plainParser('sqlmap'),
		`sqlmap:${opts.url}:${opts.param ?? 'all'}`,
	);

	return parseSqlmapOutput(result.stdout);
}
