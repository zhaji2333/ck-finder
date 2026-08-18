/**
 * nuclei 验证扫描适配器（M3）
 *
 * 复用收集引擎 execTool（超时/限速/审计/L2 缓存全内置）。
 * 目标校验由 ck-finder Scope Gate 负责（子进程层 flagMap 已补 -u/-target/-url）。
 * 输出解析：nuclei -jsonl → JSONL 解析为命中记录。
 *
 * ⚠️ nuclei JSONL 输出字段是 snake_case（template-id / matched-at / curl-command），
 * 接口字段与之对齐，避免解析到 undefined。
 */
import { execToolOrThrow } from '../adapters/executor.js';
import { jsonlParser } from '../adapters/parsers.js';

export interface NucleiHit {
	/** 模板 ID（nuclei 输出 template-id） */
	'template-id'?: string;
	/** 模板名（template 字段） */
	template?: string;
	/** 漏洞类型标签（info.tags） */
	tags?: string[];
	/** 严重程度（info.severity） */
	info?: {
		severity?: string;
		name?: string;
		description?: string;
		reference?: string[];
		tags?: string[];
	};
	/** 匹配到的 URL（matched-at） */
	'matched-at'?: string;
	/** 原始请求（request 字段） */
	request?: string;
	/** 原始响应（response 字段） */
	response?: string;
	/** 复现 curl 命令（curl-command） */
	'curl-command'?: string;
	/** 攻击类型：http/head/dns/file/network 等 */
	type?: string;
	host?: string;
	port?: string;
	/** 模板路径（template-path） */
	'template-path'?: string;
	/** 匹配状态（matcher-status） */
	'matcher-status'?: boolean;
}

export interface NucleiScanOptions {
	target: string;
	/** 模板选择器：如 '-t', 'cves/', '-tags', 'sqli' */
	templateArgs?: string[];
	/** 严重程度过滤（默认 low 及以上） */
	severity?: string;
	timeoutMs?: number;
}

/** nuclei 扫描（轻量：默认只跑 low 及以上 + 精简模板集，不限速 + 内部并发 30） */
export async function runNuclei(opts: NucleiScanOptions): Promise<NucleiHit[]> {
	const args = [
		'-u',
		opts.target,
		'-jsonl',
		'-silent',
		'-severity',
		opts.severity ?? 'low,medium,high,critical',
		'-timeout',
		'10',
		'-c',
		'30',
	];
	// 模板选择：默认跑精简必测集（去掉 dirsearch 已覆盖的 idor/traversal），可被 templateArgs 覆盖
	if (opts.templateArgs && opts.templateArgs.length > 0) {
		args.push(...opts.templateArgs);
	} else {
		args.push('-tags', 'rce,sqli,lfi,ssrf,upload,xss,deserialization,xxe');
	}

	const result = await execToolOrThrow<NucleiHit>(
		{
			command: 'nuclei',
			args,
			mode: 'active',
			timeoutMs: opts.timeoutMs ?? 10 * 60 * 1000,
		},
		jsonlParser<NucleiHit>('nuclei'),
		`nuclei:${opts.target}:${opts.templateArgs?.join(':') ?? 'default'}`,
	);
	return result.records;
}
