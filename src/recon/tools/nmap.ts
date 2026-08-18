/**
 * nmap 适配器
 *
 * 端口扫描 + 服务版本探测
 * 命令：nmap -sV -T3 -p <ports> --open -oX - <target>
 * 输出：XML（-oX -）
 *
 * 官方：https://nmap.org
 *
 * 注意：M1 阶段只解析 XML 输出为结构化记录；脚本能力（--script）留给 M2+。
 */

import { execTool } from '../adapters/executor.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';

export interface NmapServiceRecord {
	/** 目标 IP */
	ip: string;
	/** 端口 */
	port: number;
	/** 协议 tcp/udp */
	protocol: 'tcp' | 'udp';
	/** 服务名（nmap 识别） */
	service?: string;
	/** 服务版本 */
	version?: string;
	/** 产品（如 Apache、nginx） */
	product?: string;
	/** banner / 额外信息 */
	banner?: string;
	/** 端口状态 */
	state: 'open' | 'closed' | 'filtered';
}

export interface NmapOptions {
	/** 目标（IP/域名/CIDR） */
	target: string;
	/** 端口范围（如 "1-1000"、"80,443,8080"、"-"=全端口）。不传则用 nmap 默认 top 1000 */
	ports?: string;
	/** 扫描 nmap services 文件中最常出现的 N 个端口（如 100=top100, 1000=top1000）。优先级高于 ports */
	topPorts?: number;
	/** 时序模板 -T0~-T5，默认 -T3（SRC 场景保守） */
	timing?: 'T0' | 'T1' | 'T2' | 'T3' | 'T4' | 'T5';
	/** 是否启用服务版本探测（-sV） */
	serviceVersion?: boolean;
	/** 超时（毫秒） */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'nmap',
	mode: 'active',
	description: '端口扫描 + 服务版本探测（主动，限速）',
	defaultArgs: ['--open', '-oX', '-'],
	defaultTimeoutMs: 30 * 60 * 1000, // 30 分钟（全端口扫描耗时）
};

registerTool(TOOL_DEF);

/**
 * 执行 nmap 扫描
 */
export async function runNmap(opts: NmapOptions): Promise<NmapServiceRecord[]> {
	const args: string[] = [];
	if (opts.serviceVersion !== false) args.push('-sV');
	args.push(`-${opts.timing ?? 'T3'}`);
	// topPorts 优先级高于 ports；都不传则用 nmap 默认 top 1000
	if (opts.topPorts) {
		args.push('--top-ports', String(opts.topPorts));
	} else if (opts.ports) {
		args.push('-p', opts.ports);
	}
	args.push(...(TOOL_DEF.defaultArgs ?? []));
	args.push(...(opts.extraArgs ?? []));
	args.push(opts.target);

	// 决策点3：全端口扫描 / UDP 扫描 视为高危动作，需 LLM 审批
	const fullPortScan =
		opts.ports === '1-65535' || opts.ports === '0-65535' || opts.ports?.startsWith('1-6553');
	const udpScan = (opts.extraArgs ?? []).includes('-sU') || args.includes('-sU');
	const judgeAction =
		fullPortScan || udpScan ? (udpScan ? 'nmap_udp_scan' : 'nmap_sv_scan') : undefined;

	const result = await execTool(
		{
			command: 'nmap',
			args,
			mode: 'active',
			timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
			...(judgeAction ? { judgeAction } : {}),
		},
		undefined, // XML 解析器自定义实现
	);

	if (result.status !== 'ok') {
		return [];
	}

	return parseNmapXml(result.stdout);
}

/**
 * 解析 nmap XML 输出
 *
 * 简易解析器（不依赖 xml2js，避免额外依赖）：
 * 提取 <host><ports><port> 元素的关键属性
 */
export function parseNmapXml(xml: string): NmapServiceRecord[] {
	const records: NmapServiceRecord[] = [];

	// 按 <host> 分块
	const hostBlocks = xml.match(/<host[\s\S]*?<\/host>/g) ?? [];
	for (const hostBlock of hostBlocks) {
		// 提取 IP（优先 addr="x.x.x.x" 的 type="ipv4"）
		const addrMatch = hostBlock.match(/<address\s+addr="([^"]+)"\s+addrtype="ipv4"/);
		if (!addrMatch) continue;
		const ip = addrMatch[1];

		// 提取每个 <port> 元素
		const portBlocks = hostBlock.match(/<port[^>]*>[\s\S]*?<\/port>/g) ?? [];
		for (const portBlock of portBlocks) {
			const portMatch = portBlock.match(/<port\s+protocol="(tcp|udp)"\s+portid="(\d+)">/);
			if (!portMatch) continue;
			const protocol = portMatch[1] as 'tcp' | 'udp';
			const port = Number.parseInt(portMatch[2], 10);

			const stateMatch = portBlock.match(/<state\s+state="(open|closed|filtered)"/);
			const state = (stateMatch?.[1] ?? 'closed') as NmapServiceRecord['state'];
			if (state !== 'open') continue;

			const serviceMatch = portBlock.match(
				/<service\s+name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?/,
			);
			const service = serviceMatch?.[1] || undefined;
			const product = serviceMatch?.[2] || undefined;
			const version = serviceMatch?.[3] || undefined;

			// 提取 banner（service 的 extrainfo 或 script output）
			const extraMatch = portBlock.match(/extrainfo="([^"]*)"/);
			const banner = extraMatch?.[1] || undefined;

			records.push({
				ip,
				port,
				protocol,
				service,
				version: version ? (product ? `${product} ${version}` : version) : product,
				product,
				banner,
				state,
			});
		}
	}

	return records;
}
