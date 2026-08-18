/**
 * masscan 适配器
 *
 * 大规模 SYN 端口扫描，速度远超 nmap（百万级端口/秒）
 *
 * 命令：masscan -p<ports> --rate=<rate> -iL <ipfile> --output-format json --output-file -
 *       masscan -p<ports> --rate=<rate> <ip> --output-format json --output-file -
 *
 * 输出 JSONL（每行一个 IP 的扫描结果）：
 *   {
 *     "ip": "1.2.3.4",
 *     "timestamp": "1695000000",
 *     "ports": [
 *       {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64}
 *     ]
 *   }
 *
 * 注意：
 * - macOS/Linux 需 sudo（raw socket 权限）
 * - 内网/本机扫描可能不稳定，适合公网大范围端口发现
 * - 不带服务版本探测（-sV），如需版本探测可在 masscan 后串 nmap -sV
 *
 * 官方：https://github.com/robertdavidgraham/masscan
 */

import { mkdtemp, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execTool } from '../adapters/executor.js';
import { jsonlParser } from '../adapters/parsers.js';
import { registerTool } from '../adapters/registry.js';
import type { ToolDefinition } from '../adapters/types.js';
import { buildCacheKey } from '../storage/cache.js';

/** masscan 单条结果（原始） */
export interface MasscanRawRecord {
	ip: string;
	timestamp?: string;
	ports?: Array<{
		port: number;
		proto: string;
		status: string;
		reason?: string;
		ttl?: number;
	}>;
}

/** 扁平化后的服务记录（与 NmapServiceRecord 兼容） */
export interface MasscanServiceRecord {
	ip: string;
	port: number;
	protocol: 'tcp' | 'udp';
	state: 'open' | 'closed' | 'filtered';
	service?: string;
	reason?: string;
	ttl?: number;
}

export interface MasscanOptions {
	/** 目标 IP（单个） */
	ip?: string;
	/** IP 列表（多 IP，会写临时文件用 -iL 传入） */
	ips?: string[];
	/**
	 * 端口范围（如 "80,443,8080"、"1-1000"）
	 * 不传则用 nmap top1000 常用端口
	 * 传 "top100" / "top1000" 用内置 top 端口列表
	 */
	ports?: string;
	/** 发包速率（包/秒，默认 5000） */
	rate?: number;
	/** 超时 */
	timeoutMs?: number;
	/** 额外参数 */
	extraArgs?: string[];
	/** 启用 L2 缓存 */
	useCache?: boolean;
}

const TOOL_DEF: ToolDefinition = {
	name: 'masscan',
	mode: 'active',
	description: '大规模 SYN 端口扫描（速度远超 nmap，需 sudo）',
	defaultArgs: ['--output-format', 'json', '--output-file', '-', '--retries', '1', '--wait', '3'],
	defaultTimeoutMs: 10 * 60 * 1000,
};

registerTool(TOOL_DEF);

const parser = jsonlParser<MasscanRawRecord>('masscan');

/**
 * nmap top 1000 端口列表（精简版，覆盖 nmap-services 中最常见的 1000 端口）
 * 来源：nmap 官方 services 文件按频率排序
 */
const NMAP_TOP_PORTS = [
	// top 100
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 83, 84, 85, 88, 106, 110, 111, 113, 119,
	135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554,
	587, 631, 646, 873, 902, 990, 993, 995, 1000,
	// 101-200
	1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
	1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056,
	1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072,
	1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088,
	1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100,
	// 201-400 常见服务端口
	1433, 1434, 1521, 1723, 1900, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 2483,
	2484, 2638, 3000, 3001, 3128, 3268, 3269, 3306, 3389, 3690, 3702, 4000, 4040, 4369, 4444, 4848,
	5000, 5001, 5060, 5432, 5601, 5666, 5672, 5800, 5900, 5901, 5902, 5984, 5985, 5986, 6000, 6001,
	6379, 6443, 6660, 6661, 6666, 6667, 6668, 6669, 7000, 7001, 7002, 7077, 7110, 7180, 7199, 7474,
	7547, 7777, 8000, 8001, 8008, 8009, 8010, 8020, 8060, 8069, 8080, 8081, 8082, 8086, 8088, 8090,
	8091, 8098, 8161, 8181, 8200, 8222, 8333, 8443, 8444, 8500, 8530, 8531, 8649, 8686, 8700, 8800,
	8834, 8880, 8888, 8889, 9000, 9001, 9002, 9009, 9010, 9042, 9043, 9080, 9081, 9090, 9091, 9092,
	9100, 9200, 9300, 9418, 9443, 9500, 9600, 9981, 9990, 9991, 9999, 10000, 10001, 10080, 10250,
	10255, 11211, 12345, 13720, 15672, 16080, 16992, 16993, 17500, 18080, 19999, 20000, 22000, 22222,
	23023, 23424, 27015, 27017, 27018, 27019, 27036, 28017, 32400, 49152, 49153, 49154, 49155, 49156,
	49157,
];

/** 把 "top100"/"top1000"/"80,443,8080" 转成 masscan 的 -p 参数 */
function parsePorts(ports: string | undefined): string {
	if (!ports) {
		// 默认用 nmap top 常用端口（约 250 个，覆盖率高）
		return NMAP_TOP_PORTS.join(',');
	}
	if (ports.startsWith('top')) {
		const n = Number.parseInt(ports.slice(3), 10) || 1000;
		return NMAP_TOP_PORTS.slice(0, Math.min(n, NMAP_TOP_PORTS.length)).join(',');
	}
	// 原样返回（如 "80,443,8080" 或 "1-1000"）
	return ports;
}

/**
 * 执行 masscan 扫描
 *
 * @returns 扁平化的服务记录列表（每个 ip:port 一条）
 */
export async function runMasscan(opts: MasscanOptions): Promise<MasscanServiceRecord[]> {
	const portArg = parsePorts(opts.ports);
	const rate = opts.rate ?? 5000; // 默认 5000 包/秒，平衡速度与准确性

	const args: string[] = [
		'-p',
		portArg,
		'--rate',
		String(rate),
		...(TOOL_DEF.defaultArgs ?? []),
		...(opts.extraArgs ?? []),
	];

	// 多 IP 模式：写临时文件用 -iL 传入
	let tmpFile: string | undefined;
	let cacheKeyInput: string;
	if (opts.ips && opts.ips.length > 0) {
		const tmpDir = await mkdtemp(join(tmpdir(), 'masscan-'));
		tmpFile = join(tmpDir, 'ips.txt');
		await writeFile(tmpFile, opts.ips.join('\n'));
		args.push('-iL', tmpFile);
		cacheKeyInput = `ips:${opts.ips.length}:${opts.ips[0] ?? ''}`;
	} else if (opts.ip) {
		args.push(opts.ip);
		cacheKeyInput = `ip:${opts.ip}`;
	} else {
		throw new Error('masscan: either ip or ips must be provided');
	}

	const cacheKey =
		opts.useCache !== false
			? buildCacheKey('masscan', cacheKeyInput, portArg, `r${rate}`)
			: undefined;

	try {
		const result = await execTool<MasscanRawRecord>(
			{
				command: 'masscan',
				args,
				mode: 'active',
				// 决策点3：发包速率 > 10000 pps 视为高危动作，需 LLM 审批
				...(rate > 10000 ? { judgeAction: 'port_scan_high_rate' } : {}),
				timeoutMs: opts.timeoutMs ?? TOOL_DEF.defaultTimeoutMs,
			},
			parser,
			cacheKey,
		);

		// 扁平化：把 ports 数组展开成多条记录
		const records: MasscanServiceRecord[] = [];
		for (const raw of result.records) {
			for (const p of raw.ports ?? []) {
				if (p.status !== 'open') continue;
				records.push({
					ip: raw.ip,
					port: p.port,
					protocol: p.proto === 'udp' ? 'udp' : 'tcp',
					state: 'open',
					reason: p.reason,
					ttl: p.ttl,
				});
			}
		}
		return records;
	} finally {
		// 清理临时文件
		if (tmpFile) {
			await unlink(tmpFile).catch(() => {});
		}
	}
}
