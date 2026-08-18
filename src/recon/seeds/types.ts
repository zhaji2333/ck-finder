/**
 * 种子类型定义
 *
 * 6 种 seed_type 对应 6 种入口：
 * - domain       : example.com
 * - url          : https://www.example.com/path
 * - ip           : 1.2.3.4
 * - cidr         : 10.0.0.0/24
 * - ip_port      : 1.2.3.4:8080
 * - company_name : 北京某某科技有限公司
 */

export type SeedType = 'domain' | 'url' | 'ip' | 'cidr' | 'ip_port' | 'company_name';

export interface Seed {
	/** 原始输入值 */
	value: string;
	/** 归一化后的值（用于去重） */
	valueNorm: string;
	/** 种子类型 */
	seedType: SeedType;
	/** 解析后的结构化数据（按 seedType 不同） */
	parsed: ParsedSeed;
}

export type ParsedSeed =
	| { kind: 'domain'; domain: string }
	| {
			kind: 'url';
			url: string;
			scheme: string;
			host: string;
			port: number | null;
			path: string;
			domain: string;
	  }
	| { kind: 'ip'; ip: string }
	| { kind: 'cidr'; cidr: string; ip: string; prefix: number }
	| { kind: 'ip_port'; ip: string; port: number }
	| { kind: 'company_name'; company: string };

/** 归一化时抛出的错误 */
export class SeedNormalizeError extends Error {
	constructor(
		message: string,
		public readonly input: string,
	) {
		super(message);
		this.name = 'SeedNormalizeError';
	}
}
