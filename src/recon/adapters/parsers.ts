/**
 * 输出解析器：JSONL / JSON / Plain
 *
 * 大部分 ProjectDiscovery 工具支持 -json 输出 JSONL，每行一个 JSON 对象。
 */

import type { OutputParser } from './types.js';

/** JSONL 解析器：每行一个 JSON 对象，跳过空行和无效行 */
export function jsonlParser<T>(name: string): OutputParser<T> {
	return {
		name,
		format: 'jsonl',
		parse(input: string): T[] {
			const out: T[] = [];
			for (const line of input.split('\n')) {
				const trimmed = line.trim();
				if (!trimmed) continue;
				try {
					out.push(JSON.parse(trimmed) as T);
				} catch {
					// 跳过无效行（可能是工具日志混入）
				}
			}
			return out;
		},
	};
}

/** JSON 解析器：整个输入是一个 JSON（对象或数组） */
export function jsonParser<T>(name: string): OutputParser<T> {
	return {
		name,
		format: 'json',
		parse(input: string): T[] {
			const trimmed = input.trim();
			if (!trimmed) return [];
			try {
				const parsed = JSON.parse(trimmed);
				if (Array.isArray(parsed)) return parsed as T[];
				return [parsed as T];
			} catch {
				return [];
			}
		},
	};
}

/** Plain 解析器：每行一个字符串（如 subfinder 默认输出） */
export function plainParser<T = string>(
	name: string,
	transform?: (line: string) => T | null,
): OutputParser<T> {
	return {
		name,
		format: 'plain',
		parse(input: string): T[] {
			const out: T[] = [];
			for (const line of input.split('\n')) {
				const trimmed = line.trim();
				if (!trimmed) continue;
				if (transform) {
					const v = transform(trimmed);
					if (v !== null) out.push(v);
				} else {
					out.push(trimmed as unknown as T);
				}
			}
			return out;
		},
	};
}
