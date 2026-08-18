/**
 * 外部二进制探测：在 PATH 中查找工具并获取版本号。
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface BinInfo {
	found: boolean;
	path?: string;
	version?: string;
	wanted?: string;
}

export async function check(binName: string | undefined): Promise<BinInfo> {
	if (!binName) return { found: false };
	for (const flag of ['-version', '--version', '-v']) {
		try {
			const { stdout } = await execFileAsync(binName, [flag], {
				timeout: 5000,
			});
			const firstLine = stdout.split('\n')[0]?.trim() ?? '';
			const info: BinInfo = { found: true, path: binName };
			if (firstLine) info.version = firstLine;
			return info;
		} catch {
			// 尝试下一个 flag
		}
	}
	return { found: false, wanted: binName };
}
