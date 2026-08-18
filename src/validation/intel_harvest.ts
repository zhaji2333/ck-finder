import type { ValidationFinding } from './finding_store.js';
/**
 * intel 情报提炼（M4.4，借鉴 AutoHunter _harvest_intel）
 *
 * finding 出洞/确认时自动提炼三类情报：
 *   - fingerprint：指纹→打法映射（vuln_type: title → tactic）
 *   - endpoint：有效路径/未授权端点
 *   - cred：验证过的凭证（弱口令 finding）
 * worker 启动时按目标 host 指纹/root 域注入复用。
 */
import { IntelStore, rootDomain } from './intel_store.js';

/** 从 URL 提取 host 和路径 */
function parseUrl(url: string): { host: string; path: string } | null {
	try {
		const u = new URL(url);
		return { host: u.hostname.toLowerCase(), path: u.pathname };
	} catch {
		return null;
	}
}

/** 从 host 提取指纹信号（简单关键词，零网络） */
export function detectFingerprints(host: string, title: string, server?: string): string[] {
	const blob = `${host} ${title} ${server ?? ''}`.toLowerCase();
	const signals: Array<[string, string]> = [
		['spring', 'springboot'],
		['struts', 'struts2'],
		['shiro', 'shiro'],
		['ruoyi', 'ruoyi'],
		['thinkphp', 'thinkphp'],
		['sso', 'sso'],
		['coremail', 'coremail'],
		['seeyon', 'seeyon'],
		['sangfor', 'sangfor'],
		['druid', 'druid'],
		['nacos', 'nacos'],
		['jenkins', 'jenkins'],
		['gitlab', 'gitlab'],
		['grafana', 'grafana'],
		['k8s', 'kubernetes'],
		['minio', 'minio'],
		['oss', 'object-storage'],
	];
	const found: string[] = [];
	for (const [kw, fp] of signals) {
		if (blob.includes(kw)) found.push(fp);
	}
	return found;
}

/**
 * finding 确认时提炼情报入库。
 * 返回写入的条目数。
 */
export async function harvestIntelFromFinding(
	finding: ValidationFinding,
	_seedId: string,
): Promise<number> {
	const store = new IntelStore();
	const parsed = parseUrl(finding.url);
	if (!parsed) return 0;

	let count = 0;

	// fingerprint：指纹→打法
	const fps = detectFingerprints(parsed.host, finding.vulnName);
	for (const fp of fps) {
		await store.recordIntel({
			kind: 'fingerprint',
			matchKey: fp,
			payload: {
				tactic: `${String(finding.vulnType)}:${finding.vulnName}`,
				severity: finding.severity,
			},
			confidence: finding.reviewStatus === 'confirmed' ? 'verified' : 'likely',
			sourceFindingId: finding.id,
		});
		count++;
	}

	// endpoint：有效路径（非根路径才有区分度）
	if (parsed.path !== '/' && parsed.path.length > 1) {
		await store.recordIntel({
			kind: 'endpoint',
			matchKey: fps[0] ?? rootDomain(parsed.host),
			payload: { path: parsed.path, vuln_type: String(finding.vulnType) },
			confidence: finding.reviewStatus === 'confirmed' ? 'verified' : 'likely',
			sourceFindingId: finding.id,
		});
		count++;
	}

	// cred：弱口令 finding 提炼凭证
	if (String(finding.vulnType) === 'auth' && finding.vulnName.includes('弱口令')) {
		const credMatch = finding.summary.match(/弱口令\s+([\w.-]+)\/([\w.-]+)/);
		const nameMatch = finding.vulnName.match(/弱口令:\s*([\w.-]+)/);
		if (credMatch || nameMatch) {
			const username = nameMatch?.[1] ?? credMatch?.[1] ?? 'admin';
			const password = credMatch?.[2] ?? '';
			if (password) {
				await store.recordIntel({
					kind: 'cred',
					matchKey: rootDomain(parsed.host),
					payload: { username, password, url: finding.url },
					confidence: 'verified',
					sourceFindingId: finding.id,
				});
				count++;
			}
		}
	}

	return count;
}

/**
 * worker 启动时注入：按 host 指纹 + root 域查情报，渲染成 prompt 块（命中才返回）。
 */
export async function buildIntelBlock(
	host: string,
	title: string,
	server?: string,
): Promise<string | null> {
	const store = new IntelStore();
	const fps = detectFingerprints(host, title, server);
	const root = rootDomain(host);

	const entries: string[] = [];
	if (fps.length > 0) {
		const fpIntel = await store.lookupIntelMany('fingerprint', fps, 3);
		for (const e of fpIntel) {
			entries.push(
				`[指纹:${e.matchKey}] ${JSON.stringify(e.payload)}${e.confidence === 'verified' ? ' ✓验证' : ' ·疑似'}`,
			);
		}
		const epIntel = await store.lookupIntelMany('endpoint', fps, 3);
		for (const e of epIntel) {
			entries.push(
				`[端点:${e.matchKey}] ${JSON.stringify(e.payload)}${e.confidence === 'verified' ? ' ✓验证' : ' ·疑似'}`,
			);
		}
	}
	const credIntel = await store.lookupIntel('cred', root, 2);
	for (const e of credIntel) {
		const p = e.payload as { username?: string; password?: string };
		entries.push(
			`[凭证:${root}] ${p.username}/${p.password}${e.confidence === 'verified' ? ' ✓验证' : ' ·疑似'}`,
		);
	}

	if (entries.length === 0) return null;
	return `【情报库命中（跨任务复用）】\n${entries.map((e) => `- ${e}`).join('\n')}\n（情报来自历史验证，用前注意目标一致性）`;
}
