import { isFofaEnabled, searchFofaAssets } from '../recon/adapters/fofa_adapter.js';
/**
 * killsweep 通杀（M5.2，借鉴 AutoHunter killsweep.py）
 *
 * 人工确认（confirmed）的 finding → 分析是否同款产品 → FOFA 圈定同款站点 → 实打验证。
 * 通用机制：产品指纹（Server/标题/特征）→ FOFA 查询 → 同款站点打同款漏洞。
 *
 * 注意：需 FOFA_EMAIL/FOFA_KEY 配置；无 fofa 时仅分析产品通用性（不出货）。
 */
import { FindingStore, type ValidationFinding } from '../validation/finding_store.js';

export interface KillsweepResult {
	findingId: string;
	isGenericProduct: boolean;
	productName: string;
	fofaQuery: string;
	verifiedUrls: string[];
}

/** 从 finding 提取产品指纹（Server 头 / URL host / title） */
function extractProductFingerprint(f: ValidationFinding): { product: string; query: string } {
	const ev = f.evidence;
	// 从 raw_response 提取 Server 头
	const serverMatch = ev.raw_response.match(/server:\s*([^\r\n]+)/i);
	const server = serverMatch?.[1]?.trim() ?? '';
	// 从 URL 提取 host
	let host = '';
	try {
		host = new URL(f.url).hostname;
	} catch {
		host = f.url;
	}

	if (server) {
		return { product: server, query: `header="${server}"` };
	}
	return { product: host, query: `host="${host}"` };
}

/**
 * 分析 confirmed finding 是否同款产品 + fofa 圈定同款站点。
 * 返回圈定的同款 URL 列表（供实打验证）。
 */
export async function runKillsweep(finding: ValidationFinding): Promise<KillsweepResult> {
	const { product, query } = extractProductFingerprint(finding);

	// 无 fofa → 仅返回产品通用性分析（不出货）
	if (!isFofaEnabled()) {
		return {
			findingId: finding.id,
			isGenericProduct: Boolean(product),
			productName: product,
			fofaQuery: query,
			verifiedUrls: [],
		};
	}

	// fofa 查询同款站点
	const fofaResult = await searchFofaAssets({ query, maxResults: 20 });
	const verifiedUrls: string[] = [];
	for (const r of fofaResult.assets) {
		const url = r.host ? `http://${r.host}${r.port ? `:${r.port}` : ''}` : '';
		if (url && url !== finding.url) verifiedUrls.push(url);
	}

	return {
		findingId: finding.id,
		isGenericProduct: verifiedUrls.length > 0,
		productName: product,
		fofaQuery: query,
		verifiedUrls: verifiedUrls.slice(0, 10),
	};
}

/**
 * 批量通杀：对 confirmed findings 逐个分析同款产品。
 */
export async function runKillsweepBatch(limit = 20): Promise<KillsweepResult[]> {
	const store = new FindingStore();
	const confirmed = await store.listFindings({ reviewStatus: 'confirmed', limit });
	const results: KillsweepResult[] = [];
	for (const f of confirmed) {
		try {
			results.push(await runKillsweep(f));
		} catch (err) {
			console.warn(
				`[killsweep] ${f.id} 通杀分析失败: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}
	return results;
}
