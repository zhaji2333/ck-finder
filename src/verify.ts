import { auditLog } from './recon/gate/audit_log.js';
import { runDirsearch } from './recon/tools/dirsearch.js';
import { runNuclei } from './recon/tools/nuclei.js';
import { hostInScopeSync } from './security/scope_util.js';
/**
 * verify 确定性验证命令（M3，不走 LLM）
 *
 * 对授权目标批量执行：http_req 探活 → nuclei_scan → dir_brute →（可选）auth_brute，
 * 命中落 validation_findings（pending，带证据）。
 *
 * 用法：ck-finder verify --target <ip[:port]> --scope <范围> [--auth-brute]
 *   --target 可多次/逗号分隔（如 192.0.2.10:8080,192.0.2.10:8082）
 *   --auth-brute 对登录接口做弱口令尝试（授权范围内护栏放行）
 *   --login-url 指定登录接口 URL（auth_brute 目标）
 */
import { httpReqTool } from './tools/http_req.js';
import { FindingStore } from './validation/finding_store.js';

export interface VerifyOptions {
	targets: string[]; // ip:port 列表
	scope: string[];
	authBrute?: boolean;
	loginUrl?: string;
	seedId: string;
	/** 端口并发数（默认 6） */
	concurrency?: number;
}

interface VerifyTargetResult {
	target: string;
	reachable: boolean;
	httpStatus: number | null;
	nucleiHits: number;
	dirFound: number;
	findingsCreated: number;
	/** 被 dedup 拦截的重复 finding 数 */
	deduped: number;
	error?: string;
}

/** 用 httpReqTool 探活（返回状态码） */
async function probe(url: string): Promise<{ status: number | null; body: string }> {
	try {
		const res = await httpReqTool.execute('probe', { url, timeoutMs: 8000 });
		const detail = res.details;
		return { status: detail.status, body: res.content.find((c) => c.type === 'text')?.text ?? '' };
	} catch {
		return { status: null, body: '' };
	}
}

/**
 * 对单个目标执行确定性验证流程。
 */
async function verifyTarget(
	o: VerifyOptions,
	target: string,
	store: FindingStore,
): Promise<VerifyTargetResult> {
	const result: VerifyTargetResult = {
		target,
		reachable: false,
		httpStatus: null,
		nucleiHits: 0,
		dirFound: 0,
		findingsCreated: 0,
		deduped: 0,
	};
	const baseUrl = target.includes('://') ? target : `http://${target}/`;
	console.log(`\n[verify] ═══ 目标 ${target} ═══`);

	// 确定性验证也强制过 scope 校验（fail-closed）：防 verify --target 任意 IP 越权扫描
	const host = (() => {
		try {
			return new URL(baseUrl).hostname;
		} catch {
			return target.split(':')[0] ?? '';
		}
	})();
	if (!hostInScopeSync(host, o.scope)) {
		result.error = `越权拒绝：目标 ${host} 不在授权范围`;
		console.log(`[verify] 越权拒绝: ${host}`);
		return result;
	}

	// 1) 探活（httpReqTool）
	const { status, body } = await probe(baseUrl);
	result.httpStatus = status;
	if (status === null) {
		result.error = '不可达';
		console.log('[verify] 探活失败: 目标不可达');
		return result;
	}
	result.reachable = true;
	console.log(`[verify] 探活 OK: HTTP ${status}`);

	// 2) nuclei 扫描（复用 execTool 适配器，子进程层 scope 校验）
	try {
		const hits = await runNuclei({
			target: baseUrl,
			severity: 'low,medium,high,critical',
			templateArgs: ['-tags', 'rce,sqli,lfi,ssrf,upload,xss,deserialization,xxe'],
			timeoutMs: 8 * 60 * 1000,
		});
		result.nucleiHits = hits.length;
		console.log(`[verify] nuclei: ${hits.length} 条命中`);
		for (const h of hits.slice(0, 10)) {
			console.log(
				`  [${h.info?.severity ?? '?'}] ${h['template-id'] ?? h.template ?? '?'} ${h['matched-at'] ?? ''}`,
			);
		}
		// 命中 → 落 finding（证据：curl-command + 原始请求/响应）
		const severities = new Set(['critical', 'high', 'medium', 'low', 'info']);
		for (const h of hits.slice(0, 10)) {
			const sev = (h.info?.severity ?? 'medium') as string;
			const templateId = h['template-id'] ?? h.template ?? 'unknown';
			try {
				const finding = await store.insertFinding({
					seedId: o.seedId,
					vulnName: h.info?.name ?? `nuclei:${templateId}`,
					vulnType: classifyTemplate(templateId),
					severity: (severities.has(sev) ? sev : 'medium') as
						| 'critical'
						| 'high'
						| 'medium'
						| 'low'
						| 'info',
					url: h['matched-at'] ?? baseUrl,
					port: portOf(target),
					summary: `nuclei 模板 ${templateId} 命中 ${h['matched-at'] ?? ''}：${h.info?.name ?? ''}`,
					evidence: {
						poc: h['curl-command'] ?? `nuclei -u ${h['matched-at'] ?? baseUrl} -t ${templateId}`,
						raw_request: h.request ?? `nuclei template: ${templateId}`,
						raw_response: h.response ?? JSON.stringify(h).slice(0, 2000),
						kill_chain: {
							chain: [
								{ step: '扫描', detail: `nuclei 模板 ${templateId} 命中` },
								{
									step: '确认',
									detail: `matched at ${h['matched-at'] ?? ''}（存在性证明，按红线未做数据修改）`,
								},
							],
							summary: 'nuclei 模板扫描命中，存在性已验证，待手工复现确认',
						},
						self_check: {
							reproducible: true,
							prerequisites: 'nuclei 模板扫描命中（只读存在性验证）',
							impact: h.info?.description ?? '待确认',
							severity: h.info?.severity ?? 'medium',
							priority: 'P1',
						},
					},
				});
				if (finding) {
					result.findingsCreated++;
				} else {
					result.deduped++;
					console.log(`[verify] nuclei finding 重复（dedup 命中，跳过）: ${templateId}`);
				}
			} catch (err) {
				// 证据不全的跳过（不阻塞流程），但记录原因便于排查
				const msg = err instanceof Error ? err.message : String(err);
				console.log(`[verify] nuclei finding 落库失败（跳过）: ${msg.slice(0, 120)}`);
			}
		}
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.log(`[verify] nuclei 跳过: ${msg.slice(0, 100)}`);
	}

	// 3) 目录爆破（dirsearch，低危自动放行；禁用 L2 缓存——缓存命中不写输出文件导致解析空）
	try {
		const records = await runDirsearch({ url: baseUrl, timeoutMs: 5 * 60 * 1000, useCache: false });
		const found = records.filter((r) => r.status >= 200 && r.status < 400);
		result.dirFound = found.length;
		console.log(`[verify] dirsearch: 发现 ${found.length} 个路径`);
		for (const f of found.slice(0, 10)) {
			console.log(`  ${f.status} ${f.path}`);
		}
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.log(`[verify] dir_brute 跳过: ${msg.slice(0, 100)}`);
	}

	// 4) 弱口令（仅显式启用 + 授权范围内护栏）
	// 显式 --login-url 只对 host:port 匹配当前目标时执行（防多端口重复爆破同一登录接口）
	if (o.authBrute) {
		const loginUrl =
			o.loginUrl && !loginUrlMatchesTarget(o.loginUrl, target)
				? null
				: (o.loginUrl ?? detectLoginUrl(body, baseUrl));
		if (!loginUrl) {
			if (o.loginUrl) {
				console.log(`[verify] auth_brute 跳过: --login-url ${o.loginUrl} 不属于当前目标 ${target}`);
			} else {
				console.log('[verify] auth_brute 跳过: 未找到登录接口');
			}
		} else {
			const host = new URL(loginUrl).hostname;
			if (!hostInScopeSync(host, o.scope)) {
				console.log(`[verify] auth_brute 拒绝: 登录接口不在授权范围 ${loginUrl}`);
				await auditLog({
					actor: 'tool:auth_brute',
					action: 'scope_decision',
					target: loginUrl,
					decision: 'deny',
					reason: 'auth_brute 目标不在授权范围（fail-closed）',
				});
			} else {
				// 用 httpReqTool 尝试弱口令（护栏：每账号 ≤3 + 总 ≤50 + 间隔限速）
				const success = await weakPasswordAttempt(loginUrl);
				console.log(
					`[verify] auth_brute: ${success.length > 0 ? `命中 ${success.map((s) => `${s[0]}/${s[1]}`).join(', ')}` : '未命中'}`,
				);
				for (const [user, pass] of success) {
					try {
						const finding = await store.insertFinding({
							seedId: o.seedId,
							vulnName: `弱口令: ${user}`,
							vulnType: 'auth',
							severity: 'high',
							url: loginUrl,
							port: portOf(target),
							summary: `登录接口 ${loginUrl} 存在弱口令 ${user}/${pass}`,
							evidence: {
								poc: `curl -X POST ${loginUrl} -d '{"username":"${user}","password":"${pass}"}'`,
								raw_request: `POST ${loginUrl}\nContent-Type: application/json\n\n{"username":"${user}","password":"${pass}"}`,
								raw_response: '登录成功（获得会话）',
								kill_chain: {
									chain: [
										{ step: '弱口令尝试', detail: `${user}/${pass} 登录成功` },
										{ step: '进入后台', detail: '获得授权会话后可验证后台漏洞' },
									],
									summary: '登录接口无弱口令防护，直接爆破进入',
								},
								self_check: {
									reproducible: true,
									prerequisites: '目标在授权范围内',
									impact: '未授权访问后台/管理功能',
									severity: 'high',
									priority: 'P1',
								},
							},
						});
						if (finding) {
							result.findingsCreated++;
						} else {
							result.deduped++;
						}
					} catch {
						// 忽略证据问题
					}
				}
			}
		}
	}

	return result;
}

/** nuclei 模板 ID → OWASP 分类（粗略映射，容错 undefined） */
function classifyTemplate(templateId: string | undefined): string {
	const t = (templateId ?? '').toLowerCase();
	if (t.includes('sqli') || t.includes('injection')) return 'injection';
	if (t.includes('xss')) return 'xss';
	if (t.includes('ssrf')) return 'ssrf';
	if (t.includes('lfi') || t.includes('traversal')) return 'path_traversal';
	if (t.includes('rce') || t.includes('command')) return 'injection';
	if (t.includes('upload')) return 'file_upload';
	if (t.includes('idor')) return 'idor';
	if (t.includes('deserial')) return 'deserialization';
	if (t.includes('xxe')) return 'xxe';
	if (t.includes('exposure') || t.includes('info') || t.includes('leak')) return 'info_disclosure';
	return 'other';
}

function portOf(target: string): number | null {
	const m = target.match(/:(\d+)/);
	return m ? Number.parseInt(m[1], 10) : null;
}

/** --login-url 是否属于当前目标（host 相同且端口匹配，或 host 相同且目标无端口） */
function loginUrlMatchesTarget(loginUrl: string, target: string): boolean {
	try {
		const u = new URL(loginUrl);
		const tHost = target.includes('://') ? new URL(target).hostname : target.split(':')[0];
		if (u.hostname.toLowerCase() !== tHost.toLowerCase()) return false;
		const targetPort = portOf(target);
		if (targetPort === null) return true; // 目标无端口 → 视为匹配
		return u.port === String(targetPort);
	} catch {
		return false;
	}
}

/** 从探活响应中提取登录接口 URL（简单启发式） */
function detectLoginUrl(body: string, baseUrl: string): string | null {
	const patterns = [/login[^\s"\']*\.(php|html|jsp|do)?/i, /auth\/login/i];
	for (const re of patterns) {
		const m = body.match(re);
		if (m) {
			const p = m[0].replace(/^["']/, '');
			if (p.startsWith('http')) return p;
			return new URL(p, baseUrl).href;
		}
	}
	return null;
}

/** 弱口令尝试（护栏内，返回命中的 [user, pass] 列表） */
async function weakPasswordAttempt(loginUrl: string): Promise<Array<[string, string]>> {
	const accounts = ['admin', 'root', 'test'];
	const passwords = ['admin', '123456', 'password', 'admin123', 'root', '12345678', 'admin888'];
	const success: Array<[string, string]> = [];
	let attempts = 0;
	for (const user of accounts) {
		let acct = 0;
		for (const pass of passwords) {
			if (acct >= 3 || attempts >= 50) break;
			attempts++;
			acct++;
			await new Promise((r) => setTimeout(r, 800)); // 限速防锁
			try {
				const res = await httpReqTool.execute('auth', {
					url: loginUrl,
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ username: user, password: pass }),
					followRedirects: false,
				});
				const text = res.content.find((c) => c.type === 'text')?.text ?? '';
				const lower = text.toLowerCase();
				const locMatch = text.match(/location:\s*([^\r\n]+)/i);
				const location = (locMatch?.[1] ?? '').trim().toLowerCase();
				// 成功判定需显式信号（防假阳性——不能「任意 3xx 或任意 200」都算成功）
				const isSuccess =
					res.details.status >= 300 && res.details.status < 400
						? !/(login|signin|error|fail|invalid|retry|denied)/.test(location)
						: lower.includes('"success":true') || lower.includes('"token"');
				if (isSuccess) {
					success.push([user, pass]);
					break;
				}
			} catch {
				// 失败继续
			}
		}
	}
	return success;
}

/** verify 主流程（端口并行，默认并发 6；nuclei/dirsearch 每端口内部串行） */
export async function runVerify(o: VerifyOptions): Promise<VerifyTargetResult[]> {
	const store = new FindingStore();
	const results: VerifyTargetResult[] = [];

	// 并行执行（授权靶场并行 6 无压力；对真实目标可用 --concurrency 调低）
	const concurrency = Math.min(o.targets.length, o.concurrency ?? 6);
	let cursor = 0;
	const worker = async (): Promise<void> => {
		for (;;) {
			const idx = cursor++;
			if (idx >= o.targets.length) return;
			results[idx] = await verifyTarget(o, o.targets[idx]!, store);
		}
	};
	await Promise.all(Array.from({ length: concurrency }, () => worker()));

	console.log('\n[verify] ═══ 汇总 ═══');
	for (const r of results) {
		console.log(
			`  ${r.target}: ${r.reachable ? `HTTP ${r.httpStatus}` : '不可达'} · nuclei=${r.nucleiHits} · dir=${r.dirFound} · findings=${r.findingsCreated}${r.deduped > 0 ? ` · dedup=${r.deduped}` : ''}`,
		);
	}
	const total = results.reduce((a, r) => a + r.findingsCreated, 0);
	const deduped = results.reduce((a, r) => a + r.deduped, 0);
	console.log(
		`\n[verify] 本次新增 ${total} 条 finding（pending），dedup 拦截重复 ${deduped} 条（防重复入库）`,
	);
	return results;
}
