/**
 * finding_submit：漏洞 finding 提交工具（M3 终态工具）
 *
 * 强制证据 schema（validateEvidence 校验，缺字段抛错拒收）：
 *   poc / raw_request / raw_response / kill_chain / self_check 五件套。
 * worker 挖到漏洞后必须补齐完整证据才能提交。
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';
import type { FindingStatus, FindingStore } from '../validation/finding_store.js';
import { VULN_TYPES } from '../validation/schema.js';

export interface FindingSubmitDetails {
	findingId: string;
	status: FindingStatus;
}

const findingSubmitParams = Type.Object({
	seedId: Type.String({ description: '收集任务（种子）ID' }),
	vulnName: Type.String({ description: '漏洞名称，如 "SQL 注入 - id 参数"' }),
	vulnType: Type.Union([...VULN_TYPES.map((t) => Type.Literal(t))], {
		description: '漏洞分类（OWASP）',
	}),
	severity: Type.Union(
		[
			Type.Literal('critical'),
			Type.Literal('high'),
			Type.Literal('medium'),
			Type.Literal('low'),
			Type.Literal('info'),
		],
		{ description: '危害等级' },
	),
	url: Type.String({ description: '漏洞 URL（含参数与 payload）' }),
	intentId: Type.Optional(Type.String({ description: '来源意图 ID' })),
	assetId: Type.Optional(Type.String({ description: '锚点资产 ID' })),
	summary: Type.String({ description: '漏洞摘要（200 字内，结论先行）' }),
	// ---- 强制证据五件套 ----
	poc: Type.String({
		description: '复现步骤/Payload（一键可复现，如 curl 命令或完整请求序列）',
	}),
	rawRequest: Type.String({
		description: '原始请求原文（HTTP 格式，可用 http_req 的 raw_request）',
	}),
	rawResponse: Type.String({
		description: '原始响应原文（HTTP 格式，可用 http_req 的 raw_response，可截断关键部分）',
	}),
	killChain: Type.Object({
		chain: Type.Array(
			Type.Object({
				step: Type.String({ description: '攻击链步骤名，如 "输入点"/"传播"/"Sink"' }),
				detail: Type.String({ description: '该步骤细节' }),
			}),
			{ description: '攻击链步骤（成因→触发→影响），至少 1 步' },
		),
		summary: Type.String({ description: '攻击链总结' }),
	}),
	selfCheck: Type.Object({
		reproducible: Type.Boolean({ description: '是否可稳定复现' }),
		prerequisites: Type.String({ description: '利用前置条件（登录态/角色/网络/版本）' }),
		impact: Type.String({ description: '影响面（数据泄露/资金/提权/横向/持久化）' }),
		severity: Type.String({ description: '危害等级复核' }),
		priority: Type.String({ description: '修复优先级 P0/P1/P2' }),
	}),
});

export function createFindingSubmit(
	store: FindingStore,
): AgentTool<typeof findingSubmitParams, FindingSubmitDetails> {
	return {
		name: 'finding_submit',
		label: '提交漏洞 finding',
		description:
			'【终态工具，每轮只能调用一次】提交一个验证确认的漏洞 finding。必须携带完整证据五件套（poc/raw_request/raw_response/kill_chain/self_check），缺字段会被拒收。\n' +
			'证据来源：http_req 的 raw_request/raw_response 原文、实际测试的 Payload、攻击链分析与自我复核。\n' +
			'提交成功后 finding 进入 pending 状态，供 Reviewer/人工复审（M4）。',
		parameters: findingSubmitParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<FindingSubmitDetails>> => {
			// 代码层校验（缺字段抛错 → 拒收，worker 需补全）
			const finding = await store.insertFinding({
				seedId: params.seedId,
				intentId: params.intentId,
				assetId: params.assetId,
				vulnName: params.vulnName,
				vulnType: params.vulnType,
				severity: params.severity,
				url: params.url,
				summary: params.summary,
				evidence: {
					poc: params.poc,
					raw_request: params.rawRequest,
					raw_response: params.rawResponse,
					kill_chain: params.killChain,
					self_check: params.selfCheck,
				},
			});
			if (!finding) {
				// 查重命中（同 host+endpoint+类型已存在）→ 不落库，告知 worker
				return {
					content: [
						{
							type: 'text',
							text: 'finding 未提交：与已有 finding 重复（dedup_key 命中，host+路径+漏洞类型相同）。请勿重复提交，可改打其他接口/变体。',
						},
					],
					details: { findingId: '', status: 'pending' as FindingStatus },
					terminate: true,
				};
			}
			return {
				content: [
					{
						type: 'text',
						text: `finding 已提交: ${finding.id}\n漏洞: ${finding.vulnName} (${finding.severity})\nURL: ${finding.url}\n状态: pending（证据链完整 ✓）`,
					},
				],
				details: { findingId: finding.id, status: finding.status },
				terminate: true,
			};
		},
	};
}
