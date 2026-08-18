/**
 * worker 上下文管理工具（M4.6，借鉴 AutoHunter session_set/update_notes）
 *
 * - update_notes：worker 写工作笔记（跨轮记忆），每轮经 transformContext 注入 prompt
 * - session_set：登记会话 cookie/header，后续 http_req 自动携带（轻量版：存笔记里）
 *
 * 作用：历史被压缩/轮次推进时，worker 仍知道自己的进度与持有的登录态。
 */
import type { AgentTool, AgentToolResult } from '@earendil-works/pi-agent-core';
import { Type } from 'typebox';

export interface NotesStore {
	notes: string[];
	session: Record<string, unknown>;
	setNotes(notes: string): void;
	setSession(k: string, v: unknown): void;
}

export function createNotesStore(): NotesStore {
	return {
		notes: [],
		session: {},
		setNotes(n) {
			this.notes.push(n);
			if (this.notes.length > 20) this.notes = this.notes.slice(-20);
		},
		setSession(k, v) {
			this.session[k] = v;
		},
	};
}

/** 把 notes/session 渲染成每轮注入的状态块 */
export function renderSessionStatus(store: NotesStore): string {
	const parts: string[] = [];
	if (store.notes.length > 0) {
		parts.push('工作笔记:');
		for (const n of store.notes.slice(-8)) {
			parts.push(`  - ${n.slice(0, 200)}`);
		}
	}
	if (Object.keys(store.session).length > 0) {
		parts.push('会话状态:');
		for (const [k, v] of Object.entries(store.session)) {
			parts.push(`  - ${k}: ${String(v).slice(0, 100)}`);
		}
	}
	return parts.length > 0 ? `【当前工作状态】\n${parts.join('\n')}` : '';
}

// ---------------------------------------------------------------------------
// update_notes 工具
// ---------------------------------------------------------------------------

const updateNotesParams = Type.Object({
	notes: Type.String({
		description:
			'工作笔记内容（追加式）。记录：已测过的接口/参数、发现的线索、下一步计划、持有的凭证/会话。每轮自动注入 prompt，跨轮记忆。',
	}),
});

export interface NotesDetails {
	noteCount: number;
}

export const updateNotesTool: AgentTool<typeof updateNotesParams, NotesDetails> = {
	name: 'update_notes',
	label: '记录工作笔记',
	description:
		'把当前进度/线索/计划写入工作笔记（跨轮记忆）。每轮会自动显示最近笔记。重要发现、待办、已测接口务必记录，防止轮次推进丢失上下文。',
	parameters: updateNotesParams,
	execute: async (_toolCallId, params): Promise<AgentToolResult<NotesDetails>> => {
		void params;
		return {
			content: [{ type: 'text', text: 'note recorded (via transformContext store)' }],
			details: { noteCount: 0 },
		};
	},
};

/** 工厂：绑定 NotesStore 的真正 update_notes 工具（worker/escalate 用） */
export function createNotesTool(
	store: NotesStore,
): AgentTool<typeof updateNotesParams, NotesDetails> {
	return {
		name: 'update_notes',
		label: '记录工作笔记',
		description:
			'把当前进度/线索/计划写入工作笔记（跨轮记忆）。每轮会自动显示最近笔记。重要发现、待办、已测接口务必记录，防止轮次推进丢失上下文。',
		parameters: updateNotesParams,
		execute: async (_toolCallId, params): Promise<AgentToolResult<NotesDetails>> => {
			store.setNotes(params.notes);
			return {
				content: [{ type: 'text', text: `笔记已记录（共 ${store.notes.length} 条）` }],
				details: { noteCount: store.notes.length },
			};
		},
	};
}
