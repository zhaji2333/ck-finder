import { reactive } from 'vue';

// 跨 tab 共享的极简状态（导航 + 挖洞草稿）
export const nav = reactive({
  active: 'board',
});

export const huntDraft = reactive({
  seed: '',
  scope: '',
  goal: '',
  seedId: '', // 派发后跟踪的 campaign seedId（用于挖洞 tab 轮询该任务的意图）
});

/** 从任务/资产一键转到挖洞：预填 seed/scope，切到挖洞 tab */
export function goHunt(seed: string, scope: string, goal = '', seedId = '') {
  huntDraft.seed = seed;
  huntDraft.scope = scope;
  huntDraft.goal = goal;
  huntDraft.seedId = seedId;
  nav.active = 'hunt';
}
