<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import { api } from '../api';
import Panel from '../components/Panel.vue';
import { huntDraft } from '../store';

const seed = ref('');
const scope = ref('');
const goal = ref('');
const status = ref('');
const tasks = ref<Array<{ seedId: string; intents: Array<Record<string, unknown>> }>>([]);
const watchSeedId = ref('');
let pollTimer: ReturnType<typeof setInterval> | null = null;

async function launch() {
  if (!seed.value.trim()) {
    alert('请输入目标种子');
    return;
  }
  status.value = '启动中…';
  try {
    const d = await api.run({
      seed: seed.value.trim(),
      scope: scope.value ? scope.value.split(',').map((s) => s.trim()).filter(Boolean) : [],
      goal: goal.value.trim() || undefined,
      maxRounds: 2,
    });
    watchSeedId.value = d.seedId;
    status.value = `已启动 ${d.seedId.slice(0, 8)}，轮询意图…`;
    loadIntents();
    startPolling();
  } catch (e) {
    alert((e as Error).message);
    status.value = '';
  }
}

async function loadIntents() {
  try {
    const d = await api.intents(watchSeedId.value || undefined);
    if (d.intents) {
      tasks.value = d.intents.length ? [{ seedId: watchSeedId.value, intents: d.intents }] : [];
    } else {
      tasks.value = d.tasks ?? [];
    }
  } catch {
    tasks.value = [];
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(loadIntents, 3000);
}

async function clearStuck() {
  if (!confirm('将把超过 10 分钟未推进的 pending/running 意图标记为 canceled（不影响进行中任务）？')) return;
  try {
    const r = await api.cancelStuck();
    alert(`已清理 ${r.canceled} 条滞留意图`);
    loadIntents();
  } catch (e) {
    alert('清理失败: ' + (e as Error).message);
  }
}

function statusClass(st: string): string {
  return st === 'done' ? 'b-done' : st === 'running' ? 'b-running' : st === 'failed' ? 'b-failed' : 'b-pending';
}

// 站点 → 意图 可折叠展示
const expandedSites = ref<Set<string>>(new Set());
function toggleSite(id: string) {
  const s = new Set(expandedSites.value);
  if (s.has(id)) s.delete(id);
  else s.add(id);
  expandedSites.value = s;
}
function isExpanded(id: string): boolean {
  return expandedSites.value.has(id);
}
function siteName(t: { seedId: string; intents: Array<Record<string, unknown>> }): string {
  const first = t.intents[0];
  return (first?.scopeAnchor as string) || t.seedId.slice(0, 8);
}
function countBy(t: { intents: Array<Record<string, unknown>> }, st: string): number {
  return t.intents.filter((i) => i.status === st).length;
}

async function clearSite(t: { seedId: string; intents: Array<Record<string, unknown>> }) {
  if (!confirm(`清空「${siteName(t)}」的意图与事实（探索图），可重新挖？`)) return;
  try {
    const r = await api.clearIntents(t.seedId);
    alert(`已清空 ${r.intents} 条意图、${r.facts} 条事实`);
    expandedSites.value = new Set();
    loadIntents();
  } catch (e) {
    alert('清空失败: ' + (e as Error).message);
  }
}

onMounted(() => {
  if (huntDraft.seed) {
    seed.value = huntDraft.seed;
    scope.value = huntDraft.scope;
    goal.value = huntDraft.goal;
  }
  watchSeedId.value = huntDraft.seedId || '';
  if (watchSeedId.value) expandedSites.value = new Set([watchSeedId.value]);
  loadIntents();
  startPolling();
});
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">04</span><h2>自动挖洞</h2><span class="h-note">planner 派意图 → worker 执行 → 探索图</span></div>

    <Panel title="启动挖掘任务 · LAUNCH CAMPAIGN">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px">
        <div class="field"><label>目标种子 SEED</label><input v-model="seed" placeholder="域名 / URL / IP:端口" /></div>
        <div class="field"><label>授权范围 SCOPE（逗号分隔）</label><input v-model="scope" placeholder="example.com" /></div>
      </div>
      <div class="field" style="margin-top: 12px">
        <label>引导提示词 GOAL（可选，注入 planner/worker 初始提示）</label>
        <input v-model="goal" placeholder="如：重点挖掘 SQL 注入 / SSRF / 文件上传，不要挖掘反射 XSS" />
      </div>
      <div style="display: flex; gap: 10px; align-items: center">
        <button class="btn primary" @click="launch">▶ 启动挖掘</button>
        <button class="btn" @click="loadIntents">刷新进度</button>
        <button class="btn" title="把 pending/running 超 10 分钟未推进的滞留意图标记为 canceled" @click="clearStuck">清理滞留意图</button>
        <span class="hint" style="margin: 0">{{ status }}</span>
      </div>
    </Panel>

    <div class="h-sec" style="margin-top: 24px"><span class="idx">04a</span><h2>意图与事实</h2><span class="h-note">EXPLORATION GRAPH</span></div>

    <div v-if="!tasks.length" class="empty">暂无挖洞意图。先在「启动挖掘」提交任务。</div>
    <div v-for="t in tasks" :key="t.seedId" style="margin-bottom: 8px">
      <div class="row" style="cursor: pointer; padding: 10px 14px" @click="toggleSite(t.seedId)">
        <div class="row-head" style="flex-wrap: nowrap">
          <span class="mono" style="color: var(--sig); flex-shrink: 0">{{ isExpanded(t.seedId) ? '▾' : '▸' }}</span>
          <span class="row-title mono" style="min-width: 160px">{{ siteName(t) }}</span>
          <span class="mono" style="color: var(--ink-faint)">{{ t.intents.length }} 条意图</span>
          <span style="margin-left: auto; display: flex; gap: 6px; flex-shrink: 0; align-items: center">
            <span v-if="countBy(t, 'running')" class="badge b-running">{{ countBy(t, 'running') }} running</span>
            <span v-if="countBy(t, 'pending')" class="badge b-pending">{{ countBy(t, 'pending') }} pending</span>
            <span v-if="countBy(t, 'done')" class="badge b-done">{{ countBy(t, 'done') }} done</span>
            <span v-if="countBy(t, 'failed')" class="badge b-failed">{{ countBy(t, 'failed') }} failed</span>
            <button class="btn sm danger" title="清空该站点的意图与事实，重新挖" @click.stop="clearSite(t)">清空</button>
          </span>
        </div>
      </div>
      <div v-if="isExpanded(t.seedId)" style="padding-left: 14px; border-left: 1px solid var(--line); margin: 0 0 0 6px">
        <div v-for="i in t.intents" :key="String(i.id)" class="row intent">
          <div><span class="badge" :class="statusClass(String(i.status))">{{ i.status }}</span></div>
          <div>
            <div class="i-desc"><span class="i-type">#{{ i.intentType }}</span>{{ i.description }}</div>
            <div class="i-result">{{ i.resultSummary || '' }}</div>
            <div class="i-meta">{{ i.scopeAnchor }}<span v-if="i.assetId"> · asset {{ String(i.assetId).slice(0, 8) }}</span></div>
          </div>
          <div class="i-time">{{ String(i.updatedAt || '').slice(5, 16).replace('T', ' ') }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
