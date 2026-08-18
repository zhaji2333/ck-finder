<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import { api, type Group, type SeedRow } from '../api';
import Panel from '../components/Panel.vue';
import Badge from '../components/Badge.vue';
import { goHunt } from '../store';

const groups = ref<Group[]>([]);
const groupId = ref('');
const groupScopeHint = ref('');
const seed = ref('');
const mode = ref('auto');
const submitMsg = ref('');

const icpName = ref('');
const icpCompany = ref('');
const icpMsg = ref('');
const icpTasks = ref<Array<Record<string, unknown>>>([]);

const seeds = ref<SeedRow[]>([]);
const selectedIds = ref<string[]>([]);
const sources = ref<Array<Record<string, unknown>>>([]);

let pollTimer: ReturnType<typeof setInterval> | null = null;

async function loadGroups() {
  try {
    const d = await api.groups();
    groups.value = d.groups;
  } catch {
    /* ignore */
  }
}

async function loadAll() {
  loadGroups();
  try {
    const [s, src, icp] = await Promise.all([api.seeds(100), api.sources(50), api.icpList()]);
    seeds.value = s.seeds;
    sources.value = (src.sourceDumps || src.records || []) as Array<Record<string, unknown>>;
    icpTasks.value = icp.tasks as Array<Record<string, unknown>>;
  } catch (e) {
    submitMsg.value = (e as Error).message;
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(loadAll, 3000);
}

function onGroupChange() {
  const g = groups.value.find((x) => x.id === groupId.value);
  groupScopeHint.value = g ? `组范围：${(g.scope || []).join(', ')}` : '';
}

async function submitScan() {
  if (groupId.value) {
    const g = groups.value.find((x) => x.id === groupId.value);
    if (!g || !(g.scope || []).length) {
      alert('该资产组无范围');
      return;
    }
    if (!confirm(`对资产组「${g.name}」的 ${g.scope.length} 个范围提交扫描？`)) return;
    submitMsg.value = '提交资产组扫描中…';
    try {
      const r = await api.groupCollect(g.id);
      submitMsg.value = `✓ 已触发资产组「${g.name}」扫描（${r.collectStarted} 个范围），轮询进度中`;
      startPolling();
    } catch (e) {
      submitMsg.value = '提交失败: ' + (e as Error).message;
    }
    return;
  }
  if (!seed.value.trim()) {
    alert('请输入种子，或选择一个资产组');
    return;
  }
  submitMsg.value = '提交中…';
  try {
    const r = await api.seedSubmit(seed.value.trim(), mode.value);
    api.scopeChange('add', seed.value.trim()).catch(() => {});
    submitMsg.value = `已提交 ${r.seedId.slice(0, 8)}（异步扫描，轮询进度中）`;
    seed.value = '';
    startPolling();
  } catch (e) {
    submitMsg.value = '提交失败: ' + (e as Error).message;
  }
}

async function submitIcp() {
  if (!icpCompany.value.trim()) {
    alert('请输入公司名称');
    return;
  }
  icpMsg.value = '提交 ICP 反查中…';
  try {
    const r = await api.icpSubmit(icpName.value.trim(), icpCompany.value.trim());
    icpMsg.value = `✓ 已提交 ICP 查询（${r.company}），后台反查备案域名中`;
    icpName.value = '';
    icpCompany.value = '';
    loadAll();
  } catch (e) {
    icpMsg.value = '提交失败: ' + (e as Error).message;
  }
}

function toggleSel(id: string, checked: boolean) {
  selectedIds.value = checked ? [...selectedIds.value, id] : selectedIds.value.filter((x) => x !== id);
}

function selectAll() {
  const all = seeds.value.map((s) => s.id);
  selectedIds.value = selectedIds.value.length === all.length && all.length ? [] : all;
}

async function batchDelete() {
  const ids = selectedIds.value;
  if (!ids.length) {
    alert('请先勾选要删除的任务');
    return;
  }
  if (!confirm(`批量删除 ${ids.length} 个任务及其全部资产/意图/漏洞数据？`)) return;
  try {
    const r = await api.seedBatchDelete(ids);
    alert(`已批量删除 ${r.deleted} 个任务`);
    selectedIds.value = [];
    loadAll();
  } catch (e) {
    alert('批量删除失败: ' + (e as Error).message);
  }
}

async function deleteSeed(id: string) {
  if (!confirm('删除该任务及其全部资产/意图/漏洞数据（级联删除）？')) return;
  try {
    await api.seedDelete(id);
    loadAll();
  } catch (e) {
    alert('删除失败: ' + (e as Error).message);
  }
}

async function recover() {
  if (!confirm('把超过 30 分钟仍 running 的滞留任务标记为完成/失败（清理服务器重启残留）？')) return;
  try {
    const r = await api.recover();
    alert(`已恢复：清理 ${r.staleRuns} 个滞留子任务、${r.recoveredSeeds} 个任务`);
    loadAll();
  } catch (e) {
    alert('恢复失败: ' + (e as Error).message);
  }
}

function hostOf(v: string): string {
  let host = v;
  if (/^https?:\/\//.test(host)) {
    try {
      host = new URL(host).hostname;
    } catch {
      host = host.replace(/^https?:\/\//, '').split('/')[0];
    }
  }
  return host.split(':')[0];
}

function isHunting(s: SeedRow): boolean {
  return (s.intentCounts?.running ?? 0) + (s.intentCounts?.pending ?? 0) > 0;
}

function activeIntentCount(s: SeedRow): number {
  return (s.intentCounts?.running ?? 0) + (s.intentCounts?.pending ?? 0);
}

function toHunt(i: number) {
  const s = seeds.value[i];
  if (!s) return;
  goHunt(s.value, hostOf(s.value));
}

const huntingId = ref('');

async function huntNow(s: SeedRow) {
  const host = hostOf(s.value);
  if (!confirm(`对「${s.value}」直接派发挖洞（planner → worker 后台执行）？`)) return;
  huntingId.value = s.id;
  try {
    const d = await api.run({ seed: s.value, scope: [host], maxRounds: 2 });
    goHunt(s.value, host, '', d.seedId);
  } catch (e) {
    alert('派发失败: ' + (e as Error).message);
  } finally {
    huntingId.value = '';
  }
}

async function batchHunt() {
  const list = seeds.value.filter((s) => selectedIds.value.includes(s.id));
  if (!list.length) {
    alert('请先勾选要挖洞的任务');
    return;
  }
  const urls = list.map((s) => s.value);
  if (!confirm(`对 ${urls.length} 个任务批量并发直打挖洞？`)) return;
  try {
    const r = await api.hunt({ urls });
    alert(`已启动 ${r.started} 个站点挖洞，去「挖洞」tab 查看`);
    selectedIds.value = [];
    goHunt(urls[0], hostOf(urls[0]));
  } catch (e) {
    alert('批量挖洞失败: ' + (e as Error).message);
  }
}

onMounted(() => {
  loadAll();
  startPolling(); // 自动轮询：挖洞中标记/任务状态实时刷新
});
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">03</span><h2>任务管理</h2><span class="h-note">提交扫描 · ICP 备案查询 · 源码包</span></div>

    <Panel title="提交扫描任务 · SUBMIT SEED">
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 14px">
        <div class="field">
          <label>资产组 GROUP（选中后扫描该组范围）</label>
          <select v-model="groupId" @change="onGroupChange">
            <option value="">手动输入种子</option>
            <option v-for="g in groups" :key="g.id" :value="g.id">{{ g.name }}（{{ (g.scope || []).length }} 个范围）</option>
          </select>
        </div>
        <div class="field">
          <label>种子 SEED（手动时必填）</label>
          <input v-model="seed" placeholder="域名/URL/IP/CIDR/公司名" />
        </div>
        <div class="field">
          <label>模式 MODE</label>
          <select v-model="mode">
            <option value="auto">auto（URL→单站/其余→全量）</option>
            <option value="site">site（单站，不扩大范围）</option>
            <option value="full">full（全量资产发现）</option>
          </select>
        </div>
        <div class="field" style="display: flex; align-items: flex-end">
          <button class="btn primary" @click="submitScan">▶ 提交扫描</button>
        </div>
      </div>
      <div class="hint" v-if="groupScopeHint" style="margin-bottom: 4px">{{ groupScopeHint }}</div>
      <div class="hint">{{ submitMsg }}</div>
    </Panel>

    <Panel title="ICP 备案查询 · ICP QUERY（公司名 → 备案域名）">
      <div style="display: grid; grid-template-columns: 1fr 2fr 1fr; gap: 14px">
        <div class="field"><label>任务名称 NAME</label><input v-model="icpName" placeholder="如：某公司备案资产" /></div>
        <div class="field"><label>公司名称 COMPANY</label><input v-model="icpCompany" placeholder="如：北京百度网讯科技有限公司" /></div>
        <div class="field" style="display: flex; align-items: flex-end"><button class="btn primary" @click="submitIcp">▶ 查询备案</button></div>
      </div>
      <div class="hint">{{ icpMsg }}</div>
      <div class="sub-h">ICP 查询任务</div>
      <table v-if="icpTasks.length">
        <thead><tr><th>任务</th><th>公司</th><th>状态</th><th>备案域名</th><th>子域</th><th>站点</th></tr></thead>
        <tbody>
          <tr v-for="t in icpTasks" :key="String(t.id)">
            <td style="font-weight: 600">{{ t.name }}</td>
            <td class="trunc" style="max-width: 220px">{{ t.company }}</td>
            <td><Badge :value="String(t.status === 'done' ? 'done' : t.status)" /></td>
            <td class="mono">{{ t.icp_domain_count ?? 0 }}</td>
            <td class="mono">{{ t.subdomain_count ?? 0 }}</td>
            <td class="mono">{{ t.webapp_count ?? 0 }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">暂无 ICP 查询任务</div>
    </Panel>

    <Panel title="扫描任务 · SEEDS">
      <template #hd>
        <button class="btn sm primary" style="margin-left: 8px" @click="batchHunt">⚔ 批量挖洞 ({{ selectedIds.length }})</button>
        <button class="btn sm danger" @click="batchDelete">批量删除 ({{ selectedIds.length }})</button>
        <button class="btn sm" @click="selectAll">全选</button>
        <button class="btn sm" title="清理服务器重启遗留的 running 任务" @click="recover">恢复滞留</button>
        <button class="btn sm" style="margin-left: auto" @click="loadAll">刷新</button>
      </template>
      <div class="table-wrap">
        <table v-if="seeds.length">
          <thead><tr><th>✓</th><th>任务</th><th>类型</th><th>状态</th><th>资产</th><th>Web应用</th><th>进度</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="(s, i) in seeds" :key="s.id">
              <td><input type="checkbox" :checked="selectedIds.includes(s.id)" @change="toggleSel(s.id, ($event.target as HTMLInputElement).checked)" /></td>
              <td class="trunc" style="max-width: 200px">
                <span v-if="s.meta?.hunt" class="badge b-medium" style="margin-right: 4px">⚔ 挖洞</span>
                <span v-else class="badge b-pending2" style="margin-right: 4px">收集</span>
                {{ s.value }}
              </td>
              <td class="mono">{{ s.seedType }}</td>
              <td>
                <Badge :value="s.status === 'done' ? 'done' : s.status" />
                <span v-if="isHunting(s)" class="badge b-running" style="margin-left: 4px">⚔ 挖洞中 {{ activeIntentCount(s) }}</span>
              </td>
              <td class="mono">{{ s.assetCount }}</td>
              <td class="mono">{{ s.webappCount }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ s.progress?.stageLabel || s.progress?.stage || '' }}</td>
              <td>
                <button class="btn sm primary" :disabled="huntingId === s.id" @click="huntNow(s)">⚔ 一键挖洞</button>
                <button class="btn sm" @click="toHunt(i)">转到挖洞</button>
                <button class="btn sm danger" @click="deleteSeed(s.id)">删除</button>
              </td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">暂无扫描任务</div>
      </div>
    </Panel>

    <Panel title="源码包 · SOURCE DUMPS">
      <div class="table-wrap">
        <table v-if="sources.length">
          <thead><tr><th>Web应用</th><th>已还原</th><th>文件数</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="(r, i) in sources" :key="i">
              <td class="trunc" style="max-width: 240px">{{ r.webapp_id || r.webappId || '—' }}</td>
              <td><span v-if="r.restored" class="mono" style="color: var(--sig)">✓ 已还原</span><span v-else class="mono">—</span></td>
              <td class="mono">{{ r.file_count || r.fileCount || r.files || '—' }}</td>
              <td><a class="btn sm" :href="`/api/v1/sources/${r.webapp_id || r.webappId}/download`" target="_blank">下载</a></td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">暂无源码包</div>
      </div>
    </Panel>
  </div>
</template>
