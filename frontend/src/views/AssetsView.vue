<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { api, type AssetStats, type Group, type WebappRow } from '../api';
import Panel from '../components/Panel.vue';
import StatCard from '../components/StatCard.vue';
import Modal from '../components/Modal.vue';
import { goHunt } from '../store';

const stats = ref<AssetStats | null>(null);
const scope = ref<string[]>([]);

// 添加资产
const addValue = ref('');
const addCollect = ref(true);
const addMsg = ref('');

// 资产组
const groups = ref<Group[]>([]);
const showGroupModal = ref(false);
const groupName = ref('');
const groupScopeRaw = ref('');

// 资产表
const assetType = ref('webapp');
const assetScore = ref(0);
const assetQuery = ref('');
const rows = ref<any[]>([]);
const selectedIds = ref<string[]>([]);
const webapps = ref<WebappRow[]>([]);

// 清理
const purgeDomain = ref('');

// 弹窗
const assetDetail = ref<Record<string, unknown> | null>(null);
const groupDetail = ref<{ group: Group; webappTotal: number; webapps: unknown[] } | null>(null);
const ipServices = ref<any[]>([]);
const ipServicesTitle = ref('');

async function loadStats() {
  try {
    stats.value = await api.assetStats();
  } catch {
    /* ignore */
  }
}
async function loadScope() {
  try {
    scope.value = (await api.scope()).scope;
  } catch {
    /* ignore */
  }
}
async function loadGroups() {
  try {
    groups.value = (await api.groups()).groups;
  } catch {
    /* ignore */
  }
}

async function loadAssets() {
  await Promise.all([loadStats(), loadScope(), loadGroups()]);
  try {
    const d = await api.assets(assetType.value, assetQuery.value, 500);
    rows.value = d.assets;
    if (assetType.value === 'webapp') webapps.value = (d.assets as WebappRow[]).filter((w) => (w.score ?? 0) >= assetScore.value);
  } catch {
    rows.value = [];
  }
}

async function addAsset() {
  if (!addValue.value.trim()) {
    alert('请输入域名 / IP / URL');
    return;
  }
  addMsg.value = '添加中…';
  try {
    const r = await api.assetAdd(addValue.value.trim(), addCollect.value);
    addMsg.value = `✓ 已添加 ${r.seedType} ${r.value} → 白名单 ${r.scopeEntry}${r.collectStarted ? ' · 信息收集已启动' : ''}`;
    addValue.value = '';
    loadAssets();
  } catch (e) {
    addMsg.value = '添加失败: ' + (e as Error).message;
  }
}

async function removeScope(v: string) {
  try {
    await api.scopeChange('remove', v);
    loadScope();
  } catch (e) {
    alert('移除失败: ' + (e as Error).message);
  }
}

function openGroupModal() {
  groupName.value = '';
  groupScopeRaw.value = '';
  showGroupModal.value = true;
}

async function createGroup() {
  const name = groupName.value.trim();
  const scopeList = [...new Set(groupScopeRaw.value.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean))];
  if (!name) {
    alert('请输入资产组名称');
    return;
  }
  if (!scopeList.length) {
    alert('请输入资产组范围（每行一个）');
    return;
  }
  try {
    await api.groupCreate({ name, scope: scopeList });
    showGroupModal.value = false;
    loadGroups();
    loadScope();
  } catch (e) {
    alert('新建失败: ' + (e as Error).message);
  }
}

async function groupDelete(id: string) {
  if (!confirm('删除资产组（不影响已发现资产与白名单）？')) return;
  try {
    await api.groupDelete(id);
    loadGroups();
  } catch (e) {
    alert('删除失败: ' + (e as Error).message);
  }
}

async function groupCollect(id: string) {
  if (!confirm('对资产组范围触发信息收集（异步，可能耗时数分钟）？')) return;
  try {
    const r = await api.groupCollect(id);
    alert(`已触发 ${r.collectStarted} 个范围的收集`);
  } catch (e) {
    alert('收集失败: ' + (e as Error).message);
  }
}

async function showGroupDetail(id: string) {
  try {
    groupDetail.value = await api.groupDetail(id);
  } catch (e) {
    alert((e as Error).message);
  }
}

async function showAssetDetail(id: string) {
  try {
    assetDetail.value = await api.assetMetadata(id);
  } catch (e) {
    alert((e as Error).message);
  }
}

async function deepScan(id: string) {
  if (!confirm('深挖将执行 dirscan/jsmining/源码收集，耗时 5-30 分钟，确认？')) return;
  try {
    const r = await api.deepScan(id);
    alert(`深挖完成: 跑了 ${(r.ranTasks || []).join(', ')} · 终评 ${r.finalScore} L${r.finalLevel}`);
  } catch (e) {
    alert('深挖失败: ' + (e as Error).message);
  }
}

async function showIpServices(ip: string) {
  try {
    const d = await api.assets('service', ip, 200);
    ipServices.value = (d.assets as Array<Record<string, unknown>>).filter((s) => String(s.ip).replace(/\/32$/, '') === ip.replace(/\/32$/, ''));
    ipServicesTitle.value = `IP ${ip} · 端口服务`;
  } catch (e) {
    alert((e as Error).message);
  }
}

function toggleAsset(id: string, checked: boolean) {
  selectedIds.value = checked ? [...selectedIds.value, id] : selectedIds.value.filter((x) => x !== id);
}

async function huntSelected() {
  const urls = webapps.value.filter((w) => selectedIds.value.includes(w.assetId)).map((w) => w.url);
  if (!urls.length) {
    alert('请先在「站点」视图勾选要挖洞的资产');
    return;
  }
  if (!confirm(`对 ${urls.length} 个站点并发直打挖洞？`)) return;
  try {
    const r = await api.hunt({ urls });
    alert(`已启动 ${r.started} 个站点挖洞`);
    selectedIds.value = [];
    loadAssets();
  } catch (e) {
    alert('挖洞启动失败: ' + (e as Error).message);
  }
}

function selectAllWebapps() {
  const all = webapps.value.map((w) => w.assetId);
  selectedIds.value = selectedIds.value.length === all.length && all.length ? [] : all;
}

async function purge() {
  const d = purgeDomain.value.trim();
  if (!d) {
    alert('请输入要清理的域名');
    return;
  }
  if (!confirm(`将删除域名「${d}」及其子域对应的全部任务与资产数据？`)) return;
  try {
    const r = await api.purge(d);
    alert(`已清理：删除 ${r.deletedSeeds} 个任务、${r.deletedAssets} 个资产`);
    purgeDomain.value = '';
    loadAssets();
  } catch (e) {
    alert('清理失败: ' + (e as Error).message);
  }
}

async function deleteAsset(id: string) {
  if (!confirm('删除该资产及其关联数据？')) return;
  try {
    await api.assetDelete(id);
    loadAssets();
  } catch (e) {
    alert('删除失败: ' + (e as Error).message);
  }
}

function toHuntUrl(url: string) {
  let host = url;
  try {
    host = new URL(url).hostname;
  } catch {
    /* ignore */
  }
  goHunt(url, host);
}

function roleBadgeClass(role: string): string {
  return role === 'admin' ? 'b-critical' : role === 'api' ? 'b-low' : 'b-medium';
}

const statCards = computed(() => {
  if (!stats.value) return [];
  const s = stats.value;
  return [
    { num: s.domain, label: '域名', sub: `根域 ${s.types.domain ?? 0} · 子域 ${s.types.subdomain ?? 0}` },
    { num: s.ip, label: 'IP 资产', sub: `存活 ${s.alive}` },
    { num: s.webapp, label: '站点', sub: Object.entries(s.roles).slice(0, 3).map(([k, v]) => `${k} ${v}`).join(' · ') },
    { num: s.services, label: '端口服务', sub: `覆盖 IP ${s.ips}` },
  ];
});

let pollTimer: ReturnType<typeof setInterval> | null = null;
onMounted(() => {
  loadAssets();
  // 自动轮询：挖洞中标记（activeIntents）实时刷新
  pollTimer = setInterval(loadAssets, 3000);
});
onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">02</span><h2>资产管理</h2><span class="h-note">资产测绘 · 站点 / 域名 / IP / 端口服务</span></div>

    <Panel title="添加资产 · ADD ASSET（自动加入授权白名单）">
      <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap">
        <div class="field" style="flex: 1; min-width: 260px; margin: 0">
          <input v-model="addValue" placeholder="域名 / IP / URL，如 example.com 或 http://192.0.2.10:8080" />
        </div>
        <label style="display: flex; align-items: center; gap: 6px; font-family: var(--mono); font-size: 11px; color: var(--ink-dim); white-space: nowrap; cursor: pointer">
          <input v-model="addCollect" type="checkbox" /> 同时信息收集
        </label>
        <button class="btn primary" @click="addAsset">＋ 添加资产</button>
      </div>
      <div class="hint">{{ addMsg }}</div>
      <div class="sub-h">授权范围 WHITELIST（资产范围自带白名单）</div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap">
        <span v-for="s in scope" :key="s" class="badge b-reviewed" style="display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; font-size: 11px">
          {{ s }}
          <button class="icon-btn" style="width: 18px; height: 18px; font-size: 10px; border: none" title="移除白名单" @click="removeScope(s)">✕</button>
        </span>
        <span v-if="!scope.length" class="hint">（空）添加资产后自动写入白名单，或去「设置」配置</span>
      </div>
    </Panel>

    <Panel title="资产组 · ASSET GROUPS">
      <template #hd><button class="btn sm" style="margin-left: auto" @click="loadGroups">刷新</button></template>
      <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 14px">
        <button class="btn primary" @click="openGroupModal">＋ 新建资产组</button>
        <span class="hint" style="margin: 0">按「名称 + 范围」组织资产，范围每行一个（域名/IP/URL/CIDR）</span>
      </div>
      <table v-if="groups.length">
        <thead><tr><th>资产组</th><th>范围</th><th>站点</th><th>域名</th><th>创建</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="g in groups" :key="g.id">
            <td style="font-weight: 600">{{ g.name }}</td>
            <td class="mono" style="max-width: 260px; word-break: break-all">{{ (g.scope || []).join(', ') }}</td>
            <td class="mono">{{ g.webapp_count ?? 0 }}</td>
            <td class="mono">{{ g.domain_count ?? 0 }}</td>
            <td class="mono" style="color: var(--ink-faint)">{{ (g.created_at || '').slice(0, 10) }}</td>
            <td>
              <button class="btn sm" @click="showGroupDetail(g.id)">详情</button>
              <button class="btn sm" @click="groupCollect(g.id)">收集</button>
              <button class="btn sm" @click="groupDelete(g.id)">删除</button>
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">暂无资产组。新建资产组按「名称 + 范围」组织资产。</div>
    </Panel>

    <div class="stat-grid" style="grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); margin-bottom: 18px">
      <StatCard v-for="(c, i) in statCards" :key="i" :num="c.num" :label="c.label" :sub="c.sub" />
    </div>

    <div class="toolbar">
      <div class="seg">
        <button :class="{ active: assetType === 'webapp' }" @click="assetType = 'webapp'; loadAssets()">站点</button>
        <button :class="{ active: assetType === 'domain' }" @click="assetType = 'domain'; loadAssets()">域名</button>
        <button :class="{ active: assetType === 'ip' }" @click="assetType = 'ip'; loadAssets()">IP</button>
        <button :class="{ active: assetType === 'service' }" @click="assetType = 'service'; loadAssets()">端口服务</button>
      </div>
      <div class="seg">
        <button :class="{ active: assetScore === 0 }" @click="assetScore = 0; loadAssets()">全部评分</button>
        <button :class="{ active: assetScore === 60 }" @click="assetScore = 60; loadAssets()">≥60</button>
        <button :class="{ active: assetScore === 80 }" @click="assetScore = 80; loadAssets()">≥80</button>
      </div>
      <div class="field" style="margin: 0; flex: 1; max-width: 300px">
        <input v-model="assetQuery" placeholder="搜索 URL / 域名 / IP / 服务…" @keyup.enter="loadAssets" />
      </div>
      <div class="field" style="margin: 0; max-width: 200px">
        <input v-model="purgeDomain" placeholder="按域名清理，如 example.com" />
      </div>
      <button class="btn danger" title="删除该域名及其子域对应的全部资产与数据" @click="purge">清理</button>
      <button class="btn" @click="loadAssets">刷新</button>
    </div>

    <div class="toolbar" style="margin-bottom: 14px">
      <button class="btn primary" title="对勾选的站点资产并发直打挖洞" @click="huntSelected">⚔ 一键挖洞 ({{ selectedIds.length }})</button>
      <button class="btn" @click="selectAllWebapps">全选站点</button>
    </div>

    <Panel>
      <div class="table-wrap">
        <!-- 站点 -->
        <table v-if="assetType === 'webapp'">
          <thead><tr><th>✓</th><th>评分</th><th>角色</th><th>URL</th><th>技术栈</th><th>发现</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="w in webapps" :key="w.assetId">
              <td><input type="checkbox" :checked="selectedIds.includes(w.assetId)" @change="toggleAsset(w.assetId, ($event.target as HTMLInputElement).checked)" /></td>
              <td class="mono" style="font-weight: 600" :style="`color:${w.score >= 80 ? 'var(--sig)' : 'var(--ink)'}`">{{ w.score }}</td>
              <td><span v-if="w.role" class="badge" :class="roleBadgeClass(w.role)">{{ w.role }}</span><span v-else>—</span></td>
              <td class="trunc" style="max-width: 300px">{{ w.url }}</td>
              <td class="mono trunc" style="max-width: 150px; color: var(--ink-dim)">{{ (w.tech || []).join(', ').slice(0, 60) }}</td>
              <td><span v-if="w.findingCount" class="mono" style="color: var(--warn)">{{ w.findingCount }} ⚠</span><span v-else>—</span></td>
              <td class="mono" style="color: var(--ink-faint)">{{ w.statusCode ?? '—' }}<span v-if="w.loginPage" style="color: var(--warn)"> · 登录</span><span v-if="w.cdn"> · CDN</span><span v-if="w.activeIntents" class="badge b-running" style="margin-left: 4px">⚔ {{ w.activeIntents }}</span></td>
              <td>
                <button class="btn sm" @click="showAssetDetail(w.assetId)">详情</button>
                <button class="btn sm" @click="toHuntUrl(w.url)">挖洞</button>
                <button class="btn sm danger" @click="deleteAsset(w.assetId)">删除</button>
              </td>
            </tr>
            <tr v-if="!webapps.length"><td colspan="8"><div class="empty">无匹配站点</div></td></tr>
          </tbody>
        </table>

        <!-- 域名 -->
        <table v-else-if="assetType === 'domain'">
          <thead><tr><th>类型</th><th>资产值</th><th>来源</th><th>存活</th><th>发现时间</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="a in rows" :key="String(a.id)">
              <td><span class="badge" :class="a.type === 'subdomain' ? 'b-low' : 'b-medium'">{{ a.type === 'subdomain' ? '子域' : '根域' }}</span></td>
              <td class="mono" style="word-break: break-all">{{ a.value }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ a.discovered_by || '—' }}</td>
              <td><span v-if="a.alive === true" class="mono" style="color: var(--sig)">存活</span><span v-else-if="a.alive === false" class="mono" style="color: var(--danger)">失活</span><span v-else>—</span></td>
              <td class="mono" style="color: var(--ink-faint)">{{ String(a.first_seen || '').slice(0, 10) }}</td>
              <td><button class="btn sm danger" @click="deleteAsset(String(a.id))">删除</button></td>
            </tr>
            <tr v-if="!rows.length"><td colspan="6"><div class="empty">无域名资产</div></td></tr>
          </tbody>
        </table>

        <!-- IP -->
        <table v-else-if="assetType === 'ip'">
          <thead><tr><th>IP</th><th>ASN/组织</th><th>ISP</th><th>地区</th><th>CDN</th><th>端口</th><th>操作</th></tr></thead>
          <tbody>
            <tr v-for="a in rows" :key="String(a.id)">
              <td class="mono" style="font-weight: 600">{{ a.ip }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ a.asn ? `AS${a.asn} ` : '' }}{{ a.org || '—' }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ a.isp || '—' }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ [a.country, a.region, a.city].filter(Boolean).join(' ') || '—' }}</td>
              <td><span v-if="a.cdn_flag" class="mono" style="color: var(--warn)">CDN<span v-if="a.cdn_vendor">·{{ a.cdn_vendor }}</span></span><span v-else>—</span></td>
              <td class="mono">{{ a.svc_count ?? 0 }}</td>
              <td>
                <button class="btn sm" @click="showIpServices(String(a.ip))">端口</button>
                <button class="btn sm danger" @click="deleteAsset(String(a.id))">删除</button>
              </td>
            </tr>
            <tr v-if="!rows.length"><td colspan="7"><div class="empty">无 IP 资产</div></td></tr>
          </tbody>
        </table>

        <!-- 端口服务 -->
        <table v-else>
          <thead><tr><th>IP:端口</th><th>协议</th><th>服务</th><th>版本</th><th>HTTP</th><th>横幅</th><th>最后发现</th></tr></thead>
          <tbody>
            <tr v-for="a in rows" :key="String(a.id)">
              <td class="mono" style="font-weight: 600">{{ a.ip }}:{{ a.port }}</td>
              <td class="mono">{{ a.protocol || 'tcp' }}</td>
              <td class="mono" :style="`color:${a.service && a.service !== 'unknown' ? 'var(--sig)' : 'var(--ink-dim)'}`">{{ a.service || '—' }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ a.version || '' }}</td>
              <td><span v-if="a.is_http" class="mono" style="color: var(--sig)">HTTP</span><span v-else>—</span></td>
              <td class="mono trunc" style="max-width: 240px; color: var(--ink-faint)" :title="String(a.banner || '')">{{ String(a.banner || '').slice(0, 50) }}</td>
              <td class="mono" style="color: var(--ink-faint)">{{ String(a.last_seen || '').slice(0, 10) }}</td>
            </tr>
            <tr v-if="!rows.length"><td colspan="7"><div class="empty">无端口服务</div></td></tr>
          </tbody>
        </table>
      </div>
    </Panel>

    <!-- 新建资产组弹窗 -->
    <Modal title="新建资产组" :open="showGroupModal" @close="showGroupModal = false">
      <div class="field">
        <label>资产组名称 NAME</label>
        <input v-model="groupName" placeholder="如：生产环境 / 某客户目标" />
      </div>
      <div class="field">
        <label>资产组范围 SCOPE（每行一个：域名 / IP / URL / CIDR）</label>
        <textarea v-model="groupScopeRaw" rows="9" placeholder="example.com&#10;192.0.2.10&#10;*.foo.com&#10;10.0.0.0/24"></textarea>
        <div class="hint">每行一个资产，空行自动忽略；也会兼容逗号/分号分割</div>
      </div>
      <div style="display: flex; gap: 10px; align-items: center">
        <button class="btn primary" @click="createGroup">创建资产组</button>
        <button class="btn" @click="showGroupModal = false">取消</button>
      </div>
    </Modal>

    <!-- 资产详情弹窗 -->
    <Modal :open="!!assetDetail" :title="assetDetail ? String((assetDetail.webapp as any)?.url || '') : ''" @close="assetDetail = null">
      <template v-if="assetDetail">
        <div class="kv">
          <dt>角色</dt><dd>{{ (assetDetail.role as any)?.role || '—' }}（conf {{ (assetDetail.role as any)?.confidence }}）</dd>
          <dt>评分</dt><dd>{{ (assetDetail.score as any)?.score }} <span class="mono">{{ (assetDetail.score as any)?.stage }}</span></dd>
          <dt>技术栈</dt><dd>{{ ((assetDetail.webapp as any)?.tech || []).join(', ') }}</dd>
          <dt>服务器</dt><dd>{{ (assetDetail.webapp as any)?.webserver || '—' }} · WAF:{{ (assetDetail.webapp as any)?.waf || '无' }}</dd>
          <dt>CVE 线索</dt><dd>{{ ((assetDetail.known_cve_hints as any[]) || []).map((h) => `${h.cve}(${h.component})`).join('; ') || '—' }}</dd>
        </div>
        <div class="sub-h">端点 ENDPOINTS（{{ (assetDetail.endpoints as any[])?.length || 0 }}）</div>
        <div class="code-block">{{ JSON.stringify((assetDetail.endpoints as any[] || []).slice(0, 20), null, 1) }}</div>
        <div class="sub-h">JS 接口（{{ (assetDetail.js_apis as any[])?.length || 0 }}）</div>
        <div class="code-block">{{ JSON.stringify((assetDetail.js_apis as any[] || []).slice(0, 20), null, 1) }}</div>
        <div class="sub-h">参数 PARAMS（{{ (assetDetail.params as any[])?.length || 0 }}）</div>
        <div class="code-block">{{ JSON.stringify((assetDetail.params as any[] || []).slice(0, 20), null, 1) }}</div>
        <div class="sub-h">攻击面</div>
        <div class="code-block">{{ JSON.stringify(assetDetail.attack_surface || null, null, 1).slice(0, 800) }}</div>
        <div style="margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap">
          <button class="btn primary" @click="deepScan(String((assetDetail.webapp as any)?.assetId || ''))">🔍 一键深挖</button>
        </div>
      </template>
    </Modal>

    <!-- 资产组详情弹窗 -->
    <Modal :open="!!groupDetail" :title="groupDetail ? `资产组 · ${groupDetail.group.name}` : ''" @close="groupDetail = null">
      <template v-if="groupDetail">
        <div class="kv">
          <dt>名称</dt><dd>{{ groupDetail.group.name }}</dd>
          <dt>范围</dt><dd class="mono">{{ (groupDetail.group.scope || []).join(', ') }}</dd>
        </div>
        <div class="sub-h">命中站点（{{ groupDetail.webappTotal }}）</div>
        <table v-if="groupDetail.webapps.length">
          <thead><tr><th>评分</th><th>URL</th><th>角色</th><th>技术栈</th></tr></thead>
          <tbody>
            <tr v-for="w in groupDetail.webapps" :key="String((w as any).asset_id)">
              <td class="mono">{{ (w as any).score }}</td>
              <td class="trunc" style="max-width: 300px">{{ (w as any).url }}</td>
              <td>{{ (w as any).role || '—' }}</td>
              <td class="mono" style="color: var(--ink-dim)">{{ ((w as any).tech || []).join(', ').slice(0, 50) }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">该组范围暂无命中站点（先收集）</div>
      </template>
    </Modal>

    <!-- IP 端口服务弹窗 -->
    <Modal :open="!!ipServicesTitle" :title="ipServicesTitle" @close="ipServicesTitle = ''">
      <table v-if="ipServices.length">
        <thead><tr><th>端口</th><th>协议</th><th>服务</th><th>版本</th><th>HTTP</th><th>横幅</th></tr></thead>
        <tbody>
          <tr v-for="s in ipServices" :key="String(s.id)">
            <td class="mono" style="font-weight: 600">{{ s.port }}</td>
            <td class="mono">{{ s.protocol || 'tcp' }}</td>
            <td class="mono">{{ s.service || '—' }}</td>
            <td class="mono">{{ s.version || '' }}</td>
            <td>{{ s.is_http ? '✓' : '' }}</td>
            <td class="mono" style="color: var(--ink-faint)">{{ String(s.banner || '').slice(0, 60) }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="empty">该 IP 无端口服务记录</div>
    </Modal>
  </div>
</template>
