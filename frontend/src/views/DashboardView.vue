<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, type Overview, type SeedRow } from '../api';
import StatCard from '../components/StatCard.vue';
import Panel from '../components/Panel.vue';
import Badge from '../components/Badge.vue';

const loading = ref(true);
const error = ref('');
const data = ref<Overview | null>(null);
const recent = ref<SeedRow[]>([]);

async function load() {
  loading.value = true;
  error.value = '';
  try {
    const [ov, seeds] = await Promise.all([api.overview(), api.seeds(6)]);
    data.value = ov;
    recent.value = seeds.seeds;
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">01</span><h2>运营态势</h2><span class="h-note">SITUATIONAL OVERVIEW</span></div>

    <div v-if="loading" class="loading"><span class="spin"></span>同步运营数据…</div>
    <div v-else-if="error" class="empty">看板加载失败：{{ error }}</div>
    <template v-else-if="data">
      <div class="stat-grid">
        <StatCard :num="data.seeds" label="任务" :sub="`assets ${data.assets}`" />
        <StatCard :num="data.webapps" label="Web 应用" sub="评分入库" />
        <StatCard :num="data.intentsTotal" label="探索意图" :sub="`done ${data.intents.done ?? 0} · running ${data.intents.running ?? 0}`" :tone="data.intents.running ? 'warn' : ''" />
        <StatCard
          :num="data.findingsTotal"
          label="漏洞发现"
          :sub="Object.entries(data.findingBySeverity).map(([k, v]) => `${k} ${v}`).join(' · ')"
          :tone="(data.findingBySeverity.critical || data.findingBySeverity.high) ? 'danger' : ''"
        />
        <StatCard :num="data.intel.cred ?? 0" label="情报 · 凭证" :sub="`fp ${data.intel.fingerprint ?? 0} · ep ${data.intel.endpoint ?? 0}`" />
      </div>

      <Panel title="高危发现热区 · HIGH-VALUE FINDINGS">
        <table v-if="data.highValueFindings.length">
          <thead><tr><th>状态</th><th>等级</th><th>数量</th></tr></thead>
          <tbody>
            <tr v-for="f in data.highValueFindings" :key="f.reviewStatus + f.severity">
              <td><Badge :value="f.reviewStatus" /></td>
              <td><Badge :value="f.severity" /></td>
              <td class="mono">{{ f.count }}</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">暂无高危待处理 finding</div>
      </Panel>

      <Panel title="最近任务 · RECENT TASKS">
        <table v-if="recent.length">
          <thead><tr><th>任务</th><th>种子</th><th>状态</th><th>意图</th></tr></thead>
          <tbody>
            <tr v-for="x in recent" :key="x.id">
              <td class="mono">{{ x.id.slice(0, 8) }}</td>
              <td class="trunc" style="max-width: 200px">{{ x.seedType }} {{ x.value }}</td>
              <td><Badge :value="x.status === 'done' ? 'done' : x.status" /></td>
              <td class="mono">{{ x.intentsTotal }}（done {{ x.intentCounts?.done ?? 0 }}）</td>
            </tr>
          </tbody>
        </table>
        <div v-else class="empty">暂无任务</div>
      </Panel>
    </template>
  </div>
</template>
