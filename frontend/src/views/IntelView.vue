<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api } from '../api';
import StatCard from '../components/StatCard.vue';

const stats = ref<Record<string, number>>({});
const entries = ref<Array<Record<string, unknown>>>([]);
const error = ref('');

async function load() {
  error.value = '';
  try {
    const d = await api.intel();
    stats.value = d.stats ?? {};
    const es: unknown[] = [];
    for (const k of ['cred', 'fingerprint', 'endpoint']) {
      if (stats.value[k]) {
        const r = await api.intel(k);
        es.push(...(r.entries ?? []));
      }
    }
    entries.value = es as Array<Record<string, unknown>>;
  } catch (e) {
    error.value = (e as Error).message;
  }
}

onMounted(load);
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">06</span><h2>情报库</h2><span class="h-note">跨任务复用 · INTEL LIBRARY</span></div>

    <div class="stat-grid" style="grid-template-columns: repeat(4, 120px)">
      <StatCard v-for="(v, k, i) in stats" :key="k" :num="v" :label="k" />
      <div v-if="!Object.keys(stats).length" class="empty" style="grid-column: 1/-1">暂无情报</div>
    </div>

    <div v-if="error" class="empty">{{ error }}</div>
    <div v-else class="intel-grid">
      <div v-for="(e, i) in entries" :key="i" class="intel-card">
        <div class="i-kind">{{ e.kind }}</div>
        <div class="i-key">{{ e.match_key }}</div>
        <div class="i-payload">{{ JSON.stringify(e.payload) }}</div>
        <div class="i-meta">{{ e.confidence }} · hit {{ e.hit_count }} · {{ String(e.last_seen || e.first_seen || '').slice(0, 16).replace('T', ' ') }}</div>
      </div>
      <div v-if="!entries.length" class="empty">暂无情报条目</div>
    </div>
  </div>
</template>
