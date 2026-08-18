<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api } from './api';
import { nav } from './store';
import DashboardView from './views/DashboardView.vue';
import AssetsView from './views/AssetsView.vue';
import TasksView from './views/TasksView.vue';
import HuntView from './views/HuntView.vue';
import ReviewView from './views/ReviewView.vue';
import IntelView from './views/IntelView.vue';
import SettingsView from './views/SettingsView.vue';

const tabs = [
  { id: 'board', icon: '◉', label: '仪表盘 DASHBOARD', comp: DashboardView },
  { id: 'assets', icon: '▦', label: '资产管理 ASSETS', comp: AssetsView },
  { id: 'collect', icon: '⌖', label: '任务管理 TASKS', comp: TasksView },
  { id: 'hunt', icon: '⚔', label: '挖洞 HUNTING', comp: HuntView },
  { id: 'review', icon: '✎', label: '复审 REVIEW', comp: ReviewView },
  { id: 'intel', icon: '◈', label: '情报 INTEL', comp: IntelView },
  { id: 'config', icon: '⚙', label: '设置 CONFIG', comp: SettingsView },
] as const;

const activeComp = computed(() => tabs.find((t) => t.id === nav.active)?.comp);

const stApi = ref('off');
const stDb = ref('off');
const stLlm = ref('off');

async function health() {
  try {
    const h = await api.health();
    stApi.value = 'on';
    stDb.value = h.status === 'ok' ? 'on' : 'warn';
  } catch {
    stApi.value = 'off';
    stDb.value = 'off';
  }
  try {
    const c = await api.config();
    stLlm.value = c.status.llmConfigured ? 'on' : 'off';
  } catch {
    stLlm.value = 'off';
  }
}

onMounted(health);
</script>

<template>
  <div class="app">
    <aside class="sidebar">
      <div class="logo">CK</div>
      <button
        v-for="t in tabs"
        :key="t.id"
        class="nav-btn"
        :class="{ active: t.id === nav.active }"
        :title="t.label"
        @click="nav.active = t.id"
      >
        {{ t.icon }}<span class="tip">{{ t.label }}</span>
      </button>
      <div class="spacer"></div>
      <div class="nav-btn" style="cursor: default" title="v0.3"><span class="tip">ck-finder 0.3</span></div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="t-title">渗透指挥台 <span class="t-sub">/ command center</span></div>
        <div class="status-group">
          <div class="status-item"><span class="dot" :class="stApi"></span>API</div>
          <div class="status-item"><span class="dot" :class="stDb"></span>DB</div>
          <div class="status-item"><span class="dot" :class="stLlm"></span>LLM</div>
          <button class="icon-btn" title="刷新" @click="health">⟳</button>
        </div>
      </header>

      <div class="content">
        <component :is="activeComp" />
      </div>
    </div>
  </div>
</template>
