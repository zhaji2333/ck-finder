<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { api, type Finding, type ReviewRecord } from '../api';
import Panel from '../components/Panel.vue';
import Badge from '../components/Badge.vue';
import Modal from '../components/Modal.vue';

const statuses = ['pending', 'reviewed', 'confirmed', 'dismissed'];
const status = ref('pending');
const findings = ref<Finding[]>([]);
const error = ref('');
const aiBusy = ref(false);
const detail = ref<{ finding: Finding; reviews: ReviewRecord[] } | null>(null);

async function load() {
  error.value = '';
  try {
    const d = await api.reviewFindings(status.value);
    findings.value = d.findings;
  } catch (e) {
    error.value = (e as Error).message;
  }
}

async function aiReviewPending() {
  aiBusy.value = true;
  try {
    const d = await api.reviewPending();
    alert(`AI 初审完成 ${d.total} 条`);
  } catch (e) {
    alert((e as Error).message);
  } finally {
    aiBusy.value = false;
    load();
  }
}

async function showDetail(id: string) {
  try {
    detail.value = await api.reviewDetail(id);
  } catch (e) {
    alert((e as Error).message);
  }
}

async function aiReview(id: string) {
  try {
    const d = await api.reviewAi(id);
    alert(`初审: ${d.outcome.verdict}`);
    load();
  } catch (e) {
    alert((e as Error).message);
  }
}

async function decision(id: string, action: string) {
  try {
    await api.reviewDecision(id, action);
    detail.value = null;
    load();
  } catch (e) {
    alert((e as Error).message);
  }
}

function deepen(id: string) {
  const d = prompt('输入深挖定向指令（worker 将按此重新挖该目标）:');
  if (!d) return;
  api.reviewDeepen(id, d)
    .then(() => {
      alert('已打回深挖');
      load();
    })
    .catch((e) => alert((e as Error).message));
}

onMounted(load);
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">05</span><h2>漏洞复审</h2><span class="h-note">AI 初审 → 人工裁决 → 提交</span></div>

    <div class="toolbar">
      <div class="seg">
        <button v-for="s in statuses" :key="s" :class="{ active: s === status }" @click="status = s; load()">{{ s }}</button>
      </div>
      <button class="btn primary" :disabled="aiBusy" @click="aiReviewPending">🤖 AI 初审待审队列</button>
      <button class="btn" @click="load">刷新</button>
    </div>

    <div v-if="error" class="empty">{{ error }}</div>
    <div v-else-if="!findings.length" class="empty">该队列暂无 finding</div>
    <div v-else>
      <div v-for="f in findings" :key="f.id" class="row">
        <div class="row-head">
          <Badge :value="f.severity" />
          <Badge :value="f.reviewStatus" />
          <span class="row-title">{{ f.vulnName }}</span>
        </div>
        <div class="row-url">{{ f.url }}</div>
        <div class="row-sub">{{ f.summary }}</div>
        <div class="row-meta">
          <span>{{ f.vulnType }}</span>
          <span>深挖 {{ f.deepenCount ?? 0 }} 次</span>
          <span v-if="f.deepenDirective" style="color: var(--warn)">↳ {{ f.deepenDirective.slice(0, 80) }}</span>
        </div>
        <div class="row-actions">
          <button class="btn sm" @click="showDetail(f.id)">详情</button>
          <button class="btn sm" @click="aiReview(f.id)">AI 审</button>
          <button class="btn sm primary" @click="decision(f.id, 'approve')">通过</button>
          <button class="btn sm" @click="decision(f.id, 'decline')">驳回</button>
          <button class="btn sm" @click="deepen(f.id)">打回深挖</button>
        </div>
      </div>
    </div>

    <Modal :open="!!detail" :title="detail ? `${detail.finding.vulnName} [${detail.finding.severity}]` : ''" @close="detail = null">
      <template v-if="detail">
        <div class="kv">
          <dt>URL</dt><dd>{{ detail.finding.url }}</dd>
          <dt>类型</dt><dd>{{ detail.finding.vulnType }} · {{ detail.finding.status }} · 深挖{{ detail.finding.deepenCount ?? 0 }}次</dd>
          <dt>摘要</dt><dd>{{ detail.finding.summary }}</dd>
        </div>
        <div class="sub-h">POC</div><div class="code-block">{{ detail.finding.evidence?.poc }}</div>
        <div class="sub-h">RAW REQUEST</div><div class="code-block">{{ detail.finding.evidence?.raw_request.slice(0, 1500) }}</div>
        <div class="sub-h">RAW RESPONSE</div><div class="code-block">{{ (detail.finding.evidence?.raw_response || '').slice(0, 1500) }}</div>
        <div class="sub-h">SELF CHECK</div><div class="code-block">{{ JSON.stringify(detail.finding.evidence?.self_check, null, 1) }}</div>
        <div v-if="detail.reviews.length">
          <div class="sub-h">复审记录</div>
          <div v-for="(r, i) in detail.reviews" :key="i" class="row" style="padding: 8px 12px">
            <Badge :value="r.verdict" />
            <span v-if="r.reproduced" class="mono" style="color: var(--sig)">系统复现✓</span>
            <span class="mono" style="color: var(--ink-dim)">{{ r.score }}分</span>
            <div style="font-size: 12px; color: var(--ink-dim); margin-top: 4px">{{ r.reasoning }}</div>
          </div>
        </div>
      </template>
    </Modal>
  </div>
</template>
