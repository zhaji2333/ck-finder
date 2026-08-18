<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api, type ConfigField } from '../api';
import Panel from '../components/Panel.vue';

const fields = ref<ConfigField[]>([]);
const status = ref<{ llmConfigured: boolean; llmPoolProviders: number; scope: string[]; scopeGateEnabled: boolean; model: string; modelPro: string } | null>(null);
const envPath = ref('');
const msg = ref('');
const values = ref<Record<string, string>>({});
const testing = ref(false);
const saving = ref(false);

const llmFields = computed(() => fields.value.filter((f) => f.group === 'llm'));
const scopeFields = computed(() => fields.value.filter((f) => f.group === 'scope'));

async function load() {
  try {
    const d = await api.config();
    fields.value = d.fields;
    status.value = d.status;
    envPath.value = d.envPath;
    const v: Record<string, string> = {};
    for (const f of d.fields) v[f.key] = f.secret ? '' : f.value;
    values.value = v;
  } catch (e) {
    msg.value = (e as Error).message;
  }
}

async function save() {
  saving.value = true;
  msg.value = '保存中…';
  const updates: Record<string, string> = {};
  for (const f of fields.value) {
    const v = values.value[f.key] ?? '';
    if (f.type === 'boolean') {
      updates[f.key] = v;
      continue;
    }
    if (v && v.trim() !== '') updates[f.key] = v;
  }
  for (const f of fields.value) {
    if (f.type === 'json' && updates[f.key] && updates[f.key].trim() !== '') {
      try {
        JSON.parse(updates[f.key]);
      } catch {
        alert(`${f.label} 不是合法 JSON`);
        saving.value = false;
        return;
      }
    }
  }
  try {
    const r = await api.configSave(updates);
    msg.value = `✓ 已生效 ${r.changed.length} 项${r.skipped.length ? '（密钥保持不变 ' + r.skipped.length + ' 项）' : ''}（.env 已持久化）`;
    load();
  } catch (e) {
    msg.value = '保存失败: ' + (e as Error).message;
  } finally {
    saving.value = false;
  }
}

async function testLlm() {
  testing.value = true;
  msg.value = '测试 LLM 连通中（约 5-20s）…';
  try {
    const r = await api.configTestLlm();
    if (r.ok) {
      msg.value = `✓ 连通成功（${r.model}）：${r.reply}`;
      alert(`LLM 连通成功\n模型: ${r.model}\n响应: ${r.reply}`);
    } else {
      msg.value = '连通失败: ' + r.error;
      alert('LLM 连通失败:\n' + r.error);
    }
  } catch (e) {
    msg.value = '连通失败: ' + (e as Error).message;
    alert('LLM 连通失败: ' + (e as Error).message);
  } finally {
    testing.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div>
    <div class="h-sec"><span class="idx">07</span><h2>系统配置</h2><span class="h-note">AI API Key · 模型 · 授权范围（写 .env + 热加载）</span></div>

    <Panel title="LLM 运行状态 · RUNTIME STATUS">
      <div class="kv" v-if="status">
        <dt>LLM Key</dt><dd><span class="mono" :style="`color:${status.llmConfigured ? 'var(--sig)' : 'var(--warn)'}`">{{ status.llmConfigured ? '已配置 ✓' : '未配置' }}</span></dd>
        <dt>执行模型</dt><dd class="mono">{{ status.model }}</dd>
        <dt>复杂模型</dt><dd class="mono">{{ status.modelPro }}</dd>
        <dt>端点池</dt><dd class="mono">{{ status.llmPoolProviders }} provider</dd>
        <dt>授权范围</dt><dd class="mono">{{ status.scope.join(', ') || '(未设置)' }}</dd>
        <dt>Scope Gate</dt><dd class="mono">{{ status.scopeGateEnabled ? '开启' : '关闭' }}</dd>
        <dt>.env</dt><dd class="mono" style="color: var(--ink-faint)">{{ envPath }}</dd>
      </div>
    </Panel>

    <Panel title="配置项 · EDIT CONFIG">
      <template v-for="(group, label) in { llmFields, scopeFields }" :key="label">
        <div class="sub-h" style="margin-top: 0">{{ label === 'llmFields' ? 'LLM 模型与密钥' : '授权与范围' }}</div>
        <div v-for="f in group" :key="f.key" class="field">
          <label>{{ f.label }} <span style="color: var(--ink-faint)">{{ f.key }}</span></label>
          <select v-if="f.type === 'boolean'" v-model="values[f.key]">
            <option value="true">true（开启）</option>
            <option value="false">false（关闭）</option>
          </select>
          <textarea v-else-if="f.type === 'json'" v-model="values[f.key]" rows="3" :placeholder="f.placeholder"></textarea>
          <input v-else-if="f.type === 'password'" v-model="values[f.key]" type="password" :placeholder="`${f.value || '••••••'}（留空保持不变）`" />
          <input v-else v-model="values[f.key]" type="text" :placeholder="f.placeholder" />
          <div class="hint">{{ f.help }}</div>
        </div>
      </template>

      <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap">
        <button class="btn primary" :disabled="saving" @click="save">💾 保存并生效</button>
        <button class="btn" :disabled="testing" @click="testLlm">⚡ 测试 LLM 连通</button>
        <span class="hint" style="margin: 0">{{ msg }}</span>
      </div>
    </Panel>
  </div>
</template>
