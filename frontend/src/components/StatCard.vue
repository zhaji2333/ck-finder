<script setup lang="ts">
defineProps<{ num: number | string; label: string; sub?: string; tone?: '' | 'warn' | 'danger' }>();
</script>

<template>
  <div class="stat-card" :class="tone">
    <div class="num">{{ num }}</div>
    <div class="lbl">{{ label }}</div>
    <div class="sub" v-if="sub">{{ sub }}</div>
  </div>
</template>
