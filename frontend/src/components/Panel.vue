<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <div class="panel">
    <div class="panel-hd" v-if="title || $slots.hd">
      <span class="p-dot"></span>
      <span v-if="title">{{ title }}</span>
      <slot name="hd"></slot>
    </div>
    <div class="panel-bd">
      <slot></slot>
    </div>
  </div>
</template>
