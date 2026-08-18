<script setup lang="ts">
defineProps<{ title: string; open: boolean }>();
const emit = defineEmits<{ (e: 'close'): void }>();
</script>

<template>
  <div v-if="open" class="modal-mask" @click.self="emit('close')">
    <div class="modal">
      <div class="modal-hd">
        <span class="m-title">{{ title }}</span>
        <button class="icon-btn" @click="emit('close')">✕</button>
      </div>
      <div class="modal-bd">
        <slot></slot>
      </div>
    </div>
  </div>
</template>
