<script setup lang="ts">
defineProps<{ value: string }>();
</script>

<template>
  <span class="badge" :class="'b-' + value">{{ value }}</span>
</template>
