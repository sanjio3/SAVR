<template>
  <nav class="breadcrumb" aria-label="面包屑">
    <template v-for="(item, i) in items" :key="i">
      <span v-if="i > 0" class="sep">/</span>
      <RouterLink v-if="item.to" :to="item.to">{{ item.label }}</RouterLink>
      <span v-else class="current">{{ item.label }}</span>
    </template>
  </nav>
</template>

<script setup lang="ts">
import type { RouteLocationRaw } from "vue-router";

defineProps<{ items: Array<{ label: string; to?: RouteLocationRaw }> }>();
</script>
