<template>
  <!--
    首屏骨架：形状与真实内容一致，避免「空白 → 数据灌入」的跳变。
    variant 决定骨架形状，rows 决定行数。不用转圈，因为转圈不传达结构。
  -->
  <div v-if="variant === 'stat'" class="skeleton-grid" aria-hidden="true">
    <div v-for="i in count" :key="i" class="skeleton-card">
      <span class="skeleton skeleton-line" style="width: 46%" />
      <span class="skeleton skeleton-line" style="width: 62%; height: 22px" />
    </div>
  </div>

  <div v-else-if="variant === 'table'" class="skeleton-table" aria-hidden="true">
    <span class="skeleton skeleton-line" style="width: 100%; height: 16px" />
    <span v-for="i in count" :key="i" class="skeleton skeleton-line" style="width: 100%" />
  </div>

  <div v-else class="skeleton-card" aria-hidden="true">
    <span class="skeleton skeleton-line" style="width: 38%; height: 16px" />
    <span v-for="i in count" :key="i" class="skeleton skeleton-line" :style="{ width: i % 2 ? '100%' : '86%' }" />
  </div>

  <p class="sr-only" role="status">{{ label }}</p>
</template>

<script setup lang="ts">
import { computed } from "vue";

const props = withDefaults(
  defineProps<{
    variant?: "card" | "table" | "stat";
    /** 骨架条目数；stat 变体下表示卡片个数 */
    rows?: number;
    label?: string;
  }>(),
  { variant: "card", rows: 4, label: "正在加载…" },
);

const count = computed(() => props.rows);
</script>
