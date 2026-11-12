<script setup lang="ts">
// 流量类型切换：全部 / 业务逻辑 / 注入型 / 暴露配置（第三轴）。
// 全局单一 flowFilter 经 v-model 在 TaskDetailPage 各面共享，切换一次即对所有面生效。
type FlowFilter = "all" | "business_logic" | "injection" | "exposure";

const props = defineProps<{
  modelValue: FlowFilter;
  showCounts?: boolean;
  counts?: { all: number; business_logic: number; injection: number; exposure: number };
}>();

const emit = defineEmits<{
  (e: "update:modelValue", v: FlowFilter): void;
}>();

const options: { value: FlowFilter; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "business_logic", label: "业务逻辑" },
  { value: "injection", label: "注入型" },
  { value: "exposure", label: "暴露/配置" },
];
</script>

<template>
  <div class="row wrap gap-sm flow-type-switch" role="tablist" aria-label="流量类型筛选">
    <button
      v-for="o in options"
      :key="o.value"
      type="button"
      class="ghost-button tiny"
      :class="{ active: modelValue === o.value }"
      role="tab"
      :aria-selected="modelValue === o.value"
      @click="emit('update:modelValue', o.value)"
    >
      {{ o.label }}
      <span v-if="showCounts && counts" class="count-pill">{{ counts[o.value] }}</span>
    </button>
  </div>
</template>

<style scoped>
.flow-type-switch .count-pill {
  margin-left: 4px;
  font-size: 11px;
  opacity: 0.7;
}
</style>
