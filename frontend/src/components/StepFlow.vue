<script setup lang="ts">
/**
 *
 * 为什么抽：这段结构在 TaskDetailPage 里内联了 30+ 行模板，且刷新逻辑（active 判定、
 * 末步不画连接线、进度徽标只在未裁剪时给比例）与页面其他部分无关，属于纯展示职责。
 * 抽成组件后 TaskDetailPage 只负责把「阶段 → 展示项」映射好，视图层不含业务判断。
 *
 * 为什么用「预计算 items」而不是传回调：回调 props 在 TS 里会退化成 `(...args:any)=>any`，
 * 丢类型也丢可测性。改成页面侧 computed 出一个 StepFlowItem[]，组件就可以纯渲染，
 * 也能被单测直接喂数据。
 *
 * 视觉铁律（避免状态色过度铺开）：
 * - 状态色只落在 26px 小圆环与状态文字上，整行不铺色；
 * - 当前步只用左侧 2px 强调条 + 极浅底，避免与状态色打架。
 */
export interface StepFlowItem {
  key: string;
  /** 裸名（如「规则扫描」），阶段码由 code 单独承担，避免读成「A1 A1 规则扫描」 */
  label: string;
  /** 阶段码（A0/A1/D1/I2/R…），渲染在小圆环里 */
  code: string;
  status: string;
  statusLabel: string;
  progress: { done: number; total: number; showRatio: boolean };
  /** 运行中才需要展示的已耗时长；空串表示不渲染 */
  elapsed: string;
  active: boolean;
  /** 末步连接线只画左半（横向时避免向右拖出一根悬空线） */
  last: boolean;
}

defineProps<{ items: StepFlowItem[] }>();
const emit = defineEmits<{ (e: "select", key: string): void }>();
</script>

<template>
  <nav class="step-flow" aria-label="扫描流程">
    <button
      v-for="item in items"
      :key="item.key"
      type="button"
      class="step-row"
      :class="[`step-${item.status}`, { active: item.active }]"
      :aria-current="item.active ? 'step' : undefined"
      @click="emit('select', item.key)"
    >
      <span class="step-rail" aria-hidden="true">
        <span class="step-line" :class="{ 'is-last': item.last }" />
        <span class="step-dot">{{ item.code }}</span>
      </span>
      <span class="step-body">
        <span class="step-label">{{ item.label }}</span>
        <span class="step-meta">
          <span class="step-status">{{ item.statusLabel }}</span>
          <!-- 后端对 items 做了 8 条裁剪（MAX_TASKS_PER_STAGE）：裁剪时用 items 统计
               「已完成」会偏小，故只在未裁剪时给 done/total 比例，其余只显示总数
               —— 宁可少显示，不给假比例。 -->
          <span v-if="item.progress.showRatio" class="step-badge">
            {{ item.progress.done }}/{{ item.progress.total }}
          </span>
          <span v-else-if="item.progress.total" class="step-badge">
            {{ item.progress.total }} 个任务
          </span>
          <span v-if="item.elapsed" class="step-elapsed">{{ item.elapsed }}</span>
        </span>
      </span>
    </button>
  </nav>
</template>
