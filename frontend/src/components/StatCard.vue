<script setup lang="ts">
/**
 *
 * 背景：`<div class="stat-card"><span class="muted">标签</span><strong>值</strong></div>`
 * 这一形状在 10 个页面里内联出现了近百次。它本身没错，但每个页面各写一遍的结果是：
 * ① 值侧偶尔漏掉 class="num"（等宽数字对齐失效，一列数字左右抖动）；
 * ② 有的用 <span class="muted">、有的用纯文本，同一屏两种字重；
 * ③ 样式改动要摸遍所有页面。
 *
 * 设计取舍：值走**默认插槽**而不是 prop。因为值经常不是纯文本（可能带 <em>、可能带
 * 单位后缀、可能是 "-" 占位），用 prop 会逼着调用方做字符串拼装，反而更难维护。
 * 只有两个真正公共的开关做成 prop：
 *   - `num`   ：值是不是数字（决定要不要 .num 等宽数字对齐）
 *   - `count` ：需要 gsap 数字滚动时传目标值，渲染成 data-count
 *                 （RoundReporter 的滚动动画靠 [data-count] 选择器找节点）
 */
withDefaults(
  defineProps<{
    label: string;
    /** 值是数字 → 加 .num，保证等宽数字对齐 */
    num?: boolean;
    /** 需要数字滚动动画时传目标值 */
    count?: number | string | null;
  }>(),
  { num: false, count: null },
);
</script>

<template>
  <div class="stat-card">
    <span class="muted">{{ label }}</span>
    <strong :class="{ num }" :data-count="count ?? undefined">
      <slot />
    </strong>
  </div>
</template>
