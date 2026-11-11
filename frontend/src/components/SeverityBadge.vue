<script setup lang="ts">
/**
 *
 * 收敛前：每条 findings 表格里都手写
 *   `<span class="sev-badge" :class="severityTone(finding.severity)">{{ finding.severity }}</span>`
 * 共 6 处（TaskDetailPage 4 处、ChatOpsPage 1 处、SCAAssetPage 1 处）。
 * 手写的问题不是啰嗦，而是**漏写 :class 就静默失去色条**——徽章还在、颜色没了，
 * 不会报错也不会被任何检查发现。抽成组件后色条与形状绑死，调用方只给等级。
 *
 * 视觉规则（承接批次 1 的「颜色太花」整改）：
 * 中性底 + 1px 细边框 + 3px 左色条，语义只出现在左色条与文字上，不铺浅色底块。
 */
import { severityTone } from "@/domain/task-view";

const props = defineProps<{
  /** 原始等级字符串（大小写不限，如 "Critical" / "medium"） */
  level: string;
  /** 覆盖显示文案；默认按原样显示 level（保持与后端/报告口径一致，不做本地化改写） */
  text?: string;
}>();
</script>

<template>
  <span class="sev-badge" :class="severityTone(props.level)">{{ text ?? props.level }}</span>
</template>
