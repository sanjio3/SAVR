<template>
  <div class="card stack">
    <div class="row between wrap gap-sm">
      <span class="status-badge" :class="statusTone">
        <span v-if="isRunning" class="pulse-dot" />
        {{ statusText }}
      </span>
      <button class="ghost-button tiny danger-outline" @click="$emit('delete', task.id)">删除</button>
    </div>
    <strong>{{ task.name }}</strong>
    <span class="muted small">{{ task.output_dir }}</span>

    <div v-if="showProgress" class="stack gap-xs">
      <div class="progress sm" :class="isRunning ? 'tone-run' : 'tone-ok'" role="progressbar" :aria-valuenow="progressPct" aria-valuemin="0" aria-valuemax="100">
        <span :style="{ width: progressPct + '%' }" />
      </div>
      <span class="muted small num">{{ doneStages }}/{{ totalStages }} 阶段 · {{ progressPct }}%</span>
    </div>

    <div class="row wrap gap-sm muted small">
      <span v-if="elapsed">已用 {{ elapsed }}</span>
      <span v-if="findingCount !== null">发现 {{ findingCount }}</span>
      <span v-if="finishedAt">完成于 {{ finishedAt }}</span>
    </div>

    <div v-if="stuckStage" class="callout danger small">「{{ stuckStage }}」阶段已运行超过 45 分钟，可能卡住，请打开任务查看日志。</div>

    <RouterLink class="ghost-button" :to="taskHref">打开任务</RouterLink>
  </div>
</template>

<script setup lang="ts">
import { computed } from "vue";

import { formatDuration, taskBadge, taskStages } from "@/domain/task-view";
import { formatServerTime, serverElapsedMs } from "@/domain/server-time";
import { useWorkspaceStore } from "@/stores/workspaces";
import type { ScanTask } from "@/types";

defineEmits<{ delete: [taskId: number] }>();
const props = defineProps<{ task: ScanTask }>();
const workspaceStore = useWorkspaceStore();

const statusText = computed(() => taskBadge(props.task));
const isRunning = computed(() => props.task.status.toLowerCase() === "running");
const statusTone = computed(() => {
  const s = props.task.status.toLowerCase();
  if (s === "running") return "status-running";
  if (s === "completed") return "status-completed";
  if (s === "failed") return "status-failed";
  return "status-queued";
});

const stages = computed(() => taskStages(props.task));
const totalStages = computed(() => stages.value.length || 1);
const doneStages = computed(() => stages.value.filter((s) => s.status === "completed").length);
const progressPct = computed(() => Math.round((doneStages.value / totalStages.value) * 100));
const showProgress = computed(
  () => (isRunning.value || props.task.status.toLowerCase() === "completed") && doneStages.value > 0,
);

// F8：运行中且当前阶段已跑超过 45 分钟 → 提示可能卡住（数据来自 pipeline 的阶段 started_at）
// 2026-09-22 走查修正：原用 Date.parse(active.started_at) 与 Date.now() 相减，而服务端时间戳是
// UTC-naive → 在 UTC+8 下凭空多算 8 小时，任何 running 阶段都会立刻越过 45 分钟阈值误报卡死。
const stuckStage = computed(() => {
  if (!isRunning.value) return null;
  const active = stages.value.find((s) => s.status === "running");
  if (!active?.started_at) return null;
  const ms = serverElapsedMs(active.started_at);
  return ms > 45 * 60 * 1000 ? active.label : null;
});

const elapsed = computed(() => formatDuration(props.task.started_at, props.task.finished_at));
const findingCount = computed(() => {
  const n = Number(props.task.summary?.finding_count ?? 0);
  return n > 0 ? n : null;
});
const finishedAt = computed(() => (props.task.finished_at ? formatServerTime(props.task.finished_at, "") : ""));

const taskHref = computed(() => {
  const slug = workspaceStore.selectedWorkspace?.slug;
  return slug ? `/workspace/${slug}/task/${props.task.id}` : `/tasks/${props.task.id}`;
});
</script>
