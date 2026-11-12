<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>运行监控</h1>
        <p class="page-subtitle">
          所有扫描任务的实时视图：正在跑什么、跑到第几阶段、阶段内部进度、已耗时。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="refresh">刷新</button>
        <RouterLink class="button" to="/">去工作区发起扫描</RouterLink>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取任务列表…" />

    <template v-else>
      <div class="kpi-row">
        <div class="kpi is-running">
          <span class="kpi-label">运行中</span>
          <span class="kpi-value">{{ runningTasks.length }}</span>
        </div>
        <div class="kpi is-queued">
          <span class="kpi-label">排队中</span>
          <span class="kpi-value">{{ queuedTasks.length }}</span>
        </div>
        <div class="kpi is-ok">
          <span class="kpi-label">今日已完成</span>
          <span class="kpi-value">{{ todayCompleted }}</span>
        </div>
        <div class="kpi is-fail">
          <span class="kpi-label">今日失败</span>
          <span class="kpi-value">{{ todayFailed }}</span>
        </div>
      </div>

      <section class="stack">
        <h2>进行中的任务</h2>

        <div v-if="!activeTasks.length" class="empty-state">
          <strong>当前没有正在运行或排队的任务</strong>
          <span>从侧边栏进入某个工作区发起全量扫描，这里会实时显示它的阶段与进度。</span>
        </div>

        <article
          v-for="task in activeTasks"
          :key="task.id"
          class="run-card"
          :class="{ 'is-stuck': progressOf(task).stuck }"
        >
          <div class="run-card-head">
            <div class="stack gap-xs" style="min-width: 0">
              <span class="run-card-title">{{ task.name }}</span>
              <span class="muted small">
                {{ workspaceName(task.workspace_id) }} · {{ task.status === "running" ? "运行中" : "排队中" }}
              </span>
            </div>
            <div class="row gap-sm wrap">
              <span class="status-badge" :class="task.status === 'running' ? 'status-running' : 'status-queued'">
                {{ task.status === "running" ? "运行中" : "排队中" }}
              </span>
              <RouterLink class="ghost-button" :to="`/tasks/${task.id}`">打开任务</RouterLink>
            </div>
          </div>

          <template v-if="task.status === 'running'">
            <div class="stack gap-xs">
              <div class="row between wrap gap-xs">
                <span class="small">
                  第 {{ stageIndex(task) }}/{{ progressOf(task).total }} 阶段 ·
                  <!-- 阶段码（徽标语义）与裸名分开取：stageName 不含码，否则读成「R R 报告器」。 -->
                  <strong>{{ progressOf(task).stageCode }} {{ progressOf(task).stageName }}</strong>
                </span>
                <span class="small muted num">
                  {{ progressOf(task).done }}/{{ progressOf(task).total }} 阶段 · {{ progressOf(task).pct }}%
                </span>
              </div>
              <div class="progress tone-run" role="progressbar" :aria-valuenow="progressOf(task).pct" aria-valuemin="0" aria-valuemax="100">
                <span :style="{ width: progressOf(task).pct + '%' }" />
              </div>
            </div>

            <div class="stack gap-xs">
              <div class="row between wrap gap-xs">
                <span class="small muted">当前阶段内部进度</span>
                <span class="small num">{{ progressOf(task).internal.text || "该阶段未上报细粒度指标" }}</span>
              </div>
              <div
                v-if="progressOf(task).internal.pct !== null"
                class="progress tone-ok sm"
                role="progressbar"
                :aria-valuenow="progressOf(task).internal.pct || 0"
                aria-valuemin="0"
                aria-valuemax="100"
              >
                <span :style="{ width: (progressOf(task).internal.pct || 0) + '%' }" />
              </div>
              <p class="stage-hint">{{ STAGE_HINTS[progressOf(task).stageKey as never] || "" }}</p>
            </div>
          </template>

          <div class="run-meta">
            <span>全任务已用 <strong>{{ humanMs(progressOf(task).taskElapsedMs) }}</strong></span>
            <span v-if="task.status === 'running'">当前阶段已用 <strong>{{ humanMs(progressOf(task).stageElapsedMs) }}</strong></span>
            <span>累计发现 <strong>{{ findingCount(task) }}</strong></span>
            <span v-if="progressOf(task).lastActivityAt">
              最近阶段更新 <strong>{{ relativeMinutes(progressOf(task).lastActivityAt, now) }}</strong>
            </span>
          </div>

          <div v-if="progressOf(task).stuck" class="callout danger">
            当前阶段已持续 {{ progressOf(task).stageMinutes }} 分钟，超过 {{ STUCK_THRESHOLD_MINUTES }} 分钟阈值，疑似卡住。
            可打开任务查看日志确认，或联系运维检查后端与靶场进程。
          </div>
        </article>
      </section>

      <section class="stack">
        <h2>最近结束</h2>
        <div v-if="!recentTasks.length" class="empty-state">
          <strong>暂无已结束的任务</strong>
          <span>任务完成或失败后会在这里列出，便于快速回看结果与耗时。</span>
        </div>
        <div v-else class="table-wrap cols-6">
          <table>
            <thead>
              <tr>
                <th>任务</th><th>工作区</th><th>结果</th><th>耗时</th><th>发现</th><th>结束时间</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="task in recentTasks" :key="task.id">
                <td><RouterLink :to="`/tasks/${task.id}`">{{ task.name }}</RouterLink></td>
                <td>{{ workspaceName(task.workspace_id) || "-" }}</td>
                <td>
                  <span class="status-badge" :class="task.status === 'completed' ? 'status-completed' : 'status-failed'">
                    {{ task.status === "completed" ? "已完成" : "失败" }}
                  </span>
                </td>
                <td class="num">{{ humanMs(progressOf(task).taskElapsedMs) }}</td>
                <td class="num">{{ findingCount(task) }}</td>
                <td class="num">{{ shortTime(task.finished_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>

    <div v-if="error" class="callout danger">{{ error }}</div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";

import SkeletonBlock from "@/components/SkeletonBlock.vue";
import { STAGE_HINTS, taskStages } from "@/domain/task-view";
import { humanMs, relativeMinutes, STUCK_THRESHOLD_MINUTES, taskProgressSnapshot } from "@/domain/run-monitor";
import { formatServerShort, parseServerTime } from "@/domain/server-time";
import { useTableScroll } from "@/domain/table-scroll";
import { http } from "@/services/http";
import { useWorkspaceStore } from "@/stores/workspaces";
import type { ScanTask } from "@/types";

const root = ref<HTMLElement | null>(null);
const store = useWorkspaceStore();
const tasks = ref<ScanTask[]>([]);
const loading = ref(true);
const error = ref("");
/** 每秒推进一次，让「已用时」是活的而不是快照 */
const now = ref(Date.now());

let pollTimer: number | null = null;
let tickTimer: number | null = null;

useTableScroll(root);

onMounted(async () => {
  await refresh();
  pollTimer = window.setInterval(refresh, 5000);
  tickTimer = window.setInterval(() => (now.value = Date.now()), 1000);
  if (!store.items.length) void store.fetchWorkspaces().catch(() => undefined);
});

onUnmounted(() => {
  if (pollTimer) window.clearInterval(pollTimer);
  if (tickTimer) window.clearInterval(tickTimer);
});

async function refresh() {
  try {
    const { data } = await http.get<ScanTask[]>("/api/scan-tasks");
    tasks.value = data;
    error.value = "";
  } catch (caught) {
    error.value = `读取任务列表失败：${String((caught as Error)?.message || caught)}`;
  } finally {
    loading.value = false;
  }
}

const runningTasks = computed(() => tasks.value.filter((task) => task.status.toLowerCase() === "running"));
const queuedTasks = computed(() => tasks.value.filter((task) => task.status.toLowerCase() === "pending"));
const activeTasks = computed(() => [...runningTasks.value, ...queuedTasks.value]);

const recentTasks = computed(() =>
  tasks.value
    .filter((task) => task.finished_at)
    // 排序只关心先后顺序，时区偏移是常数、不影响次序；仍统一走 parseServerTime 以免读者误解
    .sort((a, b) => parseServerTime(b.finished_at) - parseServerTime(a.finished_at))
    .slice(0, 5),
);

function finishedToday(status: string) {
  return tasks.value.filter((task) => {
    if (task.status.toLowerCase() !== status || !task.finished_at) return false;
    // 「今日」判定必须用归一后的本地时间：服务端 finished_at 是 UTC-naive，
    // 直接 new Date() 会被读早 8 小时，把凌晨完成的跨日任务算到昨天。
    const at = new Date(parseServerTime(task.finished_at));
    const today = new Date();
    return (
      at.getFullYear() === today.getFullYear() &&
      at.getMonth() === today.getMonth() &&
      at.getDate() === today.getDate()
    );
  }).length;
}

const todayCompleted = computed(() => finishedToday("completed"));
const todayFailed = computed(() => finishedToday("failed"));

/** 直接计算：活跃任务只有个位数，每秒重算的代价远小于维护缓存的复杂度 */
function progressOf(task: ScanTask) {
  return taskProgressSnapshot(task);
}

function stageIndex(task: ScanTask) {
  const stages = taskStages(task);
  const index = stages.findIndex((stage) => stage.key === progressOf(task).stageKey);
  return index >= 0 ? index + 1 : stages.length;
}

function findingCount(task: ScanTask): number {
  const value = Number(task.summary?.finding_count);
  return Number.isFinite(value) ? value : 0;
}

function workspaceName(workspaceId: number | undefined) {
  if (!workspaceId) return "";
  const ws = store.items.find((item) => item.id === workspaceId);
  return ws ? ws.name || ws.slug || `工作区 #${workspaceId}` : `工作区 #${workspaceId}`;
}

function shortTime(iso?: string) {
  // 服务端时间戳是 UTC-naive，必须归一后再格式化，否则整列结束时间都早 8 小时
  return iso ? formatServerShort(iso) : "-";
}
</script>
