<template>
  <div class="shell">
    <SidebarNav
      :running-count="running.length"
      :backend-ok="backendOk"
      :context-label="contextLabel"
      :tasks="allTasks"
      :current-workspace-id="currentWorkspaceId"
      @open-settings="settingsOpen = true"
      @open-workspace-create="workspaceCreateOpen = true"
    />

    <div class="main-col">
      <header class="topbar">
        <span class="muted small">{{ routeLabel }}</span>
        <div
          v-if="primaryRunning"
          class="run-bar"
          role="button"
          tabindex="0"
          :title="`前往任务：${primaryRunning.name}`"
          @click="openRunning(primaryRunning)"
          @keydown.enter="openRunning(primaryRunning)"
        >
          <span class="pulse-dot" />
          <span>{{ primaryRunning.name }}</span>
          <span class="muted">· {{ runningStageText(primaryRunning) }}</span>
          <div class="progress sm tone-run" style="width: 90px" role="progressbar" :aria-valuenow="runningPct(primaryRunning)" aria-valuemin="0" aria-valuemax="100">
            <span :style="{ width: runningPct(primaryRunning) + '%' }" />
          </div>
          <span class="num">{{ runningPct(primaryRunning) }}%</span>
          <span v-if="running.length > 1" class="muted">· 共 {{ running.length }} 个任务运行中</span>
        </div>
        <span v-else-if="backendOk === false" class="status-badge status-failed">后端不可达</span>
        <RouterLink v-else class="muted small" to="/runs">当前无运行中的扫描</RouterLink>
      </header>

      <main class="content">
        <RouterView />
      </main>
    </div>

    <!-- 设置中心挂在根上而不是某个页面里：任何页面都能唤起，
         也不会因为路由切换被卸载（弹层打开期间切路由会把它一起带走）。 -->
    <SettingsCenterDialog :open="settingsOpen" @close="settingsOpen = false" />

    <!-- 新建工作区弹层：侧栏「工作区」组头的 + 触发，复用 WorkspacePathCreate 表单。 -->
    <AppModal :open="workspaceCreateOpen" title="新建工作区" @close="workspaceCreateOpen = false">
      <WorkspacePathCreate :busy="createBusy" :error="createError" @submit="createWorkspace" />
    </AppModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import AppModal from "@/components/AppModal.vue";
import SettingsCenterDialog from "@/components/SettingsCenterDialog.vue";
import SidebarNav from "@/components/SidebarNav.vue";
import WorkspacePathCreate from "@/components/WorkspacePathCreate.vue";
import { taskBadge, taskStages } from "@/domain/task-view";
import { http } from "@/services/http";
import { useWorkspaceStore } from "@/stores/workspaces";
import type { ScanTask } from "@/types";

const route = useRoute();
const router = useRouter();
const store = useWorkspaceStore();
const allTasks = ref<ScanTask[]>([]);
/** null = 还没拿到结果，true/false = 后端可达性 */
const backendOk = ref<boolean | null>(null);
const settingsOpen = ref(false);
const workspaceCreateOpen = ref(false);
const createBusy = ref(false);
const createError = ref("");
let healthTimer: number | null = null;
let tasksWs: WebSocket | null = null;
let wsReconnectTimer: number | null = null;

async function createWorkspace(payload: { name: string; target_path: string; description: string; target_url: string }) {
  createBusy.value = true;
  createError.value = "";
  try {
    const ws = await store.createWorkspace({
      name: payload.name,
      target_path: payload.target_path,
      description: payload.description,
      settings: payload.target_url ? { target_url: payload.target_url } : {},
    });
    workspaceCreateOpen.value = false;
    await router.push(`/workspaces/${ws.id}`);
  } catch (caught) {
    const e = caught as any;
    createError.value = e?.response?.data?.detail || e?.message || "创建失败";
  } finally {
    createBusy.value = false;
  }
}

// 全量任务由全局 WebSocket（/ws/tasks）推送维护，不再周期轮询。
// 仅保留一次性引导拉取作为 WS 未就绪时的兜底（非周期轮询）。
async function bootstrapTasks() {
  try {
    const { data } = await http.get<ScanTask[]>("/api/scan-tasks");
    allTasks.value = data;
  } catch {
    /* 后端不可达由 pollHealth 负责报，这里静默以免重复报警 */
  }
}

function tasksWsUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws/tasks`;
}

function mergeTask(task: ScanTask) {
  const idx = allTasks.value.findIndex((t) => t.id === task.id);
  if (idx >= 0) {
    const next = allTasks.value.slice();
    next[idx] = { ...next[idx], ...task };
    allTasks.value = next;
  } else {
    allTasks.value = [task, ...allTasks.value];
  }
}

function connectTasksWs() {
  if (tasksWs && (tasksWs.readyState === WebSocket.OPEN || tasksWs.readyState === WebSocket.CONNECTING)) return;
  let ws: WebSocket;
  try {
    ws = new WebSocket(tasksWsUrl());
  } catch {
    scheduleWsReconnect();
    return;
  }
  tasksWs = ws;
  // 连接真正建立就把退避计数归零，下一次断开重新从 3s 起步
  ws.onopen = () => {
    wsReconnectAttempt = 0;
  };
  ws.onmessage = (ev: MessageEvent) => {
    try {
      const msg = JSON.parse(ev.data as string) as {
        type: string;
        tasks?: ScanTask[];
        task?: ScanTask;
        event?: { event_type?: string; task_id?: number; payload?: Record<string, unknown> };
      };
      if (msg.type === "snapshot" && Array.isArray(msg.tasks)) {
        allTasks.value = msg.tasks;
      } else if (msg.type === "task_update" && msg.task) {
        mergeTask(msg.task);
      } else if (msg.type === "event" && msg.event && msg.event.event_type === "task_progress") {
        // 进度事件自带 pipeline/stage_results，直接并入内存 allTasks，使运行条实时跳动，
        // 无需额外回源；详情页仍由各自的 /ws/tasks/{id} 通道提供完整实时数据。
        const evp = msg.event;
        if (evp.task_id != null && evp.payload) {
          const idx = allTasks.value.findIndex((t) => t.id === evp.task_id);
          if (idx >= 0) {
            const cur = allTasks.value[idx];
            const p = evp.payload as Record<string, unknown>;
            const next = allTasks.value.slice();
            next[idx] = {
              ...cur,
              status: "running",
              summary: {
                ...cur.summary,
                ...(p["pipeline"] ? { pipeline: p["pipeline"] as any } : {}),
                ...(p["stage_results"]
                  ? { results: { ...(cur.summary?.results || {}), ...(p["stage_results"] as any) } }
                  : {}),
                ...(p["finding_count"] ? { finding_count: Number(p["finding_count"]) } : {}),
                current_stage: String(
                  (p["current_stage"] as string) || (p["phase"] as string) || cur.summary?.current_stage || "",
                ),
              },
            };
            allTasks.value = next;
          }
        }
      }
      // heartbeat 忽略。
    } catch {
      /* 忽略坏帧 */
    }
  };
  ws.onclose = () => {
    tasksWs = null;
    scheduleWsReconnect();
  };
  ws.onerror = () => {
    if (tasksWs) {
      try {
        tasksWs.close();
      } catch {
        /* noop */
      }
    }
  };
}

// 前端就每 3 秒去撞一次门，每次都在 vite 的 /ws 代理上留一条 ECONNRESET，
// 实测把 stack-frontend.log 刷到 2.4 万行 / 1.7MB，用户看到的现象就是「前端一直在崩」。
// 改成指数退避（3s → 上限 30s），连接成功即归零：既止住刷屏，也避免后端刚起来时
// 被重连风暴再压一次。
const WS_RECONNECT_BASE_MS = 3000;
const WS_RECONNECT_MAX_MS = 30000;
let wsReconnectAttempt = 0;

function scheduleWsReconnect() {
  if (wsReconnectTimer != null) return;
  wsReconnectAttempt += 1;
  // 指数退避并加上抖动，避免多个标签页同拍重连
  const exp = Math.min(WS_RECONNECT_BASE_MS * 2 ** (wsReconnectAttempt - 1), WS_RECONNECT_MAX_MS);
  const delay = exp + Math.floor(Math.random() * 1000);
  wsReconnectTimer = window.setTimeout(() => {
    wsReconnectTimer = null;
    connectTasksWs();
  }, delay);
}
const running = computed(() => allTasks.value.filter((t) => String(t.status).toLowerCase() === "running"));

// 侧边栏底部要显示后端是否可达。用系统自带的健康检查，它是真的在探数据库与任务表，
// 不是我另造一个 heartbeat。
async function pollHealth() {
  try {
    const { data } = await http.get<{ status?: string }>("/api/system/health");
    backendOk.value = String(data?.status || "").toLowerCase() === "ok";
  } catch {
    backendOk.value = false;
  }
}

onMounted(() => {
  bootstrapTasks();
  pollHealth();
  connectTasksWs();
  healthTimer = window.setInterval(pollHealth, 15000);
  // 侧边栏要显示「当前工作区」，首次进入时补一次工作区列表；已有数据就不重复请求
  if (!store.items.length) void store.fetchWorkspaces().catch(() => undefined);
});
onUnmounted(() => {
  if (healthTimer) window.clearInterval(healthTimer);
  if (wsReconnectTimer != null) window.clearTimeout(wsReconnectTimer);
  if (tasksWs) {
    try {
      tasksWs.close();
    } catch {
      /* noop */
    }
    tasksWs = null;
  }
});

const primaryRunning = computed(() => running.value[0] || null);

/** 从任务详情三类 URL 形状里抽出任务 id：/tasks/:id、/workspace/:slug/task/:taskId、/task/:id */
function taskIdFromPath(path: string): number | null {
  const m =
    path.match(/^\/tasks\/(\d+)/) ||
    path.match(/^\/workspace\/[^/]+\/task\/(\d+)/) ||
    path.match(/\/task\/(\d+)/);
  return m ? Number(m[1]) : null;
}

/** 侧边栏底部与顶栏左侧的上下文：让用户随时知道自己在哪个工作区 */
const contextLabel = computed(() => {
  const path = route.path;
  const wsMatch = path.match(/^\/workspaces\/(\d+)/);
  if (wsMatch) return workspaceName(Number(wsMatch[1])) || `工作区 #${wsMatch[1]}`;
  const taskId = taskIdFromPath(path);
  if (taskId !== null) {
    const task = allTasks.value.find((t) => t.id === taskId);
    if (task) return workspaceName(task.workspace_id) || `工作区 #${task.workspace_id}`;
  }
  return "全局视图";
});

/** 侧边栏工作区分组用于展开与高亮：从路由或任务反查当前工作区 id */
const currentWorkspaceId = computed<number | null>(() => {
  const path = route.path;
  const wsMatch = path.match(/^\/workspaces\/(\d+)/);
  if (wsMatch) return Number(wsMatch[1]);
  const taskId = taskIdFromPath(path);
  if (taskId !== null) {
    const task = allTasks.value.find((t) => t.id === taskId);
    if (task) return task.workspace_id ?? null;
  }
  return null;
});

const routeLabel = computed(() => {
  const map: Record<string, string> = {
    "/": "工作区",
    "/runs": "运行监控",
    "/sca": "SCA 资产中心",
    "/dast-idor": "越权扫描",
    "/autonomy": "复核队列",
    "/rule-feedback": "污点规则反哺",
    "/metrics": "评估与指标",
    "/ops": "运维看板",
    "/usage": "用量统计",
    "/settings": "全局设置",
  };
  if (map[route.path]) return map[route.path];
  if (route.path.startsWith("/tasks/") || route.path.includes("/task/")) return "任务详情";
  if (route.path.startsWith("/workspaces/")) return "工作区详情";
  return "应用安全扫描平台";
});

function workspaceName(workspaceId: number | undefined): string {
  if (!workspaceId) return "";
  const ws = store.items.find((item) => item.id === workspaceId);
  return ws ? ws.name || ws.slug || `工作区 #${workspaceId}` : "";
}

function runningPct(task: ScanTask): number {
  const stages = taskStages(task);
  const total = stages.length || 1;
  const done = stages.filter((s) => s.status === "completed").length;
  return Math.round((done / total) * 100);
}
function runningStageText(task: ScanTask): string {
  return taskBadge(task);
}
function openRunning(task: ScanTask) {
  router.push(`/tasks/${task.id}`);
}
</script>
