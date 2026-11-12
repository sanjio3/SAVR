<template>
  <button v-if="open" class="sidebar-scrim" aria-label="关闭导航" @click="open = false" />

  <aside class="sidebar" :class="{ 'is-open': open }">
    <div class="sidebar-head">
      <!-- 品牌不是本页标题：用 div 承载，保证每页只有页面标题一个 h1 -->
      <div class="brand">
        <span class="brand-mark">SAST AI</span>
        <span class="brand-sub">应用安全扫描平台</span>
      </div>
      <button class="sidebar-toggle" aria-label="打开导航" :aria-expanded="open" @click="open = !open">
        <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M4 7h16M4 12h16M4 17h16" />
        </svg>
      </button>
    </div>

    <nav class="sidebar-nav" aria-label="主导航">
      <!-- 工作区：核心对象，按动线置于最前。当前所在工作区自动展开任务列表 -->
      <div v-if="workspaceItems.length" class="nav-group">
        <div class="nav-group-head">
          <div class="nav-group-title">工作区</div>
          <button type="button" class="nav-group-add" title="新建工作区" aria-label="新建工作区" @click="emit('open-workspace-create')">
            <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14" /></svg>
          </button>
        </div>
        <div v-for="ws in workspaceItems" :key="ws.id" class="nav-ws">
          <RouterLink
            class="nav-item"
            :class="{ active: isActiveWorkspace(ws.id) }"
            :to="ws.to"
            @click="open = false"
          >
            <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path v-for="(d, i) in ICONS.folder" :key="i" :d="d" />
            </svg>
            <span class="nav-label">{{ ws.name }}</span>
            <span v-if="ws.runningCount" class="nav-hint">{{ ws.runningCount }}</span>
          </RouterLink>
          <div v-if="ws.expanded" class="nav-ws-tasks">
            <RouterLink
              v-for="t in ws.tasks"
              :key="t.id"
              class="nav-subitem"
              :class="{ active: isActiveTask(t.id) }"
              :to="`/tasks/${t.id}`"
              @click="open = false"
            >
              <span class="nav-sub-dot" :class="taskDotClass(t)" />
              <span class="nav-sub-label">{{ t.name }}</span>
              <span class="nav-sub-tag">{{ taskBadge(t) }}</span>
            </RouterLink>
            <RouterLink v-if="ws.tasks.length" class="nav-subitem nav-sub-more" :to="ws.to" @click="open = false">查看全部 →</RouterLink>
          </div>
        </div>
      </div>

      <div v-for="group in groups" :key="group.title" class="nav-group">
        <div class="nav-group-title">{{ group.title }}</div>
        <RouterLink
          v-for="item in group.items"
          :key="item.to"
          class="nav-item"
          :class="{ active: isActive(item) }"
          :to="item.to"
          @click="open = false"
        >
          <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
            <path v-for="(d, i) in ICONS[item.icon]" :key="i" :d="d" />
          </svg>
          <span class="nav-label">{{ item.label }}</span>
          <span v-if="item.abbr" class="nav-abbr">{{ item.abbr }}</span>
          <span v-if="badgeOf(item)" class="nav-hint">{{ badgeOf(item) }}</span>
        </RouterLink>
      </div>
    </nav>

    <!-- 设置不是路由页：复核队列 / 规则反哺 / 常规 / SCA 资产 / 越权扫描 / 运维看板 / 用量统计 / 组件问答
         共八个分区合并进一个弹层，省掉平级入口，也不必在页面之间来回跳。 -->
    <button type="button" class="nav-item settings-entry" @click="open = false; emit('open-settings')">
      <svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true">
        <path v-for="(d, i) in ICONS.sliders" :key="i" :d="d" />
      </svg>
      <span class="nav-label">设置</span>
      <span class="nav-hint">8 个分区</span>
    </button>

    <div class="sidebar-footer">
      <div class="ctx-row ctx-switcher">
        <button type="button" class="ctx-trigger" :title="contextLabel" @click.stop="wsMenuOpen = !wsMenuOpen">
          <span class="ctx-label">当前工作区</span>
          <span class="ctx-value">{{ contextLabel }}</span>
          <span class="ctx-caret">▾</span>
        </button>
        <div v-if="wsMenuOpen" class="ctx-menu">
          <RouterLink
            v-for="ws in (store.items || [])"
            :key="ws.id"
            class="ctx-menu-item"
            :to="`/workspaces/${ws.id}`"
            @click="wsMenuOpen = false; open = false"
          >{{ ws.name || ws.slug || `工作区 #${ws.id}` }}</RouterLink>
        </div>
      </div>
      <div class="hb-row">
        <span class="hb-dot" :class="backendOk === null ? '' : backendOk ? 'is-ok' : 'is-bad'" />
        <span>{{ backendOk === null ? "连接后端中…" : backendOk ? "后端在线" : "后端不可达" }}</span>
        <span class="hb-ver">v{{ version }}</span>
      </div>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import { useRoute } from "vue-router";

import { useWorkspaceStore } from "@/stores/workspaces";
import { taskBadge } from "@/domain/task-view";
import type { ScanTask } from "@/types";

type IconKey =
  | "grid" | "pulse" | "folder" | "chart" | "box" | "shield" | "checklist" | "beaker" | "gauge" | "sliders" | "chat" | "usage";

interface NavItem {
  to: string;
  label: string;
  icon: IconKey;
  /** 保留英文简称，便于对照代码与后端接口里的叫法 */
  abbr?: string;
  /** 额外的激活前缀（任务详情页归到运行监控下） */
  extraPrefixes?: string[];
}

const props = withDefaults(
  defineProps<{
    runningCount?: number;
    backendOk?: boolean | null;
    contextLabel?: string;
    /** 全量任务（App.vue 10 秒轮询复用），供工作区分组与任务列表 */
    tasks?: ScanTask[];
    /** 当前路由所在工作区 id，驱动工作区展开与高亮 */
    currentWorkspaceId?: number | null;
  }>(),
  { runningCount: 0, backendOk: null, contextLabel: "全部工作区", tasks: () => [], currentWorkspaceId: null },
);

const emit = defineEmits<{ "open-settings": []; "open-workspace-create": [] }>();

const route = useRoute();
const open = ref(false);
const wsMenuOpen = ref(false);
const version = __APP_VERSION__;

const store = useWorkspaceStore();

/**
 * 导航按「工作流动线」组织，不按「系统里有什么」：
 *   - 工作区（动态分组，核心对象）置顶：每个工作区进 /workspaces/:id，当前所在工作区自动展开任务列表；
 *   - 概览（全部工作区 /、运行监控 /runs，保留在跑数徽标）；
 *   - 评估（评估与指标 /metrics，答「扫得准不准」）；
 *   - 资产/运维/用量类页面（SCA 资产、越权扫描、运维看板、用量统计）
 *     不再占一级导航，收进设置弹层（共 7 个分区），深链 /sca /dast-idor /ops /usage 仍可达。
 */
const groups: { title: string; items: NavItem[] }[] = [
  {
    title: "概览",
    items: [
      { to: "/runs", label: "运行监控", icon: "pulse", extraPrefixes: ["/tasks/", "/workspace/"] },
    ],
  },
  {
    title: "评估",
    items: [
      { to: "/metrics", label: "评估与指标", icon: "chart" },
    ],
  },
];

// 内联 SVG，不引第三方图标库；只做形状提示，不做装饰
const ICONS: Record<IconKey, string[]> = {
  grid: ["M4 4h7v7H4z", "M13 4h7v7h-7z", "M4 13h7v7H4z", "M13 13h7v7h-7z"],
  folder: ["M3 6h6l2 2h10v11H3z"],
  pulse: ["M3 12h4l3-7 4 14 3-7h4"],
  box: ["M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z", "M12 12l8-4.5", "M12 12v9", "M12 12L4 7.5"],
  shield: ["M12 3l7 3v6c0 4.6-3 7.6-7 9-4-1.4-7-4.4-7-9V6l7-3z"],
  checklist: ["M4 6h2.5l1.5 2 2.5-3", "M4 16h2.5l1.5 2 2.5-3", "M14 7h6", "M14 17h6", "M14 12h6"],
  beaker: ["M9 3h6", "M10 3v6L5 18a2 2 0 001.8 3h10.4A2 2 0 0019 18l-5-9V3", "M7.6 14h8.8"],
  chart: ["M3 21h18", "M5 21V11", "M10.5 21V5", "M16 21v-7", "M21 21V8"],
  gauge: ["M3.6 17a9 9 0 1116.8 0", "M12 17l4.6-5.4"],
  sliders: ["M4 7h9", "M17 7h3", "M4 17h4", "M12 17h8", "M15 5v4", "M8 15v4"],
  chat: ["M4 5h16v11H9.5L4 20V5z"],
  // 用量统计：带外框的柱状图，区别于「指标」的裸柱（chart）
  usage: ["M3 5h18v14H3z", "M7 15V9", "M11 15V7", "M15 15v-4", "M19 15v-6"],
};

function isActive(item: NavItem): boolean {
  const path = route.path;
  if (path === item.to) return true;
  if (item.extraPrefixes?.some((prefix) => path.startsWith(prefix))) return true;
  return item.to !== "/" && path.startsWith(`${item.to}/`);
}

/** 运行监控入口上直接显示在跑的任务数，省得进页面才知道有几个在跑 */
function badgeOf(item: NavItem): string {
  if (item.to !== "/runs" || props.runningCount <= 0) return "";
  return String(props.runningCount);
}

/** 工作区分组：来自 store.items，每个工作区带最近的 5 条任务与在跑数；当前所在工作区自动展开 */
function sortTasks(a: ScanTask, b: ScanTask): number {
  const ta = Date.parse(a.started_at || a.created_at || "") || 0;
  const tb = Date.parse(b.started_at || b.created_at || "") || 0;
  if (tb !== ta) return tb - ta;
  return (b.id || 0) - (a.id || 0);
}

const workspaceItems = computed(() => {
  const all = props.tasks || [];
  return (store.items || []).map((ws) => {
    const wsTasks = all.filter((t) => t.workspace_id === ws.id);
    const runningCount = wsTasks.filter((t) => String(t.status).toLowerCase() === "running").length;
    const tasks = [...wsTasks].sort(sortTasks).slice(0, 5);
    return {
      id: ws.id,
      name: ws.name || ws.slug || `工作区 #${ws.id}`,
      to: `/workspaces/${ws.id}`,
      runningCount,
      expanded: props.currentWorkspaceId === ws.id,
      tasks,
    };
  });
});

function isActiveWorkspace(id: number): boolean {
  return props.currentWorkspaceId === id;
}

function isActiveTask(id: number): boolean {
  return route.path === `/tasks/${id}` || route.path.endsWith(`/task/${id}`);
}

/** 任务状态点配色：运行中/已完成/失败/其它 */
function taskDotClass(t: ScanTask): string {
  const s = String(t.status).toLowerCase();
  if (s === "running") return "dot-run";
  if (s === "completed" || s === "success") return "dot-done";
  if (s === "failed" || s === "error") return "dot-fail";
  return "dot-idle";
}
</script>

<style scoped>
.nav-group-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.nav-group-add {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 22px;
  height: 22px;
  padding: 0;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--color-muted);
  cursor: pointer;
  transition: background 0.16s var(--ease-out), color 0.16s var(--ease-out);
}
.nav-group-add:hover {
  background: var(--color-surface-3);
  color: var(--color-accent);
}
.nav-group-add .nav-icon {
  width: 16px;
  height: 16px;
}

.nav-ws {
  display: flex;
  flex-direction: column;
}
.nav-ws-tasks {
  display: flex;
  flex-direction: column;
  margin: 2px 0 6px 14px;
  border-left: 1px solid var(--color-border);
  padding-left: 6px;
}
.nav-subitem {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 5px 8px;
  border-radius: var(--radius-sm);
  color: var(--color-muted);
  font-size: 12px;
  text-decoration: none;
}
.nav-subitem:hover {
  background: var(--color-surface-3);
}
.nav-subitem.active {
  background: var(--color-surface-3);
  color: var(--color-ink);
}
.nav-sub-label {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.nav-sub-tag {
  font-size: 10px;
  opacity: 0.7;
}
.nav-sub-more {
  color: var(--sev-info);
  font-size: 11px;
}
.nav-sub-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--st-idle);
  flex: none;
}
.dot-run {
  background: var(--st-run);
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--st-run) 18%, transparent);
}
.dot-done {
  background: var(--st-ok);
}
.dot-fail {
  background: var(--st-fail);
}
.dot-idle {
  background: var(--st-idle);
}

.ctx-switcher {
  position: relative;
}
.ctx-trigger {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
  background: transparent;
  border: 0;
  padding: 0;
  cursor: pointer;
  color: inherit;
  font: inherit;
}
.ctx-caret {
  margin-left: auto;
  opacity: 0.6;
  font-size: 10px;
}
.ctx-menu {
  position: absolute;
  left: 0;
  right: 0;
  bottom: calc(100% + 6px);
  background: var(--color-surface);
  border: 1px solid var(--color-border-strong);
  border-radius: var(--radius-md);
  padding: 4px;
  display: flex;
  flex-direction: column;
  max-height: 220px;
  overflow: auto;
  z-index: 20;
}
.ctx-menu-item {
  padding: 6px 8px;
  border-radius: var(--radius-sm);
  color: var(--color-muted);
  text-decoration: none;
  font-size: 12px;
}
.ctx-menu-item:hover {
  background: var(--color-surface-3);
  color: var(--color-ink);
}
</style>
