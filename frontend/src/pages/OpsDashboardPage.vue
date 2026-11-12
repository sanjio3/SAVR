<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>运维看板</h1>
        <p class="page-subtitle">
          只回答「平台现在健不健康」：进程与看门狗是否在位、端口是否真在监听、队列是否在动、
          IAST 事件摄取是否跟得上生产。用量与成本请看「用量统计」，效果指标在设置中心 · 指标。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="loadAll">刷新</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取运行状态…" />

    <template v-else>
      <section class="stats-grid compact">
        <StatCard label="后端 API">{{ portState("backend") }}</StatCard>
        <StatCard label="前端">{{ portState("frontend") }}</StatCard>
        <StatCard label="统一看门狗">{{ watchdogState }}</StatCard>
        <StatCard label="运行中任务">{{ activeTasks.length }}</StatCard>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <h3>进程与看门狗</h3>
          <span class="muted small">状态文件更新于 {{ proc?.updated_at || "-" }}</span>
        </div>
        <p class="muted">
          「实时在监听」是当场连端口探出来的，不是状态文件里的记录值；两者不一致说明进程活着但端口没起来，
          或状态文件已经过期。重启次数与最近原因来自统一看门狗（launch_stack.py）。
        </p>
        <div v-if="procList.length" class="table-wrap cols-7">
          <table>
            <thead>
              <tr><th>进程</th><th>端口</th><th>PID</th><th>实时在监听</th><th>重启次数</th><th>启动时间</th><th>最近重启原因</th></tr>
            </thead>
            <tbody>
              <tr v-for="p in procList" :key="p.name">
                <td>
                  <div>{{ p.label }}</div>
                  <div class="muted small">{{ p.name }}</div>
                </td>
                <td class="num">{{ p.port ?? "-" }}</td>
                <td class="num">{{ p.pid ?? "-" }}</td>
                <td>
                  <span class="tag" :class="p.live_listening ? 'ok' : 'bad'">{{ p.live_listening ? "在监听" : "未监听" }}</span>
                  <span v-if="!p.managed_by_stack" class="muted small"> · 非看门狗托管</span>
                </td>
                <td class="num">{{ p.restarts ?? "-" }}</td>
                <td class="muted">{{ p.started_at || "-" }}</td>
                <td class="muted wrap-break">{{ p.last_restart_reason || "-" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>没有进程状态</strong>
          <span>统一看门狗未运行，或尚未写出进程状态文件。</span>
        </div>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <h3>队列</h3>
          <span class="muted small">共 {{ tasks.length }} 个任务</span>
        </div>
        <div v-if="activeTasks.length" class="table-wrap cols-4">
          <table>
            <thead><tr><th>任务</th><th>名称</th><th>状态</th><th>开始时间</th></tr></thead>
            <tbody>
              <tr v-for="t in activeTasks" :key="String(t.id)">
                <td class="num"><RouterLink :to="`/tasks/${t.id}`">#{{ t.id }}</RouterLink></td>
                <td class="wrap-break">{{ t.name }}</td>
                <td><span class="tag" :class="t.status === 'running' ? 'ok' : ''">{{ t.status }}</span></td>
                <td class="muted">{{ t.started_at || t.created_at || "-" }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>队列为空</strong>
          <span>当前没有运行中或排队中的扫描任务。</span>
        </div>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <h3>IAST 事件摄取吞吐</h3>
        </div>
        <p class="muted">排空速率长期低于生产速率即说明瓶颈在后端写库；背压窗口增长表示后端已成为限速点（此时探针会变慢而非丢事件）。</p>
        <div class="stats-grid compact">
          <StatCard label="接收事件">{{ ingest?.total_received ?? "-" }}</StatCard>
          <StatCard label="实际落库">{{ ingest?.total_written ?? "-" }}</StatCard>
          <StatCard label="去重丢弃">{{ ingest?.total_dup_skipped ?? "-" }}</StatCard>
          <StatCard label="排空速率">{{ rate(ingest?.last_drain_rate) }}</StatCard>
          <StatCard label="落库速率">{{ rate(ingest?.last_write_rate) }}</StatCard>
          <StatCard label="最近批大小">{{ ingest?.last_batch_size ?? "-" }}</StatCard>
          <StatCard label="批次耗时">{{ ms(ingest?.last_flush_ms) }}</StatCard>
          <StatCard label="刷盘次数">{{ ingest?.flushes ?? "-" }}</StatCard>
          <StatCard label="背压窗口">{{ ingest?.backpressure_windows ?? "-" }}</StatCard>
          <StatCard label="当前深度">{{ ingest?.pending_depth ?? "-" }}</StatCard>
          <StatCard label="鉴权拒绝">{{ ingest?.total_rejected ?? "-" }}</StatCard>
        </div>
      </section>
    </template>

    <div v-if="error" class="callout danger">{{ error }}</div>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { gsap } from "gsap";

import StatCard from "@/components/StatCard.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import { useTableScroll } from "@/domain/table-scroll";
import { http } from "@/services/http";
import type { ScanTask } from "@/types";

type Row = Record<string, any>;

const root = ref<HTMLElement | null>(null);
const proc = ref<Row | null>(null);
const ingest = ref<Row | null>(null);
const tasks = ref<ScanTask[]>([]);
const error = ref("");
const loading = ref(true);

useTableScroll(root);

onMounted(async () => {
  await loadAll();
  loading.value = false;
  animate();
});

async function loadAll() {
  error.value = "";
  await Promise.all([loadProcesses(), loadIngest(), loadTasks()]);
  animate();
}

async function loadProcesses() {
  try {
    const { data } = await http.get<Row>("/api/system/processes");
    proc.value = data;
  } catch (caught) { error.value = errText(caught); }
}

async function loadIngest() {
  try {
    const { data } = await http.get<Row>("/api/iast/ingest-stats");
    ingest.value = data;
  } catch (caught) { error.value = errText(caught); }
}

async function loadTasks() {
  try {
    const { data } = await http.get<ScanTask[]>("/api/scan-tasks");
    tasks.value = data;
  } catch (caught) { error.value = errText(caught); }
}

const procList = computed<Row[]>(() => {
  const raw = proc.value?.processes;
  if (!raw || typeof raw !== "object") return [];
  return Object.entries(raw as Record<string, Row>).map(([name, value]) => ({ name, ...value }));
});

/** 队列只关心「还没结束」的任务：跑完的历史任务属于运行监控，不属于运维看板 */
const activeTasks = computed(() => {
  const running = new Set(["running", "pending", "queued", "starting"]);
  return tasks.value.filter((t) => running.has(String(t.status).toLowerCase()));
});

const watchdogState = computed(() => {
  if (!proc.value) return "-";
  return proc.value.stack_manager_running ? "在岗" : "失联";
});

function portState(name: string) {
  const item = procList.value.find((p) => p.name === name);
  if (!item) return "-";
  return item.live_listening ? "在线" : "离线";
}

function rate(value: unknown) {
  const num = Number(value);
  return Number.isFinite(num) ? `${num.toFixed(0)} 条/秒` : "-";
}

function ms(value: unknown) {
  const num = Number(value);
  return Number.isFinite(num) ? `${num.toFixed(1)} ms` : "-";
}

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error).message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(root.value.querySelectorAll(".stat-card, .glow-card"), { y: 8, opacity: 0.82 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.02, ease: "power2.out" });
}
</script>
