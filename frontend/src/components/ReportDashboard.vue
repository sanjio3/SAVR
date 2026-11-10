<template>
  <section class="card stack gap-sm dash">
    <div class="row between wrap gap-sm">
      <div>
        <h3>结果看板</h3>
        <p class="muted">结论先行的结构化视图：风险分布、来源通道、验证强度、族矩阵，逐层下钻到单条证据。</p>
      </div>
      <div class="row wrap gap-xs">
        <button type="button" class="ghost-button" :class="{ active: view === 'dashboard' }" @click="view = 'dashboard'">看板</button>
        <button type="button" class="ghost-button" :class="{ active: view === 'matrix' }" @click="view = 'matrix'">族矩阵</button>
        <button type="button" class="ghost-button" :class="{ active: view === 'list' }" @click="view = 'list'">清单</button>
      </div>
    </div>

    <div v-if="loading" class="dash-hint muted">结构化数据加载中…</div>
    <div v-else-if="error" class="dash-hint err">{{ error }}</div>

    <template v-else-if="data">
      <!-- ① 结论卡：4 个关键数 + 严重度堆叠条 -->
      <div class="kpi-row">
        <div class="kpi">
          <span class="kpi-label">总发现</span>
          <strong class="kpi-num">{{ data.overview.total_findings }}</strong>
          <span class="muted kpi-sub">应用 {{ data.overview.app_findings }} · 依赖 {{ data.overview.sca_findings }}</span>
        </div>
        <div class="kpi">
          <span class="kpi-label">已确认可利用</span>
          <strong class="kpi-num ok">{{ data.overview.confirmed_specs }}</strong>
          <span class="muted kpi-sub">占入环 spec {{ pct(data.overview.spec_coverage) }}</span>
        </div>
        <div class="kpi">
          <span class="kpi-label">证据仅 DAST</span>
          <strong class="kpi-num warn">{{ countStrength('dast_only') }}</strong>
          <span class="muted kpi-sub">无可利用运行时证据</span>
        </div>
        <div class="kpi">
          <span class="kpi-label">落噪声 sink</span>
          <strong class="kpi-num bad">{{ countStrength('weak') }}</strong>
          <span class="muted kpi-sub">已确认但 sink 非本族真函数</span>
        </div>
      </div>

      <div v-if="severityRows.length" class="stack gap-xs">
        <div class="row between">
          <span class="dash-title">风险分布</span>
          <span class="muted">共 {{ data.overview.app_findings }} 条应用发现</span>
        </div>
        <div class="bar">
          <div
            v-for="s in severityRows"
            :key="s.name"
            class="bar-seg"
            :class="'sev-' + s.name.toLowerCase()"
            :style="{ flexGrow: Math.max(s.value, 0.0001) }"
            :title="`${s.name} ${s.value}`"
          />
        </div>
        <div class="legend">
          <button
            v-for="s in severityRows"
            :key="s.name"
            type="button"
            class="legend-item"
            :class="{ dim: !isActive('severity', s.name) }"
            @click="toggleFilter('severity', s.name)"
          >
            <span class="dot" :class="'dot-' + s.name.toLowerCase()" />{{ s.name }}
            <strong>{{ s.value }}</strong>
          </button>
        </div>
      </div>

      <!-- ② 来源通道 → 验证状态：看哪条通道在产有效、哪条在产噪声 -->
      <div class="two-col">
        <div class="stack gap-xs">
          <span class="dash-title">来源通道</span>
          <button
            v-for="s in topRows(data.distributions.by_source, 8)"
            :key="s.name"
            type="button"
            class="hbar-row"
            :class="{ dim: !isActive('source', s.name) }"
            @click="toggleFilter('source', s.name)"
          >
            <span class="hbar-name">{{ s.name }}</span>
            <span class="hbar-track"><span class="hbar-fill src" :style="{ width: widthOf(s.value, data.distributions.by_source) }" /></span>
            <strong class="hbar-num">{{ s.value }}</strong>
          </button>
        </div>
        <div class="stack gap-xs">
          <span class="dash-title">验证状态</span>
          <button
            v-for="s in topRows(data.distributions.by_verification, 8)"
            :key="s.name"
            type="button"
            class="hbar-row"
            :class="{ dim: !isActive('verification', s.name) }"
            @click="toggleFilter('verification', s.name)"
          >
            <span class="hbar-name">{{ s.name }}</span>
            <span class="hbar-track"><span class="hbar-fill" :class="'v-' + vClass(s.name)" :style="{ width: widthOf(s.value, data.distributions.by_verification) }" /></span>
            <strong class="hbar-num">{{ s.value }}</strong>
          </button>
        </div>
      </div>

      <!-- 筛选条 -->
      <div v-if="activeFilters.length" class="row wrap gap-xs">
        <span class="muted">已筛选</span>
        <button v-for="f in activeFilters" :key="f.dim + ':' + f.value" type="button" class="chip" @click="clearFilter(f.dim)">
          {{ f.dim }} = {{ f.value }} <span aria-hidden="true">×</span>
        </button>
        <button type="button" class="ghost-button" @click="filters = {}">全部清除</button>
        <span class="muted">命中 {{ filteredFindings.length }} / {{ data.findings.length }} 条</span>
      </div>

      <!-- ③ 族矩阵 -->
      <div v-if="view === 'matrix'" class="table-wrap cols-4">
        <table>
          <thead>
            <tr><th>族</th><th v-for="v in matrixVerifs" :key="v">{{ v }}</th><th>合计</th></tr>
          </thead>
          <tbody>
            <tr v-for="row in matrixRows" :key="row.family">
              <td>{{ row.family }}</td>
              <td v-for="v in matrixVerifs" :key="v">{{ row.cells[v] || 0 }}</td>
              <td><strong>{{ row.total }}</strong></td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- ④ 清单 -->
      <div v-else-if="view === 'list'" class="table-wrap cols-6">
        <table>
          <thead>
            <tr>
              <th>严重度</th><th>族</th><th>位置 / 端点</th><th>验证状态</th><th>运行时观测</th><th>证据强度</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(f, i) in pagedFindings" :key="i">
              <td><span class="badge" :class="'badge sev-' + (f.severity || 'low').toLowerCase()">{{ (f.severity || '—').toUpperCase() }}</span></td>
              <td>{{ f.family || f.finding_type || '—' }}</td>
              <td>
                <div>{{ f.location || '—' }}</div>
                <div v-if="f.endpoint" class="muted">{{ f.http_method }} {{ f.endpoint }}</div>
              </td>
              <td>{{ f.verification_status || '—' }}</td>
              <td class="muted">{{ f.iast_state || '—' }}</td>
              <td><span class="badge" :class="'st-' + f.evidence_strength">{{ strengthLabel(f.evidence_strength) }}</span></td>
            </tr>
          </tbody>
        </table>
        <p v-if="data.findings_truncated" class="muted">仅显示前 {{ data.findings.length }} 条（共 {{ data.findings_total }} 条）。</p>
      </div>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";

import { http } from "@/services/http";
import type { StructuredFinding, StructuredReport } from "@/types";

const props = defineProps<{ reportId: number | null }>();

type Dim = "severity" | "source" | "verification";
const PAGE = 60;

const data = ref<StructuredReport | null>(null);
const loading = ref(false);
const error = ref("");
const view = ref<"dashboard" | "matrix" | "list">("dashboard");
const filters = ref<Record<string, string>>({});
const page = ref(1);

async function load(id: number) {
  loading.value = true;
  error.value = "";
  try {
    const { data: d } = await http.get<StructuredReport>(`/api/reports/${id}/structured`);
    data.value = d;
  } catch (e) {
    error.value = `结构化数据加载失败：${(e as Error)?.message ?? e}`;
    data.value = null;
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  if (props.reportId) load(props.reportId);
});
watch(
  () => props.reportId,
  (id) => {
    filters.value = {};
    page.value = 1;
    if (id) load(id);
    else data.value = null;
  },
);

function pct(v: number): string {
  return `${(Number(v || 0) * 100).toFixed(1)}%`;
}

function toRows(rec: Record<string, number> | undefined) {
  return Object.entries(rec ?? {}).map(([name, value]) => ({ name, value: Number(value || 0) }));
}
const severityRows = computed(() => {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const rows = toRows(data.value?.distributions.severity);
  return rows.sort((a, b) => {
    const ia = order.indexOf(a.name.toUpperCase());
    const ib = order.indexOf(b.name.toUpperCase());
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
});
function topRows(rec: Record<string, number> | undefined, n: number) {
  return toRows(rec).sort((a, b) => b.value - a.value).slice(0, n);
}
function widthOf(v: number, rec: Record<string, number> | undefined): string {
  const max = Math.max(1, ...Object.values(rec ?? {}).map((x) => Number(x || 0)));
  return `${Math.max(2, (Number(v || 0) / max) * 100)}%`;
}
function vClass(name: string): string {
  const n = name.toLowerCase();
  if (n.includes("confirmed_exploitable") || n === "exploitable") return "ok";
  if (n.includes("unconfirmed")) return "warn";
  if (n.includes("no_evidence")) return "idle";
  if (n.includes("filtered") || n.includes("false")) return "neg";
  return "idle";
}
function countStrength(s: StructuredFinding["evidence_strength"]): number {
  return (data.value?.findings ?? []).filter((f) => f.evidence_strength === s).length;
}
function strengthLabel(s: StructuredFinding["evidence_strength"]): string {
  return (
    {
      strong: "强（运行时+真 sink）",
      weak: "弱（落噪声 sink）",
      dast_only: "仅 DAST",
      unverified: "待验证",
      negative: "已排除",
      detect_only: "仅检出",
    }[s] ?? s
  );
}

// —— 联动筛选 ——
const activeFilters = computed(() =>
  Object.entries(filters.value).map(([dim, value]) => ({ dim, value })),
);
function isActive(dim: Dim, value: string): boolean {
  return filters.value[dim] === value;
}
function toggleFilter(dim: Dim, value: string): void {
  const next = { ...filters.value };
  if (next[dim] === value) delete next[dim];
  else next[dim] = value;
  filters.value = next;
  page.value = 1;
}
function clearFilter(dim: string): void {
  const next = { ...filters.value };
  delete next[dim];
  filters.value = next;
  page.value = 1;
}

const filteredFindings = computed(() => {
  const f = filters.value;
  return (data.value?.findings ?? []).filter((x) => {
    if (f.severity && (x.severity || "").toUpperCase() !== f.severity.toUpperCase()) return false;
    if (f.source && (x.source || "") !== f.source) return false;
    if (f.verification && (x.verification_status || "") !== f.verification) return false;
    return true;
  });
});
const pagedFindings = computed(() => filteredFindings.value.slice(0, PAGE * page.value));

// —— 族矩阵 ——
const matrixVerifs = computed(() => {
  const set = new Set<string>();
  for (const cells of Object.values(data.value?.family_matrix ?? {})) {
    for (const v of Object.keys(cells ?? {})) set.add(v);
  }
  return [...set].sort();
});
const matrixRows = computed(() =>
  Object.entries(data.value?.family_matrix ?? {})
    .map(([family, cells]) => ({
      family,
      cells: cells as Record<string, number>,
      total: Object.values(cells ?? {}).reduce((a, b) => a + Number(b || 0), 0),
    }))
    .sort((a, b) => b.total - a.total),
);
</script>

<style scoped>
.dash { --dash-gap: 12px; }
.dash-title { font-size: 13px; font-weight: 500; }
.dash-hint { padding: 18px 0; text-align: center; }
.dash-hint.err { color: var(--sev-critical); }

.kpi-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; }
.kpi {
  display: flex; flex-direction: column; gap: 2px;
  padding: 10px 12px; border: 1px solid var(--color-border-tertiary); border-radius: var(--border-radius-md);
  background: var(--color-background-secondary);
}
.kpi-label { font-size: 12px; color: var(--color-text-secondary); }
.kpi-num { font-size: 22px; font-weight: 500; line-height: 1.2; }
.kpi-num.ok { color: var(--sev-critical); }
.kpi-num.warn { color: var(--sev-high); }
.kpi-num.bad { color: var(--sev-high); }
.kpi-sub { font-size: 11px; }

.bar { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: var(--color-background-tertiary); }
.bar-seg { min-width: 2px; }
.bar-seg.sev-critical { background: var(--sev-critical); }
.bar-seg.sev-high { background: var(--sev-high); }
.bar-seg.sev-medium { background: var(--sev-medium); }
.bar-seg.sev-low { background: var(--sev-low); }

.legend { display: flex; flex-wrap: wrap; gap: 8px; }
.legend-item {
  display: inline-flex; align-items: center; gap: 5px;
  font-size: 12px; color: var(--color-text-primary);
  background: none; border: 0; padding: 2px 4px; cursor: pointer; border-radius: 4px;
}
.legend-item.dim { opacity: 0.4; }
.dot { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.dot-critical { background: var(--sev-critical); }
.dot-high { background: var(--sev-high); }
.dot-medium { background: var(--sev-medium); }
.dot-low { background: var(--sev-low); }

.two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.hbar-row {
  display: grid; grid-template-columns: 110px 1fr 40px; align-items: center; gap: 8px;
  background: none; border: 0; padding: 2px 0; cursor: pointer; text-align: left;
  font-size: 12px; color: var(--color-text-primary);
}
.hbar-row.dim { opacity: 0.4; }
.hbar-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hbar-track { height: 8px; border-radius: 999px; background: var(--color-background-tertiary); overflow: hidden; }
.hbar-fill { display: block; height: 100%; background: var(--color-border-primary); }
.hbar-fill.src { background: var(--color-text-tertiary); }
.hbar-fill.v-ok { background: var(--sev-critical); }
.hbar-fill.v-warn { background: var(--sev-high); }
.hbar-fill.v-neg { background: var(--sev-low); }
.hbar-fill.v-idle { background: var(--color-border-primary); }
.hbar-num { text-align: right; font-weight: 500; }

.chip {
  font-size: 12px; padding: 2px 8px; border-radius: 999px; cursor: pointer;
  border: 1px solid var(--color-border-secondary); background: var(--color-background-secondary);
  color: var(--color-text-primary);
}
.badge.st-strong { background: color-mix(in srgb, var(--sev-critical) 16%, transparent); color: var(--sev-critical-ink); }
.badge.st-weak { background: color-mix(in srgb, var(--sev-high) 16%, transparent); color: var(--sev-high-ink); }
.badge.st-dast_only { background: color-mix(in srgb, var(--sev-medium) 18%, transparent); color: var(--sev-medium-ink); }
.badge.st-unverified { background: var(--color-background-tertiary); color: var(--color-text-secondary); }
.badge.st-negative { background: color-mix(in srgb, var(--sev-low) 18%, transparent); color: var(--sev-low-ink); }
.badge.st-detect_only { background: var(--color-background-tertiary); color: var(--color-text-tertiary); }
</style>
