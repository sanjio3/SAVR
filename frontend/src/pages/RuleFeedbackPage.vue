<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>污点规则反哺</h1>
        <p class="page-subtitle">
          AI 发现的 source / sink / sanitizer 候选先进候选队列，人工确认后渲染进白盒规则库，
          并自动跑一遍回归：指标不下降才允许合入，下降就标记为回归失败。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <input v-model="workspaceId" placeholder="工作区 id（可选）" style="max-width: 180px" />
        <button class="ghost-button" @click="reload">刷新</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取规则候选…" />

    <template v-else>
      <div class="stats-grid compact">
        <StatCard label="候选总数" num>{{ metrics?.total ?? "-" }}</StatCard>
        <StatCard label="已合入" num>{{ metrics?.merged ?? "-" }}</StatCard>
        <StatCard label="回归失败" num>{{ metrics?.regression_failed ?? "-" }}</StatCard>
        <StatCard label="合入率" num>{{ pct(metrics?.merge_rate) }}</StatCard>
      </div>

      <section class="card stack glow-card">
        <div>
          <h3>新增候选</h3>
          <p class="muted">匹配模式支持正则或关键字。合入与否由后续回归测试决定，这里只负责登记。</p>
        </div>
        <div class="row gap-sm wrap">
          <select v-model="form.kind" style="max-width: 150px" aria-label="候选类型">
            <option value="source">source（污点源）</option>
            <option value="sink">sink（危险汇聚点）</option>
            <option value="sanitizer">sanitizer（净化函数）</option>
          </select>
          <input v-model="form.pattern" placeholder="匹配模式（正则或关键字）" style="flex: 1; min-width: 220px" />
          <input v-model="form.language" placeholder="语言，例如 java" style="max-width: 140px" />
          <input v-model="form.family" placeholder="漏洞族，例如 sqli" style="max-width: 150px" />
          <select v-model="form.confidence" style="max-width: 130px" aria-label="置信度">
            <option value="low">低置信度</option>
            <option value="medium">中置信度</option>
            <option value="high">高置信度</option>
          </select>
          <button class="button" @click="record">登记候选</button>
        </div>
        <div v-if="error" class="callout danger">{{ error }}</div>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <div>
            <h3>候选队列</h3>
            <p class="muted">「命中」是该模式在本轮扫描里实际命中的次数，可作为优先确认的依据。</p>
          </div>
          <select v-model="filterStatus" @change="loadCandidates" style="max-width: 200px" aria-label="按状态筛选">
            <option value="">全部状态</option>
            <option value="candidate">待确认</option>
            <option value="merged">已合入</option>
            <option value="regression_failed">回归失败</option>
          </select>
        </div>
        <div v-if="candidates.length" class="table-wrap cols-9">
          <table>
            <thead><tr><th>ID</th><th>类型</th><th>匹配模式</th><th>语言</th><th>漏洞族</th><th>置信度</th><th>状态</th><th>命中</th><th></th></tr></thead>
            <tbody>
              <tr v-for="c in candidates" :key="String(c.id)">
                <td class="num">{{ c.id }}</td>
                <td>{{ kindLabel(c.kind) }}</td>
                <td><code class="wrap-break">{{ c.pattern }}</code></td>
                <td>{{ c.language }}</td>
                <td>{{ c.family }}</td>
                <td>{{ confidenceLabel(c.confidence) }}</td>
                <td><span class="tag" :class="statusClass(c.status)">{{ statusLabel(c.status) }}</span></td>
                <td class="num">{{ c.occurrences }}</td>
                <td>
                  <button v-if="c.status === 'candidate'" class="ghost-button tiny" @click="confirm(c.id)">确认为规则</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无候选规则</strong>
          <span>先在上面登记一条候选，或跑一次任务让 AI 产出 source / sink / sanitizer 候选。</span>
        </div>
      </section>

      <section v-if="lastRegression" class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <div>
            <h3>最近一次确认的回归结果</h3>
            <p class="muted">合入前会重跑一遍评估集，指标不下降才真正生效。</p>
          </div>
          <button class="ghost-button" @click="lastRegression = null">收起</button>
        </div>
        <div class="row wrap gap-md">
          <StatCard label="回归结论">{{ regressionVerdict }}</StatCard>
          <div v-for="[k, v] in regressionNumbers" :key="k" class="stat-card">
            <span class="muted">{{ humanKey(k) }}</span><strong class="num">{{ v }}</strong>
          </div>
        </div>
        <details class="advanced">
          <summary>查看后端返回的原始数据</summary>
          <pre class="code-block" style="margin-top: 10px">{{ JSON.stringify(lastRegression, null, 2) }}</pre>
        </details>
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { gsap } from "gsap";

import StatCard from "@/components/StatCard.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import { useTableScroll } from "@/domain/table-scroll";
import { http } from "@/services/http";

type Row = Record<string, any>;

const root = ref<HTMLElement | null>(null);
const candidates = ref<Row[]>([]);
const metrics = ref<Row | null>(null);
const lastRegression = ref<Row | null>(null);
const workspaceId = ref("");
const filterStatus = ref("");
const error = ref("");
const loading = ref(true);
const form = ref({ kind: "sink", pattern: "", language: "", family: "", confidence: "medium" });

useTableScroll(root);

onMounted(async () => {
  await loadAll();
  loading.value = false;
  animate();
});

function wsParam() {
  const id = Number(workspaceId.value);
  return Number.isFinite(id) && id > 0 ? id : null;
}

async function loadAll() {
  error.value = "";
  await Promise.all([loadCandidates(), loadMetrics()]);
  animate();
}

async function reload() {
  await loadAll();
}

async function loadCandidates() {
  try {
    const params: Row = {};
    const id = wsParam();
    if (id) params.workspace_id = id;
    if (filterStatus.value) params.status = filterStatus.value;
    const { data } = await http.get<Row[]>("/api/rule-feedback/taint-candidates", { params });
    candidates.value = Array.isArray(data) ? data : [];
  } catch (caught) { error.value = errText(caught); }
}

async function loadMetrics() {
  try {
    const id = wsParam();
    const { data } = await http.get<Row>("/api/rule-feedback/metrics", { params: id ? { workspace_id: id } : {} });
    metrics.value = data;
  } catch (caught) { error.value = errText(caught); }
}

async function record() {
  error.value = "";
  if (!form.value.pattern.trim()) { error.value = "匹配模式不能为空。"; return; }
  try {
    await http.post("/api/rule-feedback/taint-candidates", { ...form.value, workspace_id: wsParam() });
    form.value.pattern = "";
    await loadAll();
  } catch (caught) { error.value = errText(caught); }
}

async function confirm(ruleId: number) {
  error.value = "";
  try {
    const { data } = await http.post<Row>(`/api/rule-feedback/taint-candidates/${ruleId}/confirm`, { confirmed_by: "reviewer" });
    lastRegression.value = data.regression ?? data;
    await loadAll();
  } catch (caught) { error.value = errText(caught); }
}

function statusClass(status: string) {
  if (status === "merged") return "ok";
  if (status === "regression_failed") return "bad";
  return "";
}

function statusLabel(status: unknown) {
  const map: Record<string, string> = { candidate: "待确认", merged: "已合入", regression_failed: "回归失败" };
  return map[String(status)] || String(status || "-");
}

function kindLabel(kind: unknown) {
  const map: Record<string, string> = { source: "污点源", sink: "危险汇聚点", sanitizer: "净化函数" };
  return map[String(kind)] || String(kind || "-");
}

function confidenceLabel(value: unknown) {
  const map: Record<string, string> = { low: "低", medium: "中", high: "高" };
  return map[String(value).toLowerCase()] || String(value || "-");
}

function pct(value: unknown) {
  const num = Number(value);
  return Number.isFinite(num) ? `${(num * 100).toFixed(1)}%` : "-";
}

/** 回归结果里的关键数字：只取标量，对象/数组不再硬塞进卡片 */
const regressionNumbers = computed<[string, string][]>(() => {
  const source = (lastRegression.value || {}) as Row;
  const pairs: [string, string][] = [];
  for (const [key, value] of Object.entries(source)) {
    if (key === "regression") continue;
    if (value === null || value === undefined) continue;
    if (typeof value === "object") continue;
    pairs.push([key, typeof value === "boolean" ? (value ? "是" : "否") : String(value)]);
    if (pairs.length >= 6) break;
  }
  return pairs;
});

const regressionVerdict = computed(() => {
  const source = (lastRegression.value || {}) as Row;
  const inner = (source.regression || {}) as Row;
  const failed = inner.regression_failed ?? source.regression_failed;
  const passed = inner.passed ?? source.passed;
  if (failed === true) return "回归失败，未合入";
  if (passed === true || failed === false) return "回归通过，已合入";
  return "已返回结果，详见原始数据";
});

function humanKey(key: string) {
  const map: Record<string, string> = {
    rule_id: "规则 ID",
    candidate_id: "候选 ID",
    status: "状态",
    duration_ms: "耗时(ms)",
    sample_count: "样本数",
  };
  return map[key] || key.split("_").join(" ");
}

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error)?.message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(root.value.querySelectorAll(".stat-card, .glow-card"), { y: 8, opacity: 0.82 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.02, ease: "power2.out" });
}
</script>
