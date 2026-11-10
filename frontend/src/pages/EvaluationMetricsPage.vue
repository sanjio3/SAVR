<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>评估与指标</h1>
        <p class="page-subtitle">
          用带标注的黄金集跑一遍 AI 判定，度量精确率（P）、召回率（R）与 F1；支持多次重复的稳定性指标
          pass@3 与 pass^3，以及模型 × Prompt × 模式 × Agent 的多维矩阵对比。
          下半部分的降噪率、误杀率、覆盖度与 IAST 命中率，回答「用得好不好」。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="reload">刷新</button>
        <button class="button" :disabled="evaluating" @click="runEvaluation">{{ evaluating ? "评估中…" : "运行评估" }}</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取评估记录…" />

    <template v-else>
      <div class="stats-grid compact">
        <StatCard label="最新 F1" num>{{ pct(latest?.f1) }}</StatCard>
        <StatCard label="精确率 P" num>{{ pct(latest?.precision) }}</StatCard>
        <StatCard label="召回率 R" num>{{ pct(latest?.recall) }}</StatCard>
        <StatCard label="评估次数">{{ runs.length }}</StatCard>
      </div>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <div>
            <h3>运行历史</h3>
            <p class="muted">每次评估一行。P / R / F1 越高越好；pass@3 是 3 次里至少一次正确，pass^3 是 3 次全部正确，后者更能反映稳定性。</p>
          </div>
          <div class="row gap-sm wrap">
            <input v-model="runForm.name" placeholder="本次运行名称" style="max-width: 170px" />
            <input v-model="runForm.dataset_path" placeholder="数据集路径（留空用内置黄金集）" style="max-width: 260px" />
          </div>
        </div>
        <div v-if="runs.length" class="table-wrap cols-9">
          <table>
            <thead><tr><th>ID</th><th>名称</th><th>数据集</th><th>P</th><th>R</th><th>F1</th><th>pass@3</th><th>pass^3</th><th>样本数</th></tr></thead>
            <tbody>
              <tr v-for="r in runs" :key="String(r.id)">
                <td class="num">{{ r.id }}</td>
                <td>{{ r.name }}</td>
                <td class="muted wrap-break">{{ r.dataset }}</td>
                <td class="num">{{ pct(r.precision) }}</td>
                <td class="num">{{ pct(r.recall) }}</td>
                <td class="num"><strong>{{ pct(r.f1) }}</strong></td>
                <td class="num">{{ pct(r.pass_at_3) }}</td>
                <td class="num">{{ pct(r.pass_hat_3) }}</td>
                <td class="num">{{ r.total }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无评估记录</strong>
          <span>点击右上角「运行评估」用内置黄金集跑一次，结果会按运行逐行列出。</span>
        </div>
        <div v-if="runs.length" class="row gap-sm wrap">
          <input v-model="compareForm.a" placeholder="对比 run A id" style="max-width: 150px" />
          <input v-model="compareForm.b" placeholder="对比 run B id" style="max-width: 150px" />
          <button class="ghost-button" @click="compareRuns">对比两次运行</button>
        </div>
        <div v-if="comparison" class="callout" :class="deltaClass(comparison.delta.f1)">
          相对变化：ΔP {{ signed(comparison.delta.precision) }} · ΔR {{ signed(comparison.delta.recall) }} ·
          ΔF1 {{ signed(comparison.delta.f1) }} · Δ准确率 {{ signed(comparison.delta.accuracy) }}
        </div>
      </section>

      <section v-if="detail" class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <h3>Run #{{ detail.run.id }} · {{ detail.run.name }} 明细</h3>
          <div class="row gap-sm">
            <button class="ghost-button" @click="openRunDetail(detail.run.id)">逐条样例</button>
            <button class="ghost-button" @click="detail = null">收起</button>
          </div>
        </div>
        <div class="table-wrap cols-5">
          <table>
            <thead><tr><th>样例 ID</th><th>漏洞族</th><th>期望</th><th>实际判定</th><th>结论</th></tr></thead>
            <tbody>
              <tr v-for="item in detail.results" :key="String(item.case_id)">
                <td class="num">{{ item.case_id }}</td>
                <td>{{ item.family }}</td>
                <td>{{ item.expected }}</td>
                <td>{{ item.predicted }}</td>
                <td><span class="tag" :class="outcomeClass(item.outcome)">{{ outcomeLabel(item.outcome) }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card stack glow-card">
        <div>
          <h3>多维矩阵测评</h3>
          <p class="muted">
            同时跑多种「模型 × Prompt 版本 × 扫描模式 × Agent 实现」组合，每个组合默认重复 3 次。
            留空表示使用该系统维度的默认值；组合数 = 各维度取值数的乘积，数量大时耗时较长。
          </p>
        </div>
        <div class="row gap-sm wrap">
          <input v-model="matrixForm.models" placeholder="模型（逗号分隔）" style="max-width: 200px" />
          <input v-model="matrixForm.prompt_versions" placeholder="Prompt 版本（逗号分隔）" style="max-width: 200px" />
          <input v-model="matrixForm.scan_modes" placeholder="扫描模式（逗号分隔）" style="max-width: 200px" />
          <input v-model="matrixForm.agent_impls" placeholder="Agent 实现（逗号分隔）" style="max-width: 180px" />
          <input v-model="matrixForm.repeat" placeholder="重复次数" style="max-width: 100px" />
          <button class="ghost-button" :disabled="matrixBusy" @click="runMatrix">{{ matrixBusy ? "测评中…" : "运行矩阵测评" }}</button>
        </div>
        <div v-if="matrix" class="stack">
          <div class="muted small">共 {{ matrix.combos }} 个组合 · 每个组合重复 {{ matrix.repeat }} 次</div>
          <div v-if="matrix.rows?.length" class="table-wrap cols-9">
            <table>
              <thead><tr><th>模型</th><th>Prompt</th><th>模式</th><th>Agent</th><th>P</th><th>R</th><th>F1</th><th>pass@3</th><th>pass^3</th></tr></thead>
              <tbody>
                <tr v-for="(row, i) in matrix.rows" :key="i">
                  <td>{{ row.model }}</td><td>{{ row.prompt_version }}</td><td>{{ row.scan_mode }}</td><td>{{ row.agent_impl }}</td>
                  <td class="num">{{ pct(row.precision) }}</td><td class="num">{{ pct(row.recall) }}</td>
                  <td class="num"><strong>{{ pct(row.f1) }}</strong></td>
                  <td class="num">{{ pct(row.pass_at_3) }}</td><td class="num">{{ pct(row.pass_hat_3) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state"><span>该矩阵没有产出任何组合结果。</span></div>
          <div v-if="matrix.recommendation?.best_quality" class="row wrap gap-md">
            <div class="callout success" style="flex: 1; min-width: 260px">
              <strong>质量最优组合</strong>：{{ matrix.recommendation.best_quality.model }} / {{ matrix.recommendation.best_quality.prompt_version }} / {{ matrix.recommendation.best_quality.scan_mode }}
              · F1 {{ pct(matrix.recommendation.best_quality.f1) }}
            </div>
            <div class="callout" style="flex: 1; min-width: 260px">
              <strong>日常稳定组合</strong>：{{ matrix.recommendation.everyday.model }} / {{ matrix.recommendation.everyday.prompt_version }} / {{ matrix.recommendation.everyday.scan_mode }}
              · pass^3 {{ pct(matrix.recommendation.everyday.pass_hat_3) }}
            </div>
          </div>
        </div>
        <div v-if="error" class="callout danger">{{ error }}</div>
      </section>

      <!-- 以下三节 2026-09-21 从「运维看板」迁入：它们是效果度量（用得好不好），
           不是运行健康（平台活着没有），也不属于用量统计（用掉多少）。 -->
      <section class="card stack glow-card">
        <h3>降噪与误报</h3>
        <div class="stats-grid compact">
          <StatCard label="降噪率" num>{{ pct(ops?.denoise_rate) }}</StatCard>
          <StatCard label="误杀率" num>{{ pct(ops?.false_kill_rate) }}</StatCard>
          <StatCard label="修复采纳率" num>{{ pct(ops?.adoption_rate) }}</StatCard>
          <StatCard label="复测通过率" num>{{ pct(ops?.retest_pass_rate) }}</StatCard>
        </div>
        <div class="stats-grid compact">
          <StatCard label="总漏洞">{{ ops?.total_findings ?? "-" }}</StatCard>
          <StatCard label="净自动关闭">{{ ops?.auto_closed ?? "-" }}</StatCard>
          <StatCard label="自治关闭">{{ ops?.autonomy_closed ?? "-" }}</StatCard>
          <StatCard label="自治回滚">{{ ops?.autonomy_rolled_back ?? "-" }}</StatCard>
          <StatCard label="人工误报">{{ ops?.human_false_positive ?? "-" }}</StatCard>
          <StatCard label="误导率">{{ pct(ops?.misleading_rate) }}</StatCard>
        </div>
      </section>

      <section class="card stack glow-card">
        <h3>覆盖度</h3>
        <div class="row wrap gap-md">
          <div class="stack" style="min-width: 240px">
            <h4 class="muted">按语言</h4>
            <div v-if="hasCoverage(ops?.coverage?.by_language)" class="table-wrap cols-2">
              <table>
                <tbody>
                  <tr v-for="(count, name) in (ops?.coverage?.by_language ?? {})" :key="`lang-${name}`">
                    <td>{{ name }}</td><td class="num"><strong>{{ count }}</strong></td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-else class="muted">暂无数据</div>
          </div>
          <div class="stack" style="min-width: 240px">
            <h4 class="muted">按漏洞家族</h4>
            <div v-if="hasCoverage(ops?.coverage?.by_family)" class="stack gap-xs">
              <div class="table-wrap cols-2">
                <table>
                  <tbody>
                    <tr v-for="row in visibleFamilyRows" :key="`fam-${row.name}`">
                      <td>{{ row.name }}</td><td class="num"><strong>{{ row.count }}</strong></td>
                    </tr>
                    <tr v-if="hiddenFamilyRows.length && !showAllFamilies" class="muted">
                      <td>其余 {{ hiddenFamilyRows.length }} 个家族</td>
                      <td class="num"><strong>{{ hiddenFamilyTotal }}</strong></td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <button
                v-if="familyRows.length > FAMILY_TOP_N"
                type="button"
                class="ghost-button"
                @click="showAllFamilies = !showAllFamilies"
              >
                {{ showAllFamilies ? `收起为前 ${FAMILY_TOP_N} 个` : `展开全部 ${familyRows.length} 个家族` }}
              </button>
            </div>
            <div v-else class="muted">暂无数据</div>
          </div>
        </div>
      </section>

      <section class="card stack glow-card">
        <h3>IAST 来源统计</h3>
        <p class="muted">
          「潜在命中」= 运行时观测到该 sink 被触达，「真命中」= 攻击确证可利用；前者是必要条件，后者才是结论。
        </p>
        <div class="stats-grid compact">
          <StatCard label="SAST 假说">{{ iast?.total_hypotheses ?? "-" }}</StatCard>
          <StatCard label="IAST 观测">{{ iast?.iast_observed ?? "-" }}</StatCard>
          <StatCard label="潜在命中">{{ iast?.confirmed_runtime ?? "-" }}</StatCard>
          <StatCard label="真命中">{{ iast?.exploit_confirmed ?? "-" }}</StatCard>
          <StatCard label="潜在命中率">{{ pct(iast?.confirmed_runtime_ratio) }}</StatCard>
          <StatCard label="真命中率">{{ pct(iast?.exploit_confirmed_ratio) }}</StatCard>
        </div>
        <div v-if="iastAssets.length" class="stack">
          <h4 class="muted">按资产分布</h4>
          <div class="table-wrap cols-5">
            <table>
              <thead><tr><th>资产</th><th>假说</th><th>观测</th><th>潜在命中</th><th>真命中</th></tr></thead>
              <tbody>
                <tr v-for="a in iastAssets" :key="a.asset">
                  <td>{{ a.asset }}</td><td class="num">{{ a.total }}</td><td class="num">{{ a.observed }}</td>
                  <td class="num">{{ a.confirmed_runtime }}</td><td class="num">{{ a.exploit_confirmed }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
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
const runs = ref<Row[]>([]);
const detail = ref<Row | null>(null);
const comparison = ref<Row | null>(null);
const error = ref("");
const loading = ref(true);
const evaluating = ref(false);
const matrixBusy = ref(false);
const runForm = ref({ name: "dashboard-run", dataset_path: "" });
const compareForm = ref({ a: "", b: "" });
const matrix = ref<Row | null>(null);
const matrixForm = ref({ models: "", prompt_versions: "", scan_modes: "filter_first,pure_ai", agent_impls: "", repeat: "3" });
// 2026-09-21 从运维看板迁入的效果度量
const ops = ref<Row | null>(null);
const iast = ref<Row | null>(null);

const latest = computed(() => runs.value[0] ?? null);

useTableScroll(root);

onMounted(async () => {
  await Promise.all([loadRuns(), loadOps(), loadIast()]);
  loading.value = false;
  animate();
});

async function loadOps() {
  try {
    const { data } = await http.get<Row>("/api/metrics/ops");
    ops.value = data;
  } catch { /* 指标页首屏靠评估记录，效果度量取不到不阻断 */ }
}

async function loadIast() {
  try {
    const { data } = await http.get<Row>("/api/metrics/iast");
    iast.value = data;
  } catch { /* 同上 */ }
}

const iastAssets = computed(() => (Array.isArray(iast.value?.per_asset) ? (iast.value!.per_asset as Row[]) : []));

// 覆盖度「按漏洞家族」Top-N 裁剪：家族动辄几十个，全列会把这块撑得比相邻「按语言」长数倍。
// 只裁剪展示、不静默丢数据 —— 其余合并成一行并给出条数合计，可一键展开。
const FAMILY_TOP_N = 10;
const showAllFamilies = ref(false);
const familyRows = computed<Array<{ name: string; count: number }>>(() => {
  const raw = (ops.value?.coverage?.by_family ?? {}) as Record<string, unknown>;
  return Object.entries(raw)
    .map(([name, count]) => ({ name, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count);
});
const visibleFamilyRows = computed(() =>
  showAllFamilies.value ? familyRows.value : familyRows.value.slice(0, FAMILY_TOP_N),
);
const hiddenFamilyRows = computed(() => familyRows.value.slice(FAMILY_TOP_N));
const hiddenFamilyTotal = computed(() => hiddenFamilyRows.value.reduce((sum, row) => sum + row.count, 0));

function hasCoverage(obj: unknown) {
  return obj && typeof obj === "object" && Object.keys(obj as object).length > 0;
}

async function loadRuns() {
  error.value = "";
  const { data } = await http.get<Row[]>("/api/evaluation/runs").catch(() => ({ data: [] } as any));
  runs.value = data;
  animate();
}

async function reload() {
  detail.value = null;
  comparison.value = null;
  matrix.value = null;
  await Promise.all([loadRuns(), loadOps(), loadIast()]);
}

async function runEvaluation() {
  error.value = "";
  evaluating.value = true;
  try {
    await http.post("/api/evaluation/runs", {
      name: runForm.value.name,
      dataset_path: runForm.value.dataset_path,
    });
    await loadRuns();
  } catch (caught) {
    error.value = errText(caught);
  } finally {
    evaluating.value = false;
  }
}

async function openDetail(runId: number) {
  error.value = "";
  try {
    const { data } = await http.get<Row>(`/api/evaluation/runs/${runId}`);
    detail.value = data;
    animate();
  } catch (caught) {
    error.value = errText(caught);
  }
}

function openRunDetail(runId: number) {
  void openDetail(runId);
}

async function runMatrix() {
  error.value = "";
  matrix.value = null;
  matrixBusy.value = true;
  const list = (raw: string) => raw.split(",").map((s) => s.trim()).filter(Boolean);
  try {
    const { data } = await http.post<Row>("/api/evaluation/matrix", {
      name: "matrix-ui",
      repeat: Number(matrixForm.value.repeat) || 1,
      models: list(matrixForm.value.models),
      prompt_versions: list(matrixForm.value.prompt_versions),
      scan_modes: list(matrixForm.value.scan_modes),
      agent_impls: list(matrixForm.value.agent_impls),
    });
    matrix.value = data;
    await loadRuns();
  } catch (caught) {
    error.value = errText(caught);
  } finally {
    matrixBusy.value = false;
  }
}

async function compareRuns() {
  error.value = "";
  comparison.value = null;
  const a = Number(compareForm.value.a);
  const b = Number(compareForm.value.b);
  if (!a || !b) { error.value = "请填写两个 run id。"; return; }
  try {
    const { data } = await http.get<Row>(`/api/evaluation/compare`, { params: { run_a: a, run_b: b } });
    comparison.value = data;
  } catch (caught) {
    error.value = errText(caught);
  }
}

function pct(value: unknown) {
  const num = Number(value);
  return Number.isFinite(num) ? `${(num * 100).toFixed(1)}%` : "-";
}

function signed(value: unknown) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  const prefix = num > 0 ? "+" : "";
  return `${prefix}${(num * 100).toFixed(1)}%`;
}

function outcomeClass(outcome: string) {
  if (outcome === "true_positive" || outcome === "true_negative") return "ok";
  return "bad";
}

function outcomeLabel(outcome: string) {
  const map: Record<string, string> = {
    true_positive: "真阳性",
    true_negative: "真阴性",
    false_positive: "误报",
    false_negative: "漏报",
  };
  return map[outcome] || outcome;
}

function deltaClass(value: unknown) {
  const num = Number(value);
  if (!Number.isFinite(num) || num === 0) return "";
  return num > 0 ? "success" : "danger";
}

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error)?.message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(root.value.querySelectorAll(".stat-card, .glow-card"), { y: 8, opacity: 0.82 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.025, ease: "power2.out" });
}
</script>
