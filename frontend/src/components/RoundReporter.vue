<template>
  <section class="rr card stack">
    <!-- 顶部：任务 + LLM 配置条 -->
    <div class="rr-head">
      <div class="stack gap-xs">
        <h3>R 报告器 · 闭环对账</h3>
        <p class="muted">任务 #{{ taskId }} · 数据源 data/app.db · 生成于 {{ generatedAt }}</p>
      </div>
      <div class="rr-llm" v-if="report?.config">
        <span class="badge badge-info">LLM</span>
        <code>{{ report.config.model || report.config.llm_model || "—" }}</code>
        <span class="muted small">provider: {{ report.config.provider || report.config.llm_provider }}</span>
        <span class="muted small">a2 workers {{ report.config.a2_max_workers }} / conc {{ report.config.a2_llm_concurrency }}</span>
      </div>
    </div>

    <!-- 闭环状态横幅 -->
    <div class="rr-banner" :class="closureClass">
      <div class="rr-banner-main">
        <strong>{{ closureTitle }}</strong>
        <span class="muted">{{ closureDetail }}</span>
        <!-- 闭环分层：入环(有 TriggerSpec) vs 仅检出(无 spec，从未入环) —— 两者口径绝不可混算 -->
        <span class="muted small">
          闭环分层：入环 {{ d2.spec_backed }} 条（有 TriggerSpec）· 仅检出 {{ d2.detect_only }} 条（无 spec，未入 D1/D2）·
          D2 验证确认 {{ d2.verified }} 条 · 触达 sink {{ d2.sink }} 条
        </span>
        <!-- 仅检出的根因构成：SCA 结构上不入环 / 无路由的 sink 重复报点 / 路由已被别的 spec 覆盖 / 真·路由未绑定 -->
        <span class="muted small">
          仅检出构成：SCA {{ dOnly.sca ?? 0 }}（无运行时语义，结构上不进环）·
          无入口路由 {{ dOnly.no_route ?? 0 }}（sink 行重复报点）·
          路由已入环 {{ dOnly.dup_route ?? 0 }}（重复报点）·
          <strong>路由未绑定 {{ dOnly.unbound_route ?? 0 }}（真缺口）</strong>
        </span>
      </div>
        <!-- Q7 去密：此处原还有「D2 实确认 {{ d2.verified }}」，与上一行「D2 验证确认」是同一个数，
             同组数字在横幅里重复两遍；已去掉。本行只保留**黄金集口径**（检出/入环/缺口），
             与上一行的**全任务口径**互为补充而非重复。 -->
        <div class="rr-banner-metrics">
          <div><span class="muted small">黄金集({{ goldenTarget }}) 检出</span><strong>{{ report?.summary.detected ?? 0 }}/{{ goldenTotal }}</strong></div>
          <div><span class="muted small">黄金集({{ goldenTarget }}) 已入环</span><strong>{{ report?.summary.confirmed ?? 0 }}/{{ goldenTotal }}</strong></div>
          <div><span class="muted small">缺口</span><strong>{{ gap }}</strong></div>
        </div>
    </div>

    <!-- 标签栏 -->
    <div class="rr-tabs">
      <button
        v-for="t in tabs"
        :key="t.key"
        type="button"
        class="rr-tab"
        :class="{ active: activeTab === t.key }"
        @click="activeTab = t.key"
      >
        {{ t.label }}
      </button>
    </div>

    <!-- 内容区 -->
    <div v-if="loading" class="rr-panel muted">加载中…</div>
    <div v-else-if="error" class="rr-panel callout danger">{{ error }}</div>
    <div v-else-if="!report" class="rr-panel muted">暂无数据。</div>
    <div v-else ref="panelRef" class="rr-panel stack">

      <!-- ============ 概览 ============ -->
      <div v-show="activeTab === 'overview'" class="stack gap-md">
        <div class="rr-kpi-row">
          <div class="rr-ring-card">
            <svg viewBox="0 0 140 140" class="rr-ring">
              <circle class="rr-ring-bg" cx="70" cy="70" r="52" />
              <circle class="rr-ring-circle rr-ring-detect" cx="70" cy="70" r="52"
                data-circ="326.7" :data-max="goldenTotal" :data-val="report.summary.detected" />
            </svg>
            <div class="rr-ring-label">
              <strong :data-count="goldenTotal">0</strong><span>/{{ goldenTotal }}</span>
              <p class="muted small">DETECT 检出</p>
            </div>
          </div>
          <div class="rr-ring-card">
            <svg viewBox="0 0 140 140" class="rr-ring">
              <circle class="rr-ring-bg" cx="70" cy="70" r="52" />
              <circle class="rr-ring-circle rr-ring-confirm" cx="70" cy="70" r="52"
                data-circ="326.7" :data-max="goldenTotal" :data-val="report.summary.confirmed" />
            </svg>
            <div class="rr-ring-label">
              <strong :data-count="report.summary.confirmed">0</strong><span>/{{ goldenTotal }}</span>
              <p class="muted small">已入环（匹配 TriggerSpec）</p>
            </div>
          </div>
          <div class="rr-side-stats grid two">
            <div class="stat-card">
              <span class="muted small">A2 语意分析</span>
              <strong :data-count="report.summary.semantic_findings">0</strong>
              <span class="muted small">非 SCA 发现</span>
            </div>
            <div class="stat-card">
              <span class="muted small">TriggerSpec</span>
              <strong :data-count="report.summary.specs_total">0</strong>
              <span class="muted small">可重放探针</span>
            </div>
            <div class="stat-card">
              <span class="muted small">SCA 组件漏洞</span>
              <strong :data-count="report.summary.sca_findings">0</strong>
            </div>
            <div class="stat-card">
              <span class="muted small">IAST 事件</span>
              <strong :data-count="report.summary.iast_events.total">0</strong>
              <span class="muted small">canary 命中 {{ report.summary.iast_events.canary_match }}</span>
            </div>
          </div>
        </div>

        <!-- 基线对比 -->
        <div class="card subtle stack gap-sm" v-if="report.baseline">
          <h4>相对基线 task #{{ report.baseline.task_id }}}</h4>
          <div class="rr-delta-row">
            <div class="rr-delta" :class="deltaClass(report.summary.detected - report.baseline.summary.detected)">
              <span class="muted small">DETECT</span>
              <strong>{{ signed(report.summary.detected - report.baseline.summary.detected) }}</strong>
              <span class="muted small">({{ report.baseline.summary.detected }}→{{ report.summary.detected }})</span>
            </div>
            <div class="rr-delta" :class="deltaClass(report.summary.confirmed - report.baseline.summary.confirmed)">
              <span class="muted small">CONFIRM</span>
              <strong>{{ signed(report.summary.confirmed - report.baseline.summary.confirmed) }}</strong>
              <span class="muted small">({{ report.baseline.summary.confirmed }}→{{ report.summary.confirmed }})</span>
            </div>
            <div class="rr-delta">
              <span class="muted small">A2 语意</span>
              <strong>{{ signed(report.summary.semantic_findings - report.baseline.summary.semantic_findings) }}</strong>
            </div>
          </div>
          <p class="muted small">说明：CONFIRM 缺口并非 LLM 能力问题（本任务已锁定 GLM-4.5-air），而是确认层工程问题——靶场路由绑定 / D1 重放参数未完全打通，详见「三层诊断」。</p>
        </div>
      </div>

      <!-- ============ 漏洞清单 ============ -->
      <div v-show="activeTab === 'vulns'" class="stack gap-sm">
        <div class="row wrap gap-sm">
          <select v-model="filterKind" class="rr-select">
            <option value="all">全部类别</option>
            <option value="tech">技术漏洞</option>
            <option value="biz">业务逻辑</option>
          </select>
          <select v-model="filterStatus" class="rr-select">
            <option value="all">全部状态</option>
            <option value="confirm">仅已确认</option>
            <option value="detect">仅检出</option>
            <option value="miss">未检出</option>
          </select>
          <span class="muted small">共 {{ filteredReconcile.length }} 条</span>
        </div>
        <div class="rr-table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th><th>类型</th><th>类别</th><th>期望路由</th><th>族</th>
                <th>DETECT</th><th>CONFIRM</th><th>验证态</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="row in filteredReconcile" :key="row.id">
                <tr class="rr-row" @click="toggleExpand(row.id)">
                  <td><strong>{{ row.id }}</strong></td>
                  <td>{{ row.type }}</td>
                  <td><span class="badge" :class="row.kind === 'biz' ? 'badge-info' : row.kind === 'no_http' ? 'badge-info' : ''">{{ row.kind === 'biz' ? '业务' : row.kind === 'no_http' ? '不可重放' : '技术' }}</span></td>
                  <td class="wrap-break"><code class="small">{{ row.routes.join(' · ') }}</code></td>
                  <td class="muted small">{{ row.spec_family || row.tokens[0] }}</td>
                  <td><span class="badge" :class="statusBadge(row).detect.cls">{{ statusBadge(row).detect.label }}</span></td>
                  <td><span class="badge" :class="statusBadge(row).confirm.cls">{{ statusBadge(row).confirm.label }}</span></td>
                  <td class="muted small">{{ row.verification_status || '—' }}</td>
                </tr>
                <tr v-if="expandedId === row.id" class="rr-detail-row">
                  <td colspan="8">
                    <div class="rr-detail">
                      <div><span class="muted small">期望路由</span><code class="small wrap-break">{{ row.routes.join(' · ') }}</code></div>
                      <div><span class="muted small">命中 TriggerSpec 端点</span><code class="small wrap-break">{{ row.spec_endpoint || '—' }}</code></div>
                      <div><span class="muted small">命中族</span><code class="small">{{ row.spec_family || '—' }}</code></div>
                      <div><span class="muted small">IAST 状态</span><code class="small">{{ row.iast_state || '—' }}</code></div>
                      <div><span class="muted small">验证态</span><code class="small">{{ row.verification_status || '—' }}</code></div>
                    </div>
                  </td>
                </tr>
              </template>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ============ 三层诊断 ============ -->
      <div v-show="activeTab === 'layers'" class="grid three">
        <div class="card subtle stack gap-sm">
          <div class="row between">
            <h4>门禁1 · ap_route_gate</h4>
            <span class="flow-badge" :class="layerVerdict(report.summary.three_layer.ap_route.with_route, report.summary.three_layer.ap_route.total)">{{ layerVerdictLabel('ap', report.summary.three_layer.ap_route) }}</span>
          </div>
          <p class="muted small">A2 findings 真实 HTTP 路由填充率</p>
          <div class="rr-bar"><span :style="{ width: pct(report.summary.three_layer.ap_route.with_route, report.summary.three_layer.ap_route.total) }" class="rr-bar-fill accent" /></div>
          <div class="rr-metric-line"><span class="muted small">绑定真实路由</span><strong>{{ report.summary.three_layer.ap_route.with_route }}/{{ report.summary.three_layer.ap_route.total }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">无路由</span><strong>{{ report.summary.three_layer.ap_route.no_route }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">残缺/被拒</span><strong>{{ report.summary.three_layer.ap_route.bogus }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">已转 TriggerSpec</span><strong>{{ report.summary.three_layer.ap_route.spec_ok }}</strong></div>
          <p class="muted small" v-if="report.baseline">基线 {{ report.baseline.summary.three_layer.ap_route.with_route }}/{{ report.baseline.summary.three_layer.ap_route.total }} → 当前 {{ report.summary.three_layer.ap_route.with_route }}/{{ report.summary.three_layer.ap_route.total }}</p>
          <p class="muted small" v-else>无基线对比</p>
        </div>

        <div class="card subtle stack gap-sm">
          <div class="row between">
            <h4>门禁2 · d1_env_blocked</h4>
            <span class="flow-badge flow-confirmed">健康</span>
          </div>
          <p class="muted small">TriggerSpec 端点填充 + IAST canary 增长</p>
          <div class="rr-bar"><span :style="{ width: pct(report.summary.three_layer.d1.with_ep, report.summary.three_layer.d1.specs) }" class="rr-bar-fill ok" /></div>
          <div class="rr-metric-line"><span class="muted small">含 target_endpoint</span><strong>{{ report.summary.three_layer.d1.with_ep }}/{{ report.summary.three_layer.d1.specs }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">业务族</span><strong>{{ report.summary.three_layer.d1.biz }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">IAST 事件</span><strong>{{ report.summary.three_layer.d1.ev_tot }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">canary_match</span><strong>{{ report.summary.three_layer.d1.ev_match }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">sink_reached</span><strong>{{ report.summary.three_layer.d1.ev_sink }}</strong></div>
        </div>

        <div class="card subtle stack gap-sm">
          <div class="row between">
            <h4>门禁3 · d2_judge</h4>
            <span class="flow-badge" :class="layerVerdict(report.summary.three_layer.d2.detected, report.summary.three_layer.d2.rows)">{{ layerVerdictLabel('d2', report.summary.three_layer.d2) }}</span>
          </div>
          <p class="muted small">vuln_blackboard 硬门禁对账</p>
          <div class="rr-bar"><span :style="{ width: pct(report.summary.three_layer.d2.spec_backed ?? 0, report.summary.three_layer.d2.rows) }" class="rr-bar-fill accent" /></div>
          <div class="rr-metric-line"><span class="muted small">detected</span><strong>{{ report.summary.three_layer.d2.detected }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">入环 spec_backed（有 TriggerSpec）</span><strong>{{ report.summary.three_layer.d2.spec_backed }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">运行时确认 verified</span><strong>{{ report.summary.three_layer.d2.verified }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">仅检出 detect_only（未入环）</span><strong>{{ report.summary.three_layer.d2.detect_only }}</strong></div>
          <div class="rr-metric-line"><span class="muted small">sink_reached</span><strong>{{ report.summary.three_layer.d2.sink }}</strong></div>
          <div class="rr-metric-line muted small"><span>verification 分布</span></div>
          <div v-for="(v, k) in report.summary.three_layer.d2.verification" :key="k" class="rr-metric-line"><span class="small">{{ k }}</span><strong>{{ v }}</strong></div>
        </div>
      </div>

      <!-- ============ 运行时证据 ============ -->
      <div v-show="activeTab === 'evidence'" class="stack gap-md">
        <div class="grid three">
          <div class="stat-card"><span class="muted small">IAST 事件总数</span><strong :data-count="report.summary.iast_events.total">0</strong></div>
          <div class="stat-card"><span class="muted small">canary_match</span><strong :data-count="report.summary.iast_events.canary_match">0</strong></div>
          <div class="stat-card"><span class="muted small">sink_reached</span><strong :data-count="report.summary.iast_events.sink_reached">0</strong></div>
        </div>
        <div class="card subtle stack gap-sm">
          <h4>vuln_blackboard 验证态分布</h4>
          <div v-for="(v, k) in report.summary.three_layer.d2.verification" :key="k" class="rr-dist-row">
            <span class="small">{{ k }}</span>
            <div class="rr-bar"><span :style="{ width: pct(v, report.summary.three_layer.d2.rows) }" class="rr-bar-fill muted" /></div>
            <strong class="small">{{ v }}</strong>
          </div>
        </div>
        <div class="card subtle stack gap-sm">
          <h4>iast_state 分布</h4>
          <div v-for="(v, k) in report.summary.three_layer.d2.iast_state" :key="k" class="rr-dist-row">
            <span class="small">{{ k }}</span>
            <div class="rr-bar"><span :style="{ width: pct(v, report.summary.three_layer.d2.rows) }" class="rr-bar-fill ok" /></div>
            <strong class="small">{{ v }}</strong>
          </div>
        </div>
      </div>

      <!-- ============ 跨轮对比 ============ -->
      <div v-show="activeTab === 'compare'" class="stack gap-sm">
        <div class="row wrap gap-sm">
          <input v-model="compareIds" class="rr-compare-input" placeholder="任务 id，逗号分隔，如 12,9,10,11" />
          <button type="button" class="button" @click="runCompare">对比</button>
        </div>
        <div v-if="compareLoading" class="muted">对比中…</div>
        <div v-else-if="compareResults.length" class="rr-table-wrap">
          <table>
            <thead><tr><th>任务</th><th>DETECT</th><th>CONFIRM</th><th>ΔCONFIRM</th><th>A2 语意</th><th>TriggerSpec</th><th>IAST 事件</th></tr></thead>
            <tbody>
          <tr v-for="(c, i) in compareResults" :key="c.task_id">
            <td><strong>#{{ c.task_id }}</strong></td>
            <td>{{ c.detected }}/{{ goldenTotal }}</td>
            <td><span class="badge" :class="c.confirmed >= goldenTotal ? 'badge-success' : 'badge-warning'">{{ c.confirmed }}/{{ goldenTotal }}</span></td>
                <td class="muted">{{ i === 0 ? '—' : signed(c.confirmed - compareResults[0].confirmed) }}</td>
                <td>{{ c.semantic }}</td>
                <td>{{ c.specs }}</td>
                <td>{{ c.iast }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ============ 原始数据 ============ -->
      <div v-show="activeTab === 'raw'" class="stack gap-sm">
        <div class="row between">
          <p class="muted small">完整结构化报告（与 /api/round-report/{{ taskId }} 返回一致）</p>
          <button type="button" class="ghost-button tiny" @click="copyRaw">复制 JSON</button>
        </div>
        <pre class="rr-raw">{{ rawJson }}</pre>
      </div>

    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch, onMounted } from "vue";
import { gsap } from "gsap";
import { http } from "@/services/http";

interface ReconcileRow {
  id: number;
  type: string;
  kind: string;
  routes: string[];
  tokens: string[];
  // applicable=false → 基准类无 HTTP 入口（如 Java RMI），不计入闭环分母，detect/confirm 为 null
  applicable?: boolean;
  detect: boolean | null;
  confirm: boolean | null;
  spec_endpoint: string | null;
  spec_family: string | null;
  finding_family: string | null;
  verification_status: string | null;
  iast_state: string | null;
}
interface LayerAp { total: number; with_route: number; no_route: number; bogus: number; spec_ok: number; }
interface LayerD1 { specs: number; with_ep: number; biz: number; ev_tot: number; ev_match: number; ev_sink: number; }
interface DetectOnlyBreakdown { sca?: number; no_route?: number; dup_route?: number; unbound_route?: number; }
// 注意：本接口没有 confirmed 字段 —— 后端已改名 spec_backed（语义=存在 TriggerSpec，非「已验证」）。
// 运行时确认数一律看 verified。
interface LayerD2 { rows: number; detected: number; sink: number; verification: Record<string, number>; iast_state: Record<string, number>; spec_backed?: number; verified?: number; detect_only?: number; detect_only_breakdown?: DetectOnlyBreakdown; }
interface ThreeLayer { ap_route: LayerAp; d1: LayerD1; d2: LayerD2; }
interface ConfigSnap { provider?: string; model?: string; a2_max_workers?: number | string; a2_llm_concurrency?: number | string; llm_provider?: string; llm_model?: string; error?: string; }
interface Summary {
  sca_findings: number; semantic_findings: number; specs_total: number; findings_total: number;
  golden_target?: string; golden_total?: number; golden_not_applicable?: string[];
  // detected = 基准类被检出；confirmed = 基准类匹配到 TriggerSpec（已入环），**不是**运行时已验证
  detected: number; confirmed: number; detect_rate: number; confirm_rate: number;
  blackboard: { rows: number; detected: number; spec_backed: number; verified: number; sink: number };
  iast_events: { total: number; canary_match: number; sink_reached: number };
  three_layer: ThreeLayer; blackboard_by_family: Record<string, number>;
}
interface RoundReport {
  task_id: number; generated_at: number; config: ConfigSnap; golden_target?: string; golden_total?: number;
  summary: Summary; reconcile: ReconcileRow[];
  baseline?: RoundReport | null;
}

const props = defineProps<{ taskId: number; baselineId?: number }>();

const tabs = [
  { key: "overview", label: "概览" },
  { key: "vulns", label: "漏洞清单" },
  { key: "layers", label: "三层诊断" },
  { key: "evidence", label: "运行时证据" },
  { key: "compare", label: "跨轮对比" },
  { key: "raw", label: "原始数据" },
] as const;

type TabKey = (typeof tabs)[number]["key"];

const report = ref<RoundReport | null>(null);
const loading = ref(false);
const error = ref<string | null>(null);
const activeTab = ref<TabKey>("overview");
const panelRef = ref<HTMLElement | null>(null);
const expandedId = ref<number | null>(null);
const filterKind = ref<"all" | "tech" | "biz">("all");
const filterStatus = ref<"all" | "confirm" | "detect" | "miss">("all");

const compareIds = ref<string>("12,9,10,11");
const compareResults = ref<{ task_id: number; detected: number; confirmed: number; semantic: number; specs: number; iast: number }[]>([]);
const compareLoading = ref(false);

// 黄金集基准：由后端按靶场选择（java-sec-code=29 类中 28 类可重放 / target-mall=35），此处只消费不再写死。
// summary_only=1 的响应把 golden_* 放在 summary 内，故三级回退。
const goldenTotal = computed(() => report.value?.golden_total ?? report.value?.summary?.golden_total ?? report.value?.reconcile?.length ?? 0);
const goldenTarget = computed(() => report.value?.golden_target ?? report.value?.summary?.golden_target ?? "—");
const goldenNotApplicable = computed<string[]>(() => report.value?.summary?.golden_not_applicable ?? []);
const d2 = computed(() => report.value?.summary.three_layer.d2 ?? ({} as LayerD2));
// 「仅检出」的根因构成：只有 unbound_route 是需要修的真缺口。
const dOnly = computed<DetectOnlyBreakdown>(() => d2.value.detect_only_breakdown ?? {});
const gap = computed(() => Math.max(0, goldenTotal.value - (report.value?.summary.confirmed ?? 0)));
const closureClass = computed(() => (goldenTotal.value > 0 && gap.value === 0 ? "ok" : "warn"));
const closureTitle = computed(() => {
  if (!goldenTotal.value) return "该靶场无黄金集基准 · 不做闭环对账";
  return gap.value === 0
    ? `黄金集已全部入环 · ${goldenTotal.value}/${goldenTotal.value}（${goldenTarget.value}）`
    : `黄金集未全部入环 · 差 ${gap.value} 类（${goldenTarget.value}）`;
});
const closureDetail = computed(() => {
  if (!goldenTotal.value) {
    return "该靶场未登记黄金集真值表，报告只呈现 D2 实际验证结果，不做「已知漏洞闭环对账」。";
  }
  const c = report.value?.summary.confirmed ?? 0;
  const _na = goldenNotApplicable.value.length ? `；另有 ${goldenNotApplicable.value.join("、")} 无 HTTP 入口（结构上不可重放），不计入分母` : "";
  if (gap.value === 0) {
    return `全部 ${goldenTotal.value} 个可重放基准类均匹配到 TriggerSpec（黄金集口径）${_na}。注意「入环」不等于「运行时已验证」，后者看 verified。`;
  }
  return (
    `黄金集 = ${goldenTarget.value} 可重放基准 ${goldenTotal.value} 类；已入环 ${c}/${goldenTotal.value}，` +
    `差 ${gap.value} 类未匹配到 TriggerSpec（要求 TriggerSpec 的 target_endpoint 命中已知路由）${_na}。` +
    `「确认」是严格的已知漏洞基准，不是 D2 实际验证数——真实闭环见下方分层。`
  );
});
const generatedAt = computed(() => {
  const t = report.value?.generated_at;
  if (!t) return "—";
  const d = new Date(t * 1000);
  return d.toLocaleString("zh-CN", { hour12: false });
});
const rawJson = computed(() => (report.value ? JSON.stringify(report.value, null, 2) : ""));

const filteredReconcile = computed(() => {
  if (!report.value) return [];
  return report.value.reconcile.filter((r) => {
    if (filterKind.value !== "all" && r.kind !== filterKind.value) return false;
    // applicable=false（无 HTTP 入口，如 Java RMI）不入任何检出/确认筛选，避免算成未检出
    if (r.applicable === false) return filterStatus.value === "all";
    if (filterStatus.value === "confirm" && !r.confirm) return false;
    if (filterStatus.value === "detect" && (!r.detect || r.confirm)) return false;
    if (filterStatus.value === "miss" && r.detect) return false;
    return true;
  });
});

function pct(n: number, d: number): string {
  if (!d) return "0%";
  return `${Math.round((n / d) * 100)}%`;
}
function signed(n: number): string {
  if (n > 0) return `+${n}`;
  return String(n);
}
function deltaClass(n: number): string {
  if (n > 0) return "up";
  if (n < 0) return "down";
  return "flat";
}
function statusBadge(row: ReconcileRow) {
  if (row.applicable === false) {
    return { detect: { label: "不可重放", cls: "badge-info" }, confirm: { label: "不可重放", cls: "badge-info" } };
  }
  // 「入环」= 匹配到 TriggerSpec（后端字段 confirm），不是「运行时已验证」；
  // 运行时结论看同行 verification_status / iast_state。
  if (row.confirm) return { detect: { label: "已检出", cls: "badge-success" }, confirm: { label: "已入环", cls: "badge-success" } };
  if (row.detect) return { detect: { label: "已检出", cls: "badge-warning" }, confirm: { label: "仅检出", cls: "badge-warning" } };
  return { detect: { label: "未检出", cls: "badge-danger" }, confirm: { label: "未检出", cls: "badge-danger" } };
}
function layerVerdict(withRoute: number, total: number): string {
  if (!total) return "";
  const rate = withRoute / total;
  if (rate >= 0.6) return "flow-confirmed";
  if (rate >= 0.35) return "flow-hypothesis";
  return "flow-refuted";
}
function layerVerdictLabel(_layer: string, layer: LayerAp | LayerD2): string {
  const total = "total" in layer ? (layer as LayerAp).total : (layer as LayerD2).rows;
  const good = "with_route" in layer ? (layer as LayerAp).with_route : (layer as LayerD2).detected;
  const rate = total ? good / total : 0;
  if (rate >= 0.6) return "健康";
  if (rate >= 0.35) return "关注";
  return "泄漏";
}
function toggleExpand(id: number) {
  expandedId.value = expandedId.value === id ? null : id;
}
async function copyRaw() {
  try {
    await navigator.clipboard.writeText(rawJson.value);
  } catch {
    /* ignore */
  }
}

async function load() {
  loading.value = true;
  error.value = null;
  try {
    const params: Record<string, unknown> = {};
    if (props.baselineId) params.baseline = props.baselineId;
    const { data } = await http.get<RoundReport>(`/api/round-report/${props.taskId}`, { params });
    report.value = data;
    await nextTick();
    animatePanel();
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

async function runCompare() {
  compareLoading.value = true;
  const ids = compareIds.value.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
  try {
    const results = await Promise.all(
      ids.map(async (id) => {
        const { data } = await http.get<{ summary: Summary }>(`/api/round-report/${id}`, { params: { summary_only: 1 } });
        return {
          task_id: id,
          detected: data.summary.detected,
          confirmed: data.summary.confirmed,
          semantic: data.summary.semantic_findings,
          specs: data.summary.specs_total,
          iast: data.summary.iast_events.total,
        };
      })
    );
    compareResults.value = results;
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    compareLoading.value = false;
    await nextTick();
    animatePanel();
  }
}

function animatePanel() {
  const root = panelRef.value;
  if (!root) return;
  gsap.fromTo(
    root.children,
    { opacity: 0, y: 14 },
    { opacity: 1, y: 0, duration: 0.4, stagger: 0.05, ease: "power2.out" }
  );
  // 数字 count-up
  root.querySelectorAll<HTMLElement>("[data-count]").forEach((el) => {
    const to = parseFloat(el.getAttribute("data-count") || "0");
    const obj = { v: 0 };
    gsap.to(obj, {
      v: to,
      duration: 0.8,
      ease: "power2.out",
      onUpdate: () => {
        el.textContent = Math.round(obj.v).toString();
      },
    });
  });
  // 进度环
  root.querySelectorAll<SVGCircleElement>(".rr-ring-circle").forEach((el) => {
    const max = parseFloat(el.getAttribute("data-max") || "35");
    const val = parseFloat(el.getAttribute("data-val") || "0");
    const circ = parseFloat(el.getAttribute("data-circ") || "326.7");
    const target = circ * (1 - val / max);
    const obj = { o: circ };
    gsap.to(obj, {
      o: target,
      duration: 1.0,
      ease: "power2.out",
      onUpdate: () => {
        el.style.strokeDashoffset = String(obj.o);
      },
    });
  });
}

watch(activeTab, () => {
  nextTick(animatePanel);
});
watch(
  () => props.taskId,
  () => {
    load();
  }
);

onMounted(load);
</script>

<style scoped>
.rr-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  flex-wrap: wrap;
  gap: 12px;
}
.rr-llm {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding: 8px 12px;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--color-surface-2);
}
.rr-banner {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
  padding: 14px 18px;
  border-radius: 14px;
  border: 1px solid var(--border);
}
.rr-banner.ok {
  background: var(--surface-tint-ok);
  border-color: color-mix(in srgb, var(--st-ok) 40%, var(--color-border));
}
.rr-banner.warn {
  background: var(--surface-tint-warn);
  border-color: color-mix(in srgb, var(--sev-medium) 45%, var(--color-border));
}
.rr-banner-main {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.rr-banner-metrics {
  display: flex;
  gap: 22px;
}
.rr-banner-metrics div {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
}
.rr-banner-metrics strong {
  font-size: 20px;
}
.rr-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.rr-tab {
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 8px 14px;
  background: var(--color-on-strong);
  color: var(--ink);
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s ease;
}
.rr-tab:hover {
  border-color: var(--accent);
}
.rr-tab.active {
  background: var(--accent);
  color: var(--color-on-strong);
  border-color: var(--accent);
}
.rr-kpi-row {
  display: grid;
  grid-template-columns: 160px 160px 1fr;
  gap: 16px;
  align-items: center;
}
.rr-ring-card {
  position: relative;
  width: 160px;
  height: 160px;
}
.rr-ring {
  width: 160px;
  height: 160px;
  transform: rotate(-90deg);
}
.rr-ring-bg {
  fill: none;
  stroke: var(--color-border);
  stroke-width: 12;
}
.rr-ring-circle {
  fill: none;
  stroke-width: 12;
  stroke-linecap: round;
  stroke-dasharray: 326.7;
  stroke-dashoffset: 326.7;
}
.rr-ring-detect {
  stroke: var(--sev-info);
}
.rr-ring-confirm {
  stroke: var(--accent);
}
.rr-ring-label {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
.rr-ring-label strong {
  font-size: 30px;
  line-height: 1;
}
.rr-ring-label span {
  color: var(--muted);
}
.rr-side-stats {
  align-content: start;
}
.rr-delta-row {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}
.rr-delta {
  display: flex;
  flex-direction: column;
  padding: 8px 14px;
  border-radius: 12px;
  background: var(--color-surface-2);
  border: 1px solid var(--border);
}
.rr-delta.up strong {
  color: var(--st-ok);
}
.rr-delta.down strong {
  color: var(--sev-critical-ink);
}
.rr-select,
.rr-compare-input {
  width: auto;
  min-width: 160px;
}
.rr-compare-input {
  flex: 1;
  min-width: 240px;
}
.rr-table-wrap {
  overflow-x: auto;
}
.rr-row {
  cursor: pointer;
}
.rr-row:hover {
  background: var(--color-surface-2);
}
.rr-detail-row td {
  background: var(--color-surface-2);
}
.rr-detail {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
  padding: 6px 4px;
}
.rr-metric-line {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}
.rr-bar {
  height: 8px;
  border-radius: 999px;
  background: var(--color-border);
  overflow: hidden;
}
.rr-bar-fill {
  display: block;
  height: 100%;
  border-radius: 999px;
  transition: width 0.8s ease;
}
.rr-bar-fill.accent {
  background: var(--accent);
}
.rr-bar-fill.ok {
  background: var(--st-ok);
}
.rr-bar-fill.muted {
  background: var(--color-muted);
}
.rr-dist-row {
  display: grid;
  grid-template-columns: 160px 1fr 40px;
  align-items: center;
  gap: 10px;
}
.rr-raw {
  max-height: 460px;
  font-size: 12px;
}
.card.subtle {
  background: var(--color-surface);
}
.small {
  font-size: 12px;
}
@media (max-width: 900px) {
  .rr-kpi-row {
    grid-template-columns: 1fr;
  }
  .rr-banner-metrics {
    gap: 14px;
  }
}
</style>
