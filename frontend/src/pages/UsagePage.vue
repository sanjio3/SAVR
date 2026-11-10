<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>用量统计</h1>
        <p class="page-subtitle">
          回答「平台被用掉了多少」：扫描次数与周期、被扫代码量、LLM token 与成本、Agent 调用次数与耗时、
          按工作区分布。想知道「用得好不好」（降噪率、误杀率、覆盖度）请到设置中心 · 指标。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <input v-model="workspaceId" placeholder="工作区 id（可选）" style="max-width: 180px" />
        <button class="ghost-button" @click="load">刷新</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在汇总用量…" />

    <template v-else>
      <!-- 口径说明置顶：本页有三个数据源缺口（成本未计费、阶段未标注、调用未关联任务），
           不先讲清楚，下面的数字会被误读。 -->
      <div v-if="notes.length" class="callout">
        <strong>口径说明</strong>
        <ul class="usage-notes">
          <li v-for="(note, i) in notes" :key="i">{{ note }}</li>
        </ul>
      </div>

      <section class="card stack glow-card">
        <h3>扫描次数与周期</h3>
        <div class="stats-grid compact">
          <StatCard label="扫描总数">{{ int(scans?.total) }}</StatCard>
          <StatCard label="成功 / 失败">{{ int(statusCount('completed')) }} / {{ int(statusCount('failed')) }}</StatCard>
          <StatCard label="平均耗时">{{ dur(scans?.duration?.avg_seconds) }}</StatCard>
          <StatCard label="耗时中位数 P50">{{ dur(scans?.duration?.p50_seconds) }}</StatCard>
          <StatCard label="P95">{{ dur(scans?.duration?.p95_seconds) }}</StatCard>
          <StatCard label="最长">{{ dur(scans?.duration?.max_seconds) }}</StatCard>
        </div>
        <p class="muted">中位数与 P95 分列：扫描耗时分布很偏（快的十几分钟、慢的三四个小时），只看均值会被长尾拉高。</p>
        <div v-if="recentScans.length" class="table-wrap cols-4">
          <table>
            <thead><tr><th>任务</th><th>名称</th><th>状态</th><th>耗时</th></tr></thead>
            <tbody>
              <tr v-for="s in recentScans" :key="String(s.task_id)">
                <td class="num">
                  <RouterLink :to="`/tasks/${s.task_id}`">#{{ s.task_id }}</RouterLink>
                </td>
                <td class="wrap-break">{{ s.name }}</td>
                <td><span class="tag" :class="s.status === 'completed' ? 'ok' : 'bad'">{{ s.status }}</span></td>
                <td class="num">{{ dur(s.duration_seconds) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card stack glow-card">
        <h3>扫描代码量</h3>
        <div class="stats-grid compact">
          <StatCard label="纳入统计的扫描">{{ int(code?.scans_indexed) }}</StatCard>
          <StatCard label="累计文件数">{{ int(code?.files_total) }}</StatCard>
          <StatCard label="累计索引函数">{{ int(code?.functions_total) }}</StatCard>
          <StatCard label="累计 HTTP 入口">{{ int(code?.http_entries_total) }}</StatCard>
          <StatCard label="平均文件数 / 次">{{ int(code?.avg_files_per_scan) }}</StatCard>
        </div>
        <p class="muted">取自各任务预处理阶段实测指标（file_count / indexed_functions / http_entries）；该阶段没跑完的任务不计入，不拿别处数字顶替。</p>
        <div v-if="codeScans.length" class="table-wrap cols-5">
          <table>
            <thead><tr><th>任务</th><th>名称</th><th>文件</th><th>函数</th><th>HTTP 入口</th></tr></thead>
            <tbody>
              <tr v-for="c in codeScans" :key="String(c.task_id)">
                <td class="num"><RouterLink :to="`/tasks/${c.task_id}`">#{{ c.task_id }}</RouterLink></td>
                <td class="wrap-break">{{ c.name }}</td>
                <td class="num">{{ int(c.file_count) }}</td>
                <td class="num">{{ int(c.indexed_functions) }}</td>
                <td class="num">{{ int(c.http_entries) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <h3>LLM token 与成本</h3>
          <!-- 未计费必须显式标出来：显示「$0.00」会让人以为是免费，实际是没接单价 -->
          <span v-if="llm && !llm.billed" class="tag bad">未计费（provider 未上报单价）</span>
          <span v-else class="tag ok">${{ money(llm?.cost_usd) }}</span>
        </div>
        <div class="stats-grid compact">
          <StatCard label="调用次数">{{ int(llm?.calls) }}</StatCard>
          <StatCard label="输入 token">{{ tok(llm?.input_tokens) }}</StatCard>
          <StatCard label="输出 token">{{ tok(llm?.output_tokens) }}</StatCard>
          <StatCard label="合计 token">{{ tok(llm?.total_tokens) }}</StatCard>
          <StatCard label="可归属任务">{{ int(llm?.attributed?.calls) }}</StatCard>
          <StatCard label="未关联任务">{{ int(llm?.unassigned?.calls) }}</StatCard>
        </div>
        <div class="stats-grid compact">
          <StatCard label="单次平均耗时">{{ ms(llm?.latency?.avg_ms) }}</StatCard>
          <StatCard label="P50">{{ ms(llm?.latency?.p50_ms) }}</StatCard>
          <StatCard label="P95">{{ ms(llm?.latency?.p95_ms) }}</StatCard>
          <StatCard label="最长">{{ ms(llm?.latency?.max_ms) }}</StatCard>
          <StatCard label="累计耗时">{{ ms(llm?.latency?.total_ms) }}</StatCard>
        </div>
        <!--
          去重收益：按 prompt 前缀哈希统计「同 hash 被重复请求」的量。
          这是降本增效里唯一能事后量化的一环；上下文裁剪与结果缓存是运行期开关，
          效果不体现在历史计数上，所以在下面单列一句说明，避免被误读成「没生效」。
        -->
        <h4 class="muted">去重收益</h4>
        <div class="stats-grid compact">
          <StatCard label="不同提示词前缀">{{ int(red?.distinct_prompt_hashes) }}</StatCard>
          <StatCard label="重复前缀数">{{ int(red?.duplicated_hashes) }}</StatCard>
          <StatCard label="冗余调用">{{ int(red?.redundant_calls) }}</StatCard>
          <StatCard label="冗余 token">{{ tok(red?.redundant_tokens) }}</StatCard>
        </div>
        <p class="muted">
          冗余 = 同一提示词前缀哈希被调用多次。结果缓存在命中时短路跳过模型，这里统计的是「本可省下」的量，不是已节省量；
          上下文裁剪需显式打开（SAST_AI_MAX_INPUT_TOKENS，默认 0 = 不裁剪），未开启时不会有裁剪收益。
        </p>
        <div class="row wrap gap-md">
          <div class="stack" style="min-width: 260px">
            <h4 class="muted">按模型</h4>
            <div class="table-wrap cols-4">
              <table>
                <thead><tr><th>模型</th><th>调用</th><th>平均</th><th>P95</th></tr></thead>
                <tbody>
                  <tr v-for="m in llm?.by_model ?? []" :key="m.key">
                    <td>{{ m.key }}</td><td class="num">{{ int(m.calls) }}</td>
                    <td class="num">{{ ms(m.avg_ms) }}</td><td class="num">{{ ms(m.p95_ms) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="stack" style="min-width: 260px">
            <h4 class="muted">按阶段</h4>
            <div class="table-wrap cols-3">
              <table>
                <thead><tr><th>阶段</th><th>调用</th><th>平均</th></tr></thead>
                <tbody>
                  <tr v-for="s in llm?.by_stage ?? []" :key="s.key">
                    <td>{{ s.key }}</td><td class="num">{{ int(s.calls) }}</td><td class="num">{{ ms(s.avg_ms) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </section>

      <section class="card stack glow-card">
        <h3>Agent 调用次数与耗时</h3>
        <div class="table-wrap cols-5">
          <table>
            <thead><tr><th>Agent（purpose）</th><th>调用</th><th>输入 token</th><th>输出 token</th><th>平均耗时</th></tr></thead>
            <tbody>
              <tr v-for="a in agents" :key="a.key">
                <td>{{ a.key }}</td><td class="num">{{ int(a.calls) }}</td>
                <td class="num">{{ tok(a.input_tokens) }}</td><td class="num">{{ tok(a.output_tokens) }}</td>
                <td class="num">{{ ms(a.avg_ms) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card stack glow-card">
        <h3>按工作区分布</h3>
        <p class="muted">未关联任务的调用无法归属到工作区，不计入本表（上节已单列）。配额策略已在提交侧生效（超限返回 429），本页尚未做「用量 vs 配额」对比展示。</p>
        <div class="table-wrap cols-5">
          <table>
            <thead><tr><th>工作区</th><th>扫描次数</th><th>LLM 调用</th><th>输入 token</th><th>输出 token</th></tr></thead>
            <tbody>
              <tr v-for="w in byWorkspace" :key="String(w.workspace_id)">
                <td>{{ w.name }}</td><td class="num">{{ int(w.scans) }}</td><td class="num">{{ int(w.llm_calls) }}</td>
                <td class="num">{{ tok(w.input_tokens) }}</td><td class="num">{{ tok(w.output_tokens) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <h3>年度成本估算</h3>
          <div class="row gap-sm wrap">
            <input v-model="variance" placeholder="波动系数" style="max-width: 100px" />
            <button class="ghost-button" @click="loadCost">估算</button>
          </div>
        </div>
        <p class="muted">按已记录的单次扫描成本与触发策略频次外推。当前 model_runs 未上报单价，估算依据是 scan_cost 记录，不是按 token 反推。</p>
        <div v-if="cost && !hasCostBasis" class="callout warning">
          <strong>暂无成本记录，金额不可估算</strong>
          <p class="muted">
            本页金额全部由 scan_cost 记录外推；当前 {{ int(cost.scan_record_count) }} 条记录 →
            外推结果恒为 0，但那是「无依据」不是「零成本」，故显示「—」。已上报单价的模型才会计入。
          </p>
        </div>
        <div v-if="cost" class="stats-grid compact">
          <StatCard label="年度成本">{{ hasCostBasis ? `$${money(cost.annual_cost)}` : "—" }}</StatCard>
          <StatCard label="区间">
            {{ hasCostBasis ? `$${money(cost.annual_cost_low)} ~ $${money(cost.annual_cost_high)}` : "—" }}
          </StatCard>
          <StatCard label="均次成本">{{ hasCostBasis ? `$${money(cost.avg_scan_cost)}` : "—" }}</StatCard>
          <StatCard label="预计扫描次数/年">{{ int(cost.predicted_scans) }}</StatCard>
          <StatCard label="成本记录数">{{ int(cost.scan_record_count) }}</StatCard>
          <StatCard label="启用策略数">{{ int(cost.policy_count) }}</StatCard>
        </div>
        <div v-else class="empty-state">
          <strong>暂无成本估算</strong>
          <span>需要先有 scan_cost 记录；点击「估算」可再算一次。</span>
        </div>
        <div v-if="cost?.recommendation" class="row wrap gap-md">
          <div class="callout" style="flex: 1; min-width: 260px">
            <strong>日常扫描</strong> · {{ cost.recommendation.routine.model }}（{{ cost.recommendation.routine.scan_mode }}）
            <p class="muted">{{ cost.recommendation.routine.note }}</p>
          </div>
          <div class="callout" style="flex: 1; min-width: 260px">
            <strong>重点深扫</strong> · {{ cost.recommendation.deep.model }}（{{ cost.recommendation.deep.scan_mode }}）
            <p class="muted">{{ cost.recommendation.deep.note }}</p>
          </div>
        </div>
      </section>

      <section class="card stack glow-card">
        <h3>扫描触发策略</h3>
        <p class="muted">策略决定「代码提交 / 定时 / 手工触发」各走什么扫描模式与模型，直接决定上面的年度扫描频次与成本。</p>
        <div v-if="policies.length" class="table-wrap cols-6">
          <table>
            <thead><tr><th>策略名</th><th>触发条件</th><th>扫描模式</th><th>模型</th><th>月频次</th><th>启用</th></tr></thead>
            <tbody>
              <tr v-for="p in policies" :key="String(p.id)">
                <td>{{ p.name }}</td><td>{{ p.trigger }}</td><td>{{ p.scan_mode }}</td>
                <td>{{ p.model }}</td><td class="num">{{ int(p.monthly_frequency) }}</td>
                <td><span class="tag" :class="p.enabled ? 'ok' : 'bad'">{{ p.enabled ? "启用" : "停用" }}</span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无扫描时机策略</strong>
          <span>未配置时全部走手动扫描，年度估算也只会按既有记录外推。</span>
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

type Row = Record<string, any>;

const root = ref<HTMLElement | null>(null);
const data = ref<Row | null>(null);
const cost = ref<Row | null>(null);
const policies = ref<Row[]>([]);
const workspaceId = ref("");
const variance = ref("0.2");
const error = ref("");
const loading = ref(true);

useTableScroll(root);

onMounted(async () => {
  await load();
  loading.value = false;
  animate();
});

function params() {
  const id = Number(workspaceId.value);
  return Number.isFinite(id) && id > 0 ? { workspace_id: id } : {};
}

async function load() {
  error.value = "";
  try {
    const { data: payload } = await http.get<Row>("/api/metrics/usage", { params: params() });
    data.value = payload;
  } catch (caught) {
    error.value = errText(caught);
  }
  await Promise.all([loadCost(), loadPolicies()]);
  animate();
}

async function loadCost() {
  const v = Number(variance.value);
  try {
    const { data } = await http.get<Row>("/api/metrics/annual-cost", {
      params: { ...params(), variance: Number.isFinite(v) ? v : 0.2 },
    });
    cost.value = data;
  } catch (caught) { error.value = errText(caught); }
}

async function loadPolicies() {
  try {
    const { data } = await http.get<Row>("/api/metrics/trigger-policy", { params: params() });
    policies.value = data.policies ?? [];
  } catch (caught) { error.value = errText(caught); }
}

const scans = computed(() => data.value?.scans ?? null);
const code = computed(() => data.value?.code_volume ?? null);
const llm = computed(() => data.value?.llm ?? null);
/**
 * 成本估算是否有依据。
 *
 * 2026-09-22 走查发现：``annual_cost = avg_scan_cost × predicted_scans``，而 ``avg_scan_cost``
 * 是 ``scan_cost`` 记录里 ``cost_usd`` 的均值 —— 当前库中 ``scan_record_count = 0``，
 * 于是年度成本/区间/均次成本三张卡片整齐显示 ``$0.0000``。
 * 把「没有成本记录」渲染成「0 元」会被读成「不要钱」，与「单价未上报就显示未计费、
 * 不显示 $0.00」的既有口径（见上方 LLM 卡片）自相矛盾。故此处按无依据处理为「—」。
 */
const hasCostBasis = computed(() => Number((cost.value as Row | null)?.scan_record_count || 0) > 0);
const red = computed(() => data.value?.llm?.redundant ?? null);
const notes = computed<string[]>(() => data.value?.notes ?? []);
const agents = computed<Row[]>(() => data.value?.agents?.by_purpose ?? []);
const byWorkspace = computed<Row[]>(() => data.value?.by_workspace ?? []);
const recentScans = computed<Row[]>(() => scans.value?.recent ?? []);
const codeScans = computed<Row[]>(() => code.value?.per_scan ?? []);

function statusCount(status: string) {
  return Number(scans.value?.by_status?.[status] ?? 0);
}

function int(value: unknown) {
  const num = Number(value);
  return Number.isFinite(num) ? Math.round(num).toLocaleString("zh-CN") : "-";
}

function money(value: unknown) {
  const num = Number(value);
  return Number.isFinite(num) ? num.toFixed(4) : "-";
}

/** token 量级大，全位数字会撑爆卡片，按 M / K 收敛 */
function tok(value: unknown) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(2)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return String(Math.round(num));
}

function dur(value: unknown) {
  const sec = Number(value);
  if (!Number.isFinite(sec) || sec <= 0) return "-";
  if (sec < 60) return `${sec.toFixed(0)} 秒`;
  if (sec < 3600) return `${(sec / 60).toFixed(1)} 分钟`;
  return `${(sec / 3600).toFixed(2)} 小时`;
}

function ms(value: unknown) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  if (num < 1000) return `${num.toFixed(0)} ms`;
  if (num < 60_000) return `${(num / 1000).toFixed(1)} 秒`;
  if (num < 3_600_000) return `${(num / 60_000).toFixed(1)} 分钟`;
  return `${(num / 3_600_000).toFixed(2)} 小时`;
}

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error)?.message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(
    root.value.querySelectorAll(".stat-card, .glow-card"),
    { y: 8, opacity: 0.82 },
    { y: 0, opacity: 1, duration: 0.35, stagger: 0.02, ease: "power2.out" },
  );
}
</script>

<style scoped>
.usage-notes {
  margin: 6px 0 0;
  padding-left: 18px;
  display: grid;
  gap: 4px;
  font-size: 13px;
  color: var(--color-muted);
}
</style>
