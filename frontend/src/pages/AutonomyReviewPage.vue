<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>复核队列</h1>
        <p class="page-subtitle">
          条件式自治策略：满足「裁决 + 置信度 + 影响面」条件的漏洞可以自动处置。灰度比例决定放量范围，
          每次处置都留审计记录并支持一键回滚。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="reload">刷新</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取自治策略…" />

    <template v-else>
      <div class="stats-grid compact">
        <StatCard label="策略数">{{ policies.length }}</StatCard>
        <StatCard label="处置次数">{{ actions.length }}</StatCard>
        <StatCard label="已生效">{{ appliedCount }}</StatCard>
        <StatCard label="已回滚">{{ rolledBackCount }}</StatCard>
      </div>

      <section class="grid two">
        <div class="card stack glow-card">
          <div>
            <h3>新建 / 更新策略</h3>
            <p class="muted">策略名唯一，同名即覆盖。灰度 0% 表示只观察不处置，100% 表示全量处置。</p>
          </div>
          <label class="stack compact">
            <span class="muted">策略名（唯一）</span>
            <input v-model="policyForm.name" placeholder="例如 auto-close-fp" />
          </label>
          <label class="stack compact">
            <span class="muted">处置动作</span>
            <select v-model="policyForm.action">
              <option value="auto_close">自动关闭（标记为误报）</option>
              <option value="auto_confirm">自动确认（标记为真实漏洞）</option>
            </select>
          </label>
          <label class="stack compact">
            <span class="muted">目标裁决</span>
            <select v-model="policyForm.verdict">
              <option value="false_positive">误报（false_positive）</option>
              <option value="true_positive">真实漏洞（true_positive）</option>
            </select>
          </label>
          <label class="stack compact">
            <span class="muted">最低置信度（低于此级别的漏洞不处置）</span>
            <select v-model="policyForm.min_confidence">
              <option value="low">低</option>
              <option value="medium">中</option>
              <option value="high">高</option>
            </select>
          </label>
          <label class="stack compact">
            <span class="muted">最高影响面（超过此级别的漏洞不处置）</span>
            <select v-model="policyForm.max_impact">
              <option value="low">低危</option>
              <option value="medium">中危</option>
              <option value="high">高危</option>
              <option value="critical">严重</option>
            </select>
          </label>
          <label class="stack compact">
            <span class="muted">灰度放量比例：{{ policyForm.gray_percent }}%</span>
            <input v-model.number="policyForm.gray_percent" type="range" min="0" max="100" />
          </label>
          <label class="row gap-sm"><input v-model="policyForm.require_ai_agree" type="checkbox" style="width: auto" /> 需要人工或 AI 复核一致才处置</label>
          <label class="row gap-sm"><input v-model="policyForm.enabled" type="checkbox" style="width: auto" /> 启用该策略</label>
          <button class="button" @click="savePolicy">保存策略</button>
        </div>

        <div class="card stack glow-card">
          <div>
            <h3>现有策略</h3>
            <p class="muted">按「裁决 / 最低置信度 / 最高影响面」条件命中后，再按灰度比例决定是否真的处置。</p>
          </div>
          <div v-if="policies.length" class="table-wrap cols-7">
            <table>
              <thead><tr><th>策略名</th><th>动作</th><th>裁决</th><th>最低置信度</th><th>最高影响面</th><th>灰度</th><th>启用</th></tr></thead>
              <tbody>
                <tr v-for="p in policies" :key="String(p.id)">
                  <td>{{ p.name }}</td>
                  <td>{{ actionLabel(p.action) }}</td>
                  <td>{{ verdictLabel(p.verdict) }}</td>
                  <td>{{ levelLabel(p.min_confidence) }}</td>
                  <td>{{ levelLabel(p.max_impact) }}</td>
                  <td class="num">{{ p.gray_percent }}%</td>
                  <td><span class="tag" :class="p.enabled ? 'ok' : 'bad'">{{ p.enabled ? "启用" : "停用" }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state">
            <strong>暂无自治策略</strong>
            <span>左侧填好条件后点「保存策略」，策略列表与后续处置记录都会出现在这里。</span>
          </div>

          <h3>按 finding 试算</h3>
          <p class="muted">只做判定演示，不落库、不改变 finding 状态。</p>
          <div class="row gap-sm wrap">
            <input v-model="evaluateForm.finding_id" placeholder="finding id" style="max-width: 160px" />
            <button class="ghost-button" @click="evaluateFinding">试算</button>
          </div>
          <div v-if="evaluateResult" class="callout" :class="evaluateResult.applied ? 'success' : 'warning'">
            裁决 {{ verdictLabel(evaluateResult.decision) }} · 是否处置 {{ evaluateResult.applied ? "是" : "否" }} · {{ evaluateResult.reason }}
          </div>
        </div>
      </section>

      <section class="card stack glow-card">
        <div>
          <h3>处置审计与回滚</h3>
          <p class="muted">每条自治动作都留痕：改了哪条 finding、原状态与新状态、落在哪个灰度桶。已生效的动作可以一键回滚。</p>
        </div>
        <div v-if="actions.length" class="table-wrap cols-8">
          <table>
            <thead><tr><th>ID</th><th>策略</th><th>动作</th><th>裁决</th><th>状态变化</th><th>灰度桶</th><th>处置结果</th><th></th></tr></thead>
            <tbody>
              <tr v-for="a in actions" :key="String(a.id)">
                <td class="num">{{ a.id }}</td>
                <td>{{ a.policy_name || "-" }}</td>
                <td>{{ actionLabel(a.action) }}</td>
                <td>{{ verdictLabel(a.decision) }}</td>
                <td>{{ a.previous_status }} → {{ a.new_status || "-" }}</td>
                <td class="num">{{ a.gray_bucket }}</td>
                <td>
                  <span class="tag" :class="a.rolled_back ? 'bad' : a.applied ? 'ok' : ''">
                    {{ a.rolled_back ? "已回滚" : a.applied ? "已生效" : "已拦截未执行" }}
                  </span>
                </td>
                <td>
                  <button v-if="a.applied && !a.rolled_back" class="ghost-button tiny" @click="askRollback(a.id)">回滚</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无自治处置记录</strong>
          <span>策略命中并产生处置后，这里会列出每一条动作与回滚入口。</span>
        </div>
        <div v-if="error" class="callout danger">{{ error }}</div>
      </section>
    </template>

    <ConfirmDialog
      :open="rollbackTarget !== null"
      title="回滚这条自治处置？"
      :message="`将把 finding 的状态改回处置前的值，并记录一次回滚。动作 ID ${rollbackTarget ?? ''}。`"
      confirm-text="确认回滚"
      @confirm="doRollback"
      @cancel="rollbackTarget = null"
    />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { gsap } from "gsap";

import StatCard from "@/components/StatCard.vue";
import ConfirmDialog from "@/components/ConfirmDialog.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import { useTableScroll } from "@/domain/table-scroll";
import { http } from "@/services/http";

type Row = Record<string, any>;

const root = ref<HTMLElement | null>(null);
const policies = ref<Row[]>([]);
const actions = ref<Row[]>([]);
const error = ref("");
const loading = ref(true);
const evaluateResult = ref<Row | null>(null);
const evaluateForm = ref({ finding_id: "" });
const rollbackTarget = ref<number | null>(null);
const policyForm = ref({
  name: "auto-close-fp",
  action: "auto_close",
  verdict: "false_positive",
  min_confidence: "high",
  max_impact: "medium",
  gray_percent: 20,
  require_ai_agree: true,
  enabled: true,
});

const appliedCount = computed(() => actions.value.filter((a) => a.applied && !a.rolled_back).length);
const rolledBackCount = computed(() => actions.value.filter((a) => a.rolled_back).length);

useTableScroll(root);

onMounted(async () => {
  await loadAll();
  loading.value = false;
  animate();
});

async function loadAll() {
  error.value = "";
  const [policyResp, actionResp] = await Promise.all([
    http.get<Row[]>("/api/autonomy/policies"),
    http.get<Row[]>("/api/autonomy/actions"),
  ]).catch(() => [{ data: [] }, { data: [] }] as any);
  policies.value = policyResp.data;
  actions.value = actionResp.data;
  animate();
}

async function reload() {
  await loadAll();
}

async function savePolicy() {
  error.value = "";
  try {
    await http.post("/api/autonomy/policies", policyForm.value);
    await loadAll();
  } catch (caught) {
    error.value = errText(caught);
  }
}

async function evaluateFinding() {
  error.value = "";
  evaluateResult.value = null;
  const id = Number(evaluateForm.value.finding_id);
  if (!id) { error.value = "请输入 finding id。"; return; }
  try {
    const { data } = await http.post<Row>("/api/autonomy/evaluate", { finding_id: id });
    evaluateResult.value = data;
    await loadAll();
  } catch (caught) {
    error.value = errText(caught);
  }
}

function askRollback(actionId: number) {
  rollbackTarget.value = actionId;
}

async function doRollback() {
  const actionId = rollbackTarget.value;
  rollbackTarget.value = null;
  if (!actionId) return;
  error.value = "";
  try {
    await http.post(`/api/autonomy/actions/${actionId}/rollback`, {});
    await loadAll();
  } catch (caught) {
    error.value = errText(caught);
  }
}

function actionLabel(value: unknown) {
  const map: Record<string, string> = { auto_close: "自动关闭", auto_confirm: "自动确认" };
  return map[String(value)] || String(value || "-");
}

function verdictLabel(value: unknown) {
  const map: Record<string, string> = { false_positive: "误报", true_positive: "真实漏洞" };
  return map[String(value)] || String(value || "-");
}

function levelLabel(value: unknown) {
  const map: Record<string, string> = { low: "低", medium: "中", high: "高", critical: "严重" };
  return map[String(value).toLowerCase()] || String(value || "-");
}

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error)?.message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(root.value.querySelectorAll(".stat-card, .glow-card"), { y: 8, opacity: 0.82 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.025, ease: "power2.out" });
}
</script>
