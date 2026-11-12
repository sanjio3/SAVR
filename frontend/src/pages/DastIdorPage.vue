<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>越权扫描工作台</h1>
        <p class="page-subtitle">
          按「应用资产 → 角色账号 → API 资产 → 流量样本」准备输入，扫描会构造跨主体候选并判断这些请求是否本不该成功，
          最后交给 AI 裁决。填好之后的越权结论可以直接进入 D1 触发重放链路。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="reload">刷新</button>
        <button class="button" :disabled="scanning" @click="scanApp">{{ scanning ? "扫描中…" : "运行越权扫描" }}</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取越权资产…" />

    <template v-else>
      <div class="stats-grid compact">
        <StatCard label="应用">{{ apps.length }}</StatCard>
        <StatCard label="角色账号">{{ accounts.length }}</StatCard>
        <StatCard label="API 资产">{{ apis.length }}</StatCard>
        <StatCard label="越权发现">{{ scanResult?.finding_count ?? results.length }}</StatCard>
      </div>

      <section class="grid two">
        <div class="card stack glow-card">
          <div>
            <h3>应用与权限边界</h3>
            <p class="muted">先登记被扫应用，再声明角色边界：哪些角色之间本不该互相访问对方的数据。</p>
          </div>
          <label class="stack compact">
            <span class="muted">应用标识</span>
            <input v-model="appForm.app_id" placeholder="应用标识，例如 shop" />
          </label>
          <label class="stack compact">
            <span class="muted">应用名称</span>
            <input v-model="appForm.app_name" placeholder="应用名称，例如 商城" />
          </label>
          <label class="stack compact">
            <span class="muted">服务地址（可选，仅真实重放时需要）</span>
            <input v-model="appForm.base_url" placeholder="例如 http://127.0.0.1:8092" />
          </label>
          <label class="stack compact">
            <span class="muted">服务名</span>
            <input v-model="appForm.service_name" placeholder="服务名，例如 shop-service" />
          </label>
          <label class="stack compact">
            <span class="muted">角色边界 JSON（allow_cross_subject=true 表示允许跨主体，即不构成越权）</span>
            <textarea v-model="roleBoundariesText" rows="5" />
          </label>
          <button class="ghost-button" @click="saveApp">保存应用</button>
          <label class="stack compact">
            <span class="muted">当前操作的应用（切换后下方资产与结果会同步刷新）</span>
            <select v-model="selectedAppId">
              <option value="">请选择应用</option>
              <option v-for="app in apps" :key="String(app.app_id)" :value="String(app.app_id)">{{ app.app_name || app.app_id }}</option>
            </select>
          </label>
        </div>

        <div class="card stack glow-card">
          <div>
            <h3>角色账号导入</h3>
            <p class="muted">生产环境请用 token_ref / secret 引用方式，不要在这里明文保存真实 cookie 或 token。</p>
          </div>
          <textarea v-model="accountsText" rows="9" aria-label="角色账号 JSON" />
          <button class="ghost-button" @click="importAccounts">导入账号</button>
          <div v-if="accounts.length" class="table-wrap cols-4">
            <table>
              <thead><tr><th>账号</th><th>角色</th><th>租户</th><th>主体</th></tr></thead>
              <tbody>
                <tr v-for="item in accounts" :key="String(item.id)">
                  <td>{{ item.account_id }}</td><td>{{ item.role }}</td><td>{{ item.tenant }}</td><td>{{ item.subject }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state"><span>当前应用还没有导入角色账号。</span></div>
        </div>
      </section>

      <section class="grid two">
        <div class="card stack glow-card">
          <div>
            <h3>API 资产导入</h3>
            <p class="muted">支持直接写 API JSON；后端也接受 OpenAPI / Postman 的 JSON 结构。</p>
          </div>
          <textarea v-model="apisText" rows="10" aria-label="API 资产 JSON" />
          <button class="ghost-button" @click="importApis">导入 API</button>
          <div v-if="apis.length" class="table-wrap cols-4">
            <table>
              <thead><tr><th>方法</th><th>路径</th><th>资源标识字段</th><th>风险等级</th></tr></thead>
              <tbody>
                <tr v-for="item in apis" :key="String(item.id)">
                  <td>{{ item.method }}</td><td class="wrap-break">{{ item.path }}</td>
                  <td class="muted">{{ arrayLabel(item.resource_id_fields) }}</td><td>{{ riskLabel(item.risk_level) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state"><span>当前应用还没有导入 API 资产。</span></div>
        </div>

        <div class="card stack glow-card">
          <div>
            <h3>流量样本导入</h3>
            <p class="muted">样本要带角色 / 租户 / 主体 / 资源归属 / 响应。扫描会据此构造跨主体候选，再判断这些请求本不该成功。</p>
          </div>
          <textarea v-model="trafficText" rows="10" aria-label="流量样本 JSON" />
          <button class="ghost-button" @click="importTraffic">导入流量</button>
          <div v-if="traffic.length" class="table-wrap cols-4">
            <table>
              <thead><tr><th>路径</th><th>主体</th><th>资源归属</th><th>状态码</th></tr></thead>
              <tbody>
                <tr v-for="item in traffic" :key="String(item.id)">
                  <td class="wrap-break">{{ item.path }}</td><td>{{ item.subject }}</td>
                  <td>{{ item.resource_owner }}</td><td class="num">{{ item.status_code }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state"><span>当前应用还没有导入流量样本。</span></div>
        </div>
      </section>

      <section class="card stack glow-card">
        <div class="row between wrap gap-sm">
          <div>
            <h3>越权扫描与 AI 裁决</h3>
            <p class="muted">默认用已导入样本离线判断；勾选「真实重放」后才会向目标发真实 HTTP 请求。</p>
          </div>
          <div class="row wrap gap-md">
            <label class="row gap-sm"><input v-model="scanForm.execute_http" type="checkbox" style="width: auto" /> 真实重放（live replay）</label>
            <label class="row gap-sm"><input v-model="scanForm.allow_mutating" type="checkbox" style="width: auto" /> 允许写操作请求</label>
          </div>
        </div>
        <div v-if="scanResult" class="callout success">
          候选 {{ scanResult.candidate_count }} 条，重放 {{ scanResult.replayed_count }} 条，确认越权 {{ scanResult.finding_count }} 条
        </div>
        <div v-if="results.length" class="table-wrap cols-4">
          <table>
            <thead><tr><th>发现</th><th>置信度</th><th>指纹</th><th>裁决理由</th></tr></thead>
            <tbody>
              <tr v-for="item in results" :key="String(item.id || item.vulnerability_hash_v2)">
                <td>{{ item.display_title }}</td>
                <td>{{ item.idor?.confidence || item.decision?.confidence }}</td>
                <td><code class="wrap-break">{{ item.vulnerability_hash_v2 }}</code></td>
                <td class="muted">{{ item.idor?.decision_reason || item.decision?.decision_reason }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无越权结果</strong>
          <span>请先配置应用、角色账号、API 资产与流量样本，然后运行一次越权扫描。</span>
        </div>
        <div v-if="error" class="callout danger">{{ error }}</div>
      </section>

      <section class="card stack glow-card">
        <div>
          <h3>D1 触发重放</h3>
          <p class="muted">
            按 TriggerSpec 构造带 canary 的触发请求，发往目标站点，用来验证某条假说是否真的能在运行时打通。
            括号里是后端字段名，便于和接口文档对照。
          </p>
        </div>
        <div class="grid two">
          <div class="stack gap-sm">
            <label class="stack compact">
              <span class="muted">目标服务地址（service_url）</span>
              <input v-model="replayForm.service_url" placeholder="例如 http://127.0.0.1:8092" />
            </label>
            <label class="stack compact">
              <span class="muted">目标端点（target_endpoint）</span>
              <input v-model="replayForm.target_endpoint" placeholder="例如 /api/search" />
            </label>
            <label class="stack compact">
              <span class="muted">HTTP 方法（http_method）</span>
              <input v-model="replayForm.http_method" placeholder="GET" />
            </label>
            <label class="stack compact">
              <span class="muted">注入参数名（param_name）</span>
              <input v-model="replayForm.param_name" placeholder="例如 q" />
            </label>
            <label class="stack compact">
              <span class="muted">参数位置（param_location）</span>
              <input v-model="replayForm.param_location" placeholder="query / header / cookie / body / path" />
            </label>
            <label class="stack compact">
              <span class="muted">污点标记 canary（taint_marker）</span>
              <input v-model="replayForm.taint_marker" placeholder="留空则由后端生成" />
            </label>

            <div class="callout warning">
              <strong>第二阶段危害验证默认关闭。</strong>
              只有在「目标在白名单」+「开关开启」+「提供了危害 payload」三条同时满足时，才会发出真实的危害性请求。
            </div>
            <label class="row gap-sm"><input v-model="replayForm.phase2_enabled" type="checkbox" style="width: auto" /> 开启第二阶段危害验证</label>
            <label class="row gap-sm"><input v-model="replayForm.phase2_override" type="checkbox" style="width: auto" /> 本次交互确认覆盖（phase2_override）</label>
            <label class="stack compact">
              <span class="muted">第二阶段白名单（phase2_whitelist，逗号分隔的服务地址）</span>
              <input v-model="replayForm.phase2_whitelist" placeholder="例如 http://127.0.0.1:8092" />
            </label>
            <label class="stack compact">
              <span class="muted">危害 payload（impact_payloads，JSON 数组）</span>
              <textarea v-model="replayForm.impact_payloads" rows="3" placeholder='["rm -rf /", "DROP TABLE x;"]' />
            </label>
            <button :disabled="replayBusy" @click="runReplay">{{ replayBusy ? "重放中…" : "执行重放" }}</button>
          </div>
          <div class="stack gap-sm">
            <div v-if="replayResult" class="stack gap-xs">
              <div class="small">
                状态码 <strong>{{ replayResult.status_code ?? "-" }}</strong>
                · 已到达 <strong>{{ replayResult.reached ? "是" : "否" }}</strong>
                · 被阻断 <strong>{{ replayResult.blocked ? "是" : "否" }}</strong>
              </div>
              <div v-if="replayResult.error" class="callout danger">重放错误：{{ replayResult.error }}</div>
              <div v-if="phase2Slices.length" class="stack gap-xs">
                <strong class="small">第二阶段结果</strong>
                <div v-for="(_, k) in phase2Slices" :key="k" class="muted small">{{ k }}：状态码 {{ replayResult.slices[k]?.status_code ?? "-" }}</div>
              </div>
              <pre class="code-block">{{ replayResult.body || replayResult.response_summary || "（响应体为空）" }}</pre>
            </div>
            <div v-else class="empty-state"><span>尚未执行重放。</span></div>
          </div>
        </div>
        <div v-if="replayError" class="callout danger">{{ replayError }}</div>
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { gsap } from "gsap";

import StatCard from "@/components/StatCard.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import { useTableScroll } from "@/domain/table-scroll";
import { http } from "@/services/http";

type Row = Record<string, any>;

const root = ref<HTMLElement | null>(null);
const apps = ref<Row[]>([]);
const accounts = ref<Row[]>([]);
const apis = ref<Row[]>([]);
const traffic = ref<Row[]>([]);
const results = ref<Row[]>([]);
const scanResult = ref<Row | null>(null);
const selectedAppId = ref("");
const error = ref("");
const loading = ref(true);
const scanning = ref(false);
const replayForm = ref({ service_url: "", target_endpoint: "/", http_method: "GET", param_name: "q", param_location: "query", taint_marker: "", phase2_enabled: false, phase2_override: false, phase2_whitelist: "", impact_payloads: "" });
const replayResult = ref<Row | null>(null);
const replayBusy = ref(false);
const replayError = ref("");
const phase2Slices = computed(() => {
  const slices = replayResult.value?.slices as Record<string, Row> | undefined;
  if (!slices) return [];
  return Object.entries(slices).filter(([key]) => key.startsWith("phase2:"));
});
const appForm = ref({ app_id: "shop", app_name: "Shop", base_url: "", service_name: "shop-service", auth_type: "cookie" });
const scanForm = ref({ mode: "imported_traffic", execute_http: false, allow_mutating: false });
const roleBoundariesText = ref('[{"roles":["admin"],"allow_cross_subject":true}]');
const accountsText = ref('[{"account_id":"alice","role":"user","tenant":"t1","subject":"alice"},{"account_id":"bob","role":"user","tenant":"t2","subject":"bob"}]');
const apisText = ref('[{"method":"GET","path":"/orders/{id}","params":[{"name":"id"}],"auth_required":true,"risk_level":"high"}]');
const trafficText = ref('[{"path":"/orders/100","method":"GET","role":"user","tenant":"t1","subject":"alice","resource_owner":"alice","resource_tenant":"t1","resource_id":"100","status_code":200,"response_body":"order 100 owner alice"},{"path":"/orders/100","method":"GET","role":"user","tenant":"t2","subject":"bob","resource_owner":"alice","resource_tenant":"t1","resource_id":"100","status_code":200,"response_body":"order 100 owner alice"}]');
const activeAppId = computed(() => selectedAppId.value || appForm.value.app_id);

useTableScroll(root);

onMounted(async () => {
  await loadApps();
  loading.value = false;
  animate();
});

watch(selectedAppId, async () => loadAppAssets());

async function loadApps() {
  try {
    const { data } = await http.get<Row[]>("/api/dast/apps");
    apps.value = data;
    if (!selectedAppId.value && data.length) selectedAppId.value = String(data[0].app_id);
    await loadAppAssets();
  } catch (caught) {
    error.value = errText(caught);
  }
}

async function reload() {
  error.value = "";
  await loadApps();
  animate();
}

async function loadAppAssets() {
  if (!activeAppId.value) return;
  const [accountResp, apiResp, trafficResp, resultResp] = await Promise.all([
    http.get<Row[]>(`/api/idor/apps/${activeAppId.value}/accounts`),
    http.get<Row[]>(`/api/idor/apps/${activeAppId.value}/apis`),
    http.get<Row[]>(`/api/idor/apps/${activeAppId.value}/traffic`),
    http.get<Row>(`/api/idor/apps/${activeAppId.value}/results`),
  ]).catch(() => [{ data: [] }, { data: [] }, { data: [] }, { data: { findings: [] } }] as any);
  accounts.value = accountResp.data;
  apis.value = apiResp.data;
  traffic.value = trafficResp.data;
  results.value = Array.isArray(resultResp.data.findings) ? resultResp.data.findings : [];
  animate();
}

async function saveApp() {
  error.value = "";
  if (!appForm.value.app_id.trim()) {
    error.value = "应用标识不能为空。";
    return;
  }
  try {
    const payload = { ...appForm.value, role_boundaries: parseJson(roleBoundariesText.value, []) };
    const { data } = await http.post<Row>("/api/dast/apps", payload);
    selectedAppId.value = String(data.app_id);
    await loadApps();
  } catch (caught) {
    error.value = errText(caught);
  }
}

async function importAccounts() {
  error.value = "";
  try {
    await http.post(`/api/idor/apps/${activeAppId.value}/accounts/import`, { accounts: parseJson(accountsText.value, []) });
    await loadAppAssets();
  } catch (caught) {
    error.value = errText(caught);
  }
}

async function importApis() {
  error.value = "";
  try {
    await http.post(`/api/idor/apps/${activeAppId.value}/apis/import`, { apis: parseJson(apisText.value, []) });
    await loadAppAssets();
  } catch (caught) {
    error.value = errText(caught);
  }
}

async function importTraffic() {
  error.value = "";
  try {
    await http.post(`/api/idor/apps/${activeAppId.value}/traffic/import`, { samples: parseJson(trafficText.value, []) });
    await loadAppAssets();
  } catch (caught) {
    error.value = errText(caught);
  }
}

async function scanApp() {
  error.value = "";
  scanning.value = true;
  try {
    const { data } = await http.post<Row>(`/api/idor/apps/${activeAppId.value}/scan`, scanForm.value);
    scanResult.value = data;
    results.value = Array.isArray(data.findings) ? data.findings : [];
    animate();
  } catch (caught) {
    error.value = errText(caught);
  } finally {
    scanning.value = false;
  }
}

function parseJson(text: string, fallback: unknown) {
  try { return JSON.parse(text); } catch { error.value = "JSON 格式错误，请检查输入。"; return fallback; }
}

async function runReplay() {
  replayBusy.value = true;
  replayError.value = "";
  replayResult.value = null;
  try {
    const whitelist = replayForm.value.phase2_whitelist
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const impactPayloads = parseJson(replayForm.value.impact_payloads || "[]", []);
    const { data } = await http.post<Row>("/api/dast/replay", {
      trigger_spec: {
        target_endpoint: replayForm.value.target_endpoint,
        http_method: replayForm.value.http_method,
        param_name: replayForm.value.param_name,
        param_location: replayForm.value.param_location,
        taint_marker: replayForm.value.taint_marker,
        phase2_override: replayForm.value.phase2_override,
        impact_payloads: Array.isArray(impactPayloads) ? impactPayloads : [],
      },
      target: {
        service_url: replayForm.value.service_url,
        settings: {
          phase2_enabled: replayForm.value.phase2_enabled,
          phase2_whitelist: whitelist,
        },
      },
    });
    replayResult.value = data;
  } catch (caught) {
    replayError.value = errText(caught);
  } finally {
    replayBusy.value = false;
  }
}

function arrayLabel(value: unknown) {
  return Array.isArray(value) && value.length ? value.join(", ") : String(value || "-");
}

function riskLabel(value: unknown) {
  const text = String(value || "").toLowerCase();
  const map: Record<string, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危" };
  return map[text] || String(value || "-");
}

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error)?.message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(root.value.querySelectorAll(".stat-card, .glow-card"), { y: 8, opacity: 0.82 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.025, ease: "power2.out" });
}
</script>
