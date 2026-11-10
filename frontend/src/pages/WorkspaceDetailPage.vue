<template>
  <section class="page" v-if="store.selectedWorkspace">
    <Breadcrumb :items="[{ label: '工作区', to: '/' }, { label: store.selectedWorkspace.name }]" />

    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>{{ store.selectedWorkspace.name }}</h1>
        <p class="muted small">{{ store.selectedWorkspace.target_path }}</p>
        <div class="row wrap gap-sm env-row">
          <span class="badge badge-muted">测试环境地址</span>
          <input v-model="targetUrlDraft" class="env-input" placeholder="http://127.0.0.1:8080" />
          <button class="ghost-button tiny" :disabled="!canSaveTargetUrl" @click="saveTargetUrl">保存</button>
        </div>
      </div>
      <div class="row wrap gap-sm">
        <span v-if="store.selectedWorkspace.archived" class="status-badge status-queued">已归档</span>
      </div>
    </div>

    <div class="row wrap gap-sm">
      <button
        v-for="tab in tabs"
        :key="tab"
        type="button"
        class="ghost-button"
        :class="{ active: selectedTab === tab }"
        @click="selectedTab = tab"
      >
        {{ tab }}
      </button>
    </div>

    <section v-if="selectedTab === '扫描与运行'" class="grid two">
      <div class="card stack">
        <h2>开始扫描</h2>
        <p class="muted">所有分析模块（A1 规则 / A2 语义 / DAST 验证 / SCA / AI 复核 / 入口发现）默认全部开启，点击即跑完整链路。</p>

        <label class="stack compact">
          <span class="muted">任务名称</span>
          <input v-model="taskName" placeholder="全链路扫描" />
        </label>

        <div class="env-callout">
          <div class="row between wrap gap-sm">
            <div class="stack">
              <span class="badge badge-muted">测试环境地址（D1 重放目标）</span>
              <span class="env-url">{{ store.selectedWorkspace?.settings?.target_url || "未设置（页面顶部可填写）" }}</span>
            </div>
          </div>
          <p class="muted small">该地址会被 D1 重放器用于动态验证漏洞；未设置则只做静态分析。</p>
        </div>

        <div class="muted small">
          扫描模式、模型档位、Prompt 版本等默认参数来自
          <RouterLink to="/settings">全局设置</RouterLink>
          。
        </div>

        <details class="advanced stack">
          <summary>本次任务的 LLM 扫描强度（默认跟随全局设置：{{ PRESET_META[taskIntensity.preset].label }}）</summary>
          <p class="small muted">
            这里改的<strong>只影响本任务</strong>，不会改动全局设置、也不会影响同时在跑的其它任务。
          </p>
          <LlmIntensityPanel :model="taskIntensity" @change="onTaskIntensityChange" />
        </details>

        <button @click="createTask" :disabled="taskBusy">{{ taskBusy ? "提交中..." : "开始扫描" }}</button>
      </div>
      <div class="card stack">
        <h2>运行记录</h2>
        <div v-if="!store.tasks.length" class="muted">还没有运行记录。</div>
        <TaskPanel v-for="task in store.tasks" :key="task.id" :task="task" @delete="askRemoveTask" />
      </div>

      <details class="card advanced stack" :open="false">
        <summary>登录配置（业务差分重放账号，高级）</summary>
        <p class="muted small">配置被测应用的登录端点与预置账号，D1 会在重放前真登录取 token，用于越权 / 业务逻辑类漏洞的双账号差分验证。平台不内置任何凭据，全部由你在此填写。</p>
        <label class="stack compact">
          <span class="muted">登录端点 url（相对 service_url 或绝对地址，如 /login）</span>
          <input v-model="loginForm.url" placeholder="/login" />
        </label>
        <label class="stack compact">
          <span class="muted">HTTP 方法 method（默认 POST）</span>
          <input v-model="loginForm.method" placeholder="POST" />
        </label>
        <label class="stack compact">
          <span class="muted">token 字段名 token_field（响应体中，默认 token）</span>
          <input v-model="loginForm.token_field" placeholder="token" />
        </label>
        <label class="stack compact">
          <span class="muted">token 请求头 token_header（默认 Authorization）</span>
          <input v-model="loginForm.token_header" placeholder="Authorization" />
        </label>
        <label class="stack compact">
          <span class="muted">cookie_name（非空则 token 走该 cookie，如 mall_token）</span>
          <input v-model="loginForm.cookie_name" placeholder="留空则用请求头" />
        </label>
        <label class="row compact gap-sm">
          <input type="checkbox" v-model="loginForm.forge_alg_none" />
          <span class="muted">垂直越权：把登录取得的 JWT 改写成 alg=none 无签名令牌</span>
        </label>

        <div class="stack gap-xs">
          <div class="row between">
            <span class="muted">预置账号 credentials</span>
            <button class="ghost-button tiny" @click="addCredential">+ 添加账号</button>
          </div>
          <div v-for="(c, i) in loginForm.credentials" :key="i" class="cred-row">
            <div class="row wrap gap-sm">
              <input v-model="c.role" placeholder="role（如 admin / user，留空按特权排序）" />
              <input v-model="c.username" placeholder="username" />
              <input v-model="c.password" type="password" placeholder="password" />
              <button class="ghost-button tiny danger-outline" @click="removeCredential(i)">删除</button>
            </div>
          </div>
        </div>

        <button :disabled="!store.selectedWorkspace" @click="saveLogin">保存登录配置</button>
      </details>
    </section>

    <section v-else-if="selectedTab === 'IAST'" class="grid two">
      <div class="card stack">
        <h2>登记 IAST 目标（外部站点）</h2>
        <p class="muted">填写被测站点地址与代码路径，绑定当前工作区；探针身份从在线列表选择，也可手填兜底。</p>
        <label class="stack compact">
          <span class="muted">站点地址 target_url</span>
          <input v-model="iastForm.target_url" placeholder="http://127.0.0.1:11000" />
          <span v-if="iastForm.target_url && !iastUrlValid" class="sev-high small">请输入 http(s):// 开头的完整地址</span>
        </label>
        <label class="stack compact">
          <span class="muted">代码路径 code_path</span>
          <input v-model="iastForm.code_path" :placeholder="store.selectedWorkspace?.target_path || '本地绝对路径'" />
        </label>
        <label class="stack compact">
          <span class="muted">应用名 app_name</span>
          <input v-model="iastForm.app_name" list="iast-app-options" placeholder="选择或手填 app_name" />
          <datalist id="iast-app-options">
            <option v-for="a in appNameOptions" :key="a" :value="a" />
          </datalist>
        </label>
        <label class="stack compact">
          <span class="muted">探针标识 agent_id</span>
          <input v-model="iastForm.agent_id" list="iast-agent-options" placeholder="选择或手填 agent_id" />
          <datalist id="iast-agent-options">
            <option v-for="a in agentIdOptions" :key="a" :value="a" />
          </datalist>
        </label>
        <label class="stack compact">
          <span class="muted">探针模式 probe_mode（默认 iast）</span>
          <input v-model="iastForm.probe_mode" placeholder="iast" />
        </label>
        <label class="stack compact">
          <span class="muted">插桩包名前缀 probe_packages（默认 com.example）</span>
          <input v-model="iastForm.probe_packages" placeholder="com.example" />
        </label>
        <label class="stack compact">
          <span class="muted">目标监听端口 server_port（挂载命令据此生成 -Dserver.port）</span>
          <input v-model.number="iastForm.server_port" type="number" placeholder="8899" />
        </label>
        <label class="stack compact">
          <span class="muted">挂载探针所用 java（PATH 上的 java 或本机 JDK 绝对路径，按被扫描项目选择）</span>
          <input v-model="selectedJdkPath" placeholder="java" />
        </label>
        <label class="stack compact">
          <span class="muted">sec-probe.jar 路径（由部署方提供，相对仓库根或绝对路径）</span>
          <input v-model="probeJarPath" placeholder="probe-java/target/sec-probe.jar" />
        </label>
        <div class="muted" v-if="iastError">{{ iastError }}</div>
        <button :disabled="!canRegisterIast || iastBusy" @click="registerIastTarget">
          {{ iastBusy ? "登记中..." : "登记目标" }}
        </button>

        <div v-if="registeredSession" class="callout info stack gap-xs">
          <h3>探针挂载指引</h3>
          <p class="muted">前端已登记会话并颁发 probe_token。请在目标主机用下面命令挂载探针（JVM 启动参数）。Web 界面无法远程注入 agent，需你在目标机执行一次。</p>
          <div><span class="muted">probe_token：</span><code class="token">{{ registeredSession.probe_token }}</code></div>
          <div><span class="muted">回连地址（探针 sec.server.url）：</span><code>{{ backendBaseUrl }}</code></div>
          <div><span class="muted">心跳端点：</span><code>{{ backendBaseUrl }}/api/agent/heartbeat</code></div>
          <div><span class="muted">事件端点：</span><code>{{ backendBaseUrl }}/api/agent/events</code></div>
          <pre class="mount-cmd">{{ mountCommand(registeredSession) }}</pre>
          <button class="ghost-button" @click="copyText(mountCommand(registeredSession))">复制挂载命令</button>
          <div class="muted">探针以 -javaagent 方式挂到目标 JVM 后，会按 sec.server.url 自动向上述心跳端点上报（带 X-Agent-Token=probe_token）。心跳一上来，下方「已绑定的 IAST 目标」的 last_heartbeat 会更新，I1/D2/I2 随即开始产出运行时证据。</div>
        </div>
      </div>

      <div class="card stack">
        <h2>已绑定的 IAST 目标</h2>
        <div v-if="!workspaceIastSessions.length" class="muted">该工作区尚未绑定 IAST 目标。</div>
        <div v-else class="stack gap-sm">
          <div v-for="s in workspaceIastSessions" :key="s.id" class="project-card">
            <div class="stack">
              <strong>{{ s.app_name }} / {{ s.agent_id }}</strong>
              <div class="muted">{{ s.target_url }}</div>
              <div class="muted">状态={{ s.status }} 版本={{ s.version_status || "-" }}</div>
              <div :class="heartbeatStatus(s).online ? 'hb-online' : 'hb-offline'">
                {{ heartbeatStatus(s).text }}
              </div>
              <div v-if="s.agent_phase === 'WARMING_UP'" class="callout warning">
                探针预热中（首次请求较慢，请稍候约 1~3 分钟，预热完成自动转为就绪）
              </div>
              <div v-else-if="s.agent_phase === 'READY'" class="hb-online">
                探针就绪（已透明预热，首请求即快）
              </div>
              <div v-if="!heartbeatStatus(s).online" class="callout danger">
                探针尚未挂载或未上报：I1/D2/I2 不会有运行时数据。请按下方命令在 {{ s.target_url }} 所在主机挂载 sec-probe.jar（回连 {{ backendBaseUrl }}/api/agent/*）。
              </div>
              <div class="stack gap-xs">
                <div><span class="muted">probe_token：</span><code class="token">{{ s.probe_token }}</code></div>
                <pre class="mount-cmd">{{ mountCommand(s) }}</pre>
                <button class="ghost-button" @click="copyText(mountCommand(s))">复制挂载命令</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section v-else class="card stack">
      <h2>项目信息</h2>
      <table>
        <tbody>
          <tr>
            <th>描述</th>
            <td>{{ store.selectedWorkspace.description || "-" }}</td>
          </tr>
          <tr>
            <th>来源类型</th>
            <td>{{ String(store.selectedWorkspace.settings?.source_type || "local_path") }}</td>
          </tr>
          <tr>
            <th>是否归档</th>
            <td>{{ store.selectedWorkspace.archived ? "是" : "否" }}</td>
          </tr>
          <tr>
            <th>创建时间</th>
            <td>{{ store.selectedWorkspace.created_at }}</td>
          </tr>
          <tr>
            <th>更新时间</th>
            <td>{{ store.selectedWorkspace.updated_at }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <ConfirmDialog
      :open="Boolean(pendingTaskRemove)"
      title="删除运行记录"
      message="将删除该次运行及其存储的漏洞与报告，操作不可撤销。"
      confirm-text="删除"
      @confirm="confirmRemoveTask"
      @cancel="pendingTaskRemove = null"
    />
  </section>

  <!-- F4：工作区数据未到位时给形状一致的骨架，避免首屏闪成空白 -->
  <section v-else class="page stack" aria-busy="true">
    <SkeletonBlock variant="card" :rows="2" label="正在加载工作区…" />
    <SkeletonBlock variant="stat" :rows="3" label="正在加载运行记录…" />
    <SkeletonBlock variant="card" :rows="4" label="正在加载详情…" />
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import Breadcrumb from "@/components/Breadcrumb.vue";
import ConfirmDialog from "@/components/ConfirmDialog.vue";
import LlmIntensityPanel from "@/components/LlmIntensityPanel.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import TaskPanel from "@/components/TaskPanel.vue";
import { PRESET_META, buildOverrides, type LlmIntensity } from "@/stores/llmIntensity";
import { useIastStore } from "@/stores/iast";
import { useSettingsStore } from "@/stores/settings";
import { useWorkspaceStore } from "@/stores/workspaces";
import type { IastSession } from "@/types";

const route = useRoute();
const router = useRouter();
const store = useWorkspaceStore();
const settingsStore = useSettingsStore();
const iastStore = useIastStore();
const taskName = ref("全链路扫描");
const taskBusy = ref(false);
// 本次任务的 LLM 扫描强度：默认跟随全局设置，展开后可单独覆盖（只影响本任务）。
const taskIntensity = reactive<LlmIntensity>(
  settingsStore.defaultScanOptions
    ? { preset: settingsStore.defaultScanOptions.llm_preset, advanced: { ...settingsStore.defaultScanOptions.llm_advanced } }
    : { preset: "balanced", advanced: { ...settingsStore.intensityDefaults().advanced } },
);
function onTaskIntensityChange(next: LlmIntensity) {
  taskIntensity.preset = next.preset;
  taskIntensity.advanced = { ...next.advanced };
}
const targetUrlDraft = ref("");
const canSaveTargetUrl = computed(() => {
  const cur = store.selectedWorkspace?.settings?.target_url || "";
  return targetUrlDraft.value.trim() !== "" && targetUrlDraft.value.trim() !== cur;
});
const tabs = ["扫描与运行", "IAST", "项目信息"] as const;
const selectedTab = ref<(typeof tabs)[number]>("扫描与运行");

const iastForm = reactive({
  target_url: "",
  code_path: "",
  app_name: "",
  agent_id: "",
  probe_mode: "iast",
  probe_packages: "com.example",
  server_port: 8899,
});
const iastBusy = ref(false);
const iastError = ref("");
const appNameOptions = computed(() => Array.from(new Set(iastStore.sessions.map((s) => s.app_name).filter(Boolean))));
const agentIdOptions = computed(() => Array.from(new Set(iastStore.sessions.map((s) => s.agent_id).filter(Boolean))));
const workspaceIastSessions = computed(() => {
  const wsId = Number(route.params.id);
  return iastStore.sessions.filter((s) => s.workspace_id === wsId);
});
// F5：字段级校验——target_url 必须是 http(s) 绝对地址
const iastUrlValid = computed(() => /^https?:\/\/.+/i.test(iastForm.target_url.trim()));
const canRegisterIast = computed(
  () => iastUrlValid.value && iastForm.app_name.trim() !== "" && iastForm.agent_id.trim() !== "",
);

onMounted(async () => {
  settingsStore.loadDefaults();
  const _d = settingsStore.intensityDefaults();
  taskIntensity.preset = _d.preset;
  taskIntensity.advanced = { ..._d.advanced };
  await reloadWorkspaceData();
  syncTargetUrlDraft();
  syncLoginDraft();
  iastStore.fetchSessions().catch(() => {});
});

watch(
  () => route.params.id,
  async () => {
    await reloadWorkspaceData();
    syncTargetUrlDraft();
    syncLoginDraft();
  },
);

function syncTargetUrlDraft() {
  const url = String(store.selectedWorkspace?.settings?.target_url || "");
  targetUrlDraft.value = url;
  if (!iastForm.target_url) iastForm.target_url = url;
}

async function reloadWorkspaceData() {
  const workspaceId = Number(route.params.id);
  await Promise.all([store.fetchWorkspace(workspaceId), store.fetchTasks(workspaceId)]);
}

async function createTask() {
  taskBusy.value = true;
  try {
    const defaults = settingsStore.defaultScanOptions;
    const task = await store.createTask({
      workspace_id: Number(route.params.id),
      name: taskName.value || "全链路扫描",
      enable_a1: true,
      enable_a2: true,
      enable_verification: true,
      enable_sca: true,
      enable_ai_review: true,
      enable_entry_discovery: true,
      enable_idor: true,
      idor_app_id: defaults.idor_app_id,
      scan_mode: defaults.scan_mode,
      model_profile: defaults.model_profile,
      prompt_version: defaults.prompt_version,
      sca_severity_threshold: defaults.sca_severity_threshold,
      sca_ignore_unfixed: false,
      output_format: "both",
      // 任务级 LLM 强度覆盖：只随本任务下发，不改全局配置（平台是多任务并发的）
      llm_overrides: buildOverrides(taskIntensity),
    });
    const slug = store.selectedWorkspace?.slug;
    router.push(slug ? `/workspace/${slug}/task/${task.id}` : `/tasks/${task.id}`);
  } finally {
    taskBusy.value = false;
  }
}

async function saveTargetUrl() {
  if (!store.selectedWorkspace) return;
  const newUrl = targetUrlDraft.value.trim();
  await store.updateWorkspace(store.selectedWorkspace.id, {
    settings: { ...(store.selectedWorkspace.settings || {}), target_url: newUrl },
  });
  await store.fetchWorkspace(store.selectedWorkspace.id);
}

// 登录配置（external_target.login）。从 workspace.settings.login 加载 / 回存。
const loginForm = reactive({
  url: "",
  method: "POST",
  token_field: "token",
  token_header: "Authorization",
  cookie_name: "",
  forge_alg_none: false,
  credentials: [] as Array<{ role: string; username: string; password: string }>,
});

function syncLoginDraft() {
  const login = (store.selectedWorkspace?.settings?.login || {}) as any;
  loginForm.url = login.url || "";
  loginForm.method = login.method || "POST";
  loginForm.token_field = login.token_field || "token";
  loginForm.token_header = login.token_header || "Authorization";
  loginForm.cookie_name = login.cookie_name || "";
  loginForm.forge_alg_none = !!login.forge_alg_none;
  loginForm.credentials = Array.isArray(login.credentials)
    ? (login.credentials as any[]).map((c: any) => ({ role: c.role || "", username: c.username || "", password: c.password || "" }))
    : [];
}

async function saveLogin() {
  if (!store.selectedWorkspace) return;
  const creds = loginForm.credentials
    .filter((c) => c.username.trim() !== "")
    .map((c) => ({ role: c.role.trim(), username: c.username.trim(), password: c.password }));
  await store.updateWorkspace(store.selectedWorkspace.id, {
    settings: {
      ...(store.selectedWorkspace.settings || {}),
      login: {
        url: loginForm.url.trim(),
        method: loginForm.method.trim() || "POST",
        token_field: loginForm.token_field.trim() || "token",
        token_header: loginForm.token_header.trim() || "Authorization",
        cookie_name: loginForm.cookie_name.trim(),
        forge_alg_none: !!loginForm.forge_alg_none,
        credentials: creds,
      },
    },
  });
  await store.fetchWorkspace(store.selectedWorkspace.id);
}

function addCredential() {
  loginForm.credentials.push({ role: "", username: "", password: "" });
}

function removeCredential(i: number) {
  loginForm.credentials.splice(i, 1);
}

const pendingTaskRemove = ref<number | null>(null);
function askRemoveTask(taskId: number) {
  pendingTaskRemove.value = taskId;
}
async function confirmRemoveTask() {
  const taskId = pendingTaskRemove.value;
  pendingTaskRemove.value = null;
  if (taskId == null) return;
  await store.deleteTask(taskId);
  await reloadWorkspaceData();
}

async function registerIastTarget() {
  iastBusy.value = true;
  iastError.value = "";
  try {
    const data = await iastStore.registerSession({
      target_url: iastForm.target_url.trim(),
      code_path: iastForm.code_path.trim() || store.selectedWorkspace?.target_path || "",
      app_name: iastForm.app_name.trim(),
      agent_id: iastForm.agent_id.trim(),
      probe_mode: iastForm.probe_mode.trim() || "iast",
      probe_packages: iastForm.probe_packages.trim() || "com.example",
      server_port: Number(iastForm.server_port) || 8899,
      java_path: selectedJdkPath.value,
      workspace_id: Number(route.params.id),
    });
    registeredSession.value = data;
    await iastStore.fetchSessions();
    iastForm.target_url = "";
    iastForm.code_path = "";
    iastForm.app_name = "";
    iastForm.agent_id = "";
    iastForm.probe_mode = "iast";
    iastForm.probe_packages = "com.example";
    iastForm.server_port = 8899;
  } catch (error: any) {
    iastError.value = error?.response?.data?.detail || error?.message || "登记失败";
  } finally {
    iastBusy.value = false;
  }
}

// ---- 探针挂载指引：把会话 token + 回连端点 + 挂载命令呈现给用户（用户需在目标机执行一次） ----
// 探针（sec-probe.jar）真实配置键见 ProbeConfig.load()：sec.server.url / sec.agent.id /
// sec.app.name / sec.agent.token / sec.app.packages，支持 -D 系统属性或 SEC_* 环境变量。
const registeredSession = ref<IastSession | null>(null);
const backendBaseUrl = computed(() => `${window.location.protocol}//${window.location.hostname}:8000`);
// 2026-11-06 开源 P0：JDK 与探针 jar 路径属于部署环境，仓库不内置本机绝对路径。
// 默认给可移植的 PATH java 与相对路径，用户可在表单里直接改成实际路径。
const probeJarPath = ref<string>("probe-java/target/sec-probe.jar");
const selectedJdkPath = ref<string>("java");

function mountCommand(s: IastSession): string {
  const token = (s as any).probe_token || "<PROBE_TOKEN>";
  const packages = s.probe_packages || "com.example";
  const port = s.server_port || 8899;
  const javaExe = (s as any).java_path || selectedJdkPath.value || "java";
  return [
    `${javaExe} -Djdk.httpclient.version=HTTP_1.1 -Dsec.network.timeout.ms=5000 -javaagent:"${probeJarPath.value}" \\`,
    `  -Dsec.server.url=${backendBaseUrl.value} \\`,
    `  -Dsec.agent.id=${s.agent_id} \\`,
    `  -Dsec.app.name=${s.app_name} \\`,
    `  -Dsec.agent.token=${token} \\`,
    `  -Dsec.app.packages=${packages} \\`,
    `  -Dserver.port=${port} \\`,
    "  -jar target/java-quote-1.0.jar",
  ].join("\n");
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // 非 https 或权限受限时回退到临时 textarea + execCommand
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    } catch {
      /* 仍失败则用户可手动复制 */
    }
  }
}

function heartbeatStatus(s: IastSession): { online: boolean; text: string } {
  if (!s.last_heartbeat_at || s.last_heartbeat_at === "从未") {
    return { online: false, text: "探针尚未上报心跳（请挂载探针）" };
  }
  return { online: true, text: `最近心跳 ${s.last_heartbeat_at}` };
}
</script>
