<template>
  <section ref="root" class="page stack">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>SCA 资产中心</h1>
        <p class="page-subtitle">
          组件资产、SBOM、漏洞清单与 CVE/GHSA 影响面查询。这里的数据来自扫描时持久化的成分分析结果，
          不再只是任务里的一个工具输出。
        </p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="reload">刷新</button>
        <button class="button" :disabled="scanning" @click="runScan">{{ scanning ? "扫描中…" : "运行 SCA 扫描" }}</button>
      </div>
    </div>

    <SkeletonBlock v-if="loading" variant="stat" :rows="4" label="正在读取 SCA 资产…" />

    <template v-else>
      <div class="stats-grid compact">
        <StatCard label="可用扫描器">{{ availableToolCount }} / {{ tools.length }}</StatCard>
        <StatCard label="组件资产">{{ components.length }}</StatCard>
        <StatCard label="漏洞公告">{{ vulnerabilities.length }}</StatCard>
        <StatCard label="影响组件">{{ impactResult?.affected_component_count ?? 0 }}</StatCard>
      </div>

      <section class="card stack glow-card">
        <div>
          <h3>扫描配置</h3>
          <p class="muted">这里的参数只对本次手动扫描生效，不写入全局默认值。</p>
        </div>
        <div class="grid two">
          <div class="stack compact">
            <label class="stack compact">
              <span class="muted">项目路径</span>
              <input v-model="scanForm.project_path" placeholder="例如 /path/to/target-project" />
            </label>
            <label class="stack compact">
              <span class="muted">关联工作区 id（可选）</span>
              <input v-model.number="scanForm.workspace_id" type="number" placeholder="留空则不关联" />
            </label>
            <label class="stack compact">
              <span class="muted">扫描器</span>
              <select v-model="scanForm.tool">
                <option value="osv-scanner">osv-scanner（OSV 数据库）</option>
                <option value="trivy">trivy（Aqua 漏洞库）</option>
                <option value="grype">grype（Anchore 漏洞库）</option>
              </select>
            </label>
          </div>
          <div class="stack compact">
            <label class="stack compact">
              <span class="muted">严重度阈值（低于该级别不记录）</span>
              <select v-model="scanForm.severity_threshold">
                <option value="LOW">低危及以上</option>
                <option value="MEDIUM">中危及以上</option>
                <option value="HIGH">高危及以上</option>
                <option value="CRITICAL">仅严重</option>
              </select>
            </label>
            <label class="row gap-sm"><input v-model="scanForm.run_tool" type="checkbox" style="width: auto" /> 调用外部 SCA 工具（关闭则只读本地已有数据）</label>
            <label class="row gap-sm"><input v-model="scanForm.persist" type="checkbox" style="width: auto" /> 持久化组件 / SBOM / 漏洞资产</label>
            <label class="row gap-sm"><input v-model="scanForm.ignore_unfixed" type="checkbox" style="width: auto" /> 忽略「无修复版本」的漏洞</label>
          </div>
        </div>
        <div v-if="scanResult" class="callout success">
          扫描完成：组件 {{ scanResult.component_count || 0 }} 个，漏洞 {{ scanResult.vulnerability_count || scanResult.finding_count || 0 }} 条，SBOM {{ scanResult.sbom_path || "-" }}
        </div>
        <div v-if="error" class="callout danger">{{ error }}</div>
      </section>

      <section class="grid two">
        <div class="card stack glow-card">
          <div>
            <h3>扫描器状态</h3>
            <p class="muted">只有本机真实可用的扫描器才会被任务调用。</p>
          </div>
          <div v-if="tools.length" class="table-wrap cols-3">
            <table>
              <thead><tr><th>扫描器</th><th>可用</th><th>版本 / 安装提示</th></tr></thead>
              <tbody>
                <tr v-for="tool in tools" :key="String(tool.tool)">
                  <td>{{ tool.tool }}</td>
                  <td>
                    <span class="badge" :class="tool.available ? 'badge-success' : 'badge-warning'">
                      {{ tool.available ? "可用" : "缺失" }}
                    </span>
                  </td>
                  <td class="muted">{{ tool.version || tool.install_hint || "-" }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="empty-state">
            <strong>还没有扫描器状态</strong>
            <span>点击上方「刷新」重新探测本机 osv-scanner / trivy / grype 的可用性。</span>
          </div>
        </div>

        <div class="card stack glow-card">
          <div>
            <h3>影响面查询</h3>
            <p class="muted">按漏洞编号或组件名反查：公司哪些项目用到了它、是不是命中漏洞版本。</p>
          </div>
          <input v-model="impactForm.advisory_id" placeholder="漏洞编号，例如 CVE-2024-21538 或 GHSA-xxxx" />
          <input v-model="impactForm.component_name" placeholder="组件名，例如 flask" />
          <input v-model="impactForm.ecosystem" placeholder="生态，例如 PyPI / npm / Maven" />
          <button class="ghost-button" @click="queryImpact">查询影响面</button>
          <div v-if="impactResult" class="stack">
            <div class="callout">影响组件 {{ impactResult.affected_component_count }} 个，关联漏洞 {{ impactResult.vulnerability_count }} 条</div>
            <div v-if="impactComponents.length" class="table-wrap cols-4">
              <table>
                <thead><tr><th>生态</th><th>组件</th><th>版本</th><th>来源</th></tr></thead>
                <tbody>
                  <tr v-for="(item, index) in impactComponents" :key="index">
                    <td>{{ item.ecosystem }}</td>
                    <td>{{ item.name }}</td>
                    <td>{{ item.version }}</td>
                    <td class="muted">{{ item.source || item.source_file }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-else class="empty-state"><span>该条件没有命中任何组件。</span></div>
          </div>
        </div>
      </section>

      <section class="card stack glow-card">
        <div>
          <h3>漏洞清单</h3>
          <p class="muted">已持久化的组件漏洞公告。点开任务详情页的 SCA 阶段可以看到逐条修复建议。</p>
        </div>
        <div v-if="vulnerabilities.length" class="table-wrap cols-4">
          <table>
            <thead><tr><th>漏洞公告</th><th>组件</th><th>严重度</th><th>修复版本</th></tr></thead>
            <tbody>
              <tr v-for="item in vulnerabilities" :key="String(item.id)">
                <td><code>{{ item.advisory_id }}</code></td>
                <td>{{ item.component_name }}@{{ item.component_version }}</td>
                <td><SeverityBadge :level="item.severity" /></td>
                <td>{{ arrayLabel(item.fixed_versions) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无持久化的 SCA 漏洞</strong>
          <span>先在上面运行一次扫描，或在任务的 SCA 阶段开启「持久化组件 / SBOM / 漏洞资产」。</span>
        </div>
      </section>

      <section class="card stack glow-card">
        <div>
          <h3>组件资产</h3>
          <p class="muted">扫描识别到的第三方组件与它们的包坐标（PURL）。</p>
        </div>
        <div v-if="components.length" class="table-wrap cols-5">
          <table>
            <thead><tr><th>生态</th><th>组件</th><th>版本</th><th>来源文件</th><th>PURL</th></tr></thead>
            <tbody>
              <tr v-for="item in components" :key="`${item.id}-${item.name}`">
                <td>{{ item.ecosystem }}</td>
                <td>{{ item.name }}</td>
                <td>{{ item.version || "-" }}</td>
                <td class="muted wrap-break">{{ item.source_file }}</td>
                <td><code class="wrap-break">{{ item.purl }}</code></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="empty-state">
          <strong>暂无组件资产</strong>
          <span>运行一次 SCA 扫描并开启持久化后，这里会列出识别到的全部第三方组件。</span>
        </div>
      </section>
    </template>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { gsap } from "gsap";

import StatCard from "@/components/StatCard.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import { useTableScroll } from "@/domain/table-scroll";
import { http } from "@/services/http";

type Row = Record<string, any>;

const root = ref<HTMLElement | null>(null);
const tools = ref<Row[]>([]);
const components = ref<Row[]>([]);
const vulnerabilities = ref<Row[]>([]);
const impactResult = ref<Row | null>(null);
const scanResult = ref<Row | null>(null);
const error = ref("");
const loading = ref(true);
const scanning = ref(false);
const scanForm = ref({ project_path: "", workspace_id: undefined as number | undefined, tool: "osv-scanner", severity_threshold: "LOW", ignore_unfixed: false, run_tool: true, persist: true });
const impactForm = ref({ advisory_id: "", component_name: "", ecosystem: "" });

const impactComponents = computed<Row[]>(() => Array.isArray(impactResult.value?.affected_components) ? impactResult.value!.affected_components : []);
const availableToolCount = computed(() => tools.value.filter((tool) => tool.available).length);

useTableScroll(root);

onMounted(async () => {
  await reload();
  animate();
});

async function reload() {
  error.value = "";
  try {
    const [toolResp, componentResp, vulnResp] = await Promise.all([
      http.get<Row[]>("/api/sca/tools"),
      http.get<Row[]>("/api/sca/components"),
      http.get<Row[]>("/api/sca/vulnerabilities"),
    ]);
    tools.value = toolResp.data;
    components.value = componentResp.data;
    vulnerabilities.value = vulnResp.data;
    animate();
  } catch (caught) {
    error.value = errText(caught);
  } finally {
    loading.value = false;
  }
}

async function runScan() {
  error.value = "";
  scanning.value = true;
  try {
    const payload: Row = { ...scanForm.value };
    if (!payload.workspace_id) delete payload.workspace_id;
    const { data } = await http.post<Row>("/api/sca/scan", payload);
    scanResult.value = data;
    await reload();
  } catch (caught) {
    error.value = errText(caught);
  } finally {
    scanning.value = false;
  }
}

async function queryImpact() {
  error.value = "";
  if (!impactForm.value.advisory_id.trim() && !impactForm.value.component_name.trim()) {
    error.value = "请至少填写漏洞编号或组件名之一。";
    return;
  }
  try {
    const { data } = await http.post<Row>("/api/sca/impact-query", impactForm.value);
    impactResult.value = data;
    animate();
  } catch (caught) {
    error.value = errText(caught);
  }
}

function arrayLabel(value: unknown) {
  return Array.isArray(value) && value.length ? value.join(", ") : String(value || "-");
}

// severityTone 已收敛到 @/domain/task-view（批次 4，2026-09-22）

function errText(caught: unknown) {
  return String((caught as any)?.response?.data?.detail || (caught as Error)?.message || caught);
}

function animate() {
  if (!root.value) return;
  gsap.fromTo(root.value.querySelectorAll(".stat-card, .glow-card"), { y: 8, opacity: 0.82 }, { y: 0, opacity: 1, duration: 0.35, stagger: 0.025, ease: "power2.out" });
}
</script>
