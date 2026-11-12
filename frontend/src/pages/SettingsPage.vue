<template>
  <section class="page stack">
    <div class="hero">
      <div class="stack">
        <h1>全局设置</h1>
        <p class="page-subtitle">
          这里配置的是默认扫描参数。在工作区点「开始扫描」时会自动带上这些值，不必每次重复填写。
          修改只影响之后新建的任务，不会改变历史任务。
        </p>
      </div>
    </div>

    <section class="grid two">
      <div class="card stack glow-card">
        <div>
          <h3>默认扫描配置</h3>
          <p class="muted">以下为新建扫描任务时的默认值，可在发起任务时单独覆盖。</p>
        </div>

        <div class="stack compact">
          <h4>LLM 扫描强度（分级）</h4>
          <p class="small muted">
            普通用法只需选档位；需要针对具体模型调参时展开下方的高级参数。
            这里配的是<strong>默认值</strong>——在工作区点「开始扫描」时可以临时改，只影响那一个任务。
          </p>
          <LlmIntensityPanel :model="intensity" @change="onIntensityChange" />
        </div>

        <label class="stack compact">
          <span class="muted">扫描模式（scan_mode）</span>
          <select v-model="form.scan_mode">
            <option value="filter_first">filter_first —— 先按规则过滤，再对候选做语义分析</option>
            <option value="terminal_first">terminal_first —— 先从危险函数反向回溯入口</option>
            <option value="deep_agentic">deep_agentic —— 由智能体自主编排分析顺序</option>
          </select>
          <span class="small muted">取值原样传给后端 scan_mode 字段。</span>
        </label>

        <label class="stack compact">
          <span class="muted">模型档位标签（model_profile）</span>
          <input v-model="form.model_profile" placeholder="default" />
          <span class="small muted">
            仅作为任务标签写入并记录到 LLM 调用日志。实际请求使用的模型由后端 config.yaml 的
            llm.provider / llm.model 决定，改这里不会切换模型。
          </span>
        </label>

        <label class="stack compact">
          <span class="muted">Prompt 版本（prompt_version）</span>
          <input v-model="form.prompt_version" placeholder="terminal-first-v1" />
          <span class="small muted">传给后端用于挑选提示词模板，要与后端已存在的版本号一致，写错会退回默认模板。</span>
        </label>

        <label class="stack compact">
          <span class="muted">SCA 严重度阈值（sca_severity_threshold）</span>
          <select v-model="form.sca_severity_threshold">
            <option value="LOW">低危及以上都记录</option>
            <option value="MEDIUM">中危及以上</option>
            <option value="HIGH">高危及以上</option>
            <option value="CRITICAL">仅严重</option>
          </select>
          <span class="small muted">低于阈值的组件漏洞不会进入任务结果。</span>
        </label>

        <label class="stack compact">
          <span class="muted">越权扫描应用标识（idor_app_id）</span>
          <input v-model="form.idor_app_id" placeholder="例如 shop" />
          <span class="small muted">要填「越权扫描」页面里已登记过的应用标识，否则该阶段会取不到资产。</span>
        </label>

        <div class="row between wrap gap-sm">
          <span v-if="saved" class="badge badge-success" role="status" aria-live="polite">已保存并生效</span>
          <span v-else class="muted small" role="status" aria-live="polite">修改后点右侧按钮保存</span>
          <div class="row gap-sm">
            <button class="ghost-button" @click="askReset">恢复默认</button>
            <button @click="save">保存默认配置</button>
          </div>
        </div>
      </div>

      <div class="card stack glow-card">
        <div>
          <h3>当前生效值</h3>
          <p class="muted">新建任务时实际会发出的参数。保存后这里立即刷新。</p>
        </div>
        <div class="kv-grid">
          <div class="kv-row"><span class="muted">扫描模式</span><strong>{{ form.scan_mode }}</strong></div>
          <div class="kv-row"><span class="muted">模型档位标签</span><strong>{{ form.model_profile || "-" }}</strong></div>
          <div class="kv-row"><span class="muted">Prompt 版本</span><strong>{{ form.prompt_version || "-" }}</strong></div>
          <div class="kv-row"><span class="muted">SCA 严重度阈值</span><strong>{{ form.sca_severity_threshold }}</strong></div>
          <div class="kv-row"><span class="muted">越权应用标识</span><strong>{{ form.idor_app_id || "（未设置）" }}</strong></div>
          <div class="kv-row"><span class="muted">扫描强度</span><strong>{{ PRESET_META[intensity.preset].label }}</strong></div>
          <div class="kv-row"><span class="muted">上下文 / 输出</span><strong>{{ intensity.advanced.context_window }} / {{ intensity.advanced.max_output_tokens }}</strong></div>
          <div class="kv-row"><span class="muted">并发 / 思考 / 流式</span><strong>{{ intensity.advanced.concurrency }} / {{ intensity.advanced.think ? "开" : "关" }} / {{ intensity.advanced.stream ? "开" : "关" }}</strong></div>
          <div class="kv-row"><span class="muted">二次证明</span><strong>{{ intensity.advanced.proof_second_pass ? "开" : "关" }}</strong></div>
        </div>

        <h3>平台固定行为</h3>
        <p class="muted">
          以下开关不在这里配置，因为它们是平台的既定行为：所有分析模块默认全部开启
          （A1 规则扫描、A2 语义分析、SCA 成分分析、D1 触发重放、IAST 运行时验证、AI 入口识别、越权扫描），
          任务一旦提交即按全链路执行，不需要逐项勾选。
        </p>
        <p class="muted">
          如果只想针对某个项目临时改参数，目前的做法是进入对应工作区，在「扫描与运行」里新建任务；
          高级参数会优先读取本页的默认值。
        </p>

        <h3>存储位置</h3>
        <p class="muted">本页设置保存在浏览器的 localStorage（键 SAVR.default-scan-options），不写入后端数据库。</p>
      </div>
    </section>

    <ConfirmDialog
      :open="resetOpen"
      title="恢复默认扫描配置？"
      message="会把上面五项恢复为平台内置默认值，并清除浏览器里保存的配置。已创建的历史任务不受影响。"
      confirm-text="恢复默认"
      @confirm="doReset"
      @cancel="resetOpen = false"
    />
  </section>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";

import ConfirmDialog from "@/components/ConfirmDialog.vue";
import LlmIntensityPanel from "@/components/LlmIntensityPanel.vue";
import { PRESET_META, type LlmIntensity } from "@/stores/llmIntensity";
import { useSettingsStore } from "@/stores/settings";

const store = useSettingsStore();
const saved = ref(false);
const resetOpen = ref(false);
let savedTimer: number | null = null;

const form = reactive({
  scan_mode: "filter_first",
  model_profile: "default",
  prompt_version: "terminal-first-v1",
  sca_severity_threshold: "LOW",
  idor_app_id: "",
});

const intensity = reactive<LlmIntensity>({ preset: "balanced", advanced: { ...store.intensityDefaults().advanced } });

onMounted(() => {
  Object.assign(form, store.loadDefaults());
  const defaults = store.intensityDefaults();
  intensity.preset = defaults.preset;
  intensity.advanced = { ...defaults.advanced };
});

function onIntensityChange(next: LlmIntensity) {
  intensity.preset = next.preset;
  intensity.advanced = { ...next.advanced };
}

function save() {
  store.saveDefaults({ ...form, llm_preset: intensity.preset, llm_advanced: { ...intensity.advanced } });
  flashSaved();
}

function askReset() {
  resetOpen.value = true;
}

function doReset() {
  resetOpen.value = false;
  Object.assign(form, store.resetDefaults());
  const defaults = store.intensityDefaults();
  intensity.preset = defaults.preset;
  intensity.advanced = { ...defaults.advanced };
  flashSaved();
}

function flashSaved() {
  saved.value = true;
  if (savedTimer) window.clearTimeout(savedTimer);
  savedTimer = window.setTimeout(() => (saved.value = false), 2500);
}
</script>
