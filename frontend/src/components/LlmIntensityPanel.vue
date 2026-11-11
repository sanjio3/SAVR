<template>
  <div class="stack compact">
    <label class="stack compact">
      <span class="muted">扫描强度档位</span>
      <select :value="model.preset" @change="onPresetChange">
        <option v-for="p in presetList" :key="p" :value="p">
          {{ PRESET_META[p].label }} —— {{ PRESET_META[p].hint }}
        </option>
      </select>
      <span class="small muted">作用于本次提交的这个任务，不影响全局设置，也不影响同时在跑的其它任务。</span>
    </label>

    <details class="advanced" :open="model.preset === 'custom'">
      <summary>高级 LLM 参数（按模型能力调整，开发者）</summary>
      <div class="stack compact">
        <label class="stack compact">
          <span class="muted">上下文窗口 context_window（{{ model.advanced.context_window }} tokens）</span>
          <input
            type="range"
            :min="CTX_HARD_MIN"
            :max="CTX_HARD_MAX"
            step="1024"
            :value="model.advanced.context_window"
            @input="onNumber('context_window', $event)"
          />
          <span class="small muted">
            本机 8GB 卡实测：8192 → 24.3 tok/s、12288 → 15.5、16384 → 10.0、20480 → 7.3；
            <strong>24576 及以上会直接请求失败并卸载模型</strong>，故上限锁在 {{ CTX_HARD_MAX }}。
            注意：当前 A2 调用的实际输入中位数约 1100 tokens，调大上下文不会提升召回，只会变慢。
          </span>
        </label>

        <label class="stack compact">
          <span class="muted">输出预算 max_output_tokens</span>
          <input
            type="number"
            min="64"
            step="128"
            :value="model.advanced.max_output_tokens"
            @input="onNumber('max_output_tokens', $event)"
          />
          <span class="small muted">单轮最大生成长度。开启思考模式时必须给到 3000+，否则思维链会吃光预算、正文被截断。</span>
        </label>

        <label class="stack compact">
          <span class="muted">并发数 concurrency（{{ model.advanced.concurrency }}）</span>
          <input
            type="range"
            min="1"
            :max="CONCURRENCY_MAX"
            step="1"
            :value="model.advanced.concurrency"
            @input="onNumber('concurrency', $event)"
          />
          <span class="small muted">
            全局 LLM 准入闸门宽度。本地模型物理吞吐有限，并发超过一定值只是排队、不会更快，
            调高主要影响内存与稳定性。
          </span>
        </label>

        <label class="row gap-sm wrap">
          <input type="checkbox" :checked="model.advanced.think" @change="onBool('think', $event)" />
          <span>启用思考模式（think）</span>
        </label>
        <span class="small muted">
          思考型模型（Qwen3 等）会先产出思维链再给结论，推理更稳但明显更慢，且会占用输出预算。
          仅本地原生端点支持，OpenAI 兼容层会忽略该参数。
        </span>

        <label class="row gap-sm wrap">
          <input type="checkbox" :checked="model.advanced.stream" @change="onBool('stream', $event)" />
          <span>启用流式输出（stream）</span>
        </label>
        <span class="small muted">
          流式把「读超时」拆成首字节 + 空闲超时，长响应更不容易整体超时。本地 Ollama 原生端点的
          流式是 NDJSON，会由客户端自动降级为非流式。
        </span>

        <label class="row gap-sm wrap">
          <input
            type="checkbox"
            :checked="model.advanced.proof_second_pass"
            @change="onBool('proof_second_pass', $event)"
          />
          <span>启用二次证明（路径 C）</span>
        </label>
        <span class="small muted">
          对规则层未证成的条目，用聚焦提示词补一轮证明，补上才升级为 chain_proven。
          实测挽回率约 5%，耗时约 90 秒；关闭可省下这一步。
        </span>

        <div class="muted small">
          并发 / asyncio：「并发数」滑块即实际杠杆——它驱动全局 LLM 准入闸门
          （SAST_AI_LLM_GATE_CONCURRENCY），等价于 asyncio 调度里的并发宽度。
          评估结论：本地 8B 模型物理吞吐约 15~26 tok/s，并发超过 2 只是排队、不增吞吐，
          因此没做「真正的 asyncio 重写」，而是用准入闸门 + 文件级缓存（llm_cache，命中即跳过重算）
          来控制负载与成本。要调并发就拉上面的滑块。
        </div>
      </div>
    </details>

    <div class="kv-grid">
      <div class="kv-row"><span class="muted">上下文</span><strong>{{ model.advanced.context_window }}</strong></div>
      <div class="kv-row"><span class="muted">输出预算</span><strong>{{ model.advanced.max_output_tokens }}</strong></div>
      <div class="kv-row"><span class="muted">并发</span><strong>{{ model.advanced.concurrency }}</strong></div>
      <div class="kv-row"><span class="muted">思考模式</span><strong>{{ model.advanced.think ? "开" : "关" }}</strong></div>
      <div class="kv-row"><span class="muted">流式</span><strong>{{ model.advanced.stream ? "开" : "关" }}</strong></div>
      <div class="kv-row"><span class="muted">二次证明</span><strong>{{ model.advanced.proof_second_pass ? "开" : "关" }}</strong></div>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  CONCURRENCY_MAX,
  CTX_HARD_MAX,
  CTX_HARD_MIN,
  PRESET_META,
  advancedForPreset,
  clampAdvanced,
  type IntensityPreset,
  type LlmIntensity,
} from "@/stores/llmIntensity";

const props = defineProps<{ model: LlmIntensity }>();
const emit = defineEmits<{ (e: "change", value: LlmIntensity): void }>();

const presetList: IntensityPreset[] = ["fast", "balanced", "deep", "custom"];

function onPresetChange(event: Event) {
  const preset = (event.target as HTMLSelectElement).value as IntensityPreset;
  const advanced = advancedForPreset(preset);
  emit("change", clampAdvancedInto({ preset, advanced }));
}

function onNumber(key: "context_window" | "max_output_tokens" | "concurrency", event: Event) {
  const raw = Number((event.target as HTMLInputElement).value);
  const advanced = { ...props.model.advanced, [key]: raw };
  emit("change", clampAdvancedInto({ preset: "custom", advanced }));
}

function onBool(key: "think" | "stream" | "proof_second_pass", event: Event) {
  const checked = (event.target as HTMLInputElement).checked;
  const advanced = { ...props.model.advanced, [key]: checked };
  emit("change", clampAdvancedInto({ preset: "custom", advanced }));
}

function clampAdvancedInto(next: LlmIntensity): LlmIntensity {
  return { preset: next.preset, advanced: clampAdvanced(next.advanced) };
}
</script>
