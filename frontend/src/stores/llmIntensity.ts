/**
 * LLM 扫描强度：档位定义与任务级覆盖的构造。
 *
 * 设计要点（2026-09-20）：
 * 1. 分级 —— 普通用户只看到三个档位（快速 / 均衡 / 深度），开发者展开高级参数；
 * 2. 作用域 —— 全局设置页存的是「默认档位」，提交单个任务时可以临时覆盖，
 *    覆盖只写进该任务的 options.llm_overrides，不碰全局配置（平台是多任务并发的）；
 * 3. 上限硬约束 —— ctx 上限 20480 是本机 8GB 卡实测出来的硬边界
 *    （24576 / 32768 会直接 HTTP 500 并把模型卸载），不是拍脑袋写的数字。
 */

export type IntensityPreset = "fast" | "balanced" | "deep" | "custom";

export interface LlmAdvanced {
  context_window: number;
  max_output_tokens: number;
  think: boolean;
  concurrency: number;
  stream: boolean;
  proof_second_pass: boolean;
}

export interface LlmIntensity {
  preset: IntensityPreset;
  advanced: LlmAdvanced;
}

export const CTX_HARD_MAX = 20480;
export const CTX_HARD_MIN = 2048;
export const CONCURRENCY_MAX = 16;

/** 三档预设。数值来自本机 qwen3:8b / RTX 4060 8GB 的实测：
 *  ctx 8192 → 24.3 tok/s、12288 → 15.5、16384 → 10.0、20480 → 7.3。 */
export const PRESETS: Record<Exclude<IntensityPreset, "custom">, LlmAdvanced> = {
  fast: {
    context_window: 4096,
    max_output_tokens: 768,
    think: false,
    concurrency: 2,
    stream: false,
    proof_second_pass: false,
  },
  balanced: {
    context_window: 8192,
    max_output_tokens: 2048,
    think: false,
    concurrency: 2,
    stream: false,
    proof_second_pass: true,
  },
  deep: {
    context_window: 12288,
    max_output_tokens: 2048,
    think: true,
    concurrency: 3,
    stream: true,
    proof_second_pass: true,
  },
};

export const PRESET_META: Record<IntensityPreset, { label: string; hint: string }> = {
  fast: { label: "快速", hint: "最短耗时。上下文小、不做二次证明，适合改动后的回归验证。" },
  balanced: { label: "均衡", hint: "默认档。上下文 8192，开启二次证明，速度与召回的平衡点。" },
  deep: { label: "深度", hint: "开启思考模式与更大上下文，召回最好但明显更慢（tok/s 约降到一半）。" },
  custom: { label: "自定义", hint: "完全按下方高级参数下发，适合针对具体模型调参。" },
};

export function defaultIntensity(): LlmIntensity {
  return { preset: "balanced", advanced: { ...PRESETS.balanced } };
}

/** 档位切换时把高级参数同步为档位值（用户随后还能再改，改完自动变 custom）。 */
export function advancedForPreset(preset: IntensityPreset): LlmAdvanced {
  if (preset === "custom") return { ...PRESETS.balanced };
  return { ...PRESETS[preset] };
}

/** 前端钳制：与后端 _apply_llm_overrides 的安全边界保持一致，避免提交越界值。 */
export function clampAdvanced(input: Partial<LlmAdvanced>): LlmAdvanced {
  const base = { ...PRESETS.balanced, ...(input || {}) };
  return {
    context_window: Math.min(CTX_HARD_MAX, Math.max(CTX_HARD_MIN, Math.round(Number(base.context_window) || CTX_HARD_MIN))),
    max_output_tokens: Math.max(64, Math.round(Number(base.max_output_tokens) || 1024)),
    think: Boolean(base.think),
    concurrency: Math.min(CONCURRENCY_MAX, Math.max(1, Math.round(Number(base.concurrency) || 2))),
    stream: Boolean(base.stream),
    proof_second_pass: Boolean(base.proof_second_pass),
  };
}

/**
 * 构造提交给后端的 llm_overrides。
 * 返回空对象表示「不覆盖，用服务端 config.yaml 的默认值」——这是历史任务的兼容行为。
 */
export function buildOverrides(intensity: LlmIntensity | null | undefined): Record<string, unknown> {
  if (!intensity) return {};
  const adv = clampAdvanced(intensity.advanced);
  return {
    context_window: adv.context_window,
    max_output_tokens: adv.max_output_tokens,
    think: adv.think,
    concurrency: adv.concurrency,
    stream: adv.stream,
    proof_second_pass: adv.proof_second_pass,
  };
}
