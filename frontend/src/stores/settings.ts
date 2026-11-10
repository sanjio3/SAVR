import { defineStore } from "pinia";

import {
  clampAdvanced,
  defaultIntensity,
  type IntensityPreset,
  type LlmAdvanced,
  type LlmIntensity,
} from "./llmIntensity";

export interface DefaultScanOptions {
  scan_mode: string;
  model_profile: string;
  prompt_version: string;
  sca_severity_threshold: string;
  idor_app_id: string;
  // 2026-09-20：LLM 扫描强度默认档位（分级：普通用户看档位，开发者展开高级参数）。
  // 工作区提交任务时可以临时覆盖，覆盖只写进该任务的 options.llm_overrides。
  llm_preset: IntensityPreset;
  llm_advanced: LlmAdvanced;
}

const STORAGE_KEY = "SAVR.default-scan-options";

const FALLBACK: DefaultScanOptions = {
  scan_mode: "filter_first",
  model_profile: "default",
  prompt_version: "terminal-first-v1",
  sca_severity_threshold: "LOW",
  idor_app_id: "",
  llm_preset: "balanced",
  llm_advanced: defaultIntensity().advanced,
};

function normalizeIntensity(raw: any): { llm_preset: IntensityPreset; llm_advanced: LlmAdvanced } {
  const preset = (raw?.llm_preset || "balanced") as IntensityPreset;
  const advanced = clampAdvanced({ ...FALLBACK.llm_advanced, ...(raw?.llm_advanced || {}) });
  return { llm_preset: preset, llm_advanced: advanced };
}

export const useSettingsStore = defineStore("settings", {
  state: () => ({
    defaultScanOptions: { ...FALLBACK } as DefaultScanOptions,
  }),
  actions: {
    loadDefaults() {
      try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          const intensity = normalizeIntensity(parsed);
          this.defaultScanOptions = { ...FALLBACK, ...parsed, ...intensity };
        }
      } catch {
        this.defaultScanOptions = { ...FALLBACK };
      }
      return this.defaultScanOptions;
    },
    saveDefaults(options: Partial<DefaultScanOptions>) {
      const merged = { ...this.defaultScanOptions, ...options };
      merged.llm_advanced = clampAdvanced(merged.llm_advanced);
      this.defaultScanOptions = merged;
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.defaultScanOptions));
    },
    resetDefaults() {
      this.defaultScanOptions = { ...FALLBACK, llm_advanced: { ...FALLBACK.llm_advanced } };
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch {
        /* 隐私模式下忽略 */
      }
      return this.defaultScanOptions;
    },
    /** 全局默认档位 → 可直接用于提交任务的强度对象。 */
    intensityDefaults(): LlmIntensity {
      return {
        preset: this.defaultScanOptions.llm_preset,
        advanced: clampAdvanced(this.defaultScanOptions.llm_advanced),
      };
    },
  },
});
