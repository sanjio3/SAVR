import { STAGE_CODES, stageName, taskStages, type TaskStageKey } from "@/domain/task-view";
import { parseServerTime, serverElapsedMs } from "@/domain/server-time";
import type { ScanTask } from "@/types";

/**
 * 「当前阶段内部进度」。
 *
 * 后端各阶段暴露的指标粒度并不一致，这里只对**真有分母**的指标画进度条，
 * 没有分母的（例如 A1 的 finding_count）只报计数，不编造百分比。
 *
 * 实测各阶段可得指标（来源 summary.pipeline[key].metrics）：
 *   preprocess   file_count / endpoint_count / indexed_functions / http_entries
 *   sca          component_count / vulnerability_count / finding_count
 *   a1           finding_count
 *   a2           finding_count（闭环重跑时另有 closed_loop_iteration / closed_loop_max_iterations）
 *   a2_poc       total / done / selected_count / registered_trigger_specs   ← 唯一自带的完成度分母
 *   attack_plan  plan_count / by_family
 *   d1           candidate_count / finding_count / iast_arrivals
 *   i1 / i2      metrics 为空（数据在 summary.results 里，运行中不可得）
 *   d2           verified_count / exploitable_count / sink_reached_count / impact_count
 *                （多轮验证时另有 d2_verify_iteration / d2_verify_exploitable_count）
 *   reporting    report_count
 */
export function stageInternalProgress(
  stageKey: string,
  metrics: Record<string, unknown> | undefined,
): { pct: number | null; text: string } {
  const m = (metrics || {}) as Record<string, unknown>;
  const num = (key: string) => {
    const value = Number(m[key]);
    return Number.isFinite(value) ? value : 0;
  };

  const ratio = (done: number, total: number) => (total > 0 ? Math.min(100, Math.round((done / total) * 100)) : null);

  switch (stageKey) {
    case "a2_poc": {
      const total = num("total");
      const done = num("done");
      if (total > 0) {
        return { pct: ratio(done, total), text: `PoC 规划 ${done}/${total}` };
      }
      break;
    }
    case "a2": {
      const max = num("closed_loop_max_iterations");
      const it = num("closed_loop_iteration");
      if (max > 0) {
        return { pct: ratio(it, max), text: `闭环修复第 ${it}/${max} 轮` };
      }
      return { pct: null, text: `已产出假说 ${num("finding_count")} 条` };
    }
    case "preprocess": {
      return {
        pct: null,
        text: `已索引 ${num("indexed_functions")} 个函数 / ${num("http_entries")} 个入口 / ${num("file_count")} 个文件`,
      };
    }
    case "sca": {
      return {
        pct: null,
        text: `组件 ${num("component_count")} 个，命中漏洞 ${num("vulnerability_count") || num("finding_count")} 条`,
      };
    }
    case "a1":
      return { pct: null, text: `已命中 ${num("finding_count")} 条` };
    case "attack_plan":
      return { pct: null, text: `已生成 ${num("plan_count")} 条攻击计划` };
    case "d1":
      return {
        pct: null,
        text: `重放 ${num("candidate_count")} 条 TriggerSpec，IAST 到达 ${num("iast_arrivals")} 次，产出 ${num("finding_count")} 条`,
      };
    case "d2": {
      const iteration = num("d2_verify_iteration");
      const exploitable = num("d2_verify_exploitable_count") || num("exploitable_count");
      const prefix = iteration > 0 ? `第 ${iteration} 轮验证，` : "";
      return {
        pct: null,
        text: `${prefix}已验证 ${num("verified_count")} 条，其中可利用 ${exploitable} 条`,
      };
    }
    case "reporting":
      return { pct: null, text: `已生成 ${num("report_count")} 份报告` };
    default:
      break;
  }

  // i1 / i2 在运行期没有 metrics，退回到阶段 message，避免编数字
  return { pct: null, text: String(m.message || "") };
}

/** 单个任务在监控页需要展示的全部派生量 */
export interface TaskProgressSnapshot {
  done: number;
  total: number;
  pct: number;
  /** 正在跑（或最近跑过）的阶段 */
  stageKey: string;
  stageCode: string;
  /**
   * 阶段**裸名**（不含阶段码）。
   *
   * 2026-09-22 真实浏览器走查修正：原字段名 stageLabel、值取 stageLabel()，而 STAGE_LABELS
   * 本身已含阶段码（"R 报告器" / "A1 规则扫描" / "SCA 成分分析"）。监控页模板又写了
   * `{{ stageCode }} {{ stageLabel }}` → 渲染成「R R 报告器」「A1 A1 规则扫描」。
   * 规则与 StepFlow 一致：**阶段码只由徽标承担，文字只写名称**。故此处置为裸名。
   */
  stageName: string;
  /** 当前阶段已耗时（毫秒），未知为 0 */
  stageElapsedMs: number;
  /** 全任务已耗时（毫秒） */
  taskElapsedMs: number;
  /** 最近一次阶段时间戳，用于「多久没动静」 */
  lastActivityAt: string;
  /** 当前阶段已跑多久（分钟，四舍五入） */
  stageMinutes: number;
  /** 只有「有唯一运行阶段 + 该阶段超过卡死阈值」才判为疑似卡死 */
  stuck: boolean;
  internal: { pct: number | null; text: string };
}

/** 与 TaskPanel、项目既有判据保持一致：running 阶段超过 45 分钟无终态即提示 */
export const STUCK_THRESHOLD_MINUTES = 45;

export function taskProgressSnapshot(task: ScanTask): TaskProgressSnapshot {
  const stages = taskStages(task);
  const total = stages.length || 1;
  const done = stages.filter((stage) => stage.status === "completed").length;

  const current =
    stages.find((stage) => stage.status === "running") ||
    stages.find((stage) => stage.active) ||
    stages.find((stage) => stage.key === String(task.summary?.current_stage || task.phase || "")) ||
    stages[stages.length - 1];

  const stageElapsedMs = elapsed(current?.started_at, current?.finished_at);
  const taskElapsedMs = elapsed(task.started_at, task.finished_at);

  const stamps = stages
    .flatMap((stage) => [stage.finished_at, stage.started_at])
    .filter(Boolean)
    .sort();
  const lastActivityAt = stamps.length ? stamps[stamps.length - 1] : "";

  const stageMinutes = Math.round(stageElapsedMs / 60000);
  const running = current?.status === "running" && !task.finished_at;

  return {
    done,
    total,
    pct: Math.round((done / total) * 100),
    stageKey: current?.key || "",
    stageCode: STAGE_CODES[current?.key as TaskStageKey] || "",
    stageName: current ? stageName(current.key) : "未开始",
    stageElapsedMs,
    taskElapsedMs,
    lastActivityAt,
    stageMinutes,
    stuck: Boolean(running) && stageMinutes > STUCK_THRESHOLD_MINUTES,
    internal: stageInternalProgress(current?.key || "", current?.metrics),
  };
}

function elapsed(startedAt?: string, finishedAt?: string): number {
  // 服务端时间戳必须经 parseServerTime 归一（UTC-naive → UTC），
  // 否则 finishedAt 缺省时拿 naive UTC 跟 Date.now() 相减会平白多出一个时区偏移：
  // 实测把 20 分钟的任务显示成 8h17m，并击穿「45 分钟疑似卡住」阈值。
  return serverElapsedMs(startedAt, finishedAt);
}

/** 「3 分钟前」这类相对时间，用于心跳显示 */
export function relativeMinutes(iso: string, now = Date.now()): string {
  const at = parseServerTime(iso);
  if (Number.isNaN(at)) return "—";
  const minutes = Math.floor((now - at) / 60000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  return `${Math.floor(hours / 24)} 天前`;
}

/** 毫秒 → 1h23m / 12m30s / 45s */
export function humanMs(ms: number): string {
  if (!ms || ms < 0) return "—";
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m${sec % 60 ? `${sec % 60}s` : ""}`;
  return `${Math.floor(min / 60)}h${min % 60 ? `${min % 60}m` : ""}`;
}
