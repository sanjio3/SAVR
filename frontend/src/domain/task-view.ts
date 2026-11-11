import type { PipelineStage, ScanTask, TaskEvent } from "@/types";
import { serverElapsedMs } from "@/domain/server-time";

// 用户视角的统一扫描流程（GUI 导航）：
// A0 预处理 → SCA → A1 规则扫描 → A2 语义分析 → D1 操作器 → I1 监听器 → D2 校验器 → I2 裁决器 → R 报告器
// 说明：后端真实执行里 entry_discovery / ai_review 仍作为 stage_results 存在；
// 前端把它们收敛到对应阶段详情中（entry_discovery 并入 A0，ai_review 并入 A2），不再单独占一个导航节点。
export const TASK_STAGE_ORDER = [
  "preprocess",
  "sca",
  "a1",
  "a2",
  "attack_plan",
  "d1",
  "i1",
  "d2",
  "i2",
  "reporting",
] as const;

export type TaskStageKey = (typeof TASK_STAGE_ORDER)[number];

/**
 * 严重度 → sev-* 色调类名（唯一实现）。
 *
 * 实现（只是局部变量名不同）。这类「复制粘贴的判定函数」最怕只改一处：三个页面的徽章
 * 颜色会不一致，而且不会有任何报错。收敛到这里，由 SeverityBadge.vue 独占调用。
 *
 * 同时接受中英文（"Critical"/"严重"、"High"/"高" …），因为后端不同来源
 * （SCA 公告 / A1 规则 / A2 语义）的等级文案不统一。
 */
export function severityTone(severity: unknown): string {
  const s = String(severity ?? "").toLowerCase();
  if (s.includes("crit") || s.includes("严重")) return "sev-critical";
  if (s.includes("high") || s.includes("高")) return "sev-high";
  if (s.includes("med") || s.includes("中")) return "sev-medium";
  if (s.includes("low") || s.includes("低")) return "sev-low";
  return "sev-info";
}

// 阶段导航角标
export const STAGE_CODES: Record<TaskStageKey, string> = {
  preprocess: "A0",
  sca: "SCA",
  a1: "A1",
  a2: "A2",
  attack_plan: "AP",
  d1: "D1",
  i1: "I1",
  d2: "D2",
  i2: "I2",
  reporting: "R",
};

const STAGE_LABELS: Record<TaskStageKey, string> = {
  preprocess: "预处理",
  sca: "SCA 成分分析",
  a1: "A1 规则扫描",
  a2: "A2 语义分析",
  attack_plan: "AP 攻击计划",
  d1: "D1 操作器",
  i1: "I1 监听器",
  d2: "D2 校验器",
  i2: "I2 裁决器",
  reporting: "R 报告器",
};

/**
 *
 * 起因：流程条与阶段卡都同时渲染「阶段码徽标」和「带码的标签」，于是读出来是
 * 「A1 A1 规则扫描」（10 个阶段全中，仅 preprocess 因标签里原本没写码而幸免）。
 * 规则明确为：**阶段码只由徽标承担，文字只写名称**。需要「码 + 名」连读的地方
 * （如顶栏「运行中 · …」）继续用 stageLabel()。
 */
const STAGE_NAMES: Record<TaskStageKey, string> = {
  preprocess: "预处理",
  sca: "成分分析",
  a1: "规则扫描",
  a2: "语义分析",
  attack_plan: "攻击计划",
  d1: "操作器",
  i1: "监听器",
  d2: "校验器",
  i2: "裁决器",
  reporting: "报告器",
};

// 阶段一句话释义：让使用者不用记 A0/A1/D1/I2 这些内部代号，也能知道每格在干什么
export const STAGE_HINTS: Record<TaskStageKey, string> = {
  preprocess: "索引源码，抽取函数与 HTTP 入口",
  sca: "成分分析，比对外部组件已知漏洞",
  a1: "规则扫描，模式匹配已知漏洞特征",
  a2: "语义分析，LLM 推导入口→危险函数链路",
  attack_plan: "攻击计划，把假说投影成可执行 PoC",
  d1: "操作器，自动重放 TriggerSpec 验证假说",
  i1: "监听器，采集 IAST 运行时事件",
  d2: "校验器，逐漏洞核实 sink 是否真注入",
  i2: "裁决器，SAST 假说与 IAST 观测求差集",
  reporting: "报告器，汇总证据并生成报告",
};

export function taskBadge(task: ScanTask) {
  const status = task.status.toLowerCase();
  if (status === "completed") return "已完成";
  if (status === "failed") return "失败";
  if (status === "running") return `运行中 · ${stageLabel(task.phase)}`;
  return "排队中";
}

export function stageLabel(stage: string) {
  return STAGE_LABELS[stage as TaskStageKey] || stage || "未开始";
}

/** 只取裸名称（不带阶段码）：给「旁边已经有码徽标」的位置用，避免重复显示。 */
export function stageName(stage: string) {
  return STAGE_NAMES[stage as TaskStageKey] || STAGE_LABELS[stage as TaskStageKey] || stage || "未开始";
}

export function stageStatusLabel(status: string) {
  switch ((status || "").toLowerCase()) {
    case "completed":
      return "完成";
    case "running":
      return "进行中";
    case "failed":
      return "失败";
    case "skipped":
      return "跳过";
    case "blocked":
      // 「status=running/completed 但上游未完成」的阶段置 blocked，message="等待 d1 完成"），
      // 原先与 pending 一起映射成「未开始」→ 视觉上把「已进入链路、在等上游」伪装成「还没排到」。
      // 注意 statusLabel 是 StepFlow 里唯一可见的状态文字（message 不渲染），所以这里必须说清楚。
      return "等待上游";
    case "loading":
      return "加载中…";
    default:
      return "未开始";
  }
}

// 统一耗时格式化：60s 内显示秒，60m 内显示分秒，超过显示时分
export function formatDuration(startedAt?: string, finishedAt?: string): string {
  if (!startedAt) return "";
  // finishedAt 缺省（仍在跑）时与 Date.now() 比较，必须先把 UTC-naive 的服务端时间归一，
  // 否则本地 UTC+8 会把耗时整体多算 8 小时（详见 domain/server-time.ts）。
  const ms = serverElapsedMs(startedAt, finishedAt);
  if (!ms) return "";
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m${sec % 60 ? (sec % 60) + "s" : ""}`;
  return `${Math.floor(min / 60)}h${min % 60 ? (min % 60) + "m" : ""}`;
}

export function taskStages(task: ScanTask | null) {
  const pipeline = (task?.summary?.pipeline || {}) as Record<string, PipelineStage>;
  return TASK_STAGE_ORDER.map((key) => ({
    key,
    label: STAGE_LABELS[key],
    status: pipeline[key]?.status || "pending",
    message: pipeline[key]?.message || "",
    metrics: pipeline[key]?.metrics || {},
    started_at: pipeline[key]?.started_at || "",
    finished_at: pipeline[key]?.finished_at || "",
    active: (task?.summary?.current_stage || task?.phase) === key,
  }));
}

export function activeStage(task: ScanTask | null) {
  const current = (task?.summary?.current_stage || task?.phase || "") as TaskStageKey;
  const stages = taskStages(task);
  return (
    stages.find((item) => item.key === current) ||
    stages.find((item) => item.status === "failed") ||
    stages.find((item) => item.status === "running") ||
    stages[0]
  );
}

export function eventLogs(events: TaskEvent[]) {
  const normalized = events
    .filter(
      (event) =>
        event.event_type === "task_log" ||
        event.event_type === "task_failed" ||
        event.event_type === "task_completed" ||
        // （d2_verify_progress）也放进事件流实时滚动。此前这两类心跳被过滤掉，
        // 闭环过程除了一句「第 N/M 轮」进度条外完全黑盒。
        (event.event_type === "task_progress" && hasClosedLoopHeartbeat(event.payload)),
    )
    .slice(-60)
    .map((event) => {
      if (event.event_type === "task_progress") {
        return {
          id: `${event.id || 0}-loop`,
          tone: "muted",
          text: closedLoopHeartbeatText(event.payload),
          created_at: event.created_at || "",
        };
      }
      if (event.event_type === "task_log") {
        return {
          id: `${event.id || 0}-log`,
          tone: "muted",
          text: normalizeLogText(event.payload.message),
          created_at: event.created_at || "",
        };
      }
      if (event.event_type === "task_failed") {
        return {
          id: `${event.id || 0}-failed`,
          tone: "danger",
          text: normalizeLogText(event.payload.error_message || "任务失败"),
          created_at: event.created_at || "",
        };
      }
      return {
        id: `${event.id || 0}-done`,
        tone: "success",
        text: `任务完成，发现 ${String(event.payload.finding_count || 0)} 条结果`,
        created_at: event.created_at || "",
      };
    });
  return normalized.filter((item) => item.text);
}

//   {"i2_rerun": {"iteration":1,"max_iterations":3,"status":"running","a2_feedback":4,"replay_adjustments":0}}
//   {"d2_verify_progress": {"status":"done","iteration":0,"exploitable_count":65}}
function hasClosedLoopHeartbeat(payload: Record<string, unknown> | undefined): boolean {
  const p = payload || {};
  return Boolean(p.i2_rerun || p.d2_verify_progress);
}

function closedLoopHeartbeatText(payload: Record<string, unknown> | undefined): string {
  const p = payload || {};
  const parts: string[] = [];
  const i2 = (p.i2_rerun || null) as Record<string, unknown> | null;
  if (i2) {
    const it = Number(i2.iteration || 0);
    const mx = Number(i2.max_iterations || 0);
    const st = String(i2.status || "");
    const stText = st === "running" ? "（重跑中）" : st === "done" ? "（已收敛）" : "";
    parts.push(`I2 闭环第 ${it}/${mx} 轮${stText}`);
    parts.push(`A2 重研判 ${Number(i2.a2_feedback || 0)} 条、重放调整 ${Number(i2.replay_adjustments || 0)} 条`);
  }
  const d2 = (p.d2_verify_progress || null) as Record<string, unknown> | null;
  if (d2) {
    const it = Number(d2.iteration || 0);
    const st = String(d2.status || "");
    const ex = Number(d2.exploitable_count || 0);
    parts.push(
      `D2 验证第 ${it} 轮${st === "running" ? "（进行中）" : st === "done" ? "（完成）" : ""}${ex ? `，可利用 ${ex} 条` : ""}`,
    );
  }
  return parts.length ? `闭环 ${parts.join(" · ")}` : "";
}

function normalizeLogText(value: unknown) {
  const text = String(value || "")
    .replace(/\r/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && !/^[=\-_*#]{6,}$/.test(line))
    .join(" | ");
  return text.replace(/\s{2,}/g, " ").trim();
}
