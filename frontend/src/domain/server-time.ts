/**
 *
 * 现象（走查运行监控页时发现）：
 *   - 「最近阶段更新」显示 8 小时前，而该阶段几分钟前刚更新；
 *   - 「45 分钟无动静即疑似卡住」的阈值被瞬间击穿 —— 任何 running 阶段都会误报卡死。
 *
 * 根因：后端用 ``datetime.utcnow().isoformat()`` 落库/进 summary，得到的是
 * 而 ECMA-262 规定：不带偏移量的 date-time 字符串按**本地时间**解释。
 * 于是 UTC+8 环境下所有服务端时间都被读早了 8 小时，凡是拿它跟 ``Date.now()`` 相减的地方全错。
 *
 * 为什么在前端归一而不改后端：
 *   库里现存数据（含 summaries 里嵌套的阶段时间戳）已是 UTC-naive，前端补 "Z"
 *   能一次性修正全部历史数据与存量报告，不必迁移 DB、不必改写入侧的多处调用点。
 *   （后端写入侧仍应收敛到 timezone-aware UTC，那是另一件事，见改进清单。）
 *
 * 重要边界：**两个服务端时间戳相减不受影响**（同一个 8 小时偏移会抵消），
 * 例如阶段耗时、ETA 估算。真正需要本函数的是「服务端时间 vs 客户端现在」的比较与展示。
 */

const NAIVE_DATETIME = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?$/;
/** 已带时区：``...Z`` / ``...+08:00`` / ``...-0530`` */
const HAS_OFFSET = /(?:[Zz]|[+-]\d{2}:?\d{2})$/;
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * 把后端时间戳解析为毫秒时间戳。
 *
 * - 不带时区标识的日期时间 → 视为 UTC（这是本函数存在的全部理由）；
 * - 已带 ``Z`` / ``+08:00`` → 原样交给 ``Date.parse``；
 * - 纯日期 → 按本地零点（日期字段表达的是「哪一天」，不该被时区挪走一天）；
 * - 解析失败 / 空值 → ``NaN``。
 *
 * 用 ``Date.UTC`` 逐段构造而不拼字符串后 ``Date.parse``：ISO 规范要求「有小数秒就必须有秒」，
 * 拼 ``"T07:30.000Z"`` 这类形态在部分实现里会解析失败，逐段构造没有这个坑，
 * 也顺手把 6 位微秒截断到毫秒（后端 ``isoformat()`` 会给 6 位）。
 */
export function parseServerTime(value: string | number | null | undefined): number {
  if (value === null || value === undefined) return NaN;
  if (typeof value === "number") return Number.isFinite(value) ? value : NaN;
  const s = String(value).trim();
  if (!s) return NaN;
  if (HAS_OFFSET.test(s) || DATE_ONLY.test(s)) return Date.parse(s);
  const m = NAIVE_DATETIME.exec(s);
  if (!m) return Date.parse(s);
  const micros = (m[7] || "").slice(0, 3).padEnd(3, "0");
  return Date.UTC(
    Number(m[1]), Number(m[2]) - 1, Number(m[3]),
    Number(m[4]), Number(m[5]), Number(m[6] || "0"), Number(micros),
  );
}

/** 两个时间点之差（毫秒）。``end`` 缺省表示「到现在」。不可解析或倒挂返回 0。 */
export function serverElapsedMs(
  startedAt: string | null | undefined,
  finishedAt?: string | null,
  now = Date.now(),
): number {
  const start = parseServerTime(startedAt);
  if (Number.isNaN(start)) return 0;
  const end = finishedAt ? parseServerTime(finishedAt) : now;
  if (Number.isNaN(end) || end < start) return 0;
  return end - start;
}

/** 把后端时间戳格式化为本地时间字符串（zh-CN、24 小时制）。无法解析时返回 ``fallback``。 */
export function formatServerTime(
  value: string | number | null | undefined,
  fallback = "-",
): string {
  const at = parseServerTime(value);
  if (Number.isNaN(at)) return fallback;
  return new Date(at).toLocaleString("zh-CN", { hour12: false });
}

/** 月/日 时:分（本地时区），用于表格紧凑展示。无法解析时返回 ``fallback``。 */
export function formatServerShort(
  value: string | number | null | undefined,
  fallback = "-",
): string {
  const at = parseServerTime(value);
  if (Number.isNaN(at)) return fallback;
  const d = new Date(at);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
