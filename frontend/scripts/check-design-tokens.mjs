#!/usr/bin/env node
/**
 * 设计令牌门禁（批次 4，2026-09-22）。
 *
 * 存在原因（真实事故，不是假想）：批次 1 做「色板收敛」时用脚本批量把字面色值替换成
 * var(--token)，但脚本没有把 `:root` 的**定义行**排除在外，于是：
 *   ① 产生自引用 —— `--sev-critical: var(--sev-critical);`
 *      按 CSS 规范，自定义属性自引用属循环引用，计算值退化为 guaranteed-invalid，
 *      `.sev-critical` / `.badge-danger` / `.step-blocked` 等全站失去语义色（静默失效，
 *      构建不报错、vue-tsc 也查不出来）。
 *   ② 定义行整条丢失 —— `--color-on-strong` / `--surface-tint-*` / `--color-invert-*`
 *      共 8 个 token 被 10+ 处 var() 引用，却从未定义 → 全部悬空。
 * 两类问题都只在浏览器里以「颜色不对/变默认色」的方式显现，人工很难稳定发现。
 * 本脚本把这三类检查做成可执行门禁，接入 `npm run check:tokens` 与 `npm run build`。
 *
 * 退出码：0 = 通过；1 = 存在违规（输出逐条定位，便于直接修）。
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath, URL } from "node:url";

const SRC = fileURLToPath(new URL("../src", import.meta.url));
const ROOT_CSS = join(SRC, "styles.css");

/** 颜色字面值：hex / rgb() / rgba() / hsl() / hsla()。 */
const COLOR_LITERAL = /(#[0-9a-fA-F]{3,8}\b|\brgba?\([^)]*\)|\bhsla?\([^)]*\))/;

/**
 * 裸颜色关键字 white / black。
 * 它们同样是硬编码：`background: white` 在暗色底或换肤后必然穿帮。
 * 负向断言是必须的 —— 否则 `white-space: nowrap` 里的 `white` 会被误报。
 */
const BARE_COLOR = /\b(white|black)(?![-\w])/i;

/** 允许的例外：这些关键字不是「硬编码色值」。 */
const ALLOWED_KEYWORDS = /\b(transparent|currentColor|inherit|initial|unset|none|auto)\b/;

/** 单行豁免标记：`token-gate-ignore` 出现即跳过该行（用于确有必要的透传，需写明理由）。 */
const IGNORE_MARK = "token-gate-ignore";

const violations = [];

function record(kind, file, line, detail) {
  violations.push({ kind, file, line, detail });
}

/** 取出 `:root { ... }` 的范围（按花括号配平，不假设单层）。 */
function findRootBlock(css) {
  const m = /:root\s*\{/.exec(css);
  if (!m) return null;
  let depth = 0;
  for (let i = m.index + m[0].length - 1; i < css.length; i += 1) {
    if (css[i] === "{") depth += 1;
    else if (css[i] === "}") {
      depth -= 1;
      if (depth === 0) return { start: m.index + m[0].length, end: i };
    }
  }
  return null;
}

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

// ── 检查 1~3：styles.css ────────────────────────────────────────────────
const css = readFileSync(ROOT_CSS, "utf8");
const root = findRootBlock(css);
if (!root) {
  record("no-root-block", "styles.css", 1, "找不到 :root 令牌块，无法校验");
} else {
  const tokenBlock = css.slice(root.start, root.end);

  // 1) token 区外不得出现颜色字面值
  const scanArea = css.slice(0, root.start) + css.slice(root.end);
  for (const raw of scanArea.split("\n")) {
    if (raw.includes(IGNORE_MARK)) continue;
    const m = COLOR_LITERAL.exec(raw) || BARE_COLOR.exec(raw);
    if (m && !ALLOWED_KEYWORDS.test(m[0])) {
      record(
        "literal-outside-tokens",
        "styles.css",
        lineOf(css, css.indexOf(raw)),
        `token 区外出现颜色字面值 ${m[0]}，应改用 var(--token) 或 color-mix(...)`,
      );
    }
  }

  // 收集 token 定义
  const defined = new Set();
  for (const m of tokenBlock.matchAll(/(--[A-Za-z0-9-]+)\s*:/g)) defined.add(m[1]);

  // 2) 自引用 / 悬空引用
  for (const m of tokenBlock.matchAll(/(--[A-Za-z0-9-]+)\s*:\s*([^;]+);/g)) {
    const name = m[1];
    const value = m[2];
    for (const ref of value.matchAll(/var\(\s*(--[A-Za-z0-9-]+)/g)) {
      if (ref[1] === name) {
        record(
          "self-reference",
          "styles.css",
          lineOf(css, root.start + m.index),
          `${name}: ${value.trim()} —— 自引用会退化为 guaranteed-invalid，整条失效`,
        );
      } else if (!defined.has(ref[1])) {
        record(
          "dangling-in-token",
          "styles.css",
          lineOf(css, root.start + m.index),
          `${name} 引用了未定义的 ${ref[1]}`,
        );
      }
    }
  }

  // 3) 全文引用的 token 必须已定义
  const seen = new Set();
  for (const m of css.matchAll(/var\(\s*(--[A-Za-z0-9-]+)/g)) {
    if (!defined.has(m[1]) && !seen.has(m[1])) {
      seen.add(m[1]);
      record(
        "undefined-token",
        "styles.css",
        lineOf(css, m.index),
        `var(${m[1]}) 被引用但 :root 未定义`,
      );
    }
  }
}

// ── 检查 4：.vue / .ts 的「样式落点」不得硬编码颜色 ─────────────────────
// 范围刻意收窄到 <style> 块与内联 style 落点，而不是整文件扫描：
// 早一版整文件扫，把 <script> 注释里的 issue 编号（`// #394 流量类型切换`）当成 3 位 hex
// 报了 5 处误报。门禁一旦有误报就会被“习惯性忽略”，比没有门禁更糟，所以这里按落点判定。
function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(vue|ts)$/.test(name)) out.push(full);
  }
  return out;
}

/** 一行是否属于「样式落点」：<style> 块内，或含内联 style 属性/对象。 */
const INLINE_STYLE = /(style\s*=\s*["'`]|["'`]?\s*style\s*:\s*\{|:style\s*=|\[style\])/;

for (const file of walk(SRC)) {
  const text = readFileSync(file, "utf8");
  const lines = text.split("\n");
  const styleRanges = [];
  for (const m of text.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)) {
    styleRanges.push([m.index, m.index + m[0].length]);
  }
  lines.forEach((raw, i) => {
    if (raw.includes(IGNORE_MARK)) return;
    const offset = lines.slice(0, i).join("\n").length;
    const inStyleBlock = styleRanges.some(([a, b]) => offset >= a && offset < b);
    if (!inStyleBlock && !INLINE_STYLE.test(raw)) return;
    const m = COLOR_LITERAL.exec(raw) || BARE_COLOR.exec(raw);
    if (m && !ALLOWED_KEYWORDS.test(m[0])) {
      record(
        "literal-in-component",
        relative(SRC, file),
        i + 1,
        `样式落点出现颜色字面值 ${m[0]}，应改用 var(--token)`,
      );
    }
  });
}

// ── 汇总 ───────────────────────────────────────────────────────────────
if (!violations.length) {
  console.log("[check-design-tokens] 通过：无自引用 / 无悬空 token / 无硬编码颜色。");
  process.exit(0);
}

const byKind = violations.reduce((acc, v) => {
  (acc[v.kind] ||= []).push(v);
  return acc;
}, {});
console.error(`[check-design-tokens] 发现 ${violations.length} 处违规：\n`);
for (const [kind, items] of Object.entries(byKind)) {
  console.error(`── ${kind}（${items.length}）`);
  for (const v of items.slice(0, 60)) console.error(`   ${v.file}:${v.line}  ${v.detail}`);
  if (items.length > 60) console.error(`   … 另 ${items.length - 60} 处`);
  console.error("");
}
process.exit(1);
