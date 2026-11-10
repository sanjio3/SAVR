"""生成 java-sec-code 的「路由语义盲化」变体，用于量化 URL 布局先验依赖。

与 tools/_wb_make_blind_variant.py 的区别：
  - 那个是 OWASP Benchmark 的 @WebServlet + 文件名带 case 号；
  - jsc 是 Spring，注解形态杂：类级 @RequestMapping、@RestController(value="/x")、
    以及「类级无路径、方法级写全路径」三种并存。只认第一种会漏掉约 40% 的路由，
    残留的族语义会让结论偏乐观。
  - java-sec-code 的 application.properties 里有两份**按路径前缀**的安全配置
    （no.need.login.url / csrf.exclude.url）。只改注解不改这两份配置，盲化后原本免登录
    的端点会突然变成登录墙，302 会被误读成召回下降 —— 这是本脚本存在的首要理由。
  - 认证链路的 /login 与 /logout **不参与盲化**。workspace 4 的 login.url、
    csrf.fetch_url 与 D1 的 _login_wall_paths() / _logout_paths() 都硬依赖这两个路径；
    一起 hash 会让 L1 掉点全部落在「登录墙 302」上，无法与路由先验依赖区分。
    2026-11-07 实测：首版把二者改成 /bc42c80、/bc94d04，L1 尚未开跑即判无效。

设计：
  - 统一按「注解路径的首段」做确定性盲化（/sqli → /b19f01f），同一段全局一致。
    --scope class（默认，L1 本轮用的就是这个）对**每个**带路径注解的首段都改写，
    包括「类级无路径、方法级写全路径」的写法：/sqli/jdbc/vuln 会变成
    /bd31933/b7400f8/vuln。所以 L1 量到的 -12.5pp 是「语义先验 + 路径层结构变化」
    的合计上界，不能纯归因到语义记忆。
    --scope class-only 只改类型声明之前的类级注解首段，方法级全路径原样保留，
    用于严格只隔离类级路由语义；该 scope **尚未用于实测**，别与 632 的数字混用。
    --scope all 把后续段也 hash（更狠，需自行确认无 forward 依赖）。
  - 源码文件名不变 ⇒ data/java_sec_code_truth_v2.csv 按「文件 + 族」记账，
    **完全无需改动**。
  - 只复制构建必需项（src/pom/README），排除 .codeql-db*：本机实测整树 891M /
    3.8 万文件，且 CodeQL 库里存着旧路由，留在变体里等于把族语义又泄漏回 A1。
  - 不改原靶场、不构建、不启动任何服务。

用法：
    python tools/jsc_make_blind_variant.py
    python tools/jsc_make_blind_variant.py --scope class-only --out data/blind_variants/jsc-blind-semantic
    python tools/jsc_make_blind_variant.py --scope all --clean
    python tools/jsc_make_blind_variant.py --src /path/to/java-sec-code --out data/blind_variants/jsc-blind

产出：
    <out>/<构建必需项>         改写后的源码树
    <out>/blind_map.json       段映射、覆盖率与改写统计
    <out>/README.md            部署与验收步骤（不自动执行）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.environ.get(
    "SAST_AI_JSC_SRC",
    os.path.normpath(os.path.join(ROOT, "..", "java-sec-code")),
)
DEFAULT_OUT = os.path.join(ROOT, "data", "blind_variants", "jsc-blind")

# 带路径的注解：@RequestMapping("/x") / @GetMapping(value = "/y") /
# @RestController(value = "/qlexpress") / @Controller("/z")
_ANN_RE = re.compile(
    r'(@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping'
    r'|RestController|Controller)\s*\(\s*(?:value\s*=\s*)?)(["\'])(/[^"\']*)\2'
)
_PATH_KEYS = ("joychou.no.need.login.url", "joychou.security.csrf.exclude.url")
_TEXT_EXT = (".java", ".properties", ".html", ".htm", ".jsp", ".xml",
             ".yaml", ".yml", ".js", ".json", ".md")
_SKIP_DIRS = {".git", "target", ".idea", ".settings", "build", "out", "__pycache__"}
_COPY_ITEMS = ("src", "pom.xml", "docker-compose.yml", "README.md", "README_zh.md")

# 认证链路路径：workspace 4 的 login.url / csrf.fetch_url 与 D1 的登录墙、
# 注销端点豁免都以这些字面量为锚点。盲化它们不会增加「去先验」的说服力
# （Login.java / Index.java 本来就不在真值表里），只会把配置失配混进掉点归因。
PROTECTED_SEGMENTS = frozenset({"/login", "/logout"})

_TYPE_DECL_RE = re.compile(r'\b(?:class|interface|enum|record)\s+[A-Za-z_$][\w$]*')


def _mask_noncode(code: str) -> str:
    """把注释与字符串字面量替换成等长空格，保持字符偏移不变。

    class-only 要判断注解在类型声明之前还是之后。直接在原文上搜 ``class``
    会被字符串或注释里的假声明带偏，导致类级注解被当成方法级。掩码后偏移
    不变，可以直接拿原文本的 ``match.start()`` 与声明位置比较。
    """
    out = list(code)
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        if c == "/" and i + 1 < n and code[i + 1] == "/":
            j = code.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and code[i + 1] == "*":
            j = code.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in ('"', "'"):
            j = i + 1
            while j < n:
                if code[j] == "\\":
                    j += 2
                    continue
                if code[j] == c:
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _class_decl_pos(code: str) -> int:
    """返回第一个类型声明的字符偏移；找不到时返回文本长度（全部当方法级）。"""
    m = _TYPE_DECL_RE.search(_mask_noncode(code))
    return m.start() if m else len(code)


def build_segment_map(counts: dict) -> dict:
    """由注解路径首段构造盲化映射，认证段原样保留。"""
    return {seg: _blind_prefix(seg) for seg in sorted(counts)
            if seg not in PROTECTED_SEGMENTS}


def _blind_prefix(seg: str) -> str:
    """由旧路径段确定性派生、不含族语义的新段。同一段跨文件保持一致。"""
    return "/b" + hashlib.sha1(seg.encode("utf-8")).hexdigest()[:6]


def _is_rewritable(path: str) -> bool:
    """跳过空路径、通配符与含 Spring 路径变量的注解（改了会破坏 MVC 映射）。"""
    if not path or path in ("/", "*", "/*", "**"):
        return False
    if "{" in path or "}" in path or "*" in path:
        return False
    return path.startswith("/")


def _first_seg(path: str) -> str:
    return "/" + path.lstrip("/").split("/", 1)[0]


def _collect_segments(src_root: str, scope: str = "class"):
    """收集注解路径首段。返回 (段->出现次数, 段->文件列表, 可改写注解总数)。

    class-only 只统计类型声明之前的类级注解，让覆盖率分母与改写范围一致。
    """
    counts, by_seg, total = {}, {}, 0
    java_root = os.path.join(src_root, "src", "main", "java")
    if not os.path.isdir(java_root):
        return counts, by_seg, total
    for root, dirs, files in os.walk(java_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(".java"):
                continue
            p = os.path.join(root, fn)
            try:
                code = open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            rel = os.path.relpath(p, src_root).replace("\\", "/")
            cls_pos = _class_decl_pos(code) if scope == "class-only" else len(code)
            for m in _ANN_RE.finditer(code):
                path = m.group(3)
                if not _is_rewritable(path) or m.start() >= cls_pos:
                    continue
                total += 1
                seg = _first_seg(path)
                counts[seg] = counts.get(seg, 0) + 1
                by_seg.setdefault(seg, set()).add(rel)
    return counts, by_seg, total


def _rewrite_java(code: str, scope: str, seg_map: dict) -> tuple:
    """改写单个 java 文件的注解路径首段。返回 (新代码, 命中数)。

    class-only 只改写类型声明之前的注解（类级），方法级全路径注解原样保留，
    用于严格隔离「类级路由语义」这一种先验。
    """
    n = 0
    cls_pos = _class_decl_pos(code) if scope == "class-only" else len(code)

    def _sub(m):
        nonlocal n
        path = m.group(3)
        if not _is_rewritable(path) or m.start() >= cls_pos:
            return m.group(0)
        parts = path.lstrip("/").split("/")
        first = "/" + parts[0]
        if first not in seg_map:
            return m.group(0)
        new_parts = [seg_map[first].lstrip("/")]
        if scope == "all":
            new_parts += [_blind_prefix(first + "/" + x).lstrip("/") for x in parts[1:] if x]
        else:
            new_parts += parts[1:]
        n += 1
        return "%s%s/%s%s" % (m.group(1), m.group(2), "/".join(new_parts), m.group(2))

    return _ANN_RE.sub(_sub, code), n


def _rewrite_properties(text: str, seg_map: dict) -> tuple:
    """同步改写按路径前缀的安全白名单，否则盲化后免登录端点变登录墙。"""
    n = 0
    out_lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("#") or "=" not in line:
            out_lines.append(line)
            continue
        key, _, rest = line.partition("=")
        if key.strip() not in _PATH_KEYS:
            out_lines.append(line)
            continue
        newline = "\n" if line.endswith("\n") else ""
        new_items = []
        for item in (x.strip() for x in rest.strip().split(",") if x.strip()):
            hit = None
            for old, new in seg_map.items():
                if item == old or item == old + "/**":
                    hit = new + ("/**" if item.endswith("/**") else "")
                    break
            if hit:
                n += 1
                new_items.append(hit)
            else:
                new_items.append(item)
        out_lines.append("%s= %s%s" % (key, ", ".join(new_items), newline))
    return "".join(out_lines), n


def _rewrite_literals(text: str, seg_map: dict, protect_annotations: bool) -> tuple:
    """改写 redirect / forward / href / form action 里的旧路径字面量。

    .java 文件先把注解整段换成占位符再替换：否则注解路径会被改写两次，
    第二次拿不到 seg_map 的 key，可能把结构改坏。
    """
    holder = []

    def _hold(m):
        holder.append(m.group(0))
        return "\x00ANN%d\x00" % (len(holder) - 1)

    work = _ANN_RE.sub(_hold, text) if protect_annotations else text
    n = 0
    for old, new in sorted(seg_map.items(), key=lambda kv: -len(kv[0])):
        # 后接 / 或引号或空白，保证 /ssrf 不会误伤 /ssrf2
        rx = re.compile(r'(["\'])' + re.escape(old) + r'(?=[/"\'\s])')
        work, cnt = rx.subn(lambda m: m.group(1) + new, work)
        n += cnt
    for i, original in enumerate(holder):
        work = work.replace("\x00ANN%d\x00" % i, original)
    return work, n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEFAULT_SRC, help="java-sec-code 仓库根")
    ap.add_argument("--out", default=DEFAULT_OUT, help="变体输出目录")
    ap.add_argument("--scope", choices=("class", "class-only", "all"), default="class",
                    help="class=所有带路径注解的首段都改写（默认，L1 盲化布局轮次）；"
                         "class-only=只改类级注解首段、方法级全路径原样（未实测）；"
                         "all=后续段也 hash")
    ap.add_argument("--clean", action="store_true", help="先清空输出目录")
    args = ap.parse_args()

    src, out = os.path.abspath(args.src), os.path.abspath(args.out)
    if not os.path.isdir(src):
        print("[FATAL] 源码目录不存在：%s（可用 --src 或 SAST_AI_JSC_SRC 指定）" % src)
        return 1
    if os.path.normcase(src) == os.path.normcase(out) or out.startswith(src + os.sep):
        print("[FATAL] 输出目录不能等于或位于原源码树内，拒绝原地改写")
        return 1
    if args.clean and os.path.isdir(out):
        shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)

    def _ignore(_dir, names):
        return [n for n in names
                if n in _SKIP_DIRS or n.startswith(".codeql-db") or n.endswith(".log")]

    print("[i] 复制构建必需项：%s → %s" % (src, out))
    for item in _COPY_ITEMS:
        s, d = os.path.join(src, item), os.path.join(out, item)
        if not os.path.exists(s):
            continue
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True, ignore=_ignore)
        else:
            shutil.copy2(s, d)

    counts, by_seg, total = _collect_segments(out, args.scope)
    if not counts:
        print("[FATAL] 未找到任何可改写的注解路径，拒绝生成半盲化变体")
        return 1
    protected = {seg: counts[seg] for seg in sorted(counts)
                 if seg in PROTECTED_SEGMENTS}
    counts = {k: v for k, v in counts.items() if k not in PROTECTED_SEGMENTS}
    by_seg = {k: v for k, v in by_seg.items() if k not in PROTECTED_SEGMENTS}
    total = sum(counts.values())
    if not total:
        print("[FATAL] 过滤认证段后无可改写注解，拒绝生成半盲化变体")
        return 1
    seg_map = build_segment_map(counts)
    assert not (set(seg_map) & PROTECTED_SEGMENTS)

    n_ann = n_prop = n_lit = n_files = 0
    for root, dirs, files in os.walk(out):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if not fn.endswith(_TEXT_EXT):
                continue
            p = os.path.join(root, fn)
            try:
                text = open(p, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            original = text
            is_java = fn.endswith(".java")
            if is_java:
                text, c1 = _rewrite_java(text, args.scope, seg_map)
                n_ann += c1
            if fn.endswith("application.properties"):
                text, c2 = _rewrite_properties(text, seg_map)
                n_prop += c2
            text, c3 = _rewrite_literals(text, seg_map, protect_annotations=is_java)
            n_lit += c3
            if text != original:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(text)
                n_files += 1

    coverage = round(100.0 * n_ann / total, 1) if total else 0.0
    if n_prop == 0:
        print("[warn] 未在 application.properties 里改写任何白名单项，请人工确认配置路径")
    if coverage < 95.0:
        print("[warn] 注解覆盖率仅 %.1f%%，残留语义路径会让结论偏乐观" % coverage)

    # 认证链路一致性自检：这两处字面量一旦被改写，L1 的掉点就无法与登录墙失配区分。
    wsc = os.path.join(out, "src", "main", "java", "org", "joychou",
                       "security", "WebSecurityConfig.java")
    if os.path.isfile(wsc):
        wsc_text = open(wsc, encoding="utf-8", errors="ignore").read()
        for literal in ('loginPage("/login")', 'logoutUrl("/logout")'):
            if literal not in wsc_text:
                raise SystemExit("[FATAL] 认证字面量被改写：%s（检查 PROTECTED_SEGMENTS）" % literal)

    payload = {
        "scope": args.scope,
        "scope_note": {
            "class": "所有带路径注解的首段都改写（含方法级全路径注解），L1 盲化布局轮次 使用",
            "class-only": "只改写类型声明之前的类级注解首段，方法级路径原样保留；尚未用于实测",
            "all": "首段与后续段全部 hash",
        }[args.scope],
        "source": src,
        "segments": seg_map,
        "segment_usage": counts,
        "segment_files": {k: sorted(v) for k, v in by_seg.items()},
        "protected_segments": protected,
        "protected_reason": "workspace 4 login.url / csrf.fetch_url 与 D1 登录墙、注销豁免依赖这些路径",
        "coverage": {"rewritten_annotations": n_ann, "total_annotations": total,
                     "percent": coverage},
        "counts": {"java_annotations": n_ann, "property_items": n_prop,
                   "path_literals": n_lit, "changed_files": n_files},
        "truth": "data/java_sec_code_truth_v2.csv（源码文件名未变，按文件+族记账，无需修改）",
    }
    with open(os.path.join(out, "blind_map.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

    with open(os.path.join(out, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(
            "# jsc 路由语义盲化变体\n\n"
            "- scope: `%s`\n- 路径首段映射: %d 条（详见 blind_map.json）\n"
            "- 注解覆盖率: %.1f%%（%d/%d）\n"
            "- 改写统计: 注解 %d / 白名单项 %d / 路径字面量 %d / 文件 %d\n\n"
            "## 用途\n\n"
            "量化扫描器对 URL 布局先验的依赖：真值表按「文件 + 族」记账，源码文件名未变，\n"
            "因此 data/java_sec_code_truth_v2.csv 可原样复用。\n\n"
            "## 部署（需人工执行，本脚本不构建、不启动服务）\n\n"
            "1. 用本目录作为源码根重新构建 java-sec-code（保持 h2 profile）。\n"
            "2. 停掉 8080 上原靶场，用盲化构建产物启动到同一端口。\n"
            "3. workspace 4 的 target_path 必须同步切到本目录：A1/A2 若仍读原仓库源码，\n"
            "   路由先验并未去掉，且 D1 会按旧路由发包导致全 404，L1 结论无效。\n"
            "   target_url 与 login 配置保持不变（/login、/logout 未参与盲化）。\n"
            "   用 tools/jsc_blind_switch.py 做可逆切换，跑完务必 restore。\n"
            "4. 提交扫描任务，记录 task_id，再跑 generalization_compare.py 对照。\n\n"
            "## 验收\n\n"
            "见 docs/generalization_validation_design.md 第一层。\n"
            % (args.scope, len(seg_map), coverage, n_ann, total,
               n_ann, n_prop, n_lit, n_files)
        )

    print("[ok] 变体已生成：%s" % out)
    print("     首段 %d 条（保护认证段 %s），注解 %d/%d（%.1f%%），白名单 %d 项，字面量 %d 处，改动文件 %d 个"
          % (len(seg_map), ",".join(sorted(protected)) or "无",
             n_ann, total, coverage, n_prop, n_lit, n_files))
    print("     映射示例：", list(seg_map.items())[:5])
    return 0


if __name__ == "__main__":
    sys.exit(main())
