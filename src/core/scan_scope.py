"""扫描分片作用域：把「全集靶场」切成可逐片扫描的作用域。

扫描会让 CodeQL、本地 LLM（qwen3:8b）、D1 重放与探针三者同时爆掉，还会撞本机 Windows
缺的只是「按族分片、一片一跑、最后汇总」这一层。

设计要点：
- 分片单位**按族**（OWASP 自带 category 就是天然切片单位），族过大再按编号二次切。
- 作用域同时约束两件事：①A1 静态扫描的文件列表；②入口/路由。
  只约束路由不约束文件的话，静态阶段仍会全量扫，成本没降下来。
  OWASP 的 servlet 路径形态（/benchmark/<category>-<NN>/BenchmarkTestNNNNN）不同版本有别，
  匹配 token 恒稳，不随路由模板漂移。
"""
from __future__ import annotations

import csv
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

# expectedresults-1.2.csv 表头带前导空格（'# test name' / ' category' / ' real vulnerability'），
# 必须用带空格的键取值，这是解析该文件的既定坑。
_CSV_TEST_KEY = "# test name"
_CSV_CAT_KEY = " category"
_CSV_VULN_KEY = " real vulnerability"

# entry_type/file/line/signature/confidence/entry_hash/request_params/... 这一套，**没有 route**。# 只按 route 取 → _entry_route 恒空 → 分片收窄把入口全丢光，
# 后续任何依赖入口的链路都会空转。file 兜底后，OWASP 用例文件名全局唯一，命中语义依旧精确。
_ENTRY_ROUTE_KEYS = ("route", "path", "endpoint", "url", "servlet_path", "servlet",
                     "file", "file_path", "signature", "name")


def _norm_key(row: Dict[str, Any], want: str) -> Any:
    """按「去掉空格后与目标一致」取值，兼容表头有无前导空格两种写法。"""
    for k, v in row.items():
        if k and k.strip().lstrip("# ").lower() == want.strip().lstrip("# ").lower():
            return v
    return row.get(want)


def parse_expected_results(csv_path: str) -> List[Dict[str, Any]]:
    """解析 expectedresults CSV，返回 [{test_name, category, is_tp}]。"""
    out: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as fh:
        for row in csv.DictReader(fh):
            test = str(_norm_key(row, "test name") or "").strip()
            if not test:
                continue
            cat = str(_norm_key(row, "category") or "").strip()
            vuln = str(_norm_key(row, "real vulnerability") or "").strip().lower()
            out.append({"test_name": test, "category": cat, "is_tp": vuln in ("true", "1", "yes")})
    return out


def build_shards(cases: List[Dict[str, Any]], max_per_shard: int = 250) -> List[Dict[str, Any]]:
    """按族分片；族内超过 max_per_shard 再按编号顺序二次切分。"""
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for c in cases:
        by_cat.setdefault(c.get("category") or "unknown", []).append(c)

    shards: List[Dict[str, Any]] = []
    for cat in sorted(by_cat):
        items = sorted(by_cat[cat], key=lambda x: x.get("test_name") or "")
        if not items:
            continue
        if len(items) <= max_per_shard:
            chunks = [items]
        else:
            n = (len(items) + max_per_shard - 1) // max_per_shard
            size = (len(items) + n - 1) // n
            chunks = [items[i:i + size] for i in range(0, len(items), size)]
        for idx, chunk in enumerate(chunks, start=1):
            name = cat if len(chunks) == 1 else f"{cat}-{idx}"
            shards.append({
                "name": name,
                "category": cat,
                "cases": [c["test_name"] for c in chunk],
                "tp": sum(1 for c in chunk if c.get("is_tp")),
                "fp": sum(1 for c in chunk if not c.get("is_tp")),
                "count": len(chunk),
            })
    return shards


def map_cases_to_files(cases: Iterable[str], source_root: str) -> Dict[str, str]:
    """把用例名映射到它的 .java 源文件路径（用于约束 A1 静态扫描的文件列表）。找不到就返回空。"""
    out: Dict[str, str] = {}
    if not source_root or not os.path.isdir(source_root):
        return out
    want = {str(c).strip(): True for c in cases if c}
    for root, _dirs, files in os.walk(source_root):
        for fn in files:
            if not fn.endswith(".java"):
                continue
            stem = fn[:-5]
            if stem in want and stem not in out:
                out[stem] = os.path.join(root, fn)
                if len(out) == len(want):
                    return out
    return out


def load_shard(path: str) -> Optional[Dict[str, Any]]:
    """加载部署方提供的分片清单 JSON。"""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("cases"):
            return data
    except Exception:
        return None
    return None


def route_in_shard(route: str, shard: Optional[Dict[str, Any]]) -> bool:
    """路由是否属于该分片：用例名 token 出现在路由里即命中（不依赖路由模板形态）。"""
    if not shard or not route:
        return False
    r = str(route)
    for case in shard.get("cases") or []:
        if str(case) and str(case) in r:
            return True
    return False


def _entry_route(entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for k in _ENTRY_ROUTE_KEYS:
            v = entry.get(k)
            if v:
                return str(v)
    return ""


def filter_entries(entries: Iterable[Any], shard: Optional[Dict[str, Any]]) -> Tuple[List[Any], Dict[str, int]]:
    """按分片过滤入口发现结果。返回 (保留的入口, 统计)。shard 为空则原样返回。"""
    items = list(entries or [])
    if not shard:
        return items, {"total": len(items), "kept": len(items), "dropped": 0}
    kept = [e for e in items if route_in_shard(_entry_route(e), shard)]
    return kept, {"total": len(items), "kept": len(kept), "dropped": len(items) - len(kept)}


# 待扫文件项的「路径键」候选：FileScanner.scan 返回的是 **dict**（path/rel_path/name），
_FILE_PATH_KEYS = ("path", "file_path", "filepath", "rel_path", "name")


def _path_of_file(item: Any) -> str:
    if isinstance(item, dict):
        for k in _FILE_PATH_KEYS:
            v = item.get(k)
            if v:
                return str(v)
        return ""
    return str(item or "")


# fileinput 等打包库），另有若干 command_execution 来自压缩库里的 `eval(`/`new Function(`。
# 602 把过滤只加在 A1 启发式后，仍剩 5 条漏在别的通道（`jquery-ui-1.10.4.min.js` 的 bola
# 来自 A1 业务逻辑分析器、`jquery.tmpl.js` 的 xss 来自 A2）—— 说明**必须在文件收集阶段
# 统一过滤**，逐个通道打补丁必然漏。
#
# 判据只针对「别人写好的库 / 构建产物」，不是「前端代码」：
#   - 目录 token：libs / vendor / third-party / plugins / node_modules / bower_components /
#     dist / build / webjars / assets/vendor
#   - 压缩产物：*.min.js / *.min.css（行号无意义，无法定位）
# 只是它拿不到 route，由下游按「无路由」正常归类，不在这里一刀切掉。
# 需要恢复全量扫描时设 SAST_AI_SCAN_VENDOR=1。
VENDOR_DIR_TOKENS = (
    "/libs/", "/vendor/", "/vendors/", "/third-party/", "/thirdparty/",
    "/plugins/", "/node_modules/", "/bower_components/",
    "/dist/", "/build/", "/webjars/", "/assets/vendor/",
)

# `jquery-ui-1.10.4.min.js`），目录 token 抓不到。只对 .js/.css 生效，且必须是
# 「文件名的第一段」——`ry-ui.js`、`common.js` 这类业务文件不受影响。
VENDOR_FILE_PREFIXES = (
    "jquery", "bootstrap", "lodash", "moment", "echarts", "ztree",
    "vue", "react", "angular", "layui", "ckeditor", "ueditor", "pdf.js",
)


def is_vendor_asset(path: Any) -> bool:
    """是否为第三方库/构建产物（不该当成被测项目代码扫描）。"""
    if str(os.environ.get("SAST_AI_SCAN_VENDOR", "")).strip() in ("1", "true", "yes"):
        return False
    p = str(path or "").replace("\\", "/").lower()
    if not p:
        return False
    # 补前导斜杠：相对路径 `node_modules/x.js` 也要能命中 `/node_modules/`。
    p = "/" + p.lstrip("/")
    if p.endswith(".min.js") or p.endswith(".min.css"):
        return True
    if any(tok in p for tok in VENDOR_DIR_TOKENS):
        return True
    name = p.rsplit("/", 1)[-1]
    if name.endswith((".js", ".css")):
        stem = name.split(".", 1)[0]
        if any(stem == pre or stem.startswith(pre + "-") or stem.startswith(pre + ".")
               for pre in VENDOR_FILE_PREFIXES):
            return True
    return False


def filter_vendor_files(files: Iterable[Any]) -> Tuple[List[Any], int]:
    """从文件列表里剔除第三方库/构建产物。返回 (保留项, 剔除数)。

    入参既可以是路径字符串，也可以是 FileScanner 的 dict 项（取 rel_path，其次 path）。
    """
    kept: List[Any] = []
    dropped = 0
    for f in files or []:
        if isinstance(f, dict):
            p = f.get("rel_path") or f.get("path") or f.get("file_path") or ""
        else:
            p = f
        if is_vendor_asset(p):
            dropped += 1
            continue
        kept.append(f)
    return kept, dropped


def filter_files(files: Iterable[Any], shard: Optional[Dict[str, Any]]) -> Tuple[List[Any], Dict[str, int]]:
    """按分片约束待扫描文件列表：只保留分片用例对应的 .java。清单里没有约束字段则原样返回。

    入参既可以是路径字符串，也可以是 FileScanner 的 dict 项（取 path，其次 rel_path/name）。


    原实现只看 `files`，**`files` 为空就原样返回**，等于分片对文件范围完全无效：

        实测 neg-mini（198 用例，`files=[]`、`cases=198`）：
          [*] 分片作用域 neg-mini：文件 2843 → 保留 2843（丢弃 0）   ← 分片白做
          [*] 分片作用域 neg-mini：入口 5486 → 保留 396（丢弃 5090）  ← 入口是对的

    后果是 A2 仍然要分析全部 2843 个文件，分片「只跑 198 用例」
    的意义完全消失。而入口侧走的是 `filter_entries`（认 cases），所以问题只在文件侧、
    很隐蔽 —— 现象是「入口收窄了但还是很慢」。

    故按「文件名去扩展名后等于某个 case」匹配。
    """
    items = list(files or [])
    if not shard:
        return items, {"total": len(items), "kept": len(items), "dropped": 0}
    allowed_files = list(shard.get("files") or [])
    # 用例名两侧必须用同一套大小写归一规则：Windows 上 os.path.normcase 会转小写，
    # POSIX 上是 no-op（路径大小写敏感）。此前这里单方面 .lower，而匹配键来自
    # os.path.basename(os.path.normcase(path)) —— 在 Linux 上 normcase 不转小写，
    # 分片过滤在非 Windows 机器上直接失效（kept=0）。
    allowed_cases = {os.path.normcase(str(c).strip())
                     for c in (shard.get("cases") or []) if str(c).strip()}
    if not allowed_files and not allowed_cases:
        return items, {"total": len(items), "kept": len(items), "dropped": 0}
    # 大小写/盘符写法不同，且 FileScanner 的路径来自 prepared_scan_root（可能是 prepared 副本），
    # 与清单原样比会全落空。故取文件名级别的键来比。
    # 两级匹配：先按绝对路径精确比；比不中再退回文件名比（此时若仍为空，就是真不匹配，
    # 由调用方中止并报清晰错误，绝不静默全量）。
    allowed_full = {os.path.normcase(os.path.abspath(str(p))) for p in allowed_files}
    allowed_base = {os.path.basename(os.path.normcase(str(p))) for p in allowed_files}
    kept = []
    for f in items:
        _p = _path_of_file(f)
        _base = os.path.basename(os.path.normcase(_p))
        _stem = os.path.splitext(_base)[0]
        if os.path.normcase(os.path.abspath(_p)) in allowed_full \
                or _base in allowed_base \
                or (_stem and _stem in allowed_cases):
            kept.append(f)
    return kept, {"total": len(items), "kept": len(kept), "dropped": len(items) - len(kept)}


def summarize(shards: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "shard_count": len(shards),
        "case_count": sum(s.get("count") or 0 for s in shards),
        "tp": sum(s.get("tp") or 0 for s in shards),
        "fp": sum(s.get("fp") or 0 for s in shards),
        "by_shard": [{"name": s.get("name"), "count": s.get("count"),
                      "tp": s.get("tp"), "fp": s.get("fp")} for s in shards],
    }
