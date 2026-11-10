"""调用图反查路由：util 类里的 sink → 顺着 callers 找到 controller 的入口路由（2026-11-02）。

## 为什么需要

`sink` 常常落在**工具类**里，而工具类没有 `@RequestMapping`：

    JobInvokeUtil.invokeMethod()      ← RuoYi 定时任务 invokeTarget 注入的 sink
    HttpUtils.request()               ← jsc 的 SSRF 工具方法
    SecurityUtil.checkSSRF()          ← jsc 的 SSRF 校验方法

`route_resolver` 只按「sink 所在文件/类」找路由，工具类必然 `None`。实测：

- 若依 `JobInvokeUtil.java:37`（`Class.forName(beanName)`）→ `resolve_route_for_finding` 返回 `None`
  ⇒ 真值表里**唯一一条 in_scope 的 command_execution**（`/monitor/job/add`+`/monitor/job/run`）
  一条候选都没有。
- 同一机制也解释了 jsc 的 `urlwhitelist`（3 条 spec 全 `no-arrival`）与 `websecurityconfig`。

## 做法

用 `code_indexer` 的函数表（含 `callers` / `http_entry`）做 BFS：
从 sink 所在函数出发，逐层找 caller，**第一个带 `http_entry` 的 caller 就是它的可达入口**。
深度上限 3 层，超过就放弃（宁可漏，不可乱连）。

缓存：同一 `code_root` 的索引只建一次（一次扫描里会被调用上千次）。
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_INDEX_CACHE: Dict[str, Dict[str, Any]] = {}
_MAX_FILES = 8000          # 超过这个量级不建索引（避免把大仓拖死）
_MAX_DEPTH = 3


def _rel(p: Any) -> str:
    return str(p or "").replace("\\", "/").lstrip("./").lower()


def _under(code_root: Any, p: Any) -> str:
    """把任意形态的路径归一成「相对 code_root、正斜杠、小写」。

    2026-11-02 实杀：`_rel` 不剥 code_root 前缀，于是
    `trigger_specs.expected_sink_file` 是**绝对路径**时（RuoYi/jsc 都是），
    `_rel(绝对路径)` 与索引里的 `_rel(相对路径)` 永远不相等 ⇒ 查不到所属函数 ⇒
    调用图反查和两步桥**静默失效**。必须按 code_root 剥前缀。
    """
    s = str(p or "").replace("\\", "/").strip()
    root = str(code_root or "").replace("\\", "/").rstrip("/")
    if root and s.lower().startswith(root.lower() + "/"):
        s = s[len(root) + 1:]
    elif re.match(r"^[A-Za-z]:/", s) or s.startswith("/"):
        # 只有「绝对路径且不在 root 下」才从 /src/ 截断。
        # **相对路径不能截**：RuoYi 的 `ruoyi-quartz/src/main/java/...` 一旦被截成
        # `src/main/java/...` 就和索引里的键对不上，且拼不出真实磁盘路径。
        low = s.lower()
        i = low.find("/src/")
        if i >= 0:
            s = s[i + 1:]
    return s.lstrip("./").lower()


def _build_index(code_root: str) -> Dict[str, Any]:
    """建（并缓存）函数索引：{key: {file,line,callers,http_entry}}。"""
    if code_root in _INDEX_CACHE:
        return _INDEX_CACHE[code_root]
    idx: Dict[str, Any] = {}
    try:
        from src.core.code_indexer import CodeIndexer
        files: List[Dict[str, Any]] = []
        for dirpath, dirnames, filenames in os.walk(code_root):
            dirnames[:] = [d for d in dirnames
                           if d not in ("target", "build", "node_modules", ".git", "out")]
            for name in filenames:
                if not name.endswith(".java"):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        files.append({
                            "rel_path": os.path.relpath(full, code_root),
                            "content": f.read(),
                            "language": "java",
                        })
                except OSError:
                    continue
                if len(files) >= _MAX_FILES:
                    logger.warning("[callgraph-route] 源文件超过 %d，放弃建索引", _MAX_FILES)
                    _INDEX_CACHE[code_root] = {}
                    return {}
        idx = (CodeIndexer().index_project(files) or {}).get("functions") or {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("[callgraph-route] 建索引失败（%s），本进程内不再尝试", exc)
        idx = {}
    _INDEX_CACHE[code_root] = idx
    return idx


def clear_cache() -> None:
    _INDEX_CACHE.clear()


def route_via_callers(code_root: Optional[str], sink_file: Any, sink_line: Any,
                      max_depth: int = _MAX_DEPTH) -> Dict[str, Any]:
    """从 sink 位置顺着 callers 找最近的 HTTP 入口。返回 {route, method, hops, via}。"""
    empty = {"route": "", "method": "", "hops": 0, "via": []}
    if not code_root or not sink_file:
        return empty
    idx = _build_index(str(code_root))
    if not idx:
        return empty
    norm = _under(code_root, sink_file)
    try:
        line = int(sink_line or 0)
    except Exception:  # noqa: BLE001
        line = 0

    # 1) 找 sink 所在的函数（同文件、行号 ≤ sink_line 里最大的那个）
    best_key, best_line = "", -1
    for key, meta in idx.items():
        if not isinstance(meta, dict):
            continue
        kf = _under(code_root, meta.get("file") or key.rsplit(":", 1)[0])
        if kf != norm:
            continue
        try:
            ln = int(meta.get("line") or 0)
        except Exception:  # noqa: BLE001
            continue
        if ln <= line and ln > best_line:
            best_key, best_line = key, ln
    if not best_key:
        return empty

    # 2) 若 sink 自己就是入口（controller 里的直接 sink）
    own = idx.get(best_key) or {}
    if own.get("http_entry"):
        route, _, method = _split_entry(own["http_entry"])
        return {"route": route, "method": method, "hops": 0, "via": [best_key]}

    # 3) BFS 找 caller 里的入口
    #
    # **唯一性闸门（关键）**：工具方法常被多个端点复用，例如 jsc 的
    # `HttpUtils.request` 同时被 `/ssrf/request/vuln` 与 `/ssrf/request/sec` 调用。
    # 随便挑一个 caller 会把 sink 登记到错误端点（sec 是安全实现，登记上去就是误报）。
    # 因此只在「同一深度上恰好只有一个不同路由」时才采用；有歧义就返回空，交回上层。
    lower = {str(k).lower(): k for k in idx}
    frontier: List[Tuple[str, int]] = [(best_key, 0)]
    visited = {best_key}
    via: List[str] = [best_key]
    for depth in range(1, int(max_depth) + 1):
        nxt: List[Tuple[str, int]] = []
        entries: Dict[str, Tuple[str, str]] = {}  # route -> (method, key)
        for key, _d in frontier:
            for caller in (idx.get(key) or {}).get("callers") or []:
                ck = caller if caller in idx else lower.get(str(caller).lower())
                if not ck or ck in visited:
                    continue
                visited.add(ck)
                cmeta = idx.get(ck) or {}
                if cmeta.get("http_entry"):
                    route, _, method = _split_entry(cmeta["http_entry"])
                    if route:
                        entries.setdefault(route, (method, ck))
                        continue
                via.append(ck)
                nxt.append((ck, depth))
        if entries:
            if len(entries) == 1:
                route, (method, ck) = next(iter(entries.items()))
                return {"route": route, "method": method, "hops": depth,
                        "via": via + [ck]}
            # 多个入口 ⇒ 歧义，放弃（不猜）
            logger.debug("[callgraph-route] %s 在 %d 跳处有 %d 个候选路由，放弃",
                         norm, depth, len(entries))
            return empty
        if not nxt:
            break
        frontier = nxt
    return empty


def _split_entry(entry: Any) -> Tuple[str, str, str]:
    """把 `GET /path` 拆成 (route, verb, method)。`ANY /path` 的 verb 保留原样。"""
    text = str(entry or "").strip()
    if not text:
        return "", "", ""
    parts = text.split(None, 1)
    if len(parts) == 1:
        return parts[0], "", ""
    return parts[1], parts[0], parts[0]


# ── 两步桥：写入口 → 存储 → 触发时执行（2026-11-02）────────────────────────
#
# 有些 sink 不是由请求直接触发的，而是「先写进存储，再由调度器/队列取出来执行」：
#
#   POST /monitor/job/add   → 写入 sys_job.invoke_target（用户可控）
#   POST /monitor/job/run   → 调度器 → JobInvokeUtil.invokeMethod → Class.forName(...)
#
# 静态调用图里 `invokeMethod` 的 caller 是 Quartz 的 `doExecute`，**没有 HTTP 入口**
# ⇒ 上面所有路由解析策略都失败 ⇒ 真值表里唯一一条 in_scope 的 command_execution 零候选。
#
# 这里换一条路：从 sink 读的字段名（`getInvokeTarget()` → `invokeTarget`）
# 反查**谁在写它**（`setInvokeTarget(`），那个写方法的 HTTP 入口就是「第一步」的入口。
# 产出的路由语义是「先调这个写接口，再调触发接口」，由 spec 的 prerequisites 标注。

_GETTER_RE = re.compile(r"\.\s*(get[A-Z]\w*)\s*\(\s*\)")
_SETTER_TMPL = "set%s("


def _read_source(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def route_via_writer(code_root: Optional[str], sink_file: Any, sink_line: Any) -> Dict[str, Any]:
    """从 sink 读的字段反查「写该字段」的入口路由（两步桥的第一跳）。

    两条策略（都由确定性信息驱动，不猜）：

    1. **setter 调用点**：`setInvokeTarget(` 有显式调用 ⇒ 它的 caller 里找 http_entry。
    2. **按实体类型找写入口**：若 setter 是框架（Jackson/MyBatis）在运行时调的、
       静态没有调用点（RuoYi 的 `@RequestBody SysJob` 就是这种），
       则从 sink 函数的形参类型（`SysJob`）出发，找**参数里带该类型且有 http_entry** 的方法。

    策略 2 是关键：它把「谁把用户输入塞进了这个实体」变成「谁接收这个实体」，
    而后者在 Spring 里一定有 `@RequestBody` / `@ModelAttribute` 的入口。
    """
    empty = {"route": "", "method": "", "hops": 0, "via": [], "bridge": ""}
    if not code_root or not sink_file:
        return empty
    norm = _under(code_root, sink_file)
    try:
        line = int(sink_line or 0)
    except Exception:  # noqa: BLE001
        line = 0
    idx = _build_index(str(code_root))
    if not idx:
        return empty
    lower = {str(k).lower(): k for k in idx}

    # 找 sink 所在函数（同文件、行号 ≤ sink_line 里最大者）
    own_key, own_line, own_meta = "", -1, {}
    for key, meta in idx.items():
        if not isinstance(meta, dict):
            continue
        if _under(code_root, meta.get("file") or key.rsplit(":", 1)[0]) != norm:
            continue
        try:
            ln = int(meta.get("line") or 0)
        except Exception:  # noqa: BLE001
            continue
        if ln <= line and ln > own_line:
            own_key, own_line, own_meta = key, ln, meta
    # 读文件要用**索引里的真实相对路径**：`_under` 在剥不到 code_root 前缀时
    # 会从 `/src/` 截断，把模块前缀（`ruoyi-quartz/`）丢掉 ⇒ 拼出来的路径不存在。
    _real_rel = str(own_meta.get("file") or norm)
    full = os.path.join(str(code_root), _real_rel.replace("\\", os.sep).replace("/", os.sep))
    code = _read_source(full)
    if not code:
        return empty
    lines = code.splitlines()
    # 从函数起始行扫到 sink 行 +8：getter 常在 sink 之前若干行就被调用
    _start = max(0, (own_line - 1) if own_line else (line - 1))
    window = "\n".join(lines[_start: line + 8])
    getters = [m.group(1) for m in _GETTER_RE.finditer(window)]
    if not getters:
        return empty

    # 策略 1：setter 的显式调用点
    for getter in getters:
        setter_name = "set" + getter[3:]
        for key in idx:
            if not str(key).endswith(":" + setter_name):
                continue
            for caller in (idx.get(key) or {}).get("callers") or []:
                ck = caller if caller in idx else lower.get(str(caller).lower())
                if not ck:
                    continue
                entry = (idx.get(ck) or {}).get("http_entry")
                if not entry:
                    continue
                route, _, method = _split_entry(entry)
                if route:
                    return {"route": route, "method": method, "hops": 1,
                            "via": [ck, key], "bridge": getter}

    # 策略 2：按实体类型找写入口（setter 由框架运行时调用时用这条）
    #
    # **必须按「写」优先排序**：同一个实体往往有 list / query / export / add / edit / run
    # 一堆入口，随便取第一个会拿到只读接口（实测 RuoYi 先取到 `/monitor/job/list`）。
    # 两步桥要的是「用户输入进入存储」的那一跳，所以 add/insert/save/create 优先，
    # 其次 run/trigger/execute（触发），只读接口大幅降权。
    _JDK = ("string", "int", "long", "boolean", "double", "float", "list", "map",
            "object", "byte", "char", "short", "set", "collection", "bigdecimal")
    _WRITE_TOKENS = ("add", "insert", "save", "create", "new", "submit")
    _TRIGGER_TOKENS = ("run", "trigger", "execute", "start", "invoke", "send")
    _READ_TOKENS = ("list", "query", "select", "get", "export", "detail", "info", "page", "count")
    entity_types = []
    for p in (own_meta.get("params_typed") or []):
        t = str(p.get("type") or "").strip()
        if t and t.lower() not in _JDK and "<" not in t and "[" not in t:
            entity_types.append(t)

    def _score(route: str) -> int:
        low = str(route or "").lower()
        s = 0
        if any(t in low for t in _WRITE_TOKENS):
            s += 5
        if any(t in low for t in _TRIGGER_TOKENS):
            s += 3
        if any(t in low for t in _READ_TOKENS):
            s -= 5
        return s

    best = None
    for etype in entity_types:
        for key, meta in idx.items():
            if not isinstance(meta, dict) or not meta.get("http_entry"):
                continue
            for p in (meta.get("params_typed") or []):
                if str(p.get("type") or "").strip() != etype:
                    continue
                route, _, method = _split_entry(meta["http_entry"])
                if not route:
                    continue
                cand = {"route": route, "method": method, "hops": 1, "via": [key],
                        "bridge": "%s:%s" % (etype, getters[0]), "_score": _score(route)}
                if best is None or cand["_score"] > best["_score"]:
                    best = cand
                break
    if best:
        best.pop("_score", None)
        return best
    return empty
