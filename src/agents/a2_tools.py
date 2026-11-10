"""A2 Agentic 闭环的工具集（2026-09-17 落地）。

背景：评审把 A2 的二次分析从「单轮 prompt 注入反馈文本」升级为「带工具调用的
多轮 Agent loop」，工具集一步到位，含规则执行与 exploit 只读探测。此前 A2 唯一的外部
上下文是静态 RAG 把代码片段塞进 prompt，LLM 无法在推理中主动查证，这正是闭环里
「假说缺陷（端点幻觉 / 参数缺失）」占比高的根因之一。

本模块提供两件事：
  1. 工具定义与 JSON Schema（供支持 function calling 的 provider 使用）；
  2. 本地执行器（provider 不支持 tool calling、或离线时，由本模块兜底执行同名工具）。

工具（全部只读）：
  - code_search     代码语义检索（复用 core.code_retriever 的 RAG 能力）
  - read_file       读取源码片段（按行区间）
  - grep_symbol     符号引用检索（调用图近似：定位定义与调用点）
  - run_rule        对指定文件跑 A1 规则族（只返回匹配，不写库、不改状态）
  - probe_readonly  列出可用的 exploit 只读探测能力（只列清单，绝不触发执行）

安全边界：probe_readonly 明确只返回清单，不执行任何攻击；run_rule 只做匹配不落库；
所有文件读取都限制在项目根之内，拒绝越界路径。
"""
from __future__ import annotations

import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeout
from typing import Any, Dict, List, Optional

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# §4.2 一期（2026-09-19）：工具级超时与埋点。本地 agentic 工具此前无任何超时，
# 任一工具 hang（RAG 死锁 / grep 大仓）会直接卡死整个多轮 loop。超时后返回 ok=False
# 而非抛异常，保证 loop 不被打断（fail-open）。
TOOL_TIMEOUT_SECONDS = float(os.environ.get("SAST_AI_A2_TOOL_TIMEOUT", "10"))
# §4.2 三期（2026-09-20）：外部 MCP 工具端到端超时。外部进程（CodeQL/Semgrep/依赖查询）不可控，
# 默认给得比本地工具宽（20s），但仍有硬上限，避免外部工具 hang 死 agentic loop。
EXTERNAL_TOOL_TIMEOUT_SECONDS = float(os.environ.get("SAST_AI_MCP_TOOL_TIMEOUT", "20"))

_STATS_LOCK = threading.Lock()
_TOOL_STATS: Dict[str, Dict[str, float]] = {}
_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="a2-tool")


def _safe_path(path: str) -> str:
    """把路径限制在项目根内，拒绝越界读取（..、绝对路径逃逸）。"""
    p = str(path or "").strip()
    if not p:
        return ""
    if not os.path.isabs(p):
        p = os.path.join(_PROJECT_ROOT, p)
    real = os.path.realpath(p)
    root = os.path.realpath(_PROJECT_ROOT)
    if not (real == root or real.startswith(root + os.sep)):
        return ""
    return real


def tool_code_search(query: str, limit: int = 5) -> Dict[str, Any]:
    """代码语义检索：优先用项目 RAG，不可用时退化为关键词 grep（口径如实标注）。"""
    query = str(query or "").strip()
    if not query:
        return {"ok": False, "error": "query 为空", "results": []}
    try:
        from src.core import code_retriever as _cr

        fn = getattr(_cr, "retrieve", None) or getattr(_cr, "search", None)
        if callable(fn):
            hits = fn(query, limit=limit) or []
            return {"ok": True, "source": "rag", "results": [str(h)[:400] for h in hits][:limit]}
    except Exception as exc:
        # RAG 不可用不阻断，退化为 grep，交由下面统一处理
        pass
    return {"ok": True, "source": "grep-fallback",
            "results": _grep_project(query, limit=limit),
            "note": "RAG 不可用，退化为关键词检索"}


def _grep_project(query: str, limit: int = 5) -> List[str]:
    """轻量关键词检索：只对源码文件做行级匹配，避免全盘扫描大文件。"""
    pat = re.compile(re.escape(query), re.IGNORECASE)
    out: List[str] = []
    exts = (".java", ".py", ".xml", ".yml", ".yaml", ".properties")
    for root, dirs, files in os.walk(_PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "__pycache__", "target")]
        for name in files:
            if not name.endswith(exts):
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        if pat.search(line):
                            out.append(f"{os.path.relpath(path, _PROJECT_ROOT)}:{i}: {line.strip()[:200]}")
                            break
            except Exception:
                continue
            if len(out) >= limit:
                return out
    return out


def tool_read_file(path: str, start_line: int = 1, end_line: int = 0) -> Dict[str, Any]:
    """读取源码片段。end_line=0 表示读到文件末尾（最多 400 行，避免撑爆上下文）。"""
    real = _safe_path(path)
    if not real or not os.path.isfile(real):
        return {"ok": False, "error": f"文件不可读或越界：{path}"}
    s = max(1, int(start_line or 1))
    e = int(end_line or 0) or (s + 399)
    lines = []
    try:
        with open(real, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                if i < s:
                    continue
                if i > e:
                    break
                lines.append(f"{i}: {line.rstrip()}")
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "path": os.path.relpath(real, _PROJECT_ROOT), "lines": lines}


def tool_grep_symbol(symbol: str, limit: int = 10) -> Dict[str, Any]:
    """符号引用检索（调用图近似）：找定义与调用点，比纯关键词更聚焦标识符边界。"""
    symbol = str(symbol or "").strip()
    if not symbol:
        return {"ok": False, "error": "symbol 为空", "refs": []}
    pat = re.compile(r"\b" + re.escape(symbol) + r"\b")
    refs: List[str] = []
    exts = (".java", ".py")
    for root, dirs, files in os.walk(_PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "__pycache__", "target")]
        for name in files:
            if not name.endswith(exts):
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        if pat.search(line):
                            refs.append(f"{os.path.relpath(path, _PROJECT_ROOT)}:{i}: {line.strip()[:180]}")
            except Exception:
                continue
            if len(refs) >= limit:
                break
        if len(refs) >= limit:
            break
    return {"ok": True, "symbol": symbol, "refs": refs[:limit],
            "note": "调用图近似（标识符级检索），非精确调用链分析"}


def tool_run_rule(path: str, family: str = "") -> Dict[str, Any]:
    """对指定文件跑 A1 规则族匹配：只读返回命中，不写库、不改 finding 状态。"""
    real = _safe_path(path)
    if not real or not os.path.isfile(real):
        return {"ok": False, "error": f"文件不可读或越界：{path}"}
    try:
        with open(real, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    hits: List[Dict[str, Any]] = []
    try:
        from src.agents import a1_agent as _a1

        fn = getattr(_a1, "match_rules", None) or getattr(_a1, "scan_content", None)
        if callable(fn):
            raw = fn(content, real, family=family or None) or []
            hits = [str(h)[:300] for h in raw][:20]
            return {"ok": True, "source": "a1_agent", "hits": hits}
    except Exception:
        pass
    # 兜底：族关键词直匹配（口径如实标注，绝不冒充规则引擎结果）
    fam = str(family or "").strip().lower()
    if fam:
        pat = re.compile(re.escape(fam), re.IGNORECASE)
        hits = [f"{i}: {line.strip()[:180]}" for i, line in enumerate(content.splitlines(), 1) if pat.search(line)][:20]
    return {"ok": True, "source": "keyword-fallback", "hits": hits,
            "note": "规则引擎不可用，退化为族关键词匹配"}


def tool_probe_readonly(family: str = "") -> Dict[str, Any]:
    """列出可用的 exploit 只读探测能力（只列清单，绝不触发执行）。"""
    try:
        from src.core import tool_registry as _tr

        reg = getattr(_tr, "ToolRegistry", None)
        if reg is not None:
            items = []
            getter = getattr(reg, "list_tools", None) or getattr(reg, "all", None)
            if callable(getter):
                items = [str(t)[:120] for t in (getter() or [])]
            fam = str(family or "").lower()
            if fam:
                items = [t for t in items if fam in t.lower()] or items
            return {"ok": True, "tools": items[:20],
                    "note": "只读清单，未执行任何探测"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "tools": []}
    return {"ok": True, "tools": [], "note": "工具注册表不可用"}


# OpenAI / Anthropic tools 通用 JSON Schema（provider 支持 tool calling 时直接透传）
TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "code_search",
        "description": "按语义/关键词检索项目代码，返回相关片段（用于确认入口、参数、sink 是否真实存在）",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "检索词（类名/方法名/端点路径）"},
                           "limit": {"type": "integer", "description": "返回条数，默认 5"}},
            "required": ["query"],
        },
    },
    {
        "name": "read_file",
        "description": "读取指定源码文件的行区间，最多 400 行",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"},
                           "start_line": {"type": "integer"},
                           "end_line": {"type": "integer", "description": "0 表示读到末尾"}},
            "required": ["path"],
        },
    },
    {
        "name": "grep_symbol",
        "description": "按标识符边界检索符号的定义与调用点（调用图近似）",
        "input_schema": {
            "type": "object",
            "properties": {"symbol": {"type": "string"}, "limit": {"type": "integer"}},
            "required": ["symbol"],
        },
    },
    {
        "name": "run_rule",
        "description": "对指定文件跑 A1 规则族匹配，只读返回命中结果",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "family": {"type": "string", "description": "漏洞族，如 command_execution"}},
            "required": ["path"],
        },
    },
    {
        "name": "probe_readonly",
        "description": "列出可用的 exploit 只读探测能力清单（不执行任何探测）",
        "input_schema": {
            "type": "object",
            "properties": {"family": {"type": "string"}},
        },
    },
]


_EXECUTORS = {
    "code_search": lambda a: tool_code_search(a.get("query", ""), int(a.get("limit", 5) or 5)),
    "read_file": lambda a: tool_read_file(a.get("path", ""), int(a.get("start_line", 1) or 1), int(a.get("end_line", 0) or 0)),
    "grep_symbol": lambda a: tool_grep_symbol(a.get("symbol", ""), int(a.get("limit", 10) or 10)),
    "run_rule": lambda a: tool_run_rule(a.get("path", ""), a.get("family", "")),
    "probe_readonly": lambda a: tool_probe_readonly(a.get("family", "")),
}

# §4.2 三期（2026-09-20）：外部 MCP 工具统一命名空间。
# 本地工具（上表）与外部 MCP 工具合并为「一套工具名」，agentic 侧无感知差异。
# 外部工具名带前缀 ``mcp__<server>__<tool>``（由 McpToolBridge 生成），与本地名天然不撞。
# 注册表在模块级，进程内共享；`register_external_tools` 由 MCP 接线处调用（幂等覆盖同名）。
_EXTERNAL_SCHEMAS: List[Dict[str, Any]] = []
_EXTERNAL_EXECUTORS: Dict[str, Any] = {}
_EXTERNAL_LOCK = threading.Lock()


def register_external_tools(schemas: List[Dict[str, Any]], executor) -> int:
    """注册一批外部工具（schema 形状同 TOOL_SCHEMAS：name/description/input_schema）。

    ``executor(local_name, arguments) -> dict`` 负责把调用转发到远端。返回注册条数。
    同名覆盖，便于重复接线（如同一 MCP server 重连后 refresh）。
    """
    n = 0
    with _EXTERNAL_LOCK:
        existing = {s.get("name") for s in _EXTERNAL_SCHEMAS}
        for s in schemas or []:
            name = str((s or {}).get("name") or "").strip()
            if not name:
                continue
            if name not in existing:
                _EXTERNAL_SCHEMAS.append(dict(s))
                existing.add(name)
            else:
                for i, old in enumerate(_EXTERNAL_SCHEMAS):
                    if old.get("name") == name:
                        _EXTERNAL_SCHEMAS[i] = dict(s)
                        break
            _EXTERNAL_EXECUTORS[name] = executor
            n += 1
    return n


def clear_external_tools() -> None:
    """清空外部工具（测试隔离 / 断开所有 MCP server 时用）。"""
    with _EXTERNAL_LOCK:
        _EXTERNAL_SCHEMAS.clear()
        _EXTERNAL_EXECUTORS.clear()


def external_tool_names() -> List[str]:
    with _EXTERNAL_LOCK:
        return [s.get("name") for s in _EXTERNAL_SCHEMAS if s.get("name")]


def all_tool_schemas() -> List[Dict[str, Any]]:
    """本地工具 + 外部 MCP 工具的合并清单（三期统一命名空间）。"""
    with _EXTERNAL_LOCK:
        return list(TOOL_SCHEMAS) + list(_EXTERNAL_SCHEMAS)


def _safe_exec(fn, args: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return fn(args)
    except Exception as exc:  # 工具内部异常收敛为 ok=False，绝不冒泡打断 loop
        return {"ok": False, "error": str(exc)}


def _record_stat(name: str, ok: bool, ms: float) -> None:
    with _STATS_LOCK:
        s = _TOOL_STATS.setdefault(name, {"calls": 0, "errors": 0, "total_ms": 0.0, "max_ms": 0.0})
        s["calls"] += 1
        if not ok:
            s["errors"] += 1
        s["total_ms"] += ms
        if ms > s["max_ms"]:
            s["max_ms"] = ms


def execute_tool(name: str, arguments: Optional[Dict[str, Any]] = None,
                 timeout: Optional[float] = None) -> Dict[str, Any]:
    """执行一个工具调用（§4.2 一期：带超时 + 埋点；三期：外部 MCP 工具统一路由）。

    - 未知工具返回 ok=False（不打断 loop）；
    - 本地无此工具时，查外部 MCP 工具注册表（``mcp__<server>__<tool>``）并转发；
    - 工具执行转入独立线程，超时返回 ok=False + timed_out=True，避免 hang 卡死整个
      agentic loop。默认超时：本地 10s（env SAST_AI_A2_TOOL_TIMEOUT），外部 20s
      （env SAST_AI_MCP_TOOL_TIMEOUT，外部进程不可控故更宽容）；
    - 每次调用记录 次数/错误数/总耗时/最大耗时，供观测（tool_stats）。
    """
    name = str(name or "").strip()
    fn = _EXECUTORS.get(name)
    is_external = False
    if fn is None:
        # §4.2 三期：本地未注册 → 查外部 MCP 工具（统一命名空间）。
        with _EXTERNAL_LOCK:
            ext = _EXTERNAL_EXECUTORS.get(name)
        if ext is None:
            return {"ok": False, "error": f"未知工具：{name}",
                    "available": sorted(list(_EXECUTORS) + external_tool_names())}
        is_external = True
        fn = lambda a, _n=name, _ex=ext: _ex(_n, a)  # noqa: E731 - 转发到远端执行器
    if timeout is not None:
        to = float(timeout)
    elif is_external:
        to = EXTERNAL_TOOL_TIMEOUT_SECONDS
    else:
        to = TOOL_TIMEOUT_SECONDS
    started = time.perf_counter()
    try:
        fut = _EXECUTOR.submit(_safe_exec, fn, arguments or {})
        try:
            res = fut.result(timeout=to)
        except _FuturesTimeout:
            _record_stat(name, False, (time.perf_counter() - started) * 1000)
            return {"ok": False, "error": f"工具执行超时（>{to:.0f}s）", "timed_out": True}
    except Exception as exc:  # submit 自身异常（极少见）
        _record_stat(name, False, (time.perf_counter() - started) * 1000)
        return {"ok": False, "error": str(exc)}

    ok = bool(res.get("ok")) if isinstance(res, dict) else True
    _record_stat(name, ok, (time.perf_counter() - started) * 1000)
    return res


def tool_stats() -> Dict[str, Dict[str, float]]:
    """返回各工具的累计调用统计（次数/错误/总耗时/最大耗时）。"""
    with _STATS_LOCK:
        return {n: dict(v) for n, v in _TOOL_STATS.items()}


def reset_tool_stats() -> None:
    with _STATS_LOCK:
        _TOOL_STATS.clear()


class ToolSpec:
    """统一工具协议（§4.2 二期/三期基础）：一份定义，映射到 Anthropic 与 OpenAI 两种 schema。

    一期只用于生成提示词文本；二期（对外 MCP Server）/ 三期（对内 MCP Client）
    直接复用本类做 tools/list 与 tools/call 的映射，无需重写工具定义。
    """

    __slots__ = ("name", "description", "input_schema")

    def __init__(self, name: str, description: str, input_schema: Dict[str, Any]):
        self.name = name
        self.description = description
        self.input_schema = input_schema

    def to_anthropic(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}

    def to_openai(self) -> Dict[str, Any]:
        return {"type": "function", "function": {
            "name": self.name, "description": self.description, "parameters": self.input_schema,
        }}


def get_tool_specs() -> List[ToolSpec]:
    # §4.2 三期：含外部 MCP 工具（统一命名空间）；无外部工具时与旧版行为一致。
    return [ToolSpec(s["name"], s.get("description", ""), s.get("input_schema", {}))
            for s in all_tool_schemas()]


def tool_specs_for_provider(flavor: str) -> List[Dict[str, Any]]:
    """按 provider flavor 映射 tool schema（openai 用 parameters，anthropic 用 input_schema）。"""
    specs = get_tool_specs()
    if str(flavor).lower() in ("openai", "openai-compatible", "qwen", "doubao", "minimax", "deepseek"):
        return [s.to_openai() for s in specs]
    return [s.to_anthropic() for s in specs]
