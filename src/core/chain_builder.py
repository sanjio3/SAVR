"""确定性调用链回溯（S1）：从 SAST sink 命中回溯到 HTTP 入口。

与 A2 原先「按 family 关键词正则猜测调用链」不同，本模块直接消费 code_indexer 已经
构建好的调用图（FunctionInfo.callers / http_entry），做图可达性回溯：

    sink 方法 M（文件 F、行 L）
      → 沿 callers 向上 BFS
      → 直到某个函数的 http_entry 非空
      → 得到有序路径 [Controller@Post → Service.method → … → Sink]

这是图可达性问题，确定性强，不靠 LLM 猜，也不靠关键词正则。回溯到 http_entry 即证明
「该 sink 确实可由某个 HTTP 入口触发」，可作为 ground truth 喂给 LLM（S2）与证明门禁（S3）。
回溯不到 http_entry 时返回 reached_entry=False，调用方应保留 broad_static，不得伪造链路。
"""

import logging
from collections import deque
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__) if (__name__ != "__main__") else logging.getLogger("chain_builder")


def _as_function_dict(code_index: Any) -> Dict[str, Any]:
    """把 code_index 统一成 {func_key: func_dict}。支持 dict 形态与 CodeIndexer 对象形态。"""
    if code_index is None:
        return {}
    if isinstance(code_index, dict):
        funcs = code_index.get("functions") or {}
        if not isinstance(funcs, dict):
            return {}
        return funcs
    funcs = getattr(code_index, "functions", None)
    if isinstance(funcs, dict):
        # CodeIndexer.functions 是 {key: FunctionInfo}，这里转成纯 dict 形态，
        # 让本模块不依赖 dataclass 类型。
        out: Dict[str, Any] = {}
        for k, v in funcs.items():
            out[k] = v if isinstance(v, dict) else getattr(v, "__dict__", {})
        return out
    return {}


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def _enclosing_function(functions: Dict[str, Any], sink_file: Optional[str], sink_line: Optional[int]) -> Optional[str]:
    """在 functions 中找到包含 (sink_file, sink_line) 的函数 key。

    优先精确匹配 file；精确匹配不到时回退到 basename 匹配（code_index 用 rel_path，
    而 SAST 报的 file 可能是绝对路径）。返回离 sink_line 最近（line 最大且 <= sink_line）的函数。
    """
    if not sink_file or not sink_line:
        return None
    best_key: Optional[str] = None
    best_line = -1
    best_key_base: Optional[str] = None
    best_line_base = -1
    sb = _basename(sink_file)
    for key, info in functions.items():
        info = info if isinstance(info, dict) else {}
        f = info.get("file") or ""
        ln = int(info.get("line") or 0)
        if ln <= 0 or ln > sink_line:
            continue
        if f == sink_file:
            if ln > best_line:
                best_line = ln
                best_key = key
        elif _basename(f) == sb:
            if ln > best_line_base:
                best_line_base = ln
                best_key_base = key
    return best_key or best_key_base


def parse_http_entry(http_entry: Optional[str]) -> Dict[str, str]:
    """把 'POST /api/address/{id}' 解析成 {'method': 'POST', 'route': '/api/address/{id}'}。"""
    if not http_entry:
        return {"method": "", "route": ""}
    s = str(http_entry).strip()
    parts = s.split(None, 1)
    if len(parts) == 2:
        return {"method": parts[0].upper(), "route": parts[1].strip()}
    # 只有路由没有方法（理论不该出现），默认 GET
    return {"method": "GET", "route": s}


def build_chain_from_index(
    sink_file: Optional[str],
    sink_line: Optional[int],
    code_index: Any,
    max_hops: int = 30,
) -> Optional[Dict[str, Any]]:
    """从 sink 命中（文件 F、行 L）确定性回溯到 HTTP 入口。

    返回结构：
    {
        "reached_entry": bool,         # 是否回溯到 http_entry
        "entry_http": str,             # 命中入口的 http_entry 原文，如 'POST /api/address/{id}'
        "entry_method": str,
        "entry_route": str,
        "chain": [func_key, ...],      # 从 http_entry → sink 的有序函数 key 列表
        "chain_detail": [              # 每个 hop 的可读描述，供 prompt 与日志
            {"key":..., "name":..., "file":..., "line":..., "http_entry":..., "role":...},
            ...
        ],
    }
    回溯不到 http_entry 时返回 None（调用方保留 broad_static，不伪造）。
    """
    functions = _as_function_dict(code_index)
    if not functions:
        return None
    sink_key = _enclosing_function(functions, sink_file, sink_line)
    if not sink_key:
        return None

    # BFS 向上（沿 callers）找最短可达的 http_entry。callers 是函数 key 列表。
    parent_of: Dict[str, Optional[str]] = {sink_key: None}
    queue: "deque[str]" = deque([sink_key])
    found_entry_key: Optional[str] = None
    visited = {sink_key}
    while queue:
        node = queue.popleft()
        info = functions.get(node) if isinstance(functions.get(node), dict) else {}
        if info.get("http_entry"):
            found_entry_key = node
            break
        for caller in (info.get("callers") or []):
            if caller in visited:
                continue
            if caller not in functions:
                continue
            visited.add(caller)
            parent_of[caller] = node
            queue.append(caller)

    if not found_entry_key:
        return None

    # 从入口回溯到 sink，反转为 [entry, ..., sink]
    path: List[str] = []
    cur: Optional[str] = found_entry_key
    guard = 0
    while cur is not None and guard <= max_hops:
        path.append(cur)
        cur = parent_of.get(cur)
        guard += 1
    # parent_of[sink_key] 为 None，循环结束；path 现在是 [entry, ..., sink]
    chain_detail: List[Dict[str, Any]] = []
    for idx, key in enumerate(path):
        info = functions.get(key) if isinstance(functions.get(key), dict) else {}
        role = "entry" if idx == 0 else ("sink" if idx == len(path) - 1 else "transform")
        chain_detail.append({
            "key": key,
            "name": info.get("name") or key.split(":")[-1],
            "file": info.get("file") or "",
            "line": int(info.get("line") or 0),
            "http_entry": info.get("http_entry") or "",
            "role": role,
        })
    entry_info = functions.get(found_entry_key) if isinstance(functions.get(found_entry_key), dict) else {}
    ep = parse_http_entry(entry_info.get("http_entry") or "")
    return {
        "reached_entry": True,
        "entry_http": entry_info.get("http_entry") or "",
        "entry_method": ep["method"],
        "entry_route": ep["route"],
        "chain": path,
        "chain_detail": chain_detail,
    }


def format_chain_for_prompt(chain: Dict[str, Any]) -> str:
    """把确定性调用链格式化成注入 LLM prompt 的纯文本块（S2 使用）。"""
    if not chain or not chain.get("reached_entry"):
        return ""
    lines = ["确定性调用链（code_index 调用图回溯，权威，从 HTTP 入口到 sink）："]
    for hop in chain.get("chain_detail", []):
        loc = f"{hop.get('file')}:{hop.get('line')}" if hop.get("file") else hop.get("key", "")
        he = f"  http_entry={hop.get('http_entry')}" if hop.get("http_entry") else ""
        lines.append(f"  - [{hop.get('role')}] {hop.get('name')} @ {loc}{he}")
    return "\n".join(lines)


def populate_entry_from_chain(chain: Dict[str, Any]) -> Dict[str, str]:
    """从确定性链取出入口 route/method，用于救援 entry_resolution（S3）。"""
    ep = chain or {}
    return {
        "method": ep.get("entry_method") or "GET",
        "route": ep.get("entry_route") or "",
    }
