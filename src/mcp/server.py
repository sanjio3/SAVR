"""二期：对外 MCP Server。

把平台能力暴露成 MCP tools，让外部 IDE / agent 能消费本平台：

  - get_findings          读：按 workspace/task 取 findings（只读）
  - get_blackboard        读：取 vuln_blackboard 行（只读）
  - get_iast_events       读：取 iast_events 行（只读）
  - trigger_replay        写：触发 D1 重放（**默认禁用**，需 allow_write=True）
  - submit_rule_candidate 写：提交候选规则（**默认禁用**，需 allow_write=True）

另有 5 个 A2 只读 agentic 工具（code_search / read_file / grep_symbol / run_rule /
probe_readonly）经 ``register_local_agentic_tools`` 一并暴露，复用 ``a2_tools`` 的
白名单 + ``_safe_path`` 沙箱 + 超时（设计「安全模型不用重写」）。

安全模型（与项目铁律一致，改动前必读）：

1. **默认只读**。写工具被 ``allow_write`` 硬门控，默认 False 时直接返回结构化拒绝，
   绝不产生副作用——外部 agent 连上来不能一句话就把靶场重放/规则库改了。
2. **数据源注入**。工具不自己开 DB，而是经 ``PlatformDataProvider`` 抽象取数；默认实现
   ``SqlitePlatformDataProvider`` 只读查询，写方法一律 ``NotImplementedError``（未接）。
   这样「对外服务」与「真实副作用」解耦，测试可注入假 provider 验证协议而不触库。
3. **一处定义**。工具 schema 复用 ``a2_tools.TOOL_SCHEMAS`` 的口径（内部 snake →
   MCP camel，转换收敛在 ``protocol.tool_schema_from_spec``），不重写工具定义。

传输：stdio（NDJSON，一行一消息）。推荐入口 ``python -m src.mcp``（无 runpy 告警）；
``python -m src.mcp.server`` 亦可，但会有一条无害的 sys.modules 告警。也可在测试里对
``handle_message`` 做纯函数级驱动。
"""
from __future__ import annotations

import os
import sys
from typing import Any, Callable, Dict, List, Optional

from . import protocol as P
from .protocol import MCP_PROTOCOL_VERSION

# 只读查询的行数上限：对外服务必须自带预算，防止外部 agent 一次拉全库。
_MAX_LIMIT = 500


def _opt_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _clamp_limit(value: Any, default: int) -> int:
    n = _opt_int(value)
    if n is None:
        n = default
    return max(1, min(int(n), _MAX_LIMIT))


class PlatformDataProvider:
    """平台侧数据源抽象。默认只读；写方法未实现即视为「本部署未启用」。"""

    # ---- 只读 ----
    def findings(self, *, workspace_id: Optional[int] = None, task_id: Optional[int] = None,
                 limit: int = 50) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def blackboard(self, *, workspace_id: Optional[int] = None, task_id: Optional[int] = None,
                   limit: int = 200) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def iast_events(self, *, workspace_id: Optional[int] = None, task_id: Optional[int] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        raise NotImplementedError

    # ---- 写（默认未接，需子类覆写 + server.allow_write=True）----
    def trigger_replay(self, *, task_id: int, finding_id: Optional[int] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def submit_rule_candidate(self, *, family: str, rule_expression: str,
                              prompt_fragment: str = "",
                              workspace_id: Optional[int] = None) -> Dict[str, Any]:
        raise NotImplementedError


class SqlitePlatformDataProvider(PlatformDataProvider):
    """默认（只读）数据源：直连 app.db 做参数化查询，写方法不实现。

    沿用全仓约定 ``SAST_AI_DB_PATH`` 环境变量优先、默认 ``data/app.db``。
    """

    # 表 -> 白名单列（只暴露对外有意义的列，避免把 raw_json 等大字段全量吐出）。
    _COLS = {
        "findings": ("id, task_id, workspace_id, finding_type, severity, file_path, line, "
                     "title, source, vulnerability_hash_v2, created_at"),
        "vuln_blackboard": ("id, workspace_id, vulnerability_hash_v2, run_id, task_id, family, "
                            "detect_state, confirm_state, sink_reached, verification_status, "
                            "iast_state, target_endpoint, http_method, updated_at"),
        "iast_events": ("id, session_id, workspace_id, task_id, event_type, vuln_type, "
                        "canary_state, sink_file, sink_line, sink_method, severity, "
                        "ingested_at, sink_reached"),
    }

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or os.environ.get("SAST_AI_DB_PATH", "data/app.db")

    def _rows(self, table: str, where: str, args: List[Any], order: str, limit: int) -> List[Dict[str, Any]]:
        from src.infrastructure.db import Database
        conn = Database(self._db_path).connect()
        sql = f"SELECT {self._COLS[table]} FROM {table}"
        if where:
            sql += " WHERE " + where
        sql += f" ORDER BY {order} LIMIT ?"
        cur = conn.execute(sql, [*args, int(limit)])
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _filter(workspace_id: Optional[int], task_id: Optional[int]) -> (str, List[Any]):
        conds: List[str] = []
        args: List[Any] = []
        if workspace_id is not None:
            conds.append("workspace_id = ?")
            args.append(int(workspace_id))
        if task_id is not None:
            conds.append("task_id = ?")
            args.append(int(task_id))
        return (" AND ".join(conds), args)

    def findings(self, *, workspace_id=None, task_id=None, limit=50) -> List[Dict[str, Any]]:
        where, args = self._filter(workspace_id, task_id)
        return self._rows("findings", where, args, "id DESC", limit)

    def blackboard(self, *, workspace_id=None, task_id=None, limit=200) -> List[Dict[str, Any]]:
        where, args = self._filter(workspace_id, task_id)
        return self._rows("vuln_blackboard", where, args, "updated_at DESC, id DESC", limit)

    def iast_events(self, *, workspace_id=None, task_id=None, limit=100) -> List[Dict[str, Any]]:
        where, args = self._filter(workspace_id, task_id)
        return self._rows("iast_events", where, args, "id DESC", limit)


class McpTool:
    """一个 MCP 工具：名称 + schema + 处理器 + 读写标记。"""

    __slots__ = ("name", "description", "input_schema", "handler", "read_only")

    def __init__(self, name: str, description: str, input_schema: Dict[str, Any],
                 handler: Callable[[Dict[str, Any]], Any], read_only: bool = True):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler
        self.read_only = bool(read_only)

    def to_mcp(self) -> Dict[str, Any]:
        return P.tool_schema_from_spec(self.name, self.description, self.input_schema)


class McpServer:
    """MCP 服务器：消息分发 + 工具注册 + stdio 传输。"""

    def __init__(self, *, name: str = "savr", version: str = "1.0",
                 provider: Optional[PlatformDataProvider] = None, allow_write: bool = False):
        self.name = name
        self.version = version
        self.provider = provider or SqlitePlatformDataProvider()
        self.allow_write = bool(allow_write)
        self._tools: Dict[str, McpTool] = {}
        register_platform_tools(self)
        register_local_agentic_tools(self)

    # ---- 注册 / 列举 ----
    def register(self, tool: McpTool) -> None:
        self._tools[tool.name] = tool

    def list_tools(self) -> List[Dict[str, Any]]:
        return [t.to_mcp() for t in self._tools.values()]

    # ---- 调用 ----
    def _call_write_gate(self, tool: McpTool) -> Optional[Dict[str, Any]]:
        if tool.read_only or self.allow_write:
            return None
        return {"ok": False, "error": f"写工具 {tool.name} 已禁用（allow_write=False）",
                "hint": "如需启用，请以 allow_write=True 构造 McpServer"}

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """执行工具调用，返回 MCP ``tools/call`` 结果（content + isError）。

        工具级失败（未知工具 / 逻辑 ok=False / 抛异常 / 写门控）一律 isError=True，
        用结果而非 JSON-RPC error 返回，让外部模型看得见并能自行纠偏（MCP 约定）。
        """
        tool = self._tools.get(str(name))
        if tool is None:
            return {"content": [P.text_content({"ok": False, "error": f"未知工具：{name}"})], "isError": True}
        gate = self._call_write_gate(tool)
        if gate is not None:
            return {"content": [P.text_content(gate)], "isError": True}
        try:
            payload = tool.handler(dict(arguments or {}))
        except NotImplementedError:
            payload = {"ok": False, "error": f"工具 {tool.name} 在当前部署未启用（数据源未实现）"}
        except Exception as exc:  # 工具内部异常收敛为 isError，绝不冒泡打断服务
            payload = {"ok": False, "error": str(exc)}
        is_err = isinstance(payload, dict) and payload.get("ok") is False
        return {"content": [P.text_content(payload)], "isError": bool(is_err)}

    # ---- 消息分发 ----
    def handle_message(self, msg: Any) -> Optional[Dict[str, Any]]:
        """处理一条入站消息。返回响应；通知（无 id）返回 None（不写回）。"""
        if not isinstance(msg, dict):
            return P.make_error(None, P.INVALID_REQUEST, "消息必须是 JSON 对象")
        method = msg.get("method")
        req_id = msg.get("id")
        if not method:
            return P.make_error(req_id, P.INVALID_REQUEST, "缺少 method")
        if method == "initialize":
            return P.make_result(req_id, {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": self.version},
            })
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None  # 通知：规范要求不回响应
        if method == "ping":
            return P.make_result(req_id, {})
        if method == "tools/list":
            return P.make_result(req_id, {"tools": self.list_tools()})
        if method == "tools/call":
            params = msg.get("params") or {}
            if not isinstance(params, dict) or not params.get("name"):
                return P.make_error(req_id, P.INVALID_PARAMS, "tools/call 缺少 params.name")
            result = self.call_tool(str(params.get("name")), params.get("arguments") or {})
            return P.make_result(req_id, result)
        # 未知方法：请求回 -32601；通知静默忽略
        if P.has_id(msg):
            return P.make_error(req_id, P.METHOD_NOT_FOUND, f"未实现的方法：{method}")
        return None

    # ---- 传输 ----
    def serve_stdio(self, stdin=None, stdout=None) -> None:
        """stdio 常驻循环：一行一条 JSON-RPC 消息。EOF 即退出。"""
        inp = stdin if stdin is not None else sys.stdin
        out = stdout if stdout is not None else sys.stdout
        for raw in inp:
            line = (raw or "").strip()
            if not line:
                continue
            try:
                msg = P.loads(line)
            except Exception as exc:
                resp: Optional[Dict[str, Any]] = P.make_error(None, P.PARSE_ERROR, f"JSON 解析失败：{exc}")
            else:
                resp = self.handle_message(msg)
            if resp is not None:
                out.write(P.dumps(resp) + "\n")
                out.flush()


# ---- 平台工具注册 ----

def _schema(props: Dict[str, Any], required: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"type": "object", "properties": props, "required": required or []}


def register_platform_tools(server: McpServer) -> None:
    """把平台 5 个能力注册为标准 MCP tools。"""
    p = server.provider

    def _get_findings(a: Dict[str, Any]) -> Dict[str, Any]:
        rows = p.findings(workspace_id=_opt_int(a.get("workspace_id")),
                          task_id=_opt_int(a.get("task_id")),
                          limit=_clamp_limit(a.get("limit"), 50))
        return {"ok": True, "read_only": True, "count": len(rows), "findings": rows}

    def _get_blackboard(a: Dict[str, Any]) -> Dict[str, Any]:
        rows = p.blackboard(workspace_id=_opt_int(a.get("workspace_id")),
                            task_id=_opt_int(a.get("task_id")),
                            limit=_clamp_limit(a.get("limit"), 200))
        return {"ok": True, "read_only": True, "count": len(rows), "blackboard": rows}

    def _get_iast_events(a: Dict[str, Any]) -> Dict[str, Any]:
        rows = p.iast_events(workspace_id=_opt_int(a.get("workspace_id")),
                             task_id=_opt_int(a.get("task_id")),
                             limit=_clamp_limit(a.get("limit"), 100))
        return {"ok": True, "read_only": True, "count": len(rows), "events": rows}

    def _trigger_replay(a: Dict[str, Any]) -> Dict[str, Any]:
        task_id = _opt_int(a.get("task_id"))
        if task_id is None:
            return {"ok": False, "error": "trigger_replay 需要 task_id"}
        return p.trigger_replay(task_id=task_id, finding_id=_opt_int(a.get("finding_id")))

    def _submit_rule_candidate(a: Dict[str, Any]) -> Dict[str, Any]:
        family = str(a.get("family") or "").strip()
        expr = str(a.get("rule_expression") or "").strip()
        if not family or not expr:
            return {"ok": False, "error": "submit_rule_candidate 需要 family 与 rule_expression"}
        return p.submit_rule_candidate(family=family, rule_expression=expr,
                                       prompt_fragment=str(a.get("prompt_fragment") or ""),
                                       workspace_id=_opt_int(a.get("workspace_id")))

    server.register(McpTool(
        "get_findings", "读取平台 findings（按 workspace/task 过滤，只读）",
        _schema({"workspace_id": {"type": "integer"}, "task_id": {"type": "integer"},
                 "limit": {"type": "integer", "description": "返回条数，上限 500"}}),
        _get_findings, read_only=True))

    server.register(McpTool(
        "get_blackboard", "读取 vuln_blackboard（漏洞黑板，按 workspace/task 过滤，只读）",
        _schema({"workspace_id": {"type": "integer"}, "task_id": {"type": "integer"},
                 "limit": {"type": "integer", "description": "返回条数，上限 500"}}),
        _get_blackboard, read_only=True))

    server.register(McpTool(
        "get_iast_events", "读取 iast_events（运行时探针事件，按 workspace/task 过滤，只读）",
        _schema({"workspace_id": {"type": "integer"}, "task_id": {"type": "integer"},
                 "limit": {"type": "integer", "description": "返回条数，上限 500"}}),
        _get_iast_events, read_only=True))

    server.register(McpTool(
        "trigger_replay", "触发指定 task 的 D1 重放（写操作，默认禁用，需 allow_write=True）",
        _schema({"task_id": {"type": "integer"}, "finding_id": {"type": "integer"}},
                ["task_id"]),
        _trigger_replay, read_only=False))

    server.register(McpTool(
        "submit_rule_candidate", "提交一条候选检测规则到 staging（写操作，默认禁用，需 allow_write=True）",
        _schema({"family": {"type": "string"}, "rule_expression": {"type": "string"},
                 "prompt_fragment": {"type": "string"}, "workspace_id": {"type": "integer"}},
                ["family", "rule_expression"]),
        _submit_rule_candidate, read_only=False))


def register_local_agentic_tools(server: McpServer) -> None:
    """把 A2 只读 agentic 工具（``a2_tools.TOOL_SCHEMAS``）也暴露为 MCP tools。

    满足设计「复用 _EXECUTORS 白名单与 _safe_path 沙箱，安全模型不用重写」：
    这些工具经 ``a2_tools.execute_tool`` 执行，天然继承其白名单、路径沙箱（限制在项目根内）、
    超时与埋点，不新增任何副作用通道。全部只读，不需要 ``allow_write``。
    与平台工具同名前缀不冲突（本地名如 code_search / read_file）。
    """
    try:
        from src.agents import a2_tools
    except Exception:  # fail-open：工具层不可用时只暴露平台工具
        return
    for spec in a2_tools.TOOL_SCHEMAS:
        nm = str((spec or {}).get("name") or "").strip()
        if not nm or nm in server._tools:
            continue
        server.register(McpTool(
            nm, f"[agentic] {spec.get('description', '')}",
            spec.get("input_schema") or {"type": "object", "properties": {}},
            _make_local_agentic_handler(nm), read_only=True))


def _make_local_agentic_handler(name: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(a: Dict[str, Any]) -> Any:
        from src.agents import a2_tools
        return a2_tools.execute_tool(name, a)
    return _handler


def main() -> None:  # pragma: no cover - 进程入口
    """stdio 入口：``python -m src.mcp``（写工具默认关闭，需 SAST_AI_MCP_ALLOW_WRITE=1）。"""
    allow_write = os.environ.get("SAST_AI_MCP_ALLOW_WRITE", "0") == "1"
    server = McpServer(allow_write=allow_write)
    server.serve_stdio()


if __name__ == "__main__":  # pragma: no cover
    main()
