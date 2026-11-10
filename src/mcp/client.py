"""三期：对内 MCP Client（§4.2，2026-09-20）。

让本平台 agentic 能调用**外部** MCP 工具（CodeQL、Semgrep、依赖库查询等）：

  - McpClient            ：JSON-RPC/MCP 客户端，initialize / list_tools / call_tool
  - InProcessTransport   ：进程内直连 McpServer（测试与同进程复用；确定性、无子进程）
  - StdioTransport       ：拉起外部 MCP server 子进程，NDJSON 收发（真实外部工具）
  - McpToolBridge        ：把远端 tools 桥接进本地 ``a2_tools`` 统一命名空间

命名空间约定：``mcp__<server>__<tool>``（双下划线分隔）。与本地工具名不会撞；
``a2_tools.execute_tool`` 收到该前缀即路由到本模块注册的远端执行器。

**工具级超时**（三期硬要求）：``call_tool`` 的 ``timeout`` 参数是端到端超时——从写出请求到
拿到对应 id 的响应。stdio 传输用后台读线程 + 队列实现，超时即放弃该次调用（返回结构化错误），
不会让 agentic loop 卡在外部工具上（对齐一期 ``a2_tools.execute_tool`` 的超时语义）。
"""
from __future__ import annotations

import os
import queue
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

from . import protocol as P
from .protocol import MCP_PROTOCOL_VERSION

# 对外部 MCP 工具的默认端到端超时（秒）。外部进程不可控，超时必须比本地工具更宽容一点，
# 但仍要有硬上限，避免 agentic loop 被外部工具 hang 死。
DEFAULT_TOOL_TIMEOUT = float(os.environ.get("SAST_AI_MCP_TOOL_TIMEOUT", "20") or 20)
DEFAULT_RPC_TIMEOUT = float(os.environ.get("SAST_AI_MCP_RPC_TIMEOUT", "30") or 30)


class McpError(RuntimeError):
    """MCP 调用失败（协议错误 / 传输错误 / 超时）。"""


class McpTransport:
    """传输抽象：request 返回 result；notify 发通知（无响应）。"""

    def request(self, method: str, params: Optional[Dict[str, Any]], timeout: float) -> Dict[str, Any]:
        raise NotImplementedError

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass


class InProcessTransport(McpTransport):
    """进程内直连 McpServer。同步、确定性，``timeout`` 不适用（调用即返回）。"""

    def __init__(self, server):
        self._server = server
        self._next_id = 0

    def request(self, method: str, params: Optional[Dict[str, Any]], timeout: float) -> Dict[str, Any]:
        self._next_id += 1
        resp = self._server.handle_message(P.make_request(self._next_id, method, params))
        if not isinstance(resp, dict):
            raise McpError(f"MCP 方法 {method} 未返回响应")
        if "error" in resp:
            err = resp["error"] or {}
            raise McpError(f"{err.get('message')}（code={err.get('code')}）")
        return resp.get("result") or {}

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        self._server.handle_message(P.make_notification(method, params))


class StdioTransport(McpTransport):
    """stdio 传输：拉起外部 MCP server 子进程，NDJSON 收发，按 id 匹配响应。"""

    def __init__(self, command: List[str], cwd: Optional[str] = None,
                 env: Optional[Dict[str, str]] = None):
        if not command:
            raise ValueError("StdioTransport 需要 command")
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        self._proc = subprocess.Popen(
            command, cwd=cwd, env=full_env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", bufsize=1,
        )
        self._next_id = 0
        self._lock = threading.Lock()
        self._inbox: "queue.Queue[Any]" = queue.Queue()
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        try:
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    self._inbox.put(P.loads(line))
                except Exception:
                    continue
        finally:
            self._inbox.put(None)  # 结束哨兵

    def request(self, method: str, params: Optional[Dict[str, Any]], timeout: float) -> Dict[str, Any]:
        if self._closed:
            raise McpError("传输已关闭")
        with self._lock:
            self._next_id += 1
            req_id = self._next_id
            msg = P.make_request(req_id, method, params)
            try:
                assert self._proc.stdin is not None
                self._proc.stdin.write(P.dumps(msg) + "\n")
                self._proc.stdin.flush()
            except Exception as exc:
                raise McpError(f"写入外部 MCP server 失败：{exc}")
        deadline = time.perf_counter() + max(0.001, float(timeout))
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise McpError(f"MCP 方法 {method} 超时（>{timeout:.1f}s）")
            try:
                item = self._inbox.get(timeout=remaining)
            except queue.Empty:
                raise McpError(f"MCP 方法 {method} 超时（>{timeout:.1f}s）")
            if item is None:
                raise McpError("外部 MCP server 已退出")
            # 只取 id 匹配的响应；忽略通知/其他响应（并发请求场景）
            if isinstance(item, dict) and item.get("id") == req_id:
                if "error" in item:
                    err = item["error"] or {}
                    raise McpError(f"{err.get('message')}（code={err.get('code')}）")
                return item.get("result") or {}

    def notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            try:
                assert self._proc.stdin is not None
                self._proc.stdin.write(P.dumps(P.make_notification(method, params)) + "\n")
                self._proc.stdin.flush()
            except Exception:
                pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=3)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


class McpClient:
    """MCP 客户端：initialize → list_tools → call_tool。"""

    def __init__(self, transport: McpTransport, *, client_name: str = "savr", client_version: str = "1.0"):
        self._transport = transport
        self._client_name = client_name
        self._client_version = client_version
        self.server_info: Dict[str, Any] = {}
        self.protocol_version: str = ""
        self._initialized = False

    def initialize(self, timeout: float = DEFAULT_RPC_TIMEOUT) -> Dict[str, Any]:
        res = self._transport.request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": self._client_name, "version": self._client_version},
        }, timeout=timeout)
        self.server_info = res.get("serverInfo") or {}
        self.protocol_version = str(res.get("protocolVersion") or "")
        self._transport.notify("notifications/initialized")
        self._initialized = True
        return res

    def list_tools(self, timeout: float = DEFAULT_RPC_TIMEOUT) -> List[Dict[str, Any]]:
        res = self._transport.request("tools/list", None, timeout=timeout)
        tools = res.get("tools") or []
        return [t for t in tools if isinstance(t, dict)]

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None,
                  timeout: Optional[float] = None) -> Dict[str, Any]:
        """调用远端工具。``timeout`` 为**工具级端到端超时**（默认 DEFAULT_TOOL_TIMEOUT）。"""
        to = DEFAULT_TOOL_TIMEOUT if timeout is None else float(timeout)
        return self._transport.request("tools/call",
                                       {"name": str(name), "arguments": dict(arguments or {})},
                                       timeout=to)

    def close(self) -> None:
        self._transport.close()


class McpToolBridge:
    """把远端 MCP tools 桥接为本地 ``a2_tools`` 可消费的统一命名空间。

    生成的 schema 形状与 ``a2_tools.TOOL_SCHEMAS`` 一致（``input_schema``，snake），
    名称加前缀 ``mcp__<server>__<tool>``，与本地工具天然不冲突；``executor(name, args)``
    剥掉前缀后调用远端 ``tools/call``。
    """

    def __init__(self, client: McpClient, *, server_name: str = "mcp", prefix: str = "mcp"):
        self._client = client
        self._server_name = server_name
        self._prefix = prefix
        self._remote_names: Dict[str, str] = {}  # local_name -> remote tool name

    def _local_name(self, remote: str) -> str:
        return f"{self._prefix}__{self._server_name}__{remote}"

    def discover(self, timeout: float = DEFAULT_RPC_TIMEOUT) -> List[Dict[str, Any]]:
        """远端 tools/list → 本地 schema 列表（已加前缀）。"""
        out: List[Dict[str, Any]] = []
        for t in self._client.list_tools(timeout=timeout):
            remote = str(t.get("name") or "").strip()
            if not remote:
                continue
            local = self._local_name(remote)
            self._remote_names[local] = remote
            out.append({
                "name": local,
                "description": f"[MCP:{self._server_name}] {t.get('description') or ''}".strip(),
                "input_schema": t.get("inputSchema") or {"type": "object", "properties": {}},
            })
        return out

    def executor(self, name: str, arguments: Dict[str, Any],
                 timeout: Optional[float] = None) -> Dict[str, Any]:
        """执行一个已桥接的远端工具；未注册的名字返回结构化错误（不抛）。"""
        remote = self._remote_names.get(str(name))
        if remote is None:
            return {"ok": False, "error": f"未桥接的 MCP 工具：{name}"}
        try:
            res = self._client.call_tool(remote, arguments, timeout=timeout)
        except McpError as exc:
            return {"ok": False, "error": str(exc), "mcp": True}
        is_err = bool(res.get("isError"))
        return {"ok": not is_err, "mcp": True, "remote_tool": remote, "result": res}
