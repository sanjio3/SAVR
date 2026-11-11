"""外部 MCP server 的启动接线。

**为什么需要这个模块**：三期交付了 ``McpServer`` / ``McpClient`` / ``McpToolBridge`` 与 23 条测试，
但 ``McpToolBridge`` 在全仓**零引用** —— 没有任何调用方，外部 MCP 能力实际不可用（只有机制，
没有接线）。本模块补上这最后一公里。

``load_external_servers(config=None)``：
  1. 读配置段 ``mcp``（``config.yaml``，经 ``core.config`` 单例；也可显式传入）；
  2. ``mcp.enabled != true`` 时**直接返回 disabled** —— 行为与接线前完全一致（默认关闭）；
  3. 逐个 server 起 ``StdioTransport`` → ``McpClient.initialize`` → ``McpToolBridge.discover``；
  4. 汇总后一次 ``a2_tools.register_external_tools`` 注册进统一命名空间
     （工具名 ``mcp__<server>__<tool>``）。

三条硬约束：
  - **幂等**：进程内只加载一次（模块级锁 + flag）；``force=True`` 可重载。
  - **fail-open**：未配置 / 起不来 / 握手失败一律记入 ``errors`` 后继续，**绝不影响主扫描**。
  - **可关闭**：``close_external_servers`` 逐个关掉子进程。

配置样例（``config.yaml``）::

    mcp:
      enabled: true
      servers:
        - name: codeql
          command: ["node", "/opt/codeql-mcp/index.js"]
          cwd: "/opt/codeql-mcp"
          env:
            API_TOKEN: "${CODEQL_MCP_TOKEN}"   # 支持 ${VAR} 展开，避免密钥硬编码进配置
          enabled: true

只用标准库。
"""
from __future__ import annotations

import os
import re
import shlex
import threading
from typing import Any, Dict, List, Optional, Tuple

from src.agents import a2_tools
from src.mcp.client import McpClient, McpToolBridge, StdioTransport

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

_LOCK = threading.RLock()
_STATE: Dict[str, Any] = {
    "attempted": False,
    "enabled": False,
    "servers": [],
    "tools": [],
    "errors": [],
}
# 工具名 -> bridge，供 dispatch 用
_BRIDGES: Dict[str, McpToolBridge] = {}
# 保活：transport 句柄（关闭时用）
_TRANSPORTS: List[Any] = []


def _expand_env(value: Any) -> str:
    """展开 ``${VAR}``；未定义的变量展开为空串（避免把字面量 ``${VAR}`` 传给子进程）。

    注意 ``value is None`` 必须返回空串而不是 ``"None"`` —— 后者会被当成真实路径传给
    ``subprocess.Popen(cwd=...)``，在 Windows 上报 ``NotADirectoryError [WinError 267]``。
    """
    if value is None:
        return ""
    return _ENV_REF.sub(lambda m: os.environ.get(m.group(1), ""), str(value))


def _mcp_config(config: Any) -> Dict[str, Any]:
    """从参数或全局配置取 ``mcp`` 段。"""
    if config is None:
        try:
            from src.core.config import config as _cfg
            return dict(_cfg.get("mcp", {}) or {})
        except Exception:
            return {}
    if isinstance(config, dict):
        if isinstance(config.get("mcp"), dict):
            return dict(config["mcp"])
        # 直接把 mcp 段本身传进来
        if "servers" in config or "enabled" in config:
            return dict(config)
    return {}


def _split_command(raw: Any) -> List[str]:
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw if str(x)]
    if isinstance(raw, str) and raw.strip():
        return shlex.split(raw)
    return []


def _dispatch(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """统一入口：按工具名找到归属 bridge 并执行。未注册的名字返回结构化错误（不抛）。"""
    bridge = _BRIDGES.get(str(name))
    if bridge is None:
        return {"ok": False, "error": f"未桥接的 MCP 工具：{name}"}
    return bridge.executor(str(name), arguments or {})


def get_state() -> Dict[str, Any]:
    """返回当前接线状态的快照（供诊断 / 测试）。"""
    with _LOCK:
        return {
            "attempted": _STATE["attempted"],
            "enabled": _STATE["enabled"],
            "servers": [dict(s) for s in _STATE["servers"]],
            "tools": list(_STATE["tools"]),
            "errors": list(_STATE["errors"]),
        }


def reset_state() -> None:
    """清空接线状态与注册的外部工具（供测试）。不关子进程，如需关闭请先 close。"""
    with _LOCK:
        _STATE.update({"attempted": False, "enabled": False, "servers": [], "tools": [], "errors": []})
        _BRIDGES.clear()
        a2_tools.clear_external_tools()


def close_external_servers() -> None:
    """关掉所有由本模块拉起的外部 MCP server 子进程，并注销工具。"""
    with _LOCK:
        for tr in _TRANSPORTS:
            try:
                tr.close()
            except Exception:
                pass
        _TRANSPORTS.clear()
        _BRIDGES.clear()
        a2_tools.clear_external_tools()
        _STATE["tools"] = []


def load_external_servers(config: Any = None, *, force: bool = False) -> Dict[str, Any]:
    """按配置加载外部 MCP server 并注册其工具；返回接线结果摘要。

    ``force=True`` 时忽略幂等缓存重新加载（会先关闭已拉起的子进程）。
    """
    with _LOCK:
        if _STATE["attempted"] and not force:
            return get_state()
        if force and _TRANSPORTS:
            close_external_servers()

        cfg = _mcp_config(config)
        _STATE.update({"attempted": True, "enabled": bool(cfg.get("enabled")), "servers": []})
        if not _STATE["enabled"]:
            # 默认关闭：不拉任何子进程，行为与接线前一致
            _STATE["tools"] = []
            _STATE["errors"] = []
            return get_state()

        servers = cfg.get("servers") or []
        schemas: List[Dict[str, Any]] = []
        errors: List[str] = []
        for raw in servers:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "").strip() or f"mcp{len(_STATE['servers']) + 1}"
            if raw.get("enabled") is False:
                _STATE["servers"].append({"name": name, "tools": 0, "error": "disabled"})
                continue
            command = _split_command(raw.get("command"))
            if not command:
                msg = f"{name}: command 为空"
                errors.append(msg)
                _STATE["servers"].append({"name": name, "tools": 0, "error": msg})
                continue
            env = {}
            for k, v in (raw.get("env") or {}).items():
                env[str(k)] = _expand_env(v)
            cwd = _expand_env(raw.get("cwd")).strip() or None
            transport = None
            try:
                transport = StdioTransport(command, cwd=cwd, env=env or None)
                client = McpClient(transport, client_name="savr")
                client.initialize()
                bridge = McpToolBridge(client, server_name=name)
                found = bridge.discover()
                _TRANSPORTS.append(transport)
                for sch in found:
                    _BRIDGES[str(sch["name"])] = bridge
                schemas.extend(found)
                _STATE["servers"].append({"name": name, "tools": len(found), "error": ""})
            except Exception as exc:  # fail-open：外部进程不可控，绝不影响主链路
                msg = f"{name}: {type(exc).__name__}: {exc}"
                errors.append(msg)
                _STATE["servers"].append({"name": name, "tools": 0, "error": msg})
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass

        if schemas:
            try:
                a2_tools.register_external_tools(schemas, _dispatch)
            except Exception as exc:
                errors.append(f"register_external_tools 失败：{type(exc).__name__}: {exc}")
                schemas = []
        _STATE["tools"] = [str(s["name"]) for s in schemas]
        _STATE["errors"] = errors
        return get_state()


def ensure_external_tools_loaded(config: Any = None) -> Dict[str, Any]:
    """幂等入口：供扫描链路在启动时调用一次（未配置时零开销）。"""
    return load_external_servers(config, force=False)
