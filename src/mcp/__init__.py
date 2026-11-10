"""MCP 集成（§4.2，2026-09-20）。

  - 二期 对外 MCP Server：``McpServer`` / ``SqlitePlatformDataProvider`` / ``main``
  - 三期 对内 MCP Client：``McpClient`` / ``StdioTransport`` / ``InProcessTransport`` / ``McpToolBridge``
  - 接线：``bootstrap``（按配置拉起外部 MCP server 并注册其工具；**故意不在本文件 import**，
    因为它会 import ``src.agents.a2_tools``，放在这里会引入 import 顺序风险。
    需要时直接 ``from src.mcp.bootstrap import ensure_external_tools_loaded``）
  - 协议层：``protocol``

纯标准库；不 import 任何第三方。写工具默认关闭（``allow_write=False``）。
"""
from __future__ import annotations

from .client import (
    DEFAULT_RPC_TIMEOUT,
    DEFAULT_TOOL_TIMEOUT,
    InProcessTransport,
    McpClient,
    McpError,
    McpToolBridge,
    McpTransport,
    StdioTransport,
)
from .server import (
    McpServer,
    McpTool,
    PlatformDataProvider,
    SqlitePlatformDataProvider,
    register_platform_tools,
)

__all__ = [
    "McpServer", "McpTool", "PlatformDataProvider", "SqlitePlatformDataProvider",
    "register_platform_tools",
    "McpClient", "McpTransport", "InProcessTransport", "StdioTransport",
    "McpToolBridge", "McpError", "DEFAULT_TOOL_TIMEOUT", "DEFAULT_RPC_TIMEOUT",
]
