"""MCP Server stdio 入口（推荐）：``python -m src.mcp``。

比 ``python -m src.mcp.server`` 更干净——后者因包 ``__init__`` 已导入 ``.server``，
runpy 会告警『found in sys.modules ... prior to execution』（无害但噪声）。
写工具默认关闭，需 ``SAST_AI_MCP_ALLOW_WRITE=1`` 显式开启。
"""
from __future__ import annotations

from .server import main

if __name__ == "__main__":
    main()
