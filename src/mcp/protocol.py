"""MCP（Model Context Protocol）协议层。

纯标准库实现 JSON-RPC 2.0 + MCP  的核心消息（initialize / tools/list /
tools/call / notifications/initialized），不引入任何第三方依赖，供

  - 二期 对外 MCP Server（``src/mcp/server.py``）
  - 三期 对内 MCP Client（``src/mcp/client.py``）

共用。两侧都只依赖本模块的消息构造/解析，保证「一份协议、两处口径一致」。

设计要点（改动前必读）：

1. **帧格式**：stdio 传输按「行分隔 JSON（NDJSON）」收发，一行一消息。JSON 内不允许出现
   裸换行（``json.dumps`` 默认即转义换行），故按行切分是安全的。
2. **通知 vs 请求**：通知（notification）**没有 id**，接收方不得回响应；服务器处理通知时
   返回 ``None``，由传输层负责不写回。带 id 的才回响应。
3. **错误码**严格按 JSON-RPC 2.0：-32700 解析错误 / -32600 非法请求 / -32601 方法不存在 /
   -32602 参数非法 / -32603 内部错误。工具执行失败走 ``tools/call`` 的 ``isError=True``
   结果（不是 JSON-RPC error），这是 MCP 的约定——工具级失败要让模型看见并自行纠偏。
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

JSONRPC_VERSION = "2.0"
# 与  版 MCP 对齐；tools 能力是本期依赖的唯一 capability。
MCP_PROTOCOL_VERSION = "2024-11-05"

# JSON-RPC 2.0 标准错误码
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def make_result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    """构造成功响应。"""
    return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "result": result or {}}


def make_error(req_id: Any, code: int, message: str,
               data: Optional[Any] = None) -> Dict[str, Any]:
    """构造错误响应。``data`` 为可选补充信息（不参与协议判定，仅调试用）。"""
    err: Dict[str, Any] = {"code": int(code), "message": str(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": req_id, "error": err}


def make_request(req_id: Any, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """构造请求（带 id，需对方回响应）。"""
    msg: Dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": req_id, "method": str(method)}
    if params is not None:
        msg["params"] = params
    return msg


def make_notification(method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """构造通知（无 id，对方不回响应）。"""
    msg: Dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": str(method)}
    if params is not None:
        msg["params"] = params
    return msg


def has_id(msg: Any) -> bool:
    """是否带 id（即是否为需要回响应的请求）。通知不带 id。"""
    return isinstance(msg, dict) and "id" in msg


def is_request(msg: Any) -> bool:
    """是否为合法 JSON-RPC 请求（有 method 且有 id）。"""
    return isinstance(msg, dict) and "method" in msg and has_id(msg)


def is_notification(msg: Any) -> bool:
    """是否为 JSON-RPC 通知（有 method 但无 id）。"""
    return isinstance(msg, dict) and "method" in msg and not has_id(msg)


def dumps(msg: Any) -> str:
    """序列化为单行 JSON（不转义非 ASCII，便于人读；换行被 JSON 转义，不破坏 NDJSON 帧）。"""
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":"))


def loads(line: str) -> Any:
    """解析一行 JSON。非法输入抛 ``ValueError``（由调用方收敛为 -32700）。"""
    return json.loads(line)


def tool_schema_from_spec(name: str, description: str, input_schema: Dict[str, Any]) -> Dict[str, Any]:
    """把内部工具定义映射为 MCP ``tools/list`` 元素（``input_schema`` → ``inputSchema``）。

    内部 ``a2_tools.TOOL_SCHEMAS`` 用 ``input_schema``（snake）；MCP 用 ``inputSchema``
    （camel）。集中在此转换，避免两处口径漂移。
    """
    return {
        "name": str(name),
        "description": str(description or ""),
        "inputSchema": dict(input_schema or {"type": "object", "properties": {}}),
    }


def text_content(payload: Any) -> Dict[str, Any]:
    """把任意可 JSON 化的结果包成 MCP ``tools/call`` 的 content 元素。

    非字符串一律 JSON 序列化——工具返回的是结构化数据，模型侧需要可解析文本。
    """
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, ensure_ascii=False, default=str)
    return {"type": "text", "text": text}
