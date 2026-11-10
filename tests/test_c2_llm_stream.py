"""C2 流式（SSE）调用层单测 —— 本地 SSE mock 服务，不依赖真实 provider。

覆盖 C2-流式异步介绍-2026-09-18.md 第五节第 5 条「验证方式」：
- SSE 分块拼接（增量语义 / 累积全文语义）
- ttfb_ms 与 chunk_count 埋点
- chunk 间 idle 超时（把整体读超时语义改成 idle 的关键行为）
- SAST_AI_LLM_STREAM=0 时回退到一次性 JSON 响应
- 非流式响应（provider 不支持 stream）兼容解析
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src.agents import a2_ai_agent


# ---------------------------------------------------------------- mock server

class _SSEServer(HTTPServer):
    """可配置的 mock 服务：mode 决定返回形态，events 决定 SSE 内容。"""

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.mode = "anthropic"       # anthropic | openai | json
        self.events = []
        self.idle_after = 0.0         # 首个事件后挂起多少秒（模拟 provider 卡住）
        self.last_payload = None
        self.json_body = {}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):  # 静音，避免污染测试输出
        pass

    def do_POST(self):
        srv = self.server
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            srv.last_payload = json.loads(raw or b"{}")
        except ValueError:
            srv.last_payload = {}

        if srv.mode == "json":
            body = json.dumps(srv.json_body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for idx, event in enumerate(srv.events):
            chunk = f"data: {json.dumps(event)}\n\n".encode("utf-8")
            self.wfile.write(chunk)
            self.wfile.flush()
            if idx == 0 and srv.idle_after:
                # 首块后挂起：用于验证「chunk 间 idle 超时」而非整体读超时
                time.sleep(srv.idle_after)
        self.wfile.flush()


@pytest.fixture
def server():
    srv = _SSEServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def _anthropic_events(texts):
    events = [{"type": "message_start", "message": {}}]
    events += [
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": t}}
        for t in texts
    ]
    events.append({"type": "message_stop"})
    return events


def _openai_events(texts):
    events = [{"choices": [{"delta": {"content": t}, "finish_reason": None}]} for t in texts]
    events.append({"choices": [{"delta": {}, "finish_reason": "stop"}]})
    return events


# ---------------------------------------------------------------- cases

def test_anthropic_stream_concatenates_and_instruments(server):
    server.mode = "anthropic"
    server.events = _anthropic_events(["Hello", " ", "world"])

    client = a2_ai_agent.AnthropicClient(api_key="k")
    client.base_url = f"http://127.0.0.1:{server.server_address[1]}"

    out = client.create_message("sys", [{"role": "user", "content": "hi"}])
    assert out == "Hello world", "SSE 增量片段应拼接为完整文本"

    # 埋点：C2 第五节第 4 条
    tele = client.last_call_telemetry
    assert tele["streamed"] is True
    assert tele["chunk_count"] == 3
    assert tele["ttfb_ms"] >= 0
    assert tele["elapsed_ms"] >= 0
    # payload 必须带 stream=True，否则服务端不会走 SSE
    assert server.last_payload.get("stream") is True


def test_openai_stream_concatenates(server):
    server.mode = "openai"
    server.events = _openai_events(["foo", "-bar"])

    client = a2_ai_agent.OpenAIChatClient(api_key="k", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1")
    out = client.create_message("sys", [{"role": "user", "content": "hi"}])
    assert out == "foo-bar"
    assert client.last_call_telemetry["chunk_count"] == 2


def test_stream_handles_accumulated_full_text(server):
    """部分 provider 每段回传「至今累积全文」而非增量，不应重复拼接。"""
    server.mode = "openai"
    server.events = _openai_events(["Hel", "Hell", "Hello"])

    client = a2_ai_agent.OpenAIChatClient(api_key="k", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1")
    out = client.create_message("sys", [{"role": "user", "content": "hi"}])
    assert out == "Hello", "累积全文语义下重复拼接会得到 HelHellHello"


def test_idle_timeout_aborts_stream(monkeypatch, server):
    """provider 首块后卡住：应由 chunk idle 上限中断，而不是等整体读超时。"""
    server.mode = "openai"
    server.events = _openai_events(["start"])
    server.idle_after = 3.0

    monkeypatch.setattr(a2_ai_agent, "LLM_IDLE_TIMEOUT", 1)
    client = a2_ai_agent.OpenAIChatClient(api_key="k", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1")

    started = time.perf_counter()
    with pytest.raises(Exception) as excinfo:
        client.create_message("sys", [{"role": "user", "content": "hi"}])
    elapsed = time.perf_counter() - started
    assert elapsed < 3.0, f"应在 idle 上限（1s）附近中断，实际耗时 {elapsed:.1f}s"
    assert "timed out" in str(excinfo.value).lower() or "timeout" in str(excinfo.value).lower()


def test_stream_disabled_falls_back_to_json(monkeypatch, server):
    server.mode = "json"
    server.json_body = {"content": [{"text": "plain-response"}]}

    monkeypatch.setenv("SAST_AI_LLM_STREAM", "0")
    client = a2_ai_agent.AnthropicClient(api_key="k")
    client.base_url = f"http://127.0.0.1:{server.server_address[1]}"

    out = client.create_message("sys", [{"role": "user", "content": "hi"}])
    assert out == "plain-response"
    assert client.last_call_telemetry["streamed"] is False
    assert "stream" not in server.last_payload, "关闭流式后不应再带 stream 字段"


def test_non_sse_response_still_parsed(server):
    """provider 忽略 stream 参数直接返回 JSON 时，按一次性响应解析，不报错。"""
    server.mode = "json"
    server.json_body = {"choices": [{"message": {"content": "no-stream-support"}}]}

    client = a2_ai_agent.OpenAIChatClient(api_key="k", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1")
    out = client.create_message("sys", [{"role": "user", "content": "hi"}])
    assert out == "no-stream-support"
    assert client.last_call_telemetry["streamed"] is False


def test_reasoning_fallback_for_deepseek_style(server):
    """推理型模型：正文为空时回退思维链（沿用原非流式语义），绝不返回空串。"""
    server.mode = "openai"
    server.events = [
        {"choices": [{"delta": {"reasoning_content": "think..."}, "finish_reason": None}]},
        {"choices": [{"delta": {}, "finish_reason": "stop"}]},
    ]
    client = a2_ai_agent.DeepseekClient(api_key="k", base_url=f"http://127.0.0.1:{server.server_address[1]}/v1")
    out = client.create_message("sys", [{"role": "user", "content": "hi"}])
    assert out == "think..."
    # 思维链不进埋点
    assert "reasoning_text" not in client.last_call_telemetry
