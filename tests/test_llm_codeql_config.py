"""配置接线测试：CodeQL bin 路径 / GLM gateway 从根配置激活；D1 AI 语义复核门禁。

核心保证：
1. 缺失 LLM/CodeQL 配置时，所有模块自动回落离线（与既有 359 基线行为一致，可测试）。
2. 根 config.yaml 带 GLM key + codeql.bin_path 时，Agent 构造出「在线」gateway 与可用 CodeQLAdapter。
3. D1 的 AI 语义复核是 best-effort：无 gateway / gateway 离线 / 解析失败时一律回落启发式，
   绝不改变确定性重放结果（保证既有测试不退化）。
"""
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

import pytest

from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.agents.a1_codeql_semantic_agent import A1CodeQLSemanticAgent
from src.agents.a1_business_logic_ai_agent import A1BusinessLogicAIAgent
from src.core.model_gateway import ModelGateway, gateway_from_config
from src.application.d1_service import D1Service
from src.iast.orchestrator import DastImpact


# ---------------- CodeQLAdapter：bin 路径解析 ----------------
def test_codeql_adapter_uses_existing_bin(monkeypatch):
    # 2026-10-20：CodeQL 默认禁用，本测试验 bin 存在性，需显式开启。
    monkeypatch.setenv("SAST_AI_ENABLE_CODEQL", "1")
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        path = f.name
    try:
        assert CodeQLAdapter(codeql_bin=path).is_available() is True
        assert CodeQLAdapter(codeql_bin="C:/does/not/exist/codeql.exe").is_available() is False
    finally:
        os.unlink(path)


def test_codeql_adapter_env_fallback(monkeypatch):
    monkeypatch.delenv("CODEQL_BIN", raising=False)
    # 不存在的 env 路径 → 不可用；存在路径 → 可用
    monkeypatch.setenv("CODEQL_BIN", "C:/no/such/codeql.exe")
    assert CodeQLAdapter().is_available() is False


# ---------------- gateway_from_config：从根配置激活 GLM ----------------
def test_gateway_from_config_empty_is_offline():
    gw = gateway_from_config({})
    assert gw.is_offline is True


def test_gateway_from_config_activates_glm():
    cfg = {
        "llm": {"provider": "anthropic-compatible", "model": "glm-4.5-air"},
        "anthropic_compatible": {
            "api_key": "example-key-for-tests",
            "base_url": "https://open.bigmodel.cn/api/anthropic",
            "model": "glm-4.5-air",
        },
    }
    gw = gateway_from_config(cfg)
    assert gw.is_offline is False
    assert gw.provider == "anthropic-compatible"


def test_gateway_from_config_glm_alias_normalized_with_key():
    # glm 别名应归一到 anthropic-compatible；带 key 时在线
    gw = gateway_from_config({
        "llm": {"provider": "glm"},
        "anthropic_compatible": {"api_key": "k", "base_url": "https://open.bigmodel.cn/api/anthropic"},
    })
    assert gw.provider == "anthropic-compatible"
    assert gw.is_offline is False


def test_gateway_from_config_glm_alias_offline_without_key():
    # glm 别名但无 key → 回落离线（provider 退化为 offline-heuristic）
    gw = gateway_from_config({"llm": {"provider": "glm"}})
    assert gw.is_offline is True


# ---------------- 注入类 / 业务逻辑 Agent：携带配置激活 ----------------
def test_injection_agent_activates_codeql_and_glm_from_config():
    cfg = {
        "a1_use_codeql": True,
        "codeql": {"bin_path": "C:/fake/codeql.exe"},
        "llm": {"provider": "anthropic-compatible", "model": "glm-4.5-air"},
        "anthropic_compatible": {"api_key": "k", "base_url": "https://open.bigmodel.cn/api/anthropic"},
    }
    agent = A1CodeQLSemanticAgent(cfg)
    assert agent._codeql.is_available() is False  # 假路径 → 不可用，符合预期
    assert agent.gateway.is_offline is False  # GLM 在线


def test_business_logic_agent_offline_by_default():
    agent = A1BusinessLogicAIAgent()  # 无 config → 离线兜底
    assert agent.gateway.is_offline is True


def test_business_logic_agent_online_with_glm_config():
    cfg = {
        "llm": {"provider": "anthropic-compatible", "model": "glm-4.5-air"},
        "anthropic_compatible": {"api_key": "k", "base_url": "https://open.bigmodel.cn/api/anthropic"},
    }
    agent = A1BusinessLogicAIAgent(cfg)
    assert agent.gateway.is_offline is False


# ---------------- D1 AI 语义复核：门禁（不破坏确定性重放） ----------------
class _FakeGateway:
    def __init__(self, offline: bool, text: str):
        self.is_offline = offline
        self._text = text

    def complete(self, purpose: str, prompt: str, context: Optional[dict] = None) -> Any:
        class _R:
            pass
        r = _R()
        r.text = self._text
        return r


def _impact(body: str = "ok", status: int = 200):
    return DastImpact(reached=True, status_code=status, body=body[:2000])


def test_d1_ai_overlay_none_without_gateway():
    svc = D1Service()  # 无 gateway
    assert svc._ai_overlay_judgement("vertical_privesc", {}, _impact()) is None


def test_d1_ai_overlay_none_when_gateway_offline():
    svc = D1Service(gateway=_FakeGateway(offline=True, text="{}"))
    assert svc._ai_overlay_judgement("vertical_privesc", {}, _impact()) is None


def test_d1_ai_overlay_true_when_online_says_true():
    svc = D1Service(gateway=_FakeGateway(offline=False, text='{"verdict": true, "reason": "leaked"}'))
    assert svc._ai_overlay_judgement("vertical_privesc", {"target_endpoint": "/api/x"}, _impact()) is True


def test_d1_ai_overlay_false_when_online_says_false():
    svc = D1Service(gateway=_FakeGateway(offline=False, text='{"verdict": false}'))
    assert svc._ai_overlay_judgement("calculation_logic", {}, _impact()) is False


def test_d1_ai_overlay_none_on_unparseable_response():
    svc = D1Service(gateway=_FakeGateway(offline=False, text="not json at all"))
    assert svc._ai_overlay_judgement("auth_session", {}, _impact()) is None


def test_d1_verify_accepted_surfaces_overlay_fields():
    # 离线 gateway（默认）时 ai_overlay 应为 None，heuristic_confirmed 与 confirmed 一致
    svc = D1Service(gateway=_FakeGateway(offline=True, text="{}"))
    out = svc._verify_accepted(
        {"target_endpoint": "/api/admin", "http_method": "GET"},
        {"service_url": "http://127.0.0.1:1", "auth_context": {"auth_headers": {}}},
        category="vertical_privesc",
    )
    assert out["ai_overlay"] is None
    assert out["confirmed"] == out["heuristic_confirmed"]


def test_d1_verify_accepted_overlay_overrides_when_online():
    svc = D1Service(gateway=_FakeGateway(offline=False, text='{"verdict": false}'))
    # 即便启发式可能判 confirmed（取决于网络），AI=false 必须覆盖为 False
    out = svc._verify_accepted(
        {"target_endpoint": "/api/admin", "http_method": "GET"},
        {"service_url": "http://127.0.0.1:1", "auth_context": {"auth_headers": {}}},
        category="vertical_privesc",
    )
    assert out["ai_overlay"] is False
    assert out["confirmed"] is False
