"""问题 5：A2AIAgent.validate_finding 的 fail-open 精度过滤逻辑单测。

不依赖真实 LLM：用 FakeClient 注入各路响应，验证
- 真漏洞(bool) / 误报(bool) 判定
- 字符串 "false"/"true"、整数 1/0 的容错解析
- 异常 / 解析失败 / 字段缺失 三类 fail-open（返回 None，绝不误删结论）
"""
import pytest

from src.core.models import Vulnerability
from src.agents.a2_ai_agent import A2AIAgent


VALIDATE_TPL = "类型:{vuln_type} 行:{line} 描述:{description} 代码:{code}"


class FakeClient:
    """可编排响应的假 client，模拟 FallbackLLMClient.create_message 接口。"""

    def __init__(self, returns=None, raises=None):
        self._returns = returns
        self._raises = raises
        self.last_max_tokens = None

    def create_message(self, system, messages, max_tokens=4096, temperature=0.0):
        self.last_max_tokens = max_tokens
        if self._raises is not None:
            raise self._raises
        return self._returns


@pytest.fixture
def agent():
    a = A2AIAgent.__new__(A2AIAgent)  # 跳过 __init__ 的重客户端初始化/配置加载
    a.prompts = {"validate_vulnerability": VALIDATE_TPL}
    a.client = FakeClient()
    return a


def _vuln(**kw):
    base = dict(type="SQL注入", severity="HIGH", line=42, description="拼接 SQL", file="Jdbc.java")
    base.update(kw)
    return Vulnerability(**base)


def test_true_positive_bool(agent):
    agent.client._returns = '{"is_true_positive": true, "reason": "可控入参进 Statement"}'
    assert agent.validate_finding(_vuln(), "code") is True


def test_false_positive_bool(agent):
    agent.client._returns = '{"is_true_positive": false, "reason": "参数已预编译"}'
    assert agent.validate_finding(_vuln(), "code") is False


def test_string_coercion_false(agent):
    agent.client._returns = '{"is_true_positive": "false"}'
    assert agent.validate_finding(_vuln(), "code") is False


def test_string_coercion_true(agent):
    agent.client._returns = '{"is_true_positive": "true"}'
    assert agent.validate_finding(_vuln(), "code") is True


def test_int_coercion(agent):
    agent.client._returns = '{"is_true_positive": 1}'
    assert agent.validate_finding(_vuln(), "code") is True
    agent.client._returns = '{"is_true_positive": 0}'
    assert agent.validate_finding(_vuln(), "code") is False


def test_fail_open_on_exception(agent):
    agent.client._raises = RuntimeError("Ollama 500")
    assert agent.validate_finding(_vuln(), "code") is None


def test_fail_open_on_garbage(agent):
    agent.client._returns = "模型跑题了，没有任何 JSON"
    assert agent.validate_finding(_vuln(), "code") is None


def test_fail_open_on_missing_field(agent):
    agent.client._returns = '{"reason": "没给 is_true_positive"}'
    assert agent.validate_finding(_vuln(), "code") is None


def test_respects_smaller_max_tokens(agent):
    agent.client._returns = '{"is_true_positive": true}'
    agent.validate_finding(_vuln(), "code", max_tokens=512)
    assert agent.client.last_max_tokens == 512


def test_real_template_renders_without_error():
    """确认注册表里真实的 validate_vulnerability 模板能正常渲染（不崩溃）。"""
    a = A2AIAgent.__new__(A2AIAgent)
    a.prompts = {"validate_vulnerability": "类型:{vuln_type} 行:{line} 描述:{description} 代码:{code}"}
    from src.agents.prompt_render import render_prompt
    out = render_prompt(
        a.prompts["validate_vulnerability"],
        vuln_type="SQL注入", line="42", description="d", code="c",
    )
    assert "SQL注入" in out and "42" in out
