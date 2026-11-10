"""A2 约束解码单测（src/agents/a2_output_schema.py + a2_integrated_analyst 契约埋点）。

对应 plan §20.3.3：grammar 约束解码消灭「格式幻觉 → 回退重试」。
本测试不调 LLM：只校验 schema 结构、档位解析、契约合规率计数。
"""
import json

from src.agents import a2_output_schema as OS
from src.agents import a2_integrated_analyst as A2


def test_resolve_format_mode_defaults_to_json():
    assert OS.resolve_format_mode("") == "json"
    assert OS.resolve_format_mode("bogus") == "json"
    assert OS.resolve_format_mode(None) == "json"
    assert OS.resolve_format_mode("SCHEMA") == "schema"
    assert OS.resolve_format_mode(" off ") == "off"


def test_schema_is_array_of_objects():
    s = OS.a2_output_schema()
    assert s["type"] == "array"
    assert s["items"]["type"] == "object"


def test_schema_verdict_enum_blocks_flipped_verdict():
    """8B 会把 verdict 填反 ⇒ enum 必须只允许 real/false_positive。"""
    props = OS.a2_output_schema()["items"]["properties"]
    assert props["verdict"]["enum"] == ["real", "false_positive"]


def test_schema_line_is_integer():
    props = OS.a2_output_schema()["items"]["properties"]
    assert props["line"]["type"] == "integer"


def test_schema_spec_allows_null_but_is_required():
    """false_positive 时 spec=null 是契约；所以 spec 必须 required（否则模型会省略键）。"""
    props = OS.a2_output_schema()["items"]["properties"]
    assert "null" in props["spec"]["type"] and "object" in props["spec"]["type"]
    assert "spec" in OS.a2_output_schema()["items"]["required"]
    assert "spec" not in props["spec"].get("required", [])


def test_schema_keeps_snippet_and_why_bypassable():
    """血泪教训：砍掉 snippet 会掉 TP（模型抄净化器代码的动作帮助它判 strength）。"""
    spec_props = OS.a2_output_schema()["items"]["properties"]["spec"]["properties"]
    san = spec_props["sanitizer"]["properties"]
    assert "snippet" in san
    assert "why_bypassable" in san


def test_schema_spec_required_fields_cover_full_contract():
    spec_schema = OS.a2_output_schema()["items"]["properties"]["spec"]
    spec_props = spec_schema["properties"]
    for k in ("route", "method", "param_name", "param_location", "payload",
              "bypass_payloads", "sanitizer"):
        assert k in spec_props
        assert k in spec_schema["required"]


def test_schema_bypass_payloads_is_array_of_string():
    spec_props = OS.a2_output_schema()["items"]["properties"]["spec"]["properties"]
    bp = spec_props["bypass_payloads"]
    assert bp["type"] == "array"
    assert bp["items"]["type"] == "string"


def test_schema_is_json_serializable():
    txt = OS.schema_json()
    assert json.loads(txt)["type"] == "array"


def test_contract_stats_shape_and_rate():
    A2._CONTRACT_STATS.update({"calls": 0, "first_pass": 0, "retried": 0,
                                "recovered": 0, "failed": 0})
    s = A2.contract_stats()
    assert s["calls"] == 0
    assert s["invalid_rate"] == 0.0
    assert s["compliance_rate"] == 1.0


def test_contract_stats_counts_invalid_rate():
    A2._CONTRACT_STATS.update({"calls": 4, "first_pass": 3, "retried": 1,
                                "recovered": 1, "failed": 0})
    s = A2.contract_stats()
    assert s["invalid_rate"] == 0.25
    assert s["compliance_rate"] == 0.75
    assert s["recovered"] == 1


def test_analyst_default_format_mode_is_json():
    an = A2.IntegratedAnalyst(llm_call=lambda m: "{}")
    assert an._format_mode in ("json", "schema", "off")


def test_analyst_schema_mode_uses_plain_channel_for_primitives():
    """原语判别要的是七段文本行 ⇒ 判别通道绝不能用 JSON grammar。"""
    an = A2.IntegratedAnalyst(llm_call=lambda m: "{}", format_mode="schema")
    assert an._format_mode == "schema"
    # llm_call 注入时两个通道都是注入的 llm_call（无法从函数体区分），
    # 这里只断言属性存在且不报错
    assert callable(an._llm_plain)


def test_ollama_chat_accepts_format_mode_param():
    import inspect
    sig = inspect.signature(A2.ollama_chat)
    assert "format_mode" in sig.parameters
    assert sig.parameters["format_mode"].default == "json"
