"""I2 判因（src/agents/i2_judge.py）单测：两级决策 + 契约校验 + 观察包。

不打真 LLM：规则分支全覆盖，LLM 分支用假 callable 注入（正常 / 字段越界 / 抛错三条路径）。
"""
import json

from src.agents import i2_judge
from src.agents.i2_judge import ObservationPacket, build_packet, decide, llm_decide, rule_decide


def _spec(**kw):
    base = {
        "id": 1, "task_id": 99, "family": "sql_injection",
        "target_endpoint": "/sqli-00/BenchmarkTest00100", "http_method": "POST",
        "param_name": "BenchmarkTest00100", "param_location": "cookie",
        "attack_payloads_json": json.dumps(["' OR '1'='1"]),
        "filter_spec_json": "{}", "oracle_state": "", "oracle_signal": "",
        "verification_status": "unconfirmed",
    }
    base.update(kw)
    return base


def _packet(**kw):
    return build_packet(spec=_spec(**kw), attempts=[], round_no=1)


# ───────────────────────── 观察包 ─────────────────────────

def test_build_packet_parses_json_and_oracle():
    pk = _packet(filter_spec_json=json.dumps({"kind": "deny", "patterns": ["'"]}),
                 oracle_state="exploitable", oracle_signal="boolean_diff")
    assert pk.payloads == ["' OR '1'='1"]
    assert pk.filter_spec["kind"] == "deny"
    assert pk.oracle["verdict"] == "exploitable"
    assert "POST /sqli-00" in json.dumps(pk.to_prompt_dict(), ensure_ascii=False)


def test_build_packet_tolerates_garbage_json():
    pk = _packet(attack_payloads_json="{not json", filter_spec_json="[1,2")
    assert pk.payloads == [] and pk.filter_spec == {}


# ───────────────────────── 第一级：规则 ─────────────────────────

def test_rule_oracle_exploitable_confirms():
    d = rule_decide(_packet(oracle_state="exploitable", oracle_signal="time_delay"))
    assert d["verdict"] == "confirmed" and d["action"] == "give_up" and d["source"] == "rule"


def test_rule_oracle_not_exploitable_is_false_positive():
    d = rule_decide(_packet(oracle_state="not_exploitable", oracle_signal="reflection_escaped"))
    assert d["verdict"] == "false_positive"


def test_rule_no_payload_asks_for_new_payload():
    d = rule_decide(_packet(attack_payloads_json="[]"))
    assert d["action"] == "change_payload" and d["verdict"] == "payload_problem"


def test_rule_property_family_gives_up():
    for fam in ("weak_hash", "weak_crypto", "weak_random", "secure_cookie",
                "insecure crypto algorithm"):
        assert rule_decide(_packet(family=fam))["verdict"] == "false_positive"


def test_rule_ambiguous_returns_none():
    assert rule_decide(_packet()) is None


# ───────────────────────── 契约校验 ─────────────────────────

def test_validate_rejects_out_of_enum():
    assert i2_judge._validate({"verdict": "maybe", "action": "give_up"}) is None
    assert i2_judge._validate({"verdict": "confirmed", "action": "hack"}) is None
    assert i2_judge._validate({"verdict": "confirmed", "action": "change_payload"}) is None  # 缺 payload


def test_validate_accepts_and_normalizes():
    ok = i2_judge._validate({"verdict": "CONFIRMED", "action": "Change_Payload",
                             "payload": "x' OR 1=1", "reason": "r" * 200, "confidence": "1.7"})
    assert ok["verdict"] == "confirmed" and ok["action"] == "change_payload"
    assert ok["confidence"] == 1.0 and len(ok["reason"]) <= 120


# ───────────────────────── 第二级：LLM（注入假实现） ─────────────────────────

class _FakeOllama:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, messages, timeout=120.0):
        self.calls += 1
        out = self.responses.pop(0) if self.responses else ""
        if isinstance(out, Exception):
            raise out
        return out


def test_llm_decide_happy_path():
    fake = _FakeOllama([json.dumps({"verdict": "payload_problem", "action": "change_payload",
                                    "payload": "x'/**/OR/**/1=1", "reason": "被引号净化",
                                    "confidence": 0.8})])
    a2 = __import__("src.agents.a2_integrated_analyst", fromlist=["x"])
    orig = a2.ollama_chat
    a2.ollama_chat = fake
    try:
        d = llm_decide(_packet())
    finally:
        a2.ollama_chat = orig
    assert d["source"] == "llm" and d["action"] == "change_payload" and fake.calls == 1


def test_llm_decide_retries_once_then_falls_back():
    fake = _FakeOllama(["not json at all", "{bad"])
    a2 = __import__("src.agents.a2_integrated_analyst", fromlist=["x"])
    orig = a2.ollama_chat
    a2.ollama_chat = fake
    try:
        d = llm_decide(_packet())
    finally:
        a2.ollama_chat = orig
    assert d["source"] == "fallback" and fake.calls == 2


def test_llm_decide_exception_falls_back():
    fake = _FakeOllama([RuntimeError("boom")])
    a2 = __import__("src.agents.a2_integrated_analyst", fromlist=["x"])
    orig = a2.ollama_chat
    a2.ollama_chat = fake
    try:
        d = llm_decide(_packet())
    finally:
        a2.ollama_chat = orig
    assert d["source"] == "fallback"


def test_decide_two_level_routing():
    # obvious → 规则，不碰 LLM
    fake = _FakeOllama([json.dumps({"verdict": "confirmed", "action": "give_up", "payload": ""})])
    a2 = __import__("src.agents.a2_integrated_analyst", fromlist=["x"])
    orig = a2.ollama_chat
    a2.ollama_chat = fake
    try:
        d = decide(_packet(oracle_state="exploitable", oracle_signal="file_signature"))
        assert d["source"] == "rule" and fake.calls == 0
        # ambiguous → LLM
        d2 = decide(_packet())
        assert d2["source"] == "llm" and fake.calls == 1
        # LLM 关闭 → 保守规则
        d3 = decide(_packet(), llm_enabled=False)
        assert d3["source"] == "rule" and d3["action"] == "adjust_window"
    finally:
        a2.ollama_chat = orig


def test_validate_payload_required_only_for_change_payload():
    """2026-10-25 放宽：只有 change_payload 必须给 payload。

    早期对 change_location 等也强制 payload ⇒ 「LLM 说该换 cookie 位置」被判不合格、
    两次后降级成 adjust_window，最有用的信息被丢掉。
    """
    from src.agents.i2_judge import _validate

    # change_location 不带 payload：合格
    ok = _validate({"verdict": "approach_problem", "action": "change_location",
                    "reason": "该换 cookie 位置", "confidence": 0.7})
    assert ok and ok["action"] == "change_location" and ok["payload"] == ""

    # change_encoding 不带 payload：合格
    ok2 = _validate({"verdict": "payload_problem", "action": "change_encoding",
                     "reason": "编码问题", "confidence": 0.6})
    assert ok2 and ok2["action"] == "change_encoding"

    # change_payload 不带 payload：不合格
    assert _validate({"verdict": "payload_problem", "action": "change_payload",
                      "reason": "换弹"}) is None

    # change_payload 带 payload：合格
    ok3 = _validate({"verdict": "payload_problem", "action": "change_payload",
                     "payload": "' OR 1=1--", "reason": "换弹"})
    assert ok3 and ok3["payload"] == "' OR 1=1--"

    # 越界动作/判因仍然拒绝
    assert _validate({"verdict": "confirmed", "action": "nuke"}) is None
    assert _validate({"verdict": "maybe", "action": "give_up"}) is None
