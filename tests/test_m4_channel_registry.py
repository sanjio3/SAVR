"""M4 D2 通道注册表：证明力分级 / 不短路仲裁 / 重放预算。

每条用例都对着一条具体的设计红线（见 src/core/evidence_channels.py 文件头），
改仲裁逻辑前先跑这里——这里挂了说明「证明力」又被链序或证据缺失绑架了。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core import evidence_channels as ec  # noqa: E402
from src.agents.d2_facade import _verify_sink_result  # noqa: E402


# ── 证明力分级 ──

def test_strength_ordering():
    assert ec.CHANNEL_STRENGTH["oob_callback"] == 4
    assert ec.CHANNEL_STRENGTH["result_point_diff"] == 3
    assert ec.CHANNEL_STRENGTH["semantic_diff"] == 3
    assert ec.CHANNEL_STRENGTH["time_blind"] == 2
    assert ec.CHANNEL_STRENGTH["probe_sink_assert"] == 2
    assert ec.CHANNEL_STRENGTH["code_property"] == 1
    assert ec.CHANNEL_STRENGTH["none"] == 0


def test_priority_is_deterministic():
    """同证明力必须有唯一顺序，否则同一批 spec 两次跑出两种结论。"""
    prios = [ec._CHANNEL_PRIORITY[c] for c in ec.CHANNEL_STRENGTH]
    assert len(prios) == len(set(prios))


# ── 不短路仲裁 ──

def test_no_short_circuit_all_channels_run():
    """适用通道全跑，不短路：语义差分成立时探针通道也留下了产出。"""
    v = _verify_sink_result(
        {"state": "business-logic-confirmed"},
        {"reached": True, "business_logic": {"confirmed": True, "category": "bola"}},
        "bola",
    )
    names = [c["channel"] for c in v["evidence_channels"]]
    assert "semantic_diff" in names
    assert "probe_sink_assert" in names
    assert "none" in names


def test_higher_strength_wins_over_probe_assert():
    """语义差分（3）必须盖过探针断言（2）——原 if-return 链做不到这件事。"""
    v = _verify_sink_result(
        {"state": "sink-reached-probe", "sink_file": "java.lang.Runtime.exec"},
        {"reached": True, "status_code": 200,
         "business_logic": {"confirmed": True, "category": "bola"}},
        "bola",
    )
    assert v["primary_channel"] == "semantic_diff"
    assert v["evidence_strength"] == 3
    assert v["harmful"] is True


def test_time_blind_beats_none_fallback():
    """时间盲注（2）必须盖过兜底（0）——原链序里它在 fallback 之前，不能回退。"""
    v = _verify_sink_result(
        {"state": "no-arrival"},
        {"reached": False, "sleep_seconds_hint": 3, "elapsed_ms": 3200,
         "baseline_elapsed_ms": 120},
        "sqli",
    )
    assert v["primary_channel"] == "time_blind"
    assert v["evidence_strength"] == 2
    assert v["harmful"] is True


def test_absence_of_evidence_is_not_evidence_of_absence():
    """带外没收到回调是 definitive=False，绝不能把探针的正向结论推翻。"""
    v = _verify_sink_result(
        {"state": "sink-reached-probe", "sink_file": "java.lang.Runtime.exec",
         "oob": {"token": "tok-no-callback"}},
        {"reached": True, "status_code": 200},
        "command_execution",
    )
    oob = next(c for c in v["evidence_channels"] if c["channel"] == "oob_callback")
    assert oob["definitive"] is False
    assert v["harmful"] is True
    assert "oob_callback" not in v["conflicting_channels"]


def test_probe_fallback_is_not_definitive():
    """探针没断言 = 证据缺失，不是无害证据（否则会压过时间盲注复刻旧链序）。"""
    out = ec._EVALUATORS["probe_sink_assert"]({
        "family": "", "iast": {"state": "no-arrival"}, "dast": {"reached": False},
        "facts": {}, "spec": {},
    })
    assert out["definitive"] is False


def test_conflict_marking_excludes_none():
    """兜底通道恒为 harmful=False，把它算冲突会给每条确认都打上假冲突。"""
    v = _verify_sink_result(
        {"state": "sink-reached-probe", "sink_file": "java.lang.Runtime.exec"},
        {"reached": True, "status_code": 200},
        "command_execution",
    )
    assert v["harmful"] is True
    assert v["conflicting_channels"] == []


def test_conflict_marking_real_conflict():
    """真冲突要留痕：代码属性说不算可利用、探针说有害，两方都记下来。"""
    v = _verify_sink_result(
        {"state": "sink-reached", "sink_file": "java.util.Random.nextInt"},
        {"reached": True, "status_code": 200},
        "weak_random",
    )
    names = [c["channel"] for c in v["evidence_channels"]]
    assert "code_property" in names
    assert "code_property" in v["conflicting_channels"]
    assert v["channel_conflict"] is True


# ── 重放预算 ──

def test_budget_reserves_baseline():
    """5 次预算含基线 → 可用额度 4。"""
    p = ec.plan_channels("sqli", budget=5)
    assert p["usable"] == 4
    assert p["baseline_cost"] == 1


def test_budget_drops_lowest_strength_first():
    """预算不够时按证明力从低到高砍：先砍时间盲注（2），保住带外（4）。"""
    p = ec.plan_channels("command_execution", budget=2)   # 可用额度仅 1
    assert "oob_callback" in p["planned"]
    assert any(d["channel"] == "time_blind" for d in p["dropped"])
    assert all(d["reason"] == "over_budget" for d in p["dropped"])


def test_budget_never_drops_free_or_probe_channel():
    """探针断言代价 0（复用 canary 主重放），任何预算下都不该被砍。"""
    for b in (1, 2, 3, 5):
        assert "probe_sink_assert" in ec.plan_channels("sqli", budget=b)["planned"]


def test_dropped_channel_recorded_as_not_attempted():
    """被预算砍掉的通道要标 dropped_over_budget，别被对账读成「投了没打中」。"""
    outcomes = ec.evaluate_all("command_execution", {}, {}, budget=2)
    rec = next(o for o in outcomes if o["channel"] == "time_blind")
    assert rec.get("dropped_over_budget") is True
    assert rec["definitive"] is False


def test_plan_cost_within_budget():
    for fam in ("sqli", "bola", "xss", "weak_random", "deserialization", "command_execution"):
        p = ec.plan_channels(fam, budget=5)
        assert p["spend"] <= p["usable"], fam


# ── 向后兼容 ──

def test_verdict_keeps_legacy_keys():
    """下游 _build_verification_result / _confirm_gate_decide 读这五个键，一个都不能少。"""
    v = _verify_sink_result({"state": "no-arrival"}, {"reached": False})
    for k in ("harmful", "sink_reached", "confidence", "reason", "evidence"):
        assert k in v, k


def test_legacy_degraded_branch_preserved():
    v = _verify_sink_result(
        {"state": "sink-reached", "sink_file": "com.x.Runtime.exec"},
        {"reached": True, "attack_degraded": True, "status_code": 200},
        "command_execution",
    )
    assert v["harmful"] is False
    assert v["sink_reached"] is True
    assert v.get("attack_degraded") is True


def test_legacy_noise_sink_yields_sink_reached_false():
    """_build_verification_result 的 _false_sink_reached 靠 sink_reached is False 判噪声 sink。

    响应写入类 sink 对 CRLF 是**真 sink**，对注入族才是噪声——用 sqli 造噪声场景，
    别拿 crlf 造（那样 sink_reached=True 才是对的）。
    注意 iast_evidence 的权威键是 matched_sink_file / reached_sink_files，
    不是 sink_file（后者是本模块自己塞的展示字段，身份校验不读它）。
    """
    v = _verify_sink_result(
        {"state": "sink-reached",
         "matched_sink_file": "org.apache.catalina.connector.Response.addHeader"},
        {"reached": True},
        "sqli",
    )
    assert v["sink_reached"] is False
    assert v["harmful"] is False


def test_deserialization_fields_preserved():
    v = _verify_sink_result(
        {"state": "no-arrival",
         "events": [{"sink_file": "java.io.ObjectInputStream.readObject"}]},
        {"reached": True},
        "deserialization",
    )
    # 反序列化链路判据取决于探针事件形态；此处只保证键位与不短路结构不丢
    assert "evidence_channels" in v
    assert isinstance(v["evidence_channels"], list)


# ── 健壮性 ──

def test_single_channel_exception_does_not_kill_arbitration():
    """单通道崩了只记 error 留痕，绝不拖垮整条裁决。"""
    original = ec._EVALUATORS["probe_sink_assert"]

    def _boom(_ctx):
        raise RuntimeError("boom")

    ec._EVALUATORS["probe_sink_assert"] = _boom
    try:
        v = _verify_sink_result({"state": "sink-reached-probe",
                                 "sink_file": "java.lang.Runtime.exec"},
                                {"reached": True}, "command_execution")
        err = next((c for c in v["evidence_channels"] if c["channel"] == "probe_sink_assert"), None)
        assert err is not None
        assert err["definitive"] is False
        assert v["primary_channel"] == "none"
    finally:
        ec._EVALUATORS["probe_sink_assert"] = original


def test_arbitrate_with_no_definitive_outcome():
    v = ec.arbitrate([])
    assert v["primary_channel"] == "none"
    assert v["evidence_strength"] == 0
    assert v["harmful"] is False


def test_applicability_is_evidence_driven_not_family_only():
    """族名缺失/归一失败时，已投放的证据形态本身必须让通道成立。

    事故原型：只按族名判适用性时，family="" 的 spec 上业务差分与时间盲注双双消失，
    直接把两条既有用例打挂。族名是上游主张，证据是既成事实——事实优先。
    """
    assert "semantic_diff" in ec.applicable_channels(
        "", evidence={"business_logic": {"confirmed": True, "category": "bola"}})
    assert "time_blind" in ec.applicable_channels("", evidence={"sleep_seconds_hint": 3})
    assert "oob_callback" in ec.applicable_channels("", evidence={"oob_token": "t"})
    assert "result_point_diff" in ec.applicable_channels(
        "", evidence={"result_point_diff": {"matched": True}})
    assert ec.applicable_channels("") == ["probe_sink_assert"]


def test_code_property_family_detection():
    assert ec.is_code_property_family("weak_random") is True
    assert ec.is_code_property_family("weak_hash") is True
    assert ec.is_code_property_family("sqli") is False
