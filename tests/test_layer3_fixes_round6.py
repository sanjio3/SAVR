"""jsc 626→627 回归锁：剩余六个真值点的结构性根因。

覆盖四类修复：
  1. 靶场数据源：launch_java_seccode.py 默认带 h2 profile（sqli 布尔对可达）；
  2. 两族接入行为 oracle：expression_injection / deserialization 的探测臂与判据；
  3. D1 投递：body 型 spec 的探测臂走裸串，且不再复用主载荷；
  4. D2 关联：孤儿 spec 用登记的 vhash 反查，不再每轮补入却每轮零重放。

证据边界（必须保持）：deser_object_accepted 只证明「攻击者可控字节被反序列化
器完整解析」，不等于 RCE 命令执行。判据与闸门都要按弱证据处理，避免 625 那种
「召回改善换来红线误报恶化」。
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


# ── 1. 靶场 h2 profile ────────────────────────────────────────────────


def test_watchdog_defaults_to_h2_profile_and_is_reversible():
    src = _read("scripts/launch/launch_java_seccode.py")
    assert "application-h2.properties" in src
    assert 'JSC_SPRING_ARGS' in src
    assert '"-jar", jar] + JSC_SPRING_ARGS' in src
    assert 'SAST_AI_JSC_H2' in src

    import importlib.util
    path = ROOT / "scripts" / "launch" / "launch_java_seccode.py"
    old = os.environ.pop("SAST_AI_JSC_H2", None)
    try:
        spec = importlib.util.spec_from_file_location("_wb_lj_default", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.JSC_SPRING_ARGS == ["--spring.profiles.active=h2"]
        os.environ["SAST_AI_JSC_H2"] = "0"
        spec2 = importlib.util.spec_from_file_location("_wb_lj_off", path)
        mod2 = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(mod2)
        assert mod2.JSC_SPRING_ARGS == []
    finally:
        if old is None:
            os.environ.pop("SAST_AI_JSC_H2", None)
        else:
            os.environ["SAST_AI_JSC_H2"] = old


# ── 2. 新族接入 oracle ────────────────────────────────────────────────


def test_new_families_are_registered_and_canonicalized():
    from src.iast import response_oracle as O
    assert "expression_injection" in O.ORACLE_FAMILIES
    assert "deserialization" in O.ORACLE_FAMILIES
    assert O.canonical_family("expression_injection") == "expression_injection"
    assert O.canonical_family("deserialization") == "deserialization"
    assert O.canonical_family("qlexpress") == "expression_injection"
    assert O.canonical_family("xstream") == "deserialization"
    assert "expression_injection" in O.oracle_families_from_env()
    assert "deserialization" in O.oracle_families_from_env()


def test_expression_probes_require_evaluation_not_reflection():
    from src.iast import response_oracle as O
    ps = O.build_probes("expression_injection", probe_token="238743")
    assert [p.arm for p in ps] == ["benign", "expr_eval", "expr_eval"]
    assert all("+" in p.payload or "*" in p.payload for p in ps[1:])

    good = O.judge("expression_injection", [
        O.ArmResult("benign", '"SASTAI_BENIGN"', status=200,
                    body="SASTAI_BENIGN", note="expr_const"),
        O.ArmResult("expr_eval", '"SASTAI_" + "238743"', status=200,
                    body="SASTAI_238743", note="expr_concat:238743"),
    ])
    assert good["verdict"] == "exploitable" and good["signal"] == "expr_eval"

    # 纯回显必须挡下：这是 625 红线误报的同类陷阱。
    echo = O.judge("expression_injection", [
        O.ArmResult("expr_eval", '"SASTAI_" + "238743"', status=200,
                    body='"SASTAI_" + "238743"', note="expr_concat:238743"),
        O.ArmResult("expr_eval", "111 * 7", status=200,
                    body="111 * 7", note="expr_arith"),
    ])
    assert echo["verdict"] == "inconclusive"
    assert echo["signal"] == "no_expr_eval"

    # 算术臂独立成立
    arith = O.judge("expression_injection", [
        O.ArmResult("expr_eval", "111 * 7", status=200,
                    body="777", note="expr_arith"),
    ])
    assert arith["signal"] == "expr_eval"

    miss = O.judge("expression_injection", [])
    assert miss["verdict"] == "inconclusive"


def test_deserialization_negative_positive_control():
    from src.iast import response_oracle as O
    ps = O.build_probes("deserialization", probe_token="238743",
                        payload="rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==")
    assert ps[0].arm == "deser_invalid"
    assert [p.arm for p in ps[1:]] == ["deser_valid", "deser_valid"]
    assert any("java.lang.String" in p.payload for p in ps)

    good = O.judge("deserialization", [
        O.ArmResult("deser_invalid", "SASTAI_NOT_AN_OBJECT_238743", status=500,
                    body='{"exception":"com.thoughtworks.xstream.io.StreamException"}',
                    note="negative_control"),
        O.ArmResult("deser_valid", "<java.lang.String>SASTAI_ORACLE</java.lang.String>",
                    status=200, body="xstream", note="xstream_object_xml"),
    ])
    assert good["verdict"] == "exploitable"
    assert good["signal"] == "deser_object_accepted"
    # 证据边界必须写进 reason，不能冒充 RCE 实证
    assert "不等同于 RCE" in good["reason"]

    # Shiro 阴臂是 200 + "decrypt error"，也必须认作失败对照
    shiro = O.judge("deserialization", [
        O.ArmResult("deser_invalid", "AAAA", status=200,
                    body="RememberMe cookie decrypt error. Set deleteMe cookie success.",
                    note="negative_control"),
        O.ArmResult("deser_valid", "AAAAAAAAAAAAAAAAAAAAABhMtw", status=200,
                    body="Shiro deserialize", note="primary_payload"),
    ])
    assert shiro["signal"] == "deser_object_accepted"

    # 阴臂也被正常接受 ⇒ 无法区分是否真的反序列化过，不得确认
    flat = O.judge("deserialization", [
        O.ArmResult("deser_invalid", "SASTAI_NOT_AN_OBJECT_238743", status=200,
                    body="ok", note="negative_control"),
        O.ArmResult("deser_valid", "<java.lang.String>SASTAI_ORACLE</java.lang.String>",
                    status=200, body="ok", note="xstream_object_xml"),
    ])
    assert flat["verdict"] == "inconclusive"
    assert flat["signal"] == "negative_control_accepted"


# ── 3. 信号映射与红线闸门 ──────────────────────────────────────────────


def test_new_signals_are_accepted_by_confirmation_chain():
    from src.cli.benchmark_cli import (
        _oracle_positive_signal, _oracle_gate_signal,
        _RESPONSE_ONLY_ORACLE_SIGNALS)
    assert _oracle_positive_signal("expression_injection", "exploitable", "expr_eval") == "expr_eval"
    assert _oracle_positive_signal("deserialization", "exploitable", "deser_object_accepted") == "deser_object_accepted"
    assert _oracle_positive_signal("sql_injection", "exploitable", "time_delay") == "time_delay"
    assert _oracle_positive_signal("command_execution", "exploitable", "time_delay") == "time_delay"
    # 跨族信号依旧不认
    assert _oracle_positive_signal("xss", "exploitable", "expr_eval") == ""
    assert _oracle_positive_signal("deserialization", "inconclusive", "expr_eval") == ""
    assert "expr_eval" in _RESPONSE_ONLY_ORACLE_SIGNALS
    assert "deser_object_accepted" in _RESPONSE_ONLY_ORACLE_SIGNALS


def test_deser_signal_keeps_625_redline_filename_constraint():
    from src.cli.benchmark_cli import _oracle_gate_signal
    for f in ("XStreamRce.java", "Deserialize.java", "Shiro.java"):
        assert _oracle_gate_signal("deserialization", "exploitable",
                                   "deser_object_accepted", sink_file=f) == "deser_object_accepted"
    # 族误标到无关文件必须被挡下（625 三条红线误报的同一纪律）
    assert _oracle_gate_signal("deserialization", "exploitable",
                               "deser_object_accepted", sink_file="Log4j.java") == ""
    # expr_eval 是强因果信号，不受文件名限制，但也不得跨族
    assert _oracle_gate_signal("expression_injection", "exploitable", "expr_eval",
                               sink_file="QLExpress.java") == "expr_eval"
    assert _oracle_gate_signal("xss", "exploitable", "expr_eval",
                               sink_file="QLExpress.java") == ""


# ── 4. D1 裸 body 投递 ─────────────────────────────────────────────────


def test_d1_oracle_uses_raw_body_for_new_families():
    src = _read("src/application/d1_service.py")
    # 628：硬编码族判断升级为「主请求 / 探测臂共用」的纯函数判据。
    # 627 的 fastjson 退步正是探测臂发裸串、主请求发 JSON 字典，两边结论不可比。
    assert "needs_raw_body_payload(fam, param_name, ploc, content_type)" in src
    assert "def needs_raw_body_payload(" in src
    assert 'body = p.payload' in src
    # 非新族的 body 通道也必须显式重建，否则探测臂永远发主载荷
    assert 'body = dict(body) if isinstance(body, dict) else {}' in src
    assert 'body[param_name] = p.payload' in src
    # 裸串必须走 data=；主请求与探测臂共用同一线格式映射，绝不再走 json=
    assert 'def body_data_json(' in src
    assert '_data, _json = body_data_json(body, content_type)' in src


# ── 5. 孤儿 spec 的 vhash 关联 ─────────────────────────────────────────


def _orphan_spec(spec_id, status="unconfirmed", vhash="v", endpoint="/vuln1",
                 replayable=1):
    import json
    return {
        "id": spec_id, "verification_status": status,
        "vulnerability_hash_v2": vhash, "target_endpoint": endpoint,
        "replayable": replayable, "family": "expression_injection",
        "expected_sink_file": "src/QLExpress.java", "expected_sink_line": 26,
        "category": "", "raw_json": json.dumps({"type": "expression_injection",
                                                "file": "src/QLExpress.java", "line": 26}),
    }


class _FakeDB:
    def __init__(self, replayed):
        self.replayed = set(replayed)

    def execute(self, sql, args=None, **kw):
        if "replay_attempts" in sql:
            return [{"spec_id": x} for x in self.replayed]
        return []


def test_orphan_vuln_reuses_registered_spec_vhash():
    from src.cli.benchmark_cli import _enqueue_orphan_trigger_specs
    by = {"k": [_orphan_spec(1, vhash="aaaa1111"),
                _orphan_spec(2, vhash="bbbb2222", endpoint="/xstream")]}
    vulns = []
    n = _enqueue_orphan_trigger_specs(vulns, by, db=_FakeDB(set()), task_id=627)
    assert n == 2
    for v in vulns:
        assert v["_orphan_spec_vhash"] == v["vuln_vhash"]
        assert v["vuln_vhash"] in ("aaaa1111", "bbbb2222")
        assert v["exploit_spec"]["entry"]["route"]


def test_covered_but_never_replayed_spec_is_still_enqueued():
    """625 实测：/vuln1 有 finding 覆盖、却零 replay_attempts，旧逻辑永久跳过。"""
    from src.cli.benchmark_cli import _enqueue_orphan_trigger_specs
    spec = _orphan_spec(7, vhash="cccc3333")
    vulns = [{"vuln_vhash": "cccc3333", "type": "expression_injection",
              "file": "src/QLExpress.java", "line": 26}]
    n = _enqueue_orphan_trigger_specs(vulns, {"k": [spec]},
                                      db=_FakeDB(set()), task_id=627)
    assert n == 1
    assert vulns[-1]["_orphan_spec_vhash"] == "cccc3333"
    # 已重放过的 spec 不重复补入
    vulns2 = []
    n2 = _enqueue_orphan_trigger_specs(vulns2, {"k": [_orphan_spec(8, vhash="dddd4444")]},
                                       db=_FakeDB({8}), task_id=627)
    assert n2 == 0


def test_d2_main_loop_prefers_orphan_vhash_and_skips_stable_shortcut():
    src = _read("src/cli/benchmark_cli.py")
    assert '_orphan_vh = str(vuln.get("_orphan_spec_vhash") or "").strip()' in src
    assert '_vhash = _orphan_vh or _vh2(canonicalize_vuln_for_hash(vuln))' in src
    assert '_stable_keys = [] if _orphan_vh else _stable_vuln_keys(vuln)' in src


def test_625_zero_replay_specs_get_correct_vhash_in_dry_run():
    """用 625 真实数据回归：六条零重放 spec 必须带与自身一致的关联键。"""
    db = ROOT / "data" / "app.db"
    if not db.exists():
        pytest.skip("no local app.db")
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute(
        "select * from trigger_specs where task_id=625")]
    if not rows:
        pytest.skip("run 625 not present")
    by = {}
    for r in rows:
        by.setdefault(r["vulnerability_hash_v2"], []).append(r)
    replayed = {x[0] for x in con.execute(
        "select distinct spec_id from replay_attempts where task_id=625")}
    from src.cli.benchmark_cli import _enqueue_orphan_trigger_specs
    vulns = []
    _enqueue_orphan_trigger_specs(vulns, by, db=_FakeDB(replayed), task_id=625)
    vhs = {v.get("_orphan_spec_vhash") for v in vulns if v.get("_orphan_spec_vhash")}
    for f in ("QLExpress.java", "XStreamRce.java", "Shiro.java"):
        matched = [r["vulnerability_hash_v2"] for r in rows
                   if f.lower() in str(r["expected_sink_file"]).lower()
                   and r["id"] not in replayed]
        assert any(v in vhs for v in matched), (f, matched, vhs)
    con.close()
