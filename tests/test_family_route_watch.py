"""E/F/I 组落地单测（2026-09-28）：族路由判定 + missing_route 观测面 + defect 五类分流。"""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.family_verdict import (  # noqa: E402
    CONFIRMED_CODE_PROPERTY,
    apply_family_route,
    judge_algorithm_family,
    judge_attribute_family,
    route_for,
)
from src.core.missing_route_watch import build_missing_route_watch  # noqa: E402
from src.agents.i2_feedback import classify_defect, defect_subclass_counts  # noqa: E402


# ---------- I：族路由 ----------
def test_route_for_families():
    assert route_for("weak_hash") == "algorithm"
    assert route_for("weak-crypto") == "algorithm"
    assert route_for("secure_cookie") == "attribute"
    assert route_for("securecookie") == "attribute"
    assert route_for("sql_injection") == "dataflow"
    assert route_for("") == "dataflow"


def _ev(sink, arg):
    return {"sink_file": sink, "source_value": arg, "evidence_json": ""}


def test_algorithm_family_weak_algo_confirmed():
    status, detail = judge_algorithm_family([_ev("java.security.MessageDigest.getInstance", "[MD5, SUN]")])
    assert status == CONFIRMED_CODE_PROPERTY and "MD5" in detail.lower() or "md5" in detail


def test_algorithm_family_sha_is_weak():
    """Java 里 'SHA' 即 SHA-1，属弱算法。"""
    status, _ = judge_algorithm_family([_ev("java.security.MessageDigest.getInstance", "[SHA, SUN]")])
    assert status == CONFIRMED_CODE_PROPERTY


def test_algorithm_family_strong_algo_unconfirmed():
    """强算法（SHA-256）不是弱哈希漏洞：应判 unconfirmed，而非确认态。

    run 364 实测：原实现返回 confirmed_sink_control（确认态），导致 OWASP hash
    的 safe 用例 41 条全部被算成 FP。强算法/参数未记录时弱算法主张不成立。
    """
    status, detail = judge_algorithm_family([_ev("java.security.MessageDigest.getInstance", "[SHA-256, SUN]")])
    assert status == "unconfirmed" and "不弱" in detail


def test_algorithm_family_no_event_unconfirmed():
    status, detail = judge_algorithm_family([_ev("java.lang.Runtime.exec", "[cmd]")])
    assert status == "unconfirmed" and "借链路" in detail or "未观测" in detail


def test_attribute_family_false_flag_confirmed():
    status, _ = judge_attribute_family([_ev("javax.servlet.http.Cookie.setSecure", "[false]")])
    assert status == CONFIRMED_CODE_PROPERTY


def test_attribute_family_true_flag_unconfirmed():
    status, detail = judge_attribute_family([
        _ev("javax.servlet.http.Cookie.setSecure", "[true]"),
        _ev("javax.servlet.http.Cookie.setHttpOnly", "[true]"),
    ])
    assert status == "unconfirmed" and "显式开启" in detail


def test_attribute_family_no_event_no_assertion():
    status, _ = judge_attribute_family([_ev("java.lang.Runtime.exec", "x")])
    assert status == "unconfirmed"


def test_apply_family_route_only_touches_confirmed():
    evs = [_ev("java.security.MessageDigest.getInstance", "[MD5]") ]
    # confirmed_exploitable → 重判
    s1, d1 = apply_family_route("weak_hash", "confirmed_exploitable", evs)
    assert s1 == CONFIRMED_CODE_PROPERTY and d1["applied"] is True
    # no_evidence → 不动
    s2, d2 = apply_family_route("weak_hash", "no_evidence", evs)
    assert s2 == "no_evidence" and d2["applied"] is False
    # 数据流族 → 不动
    s3, d3 = apply_family_route("sql_injection", "confirmed_exploitable", evs)
    assert s3 == "confirmed_exploitable" and d3["applied"] is False


# ---------- E：missing_route 观测面 ----------
def _db():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INT, target_endpoint TEXT)")
    con.execute("CREATE TABLE findings (id INTEGER PRIMARY KEY, task_id INT, vulnerability_hash_v2 TEXT, file_path TEXT)")
    return con


def test_watch_classifies_covered_true_miss_cross_file():
    con = _db()
    # 已覆盖用例：00153 有 spec
    con.execute("INSERT INTO trigger_specs (task_id, target_endpoint) VALUES (1, '/xss-00/BenchmarkTest00153')")
    # findings：已覆盖的重复假说 / 真漏报 / 跨文件
    con.execute("INSERT INTO findings (task_id, vulnerability_hash_v2, file_path) VALUES (1,'h1','src/x/BenchmarkTest00153.java')")
    con.execute("INSERT INTO findings (task_id, vulnerability_hash_v2, file_path) VALUES (1,'h2','src/x/BenchmarkTest02677.java')")
    con.execute("INSERT INTO findings (task_id, vulnerability_hash_v2, file_path) VALUES (1,'h3','src/x/HelperUtil.java')")
    reasons = [
        {"vulnerability_hash_v2": "h1", "family": "xss", "reason": "missing_route"},
        {"vulnerability_hash_v2": "h2", "family": "sensitive_data_exposure", "reason": "missing_route"},
        {"vulnerability_hash_v2": "h3", "family": "weak_password", "reason": "missing_route"},
        {"vulnerability_hash_v2": "h4", "family": "xss", "reason": "invalid_param_name"},  # 不在观测面
    ]
    w = build_missing_route_watch(con, 1, reasons)
    assert w["watch_total"] == 3
    assert w["covered_dropped"] == 1
    assert len(w["true_miss"]) == 1 and w["true_miss"][0]["case"] == "BenchmarkTest02677"
    assert len(w["cross_file"]) == 1 and w["cross_file"][0]["vulnerability_hash_v2"] == "h3"


def test_watch_empty_reasons():
    con = _db()
    assert build_missing_route_watch(con, 1, [])["watch_total"] == 0


# ---------- F-3：defect 五类分流 ----------
def test_defect_subclass_classification():
    assert classify_defect({"reason": "端点幻觉：/admin/x 不存在"}) == "endpoint_hallucination"
    assert classify_defect({"reason": "缺失参数 username"}) == "missing_parameter"
    assert classify_defect({"reason": "族误判：ssrf 应为 path_traversal"}) == "family_mislabel"
    assert classify_defect({"reason": "链路不符：缺 helper 节点"}) == "chain_mismatch"
    assert classify_defect({"reason": "其他"}) == "insufficient_evidence"


def test_defect_subclass_counts_and_actions():
    r = defect_subclass_counts([
        {"reason": "端点幻觉"}, {"reason": "端点幻觉"}, {"reason": "其他"},
    ])
    assert r["counts"] == {"endpoint_hallucination": 2, "insufficient_evidence": 1}
    assert r["bound_actions"]["endpoint_hallucination"] == "a2_rerun"
    assert r["bound_actions"]["insufficient_evidence"] == "record_only"
    assert defect_subclass_counts([]) == {}
