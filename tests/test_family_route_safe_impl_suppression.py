"""P2 算法/属性族「安全实现」正证据抑制的回归锁（2026-10-18 落地）。

背景：family_route postpass 此前只改 verification_status，而对账口径
（tools/owasp_run_shards.py L414）只按 suppressed_by_safe_verdict=0 过滤检出集合
⇒ 算法族的 FP 清不掉（run 364 hash 41 条 confirmed_sink_control FP、run 373 crypto
56 条 FP 全部卡在这里）。P2 在族路由后处理里补写 suppressed，判据 = 运行时探针事件里的
**正证据**：算法 sink 到达且算法名不弱（SHA-256 等）/ Cookie flag 显式置 true。

纪律（与数据流族值级闸 absent / no_event 二分同构）：
  正证据（到达 sink 但内容安全） → 抑制；
  无证据（什么都没观测到 / 算法参数未记录） → fail-open 保留；
  TP 主张（弱算法黑名单 / flag 显式 false / confirmed_code_property 旧态） → 永不抑制。

P1b 离线复算（run 361/364/373 真实 spec + iast_events）实测：
  0 TP 用例丢失；hash FP -41 用例、crypto FP -20 用例、mini FP -3 用例。
"""
from __future__ import annotations

import sqlite3

import pytest

from src.cli.benchmark_cli import _apply_family_route_postpass
from src.core.family_verdict import judge_safe_implementation

_IDENT = "s4st41" + "a" * 16


class _FakeDB:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def execute(self, sql, params=(), fetchall=False):
        cur = self.conn.execute(sql, tuple(params))
        rows = [dict(r) for r in cur.fetchall()]
        self.conn.commit()
        return rows if fetchall else rows


@pytest.fixture()
def db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INTEGER, family TEXT, "
        "capability_family TEXT, taint_marker TEXT, session_id INTEGER, "
        "verification_status TEXT, iast_state TEXT, suppressed_by_safe_verdict INTEGER DEFAULT 0, "
        "suppress_rule TEXT, expected_sink_file TEXT DEFAULT '')")
    conn.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY, task_id INTEGER, canary TEXT, "
        "sink_file TEXT, source_value TEXT, evidence_json TEXT, canary_state TEXT)")
    yield _FakeDB(conn)
    conn.close()


def _add_spec(db, task_id, spec_id, family, marker, status, iast_state="sink-reached-probe",
              cap_family="", suppressed=0, rule=None):
    db.execute(
        "INSERT INTO trigger_specs (id, task_id, family, capability_family, taint_marker, "
        "session_id, verification_status, iast_state, suppressed_by_safe_verdict, suppress_rule) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (spec_id, task_id, family, cap_family, marker, 1, status, iast_state, suppressed, rule))


def _add_event(db, task_id, event_id, sink_file, source_value="", canary=_IDENT):
    db.execute(
        "INSERT INTO iast_events (id, task_id, canary, sink_file, source_value, "
        "evidence_json, canary_state) VALUES (?,?,?,?,?,?,?)",
        (event_id, task_id, canary, sink_file, source_value, "{}", "sink-reached-probe"))


def _supp_of(db, spec_id):
    rows = db.execute(
        "SELECT verification_status, iast_state, COALESCE(suppressed_by_safe_verdict,0) AS s, "
        "suppress_rule FROM trigger_specs WHERE id=?", (spec_id,), fetchall=True)
    r = rows[0]
    return r["verification_status"], r["iast_state"], int(r["s"]), r["suppress_rule"]


# —— judge_safe_implementation 判据单测 ——

def _algo_ev(algo):
    return [{"sink_file": "java.security.MessageDigest.getInstance", "source_value": f"[{algo}, SUN]",
             "evidence_json": "{}"}]


def test_judge_strong_algo_is_safe_impl():
    ok, rule = judge_safe_implementation("weak_hash", _algo_ev("SHA-256"))
    assert ok is True and rule == "algorithm_not_weak:sha-256"


def test_judge_weak_algo_is_never_safe_impl():
    for algo in ("MD5", "SHA-1", "DES/CBC/PKCS5PADDING"):
        ok, _ = judge_safe_implementation("weak_crypto", _algo_ev(algo))
        assert ok is False, f"{algo} 是弱算法 = TP 主张，永不判安全实现"


def test_judge_no_events_is_fail_open():
    assert judge_safe_implementation("weak_hash", []) == (False, "")


def test_judge_algo_sink_without_param_is_fail_open():
    """算法 sink 到了但参数没记录 —— 无证据，不许诛心。"""
    evs = [{"sink_file": "java.security.MessageDigest.getInstance", "source_value": "[]",
            "evidence_json": "{}"}]
    assert judge_safe_implementation("weak_hash", evs) == (False, "")


def test_judge_cookie_flag_true_is_safe_impl():
    evs = [{"sink_file": "javax.servlet.http.Cookie.setSecure", "source_value": "[true]",
            "evidence_json": "{}"}]
    ok, rule = judge_safe_implementation("secure_cookie", evs)
    assert ok is True and "cookie_flag_set_true" in rule


def test_judge_cookie_flag_false_is_never_safe_impl():
    evs = [{"sink_file": "javax.servlet.http.Cookie.setSecure", "source_value": "[false]",
            "evidence_json": "{}"}]
    assert judge_safe_implementation("secure_cookie", evs) == (False, "")


def test_judge_cookie_ctor_only_is_fail_open():
    """只有 Cookie.<init>、没有任何 flag 事件 —— 这正是 TP 主张方向，不得抑制。"""
    evs = [{"sink_file": "javax.servlet.http.Cookie.<init>", "source_value": "[X, whatever]",
            "evidence_json": "{}"}]
    assert judge_safe_implementation("secure_cookie", evs) == (False, "")


def test_judge_random_family_has_no_safe_evidence():
    """weak_random 没有正安全证据可用（观测不到 Random ≠ 用了 SecureRandom）。"""
    assert judge_safe_implementation("weak_random", _algo_ev("SHA-256")) == (False, "")


def test_judge_dataflow_family_is_untouched():
    assert judge_safe_implementation("sql_injection", _algo_ev("SHA-256")) == (False, "")


# —— post-pass 接线回归 ——

def test_hash_confirmed_sink_control_with_strong_algo_is_suppressed(db):
    """run 364 的 41 条 hash FP 形态：confirmed_sink_control + 算法不弱 → 抑制。"""
    _add_spec(db, 1, 11, "weak_hash", _IDENT + "P1", "confirmed_sink_control")
    _add_event(db, 1, 101, "java.security.MessageDigest.getInstance", "[SHA-384, SUN]")
    n = _apply_family_route_postpass(1, db)
    assert n == 1
    status, iast_state, supp, rule = _supp_of(db, 11)
    assert supp == 1
    assert status == "unconfirmed"
    assert rule == "family-route:safe_impl:algorithm_not_weak:sha-384"
    assert iast_state == "sink-reached-probe", "到达态不得因抑制假退化"


def test_hash_without_events_is_not_suppressed(db):
    """什么都没观测到 → 不抑制（探针可能漏观测，杀了就是丢召回）。

    注意：P1 的**状态降级**（confirmed_sink_control → unconfirmed）此时照常发生（n=1），
    那是确认态口径的清理；P2 的 suppression 才是对账口径的清理，此处必须为 0。
    """
    _add_spec(db, 2, 21, "weak_hash", _IDENT + "P2", "confirmed_sink_control")
    n = _apply_family_route_postpass(2, db)
    status, _iast, supp, rule = _supp_of(db, 21)
    assert supp == 0 and rule is None
    assert status == "unconfirmed", "P1 降级仍应发生"


def test_crypto_weak_algo_is_tp_and_never_suppressed(db):
    """弱加密（DES）是 TP 主张，走 confirmed_code_property，不抑制。"""
    _add_spec(db, 3, 31, "weak_crypto", _IDENT + "P3", "confirmed_exploitable")
    _add_event(db, 3, 301, "javax.crypto.Cipher.getInstance", "[DES/CBC/PKCS5PADDING, SunJCE]")
    n = _apply_family_route_postpass(3, db)
    status, _iast, supp, _rule = _supp_of(db, 31)
    assert supp == 0
    assert status == "confirmed_code_property"


def test_cookie_flag_true_on_sink_reached_is_suppressed(db):
    _add_spec(db, 4, 41, "secure_cookie", _IDENT + "P4", "sink_reached",
              iast_state="no-iast-evidence")
    _add_event(db, 4, 401, "javax.servlet.http.Cookie.setSecure", "[true]")
    n = _apply_family_route_postpass(4, db)
    assert n == 1
    status, iast_state, supp, rule = _supp_of(db, 41)
    assert supp == 1 and status == "unconfirmed"
    assert "cookie_flag_set_true" in rule
    assert iast_state == "family-route:safe-impl", "非到达态才写路由标记"


def test_code_property_status_is_never_suppressed(db):
    """confirmed_code_property 旧态是 TP 主张，双保险不抑制。"""
    _add_spec(db, 5, 51, "secure_cookie", _IDENT + "P5", "confirmed_code_property")
    _add_event(db, 5, 501, "javax.servlet.http.Cookie.setHttpOnly", "[true]")
    n = _apply_family_route_postpass(5, db)
    assert n == 0
    assert _supp_of(db, 51)[2] == 0


def test_already_suppressed_spec_is_skipped(db):
    """已被别的手段抑制过的 spec 不重复处理，保住既有归因。"""
    _add_spec(db, 6, 61, "weak_hash", _IDENT + "P6", "unconfirmed",
              suppressed=1, rule="safe-pattern:if_const:a==1→const")
    _add_event(db, 6, 601, "java.security.MessageDigest.getInstance", "[SHA-256, SUN]")
    n = _apply_family_route_postpass(6, db)
    assert n == 0, "已抑制 spec 不得被 P2 重复计数/改写"
    assert _supp_of(db, 61)[3] == "safe-pattern:if_const:a==1→const"


def test_capability_family_fallback_still_works(db):
    """family 写错但 capability_family 正确（broken_access_control/secure_cookie）也要接住。"""
    _add_spec(db, 7, 71, "broken_access_control", _IDENT + "P7", "sink_reached",
              cap_family="secure_cookie")
    _add_event(db, 7, 701, "javax.servlet.http.Cookie.setSecure", "[true]")
    n = _apply_family_route_postpass(7, db)
    assert n == 1
    assert _supp_of(db, 71)[2] == 1


# —— 静态安全随机判据（2026-10-19 r111 weakrand 实证）——
# random_source 路由没有运行时正证据，P2 恒 False；改由源码静态正证据兜底：
# 只用 SecureRandom 且无弱随机调用 → 抑制。TP（只用 java.util.Random）永不抑制。

def _mk_src(tmp_path, fname, body):
    pkg = tmp_path / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / fname).write_text(body, encoding="utf-8")
    return pkg


def _reset_source_cache():
    from src.iast import source_infer as _si
    _si._RESOLVE_CACHE.clear()
    _si._BASENAME_INDEX.clear()


def test_static_rng_secure_only_is_suppressed(db, tmp_path, monkeypatch):
    _mk_src(tmp_path, "BenchmarkTest00094.java",
            'double rand = java.security.SecureRandom.getInstance("SHA1PRNG").nextDouble();\n')
    monkeypatch.setenv("SAST_AI_SOURCE_ROOTS", str(tmp_path))
    _reset_source_cache()
    _add_spec(db, 1, 1, "weak_random", _IDENT, "confirmed_exploitable", iast_state="no-arrival")
    db.execute("UPDATE trigger_specs SET expected_sink_file='BenchmarkTest00094.java' WHERE id=1")
    _apply_family_route_postpass(1, db)
    st, iast, supp, rule = _supp_of(db, 1)
    assert supp == 1, "只用 SecureRandom 应判安全实现并写 suppressed"
    assert "static_safe_rng" in (rule or "")
    assert st == "unconfirmed"


def test_static_rng_weak_only_not_suppressed(db, tmp_path, monkeypatch):
    _mk_src(tmp_path, "BenchmarkTest00023.java",
            'float rand = new java.util.Random().nextFloat();\n')
    monkeypatch.setenv("SAST_AI_SOURCE_ROOTS", str(tmp_path))
    _reset_source_cache()
    _add_spec(db, 2, 2, "weak_random", _IDENT, "confirmed_exploitable", iast_state="no-arrival")
    db.execute("UPDATE trigger_specs SET expected_sink_file='BenchmarkTest00023.java' WHERE id=2")
    _apply_family_route_postpass(2, db)
    _st, _iast, supp, _rule = _supp_of(db, 2)
    assert supp == 0, "弱随机 = TP 主张，永不抑制"


def test_static_rng_overrides_cp_when_capability_is_weak_random(db, tmp_path, monkeypatch):
    """r112 实证 16 例：family 被 SHA 样板误判成 weak_hash → confirmed_code_property，
    但 capability_family=weak_random 且源码仅用 SecureRandom ⇒ 允许越过 CP 护栏抑制。"""
    _mk_src(tmp_path, "BenchmarkTest00182.java",
            'double stuff = java.security.SecureRandom.getInstance("SHA1PRNG").nextGaussian();\n')
    monkeypatch.setenv("SAST_AI_SOURCE_ROOTS", str(tmp_path))
    _reset_source_cache()
    _add_spec(db, 3, 3, "weak_hash", _IDENT, "confirmed_code_property",
              iast_state="sink-reached-probe", cap_family="weak_random")
    db.execute("UPDATE trigger_specs SET expected_sink_file='BenchmarkTest00182.java' WHERE id=3")
    _apply_family_route_postpass(3, db)
    _st, _i, supp, rule = _supp_of(db, 3)
    assert supp == 1, "capability=weak_random + SecureRandom-only 应越过 CP 护栏抑制"
    assert "static_safe_rng" in (rule or "")


def test_static_rng_does_not_override_cp_without_random_capability(db, tmp_path, monkeypatch):
    """capability 不是 weak_random 时，confirmed_code_property 仍是 TP 主张，永不抑制。"""
    _mk_src(tmp_path, "BenchmarkTest00999.java",
            'double stuff = java.security.SecureRandom.getInstance("SHA1PRNG").nextGaussian();\n')
    monkeypatch.setenv("SAST_AI_SOURCE_ROOTS", str(tmp_path))
    _reset_source_cache()
    _add_spec(db, 4, 4, "weak_hash", _IDENT, "confirmed_code_property",
              iast_state="sink-reached-probe", cap_family="weak_hash")
    db.execute("UPDATE trigger_specs SET expected_sink_file='BenchmarkTest00999.java' WHERE id=4")
    _apply_family_route_postpass(4, db)
    _st, _i, supp, _rule = _supp_of(db, 4)
    assert supp == 0
