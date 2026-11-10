# -*- coding: utf-8 -*-
"""回归锁：探针 token 单一真值源 + 不对齐 fail-closed + 发车握手。

锁定不变量：
  A. DB 按 (workspace_id, app_name, agent_id) 三元组取唯一权威 token；
  B. 环境变量与 DB 不一致时 fail-closed，绝不「各挑一个」继续跑；
  C. token 无默认、无内置凭据；DB 无会话且禁用 fallback 时抛错；
  D. 允许 fallback 时也必须带 warning 且 source=env_fallback；
  E. 输出脱敏，只留前缀；
  F. preflight：token 不对齐 / 探针离线 / 后端鉴权失败一律 ready=False；
  G. 空事件批次握手成功（session_id 非空、errors 空）且不刷心跳、不写事件。
"""
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.iast import probe_token as pt  # noqa: E402
from tools import probe_preflight as pp  # noqa: E402

DB_TOKEN = "db-token-abcdefghijklmnopqrstuvwxyz"
ENV_TOKEN = "env-token-abcdefghijklmnopqrstuvwxyz"


def make_db(tmp_path, *, token=DB_TOKEN, workspace_id=7,
            app="benchmark", agent="owasp-benchmark-full",
            heartbeat=None, status="ready"):
    path = str(tmp_path / "app.db")
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE iast_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "workspace_id INTEGER, app_name TEXT, agent_id TEXT, probe_token TEXT, "
        "status TEXT, version_status TEXT, last_heartbeat_at TEXT, target_url TEXT)")
    con.execute(
        "INSERT INTO iast_sessions (workspace_id, app_name, agent_id, probe_token, "
        "status, version_status, last_heartbeat_at, target_url) VALUES (?,?,?,?,?,?,?,?)",
        (workspace_id, app, agent, token, status, "unverified",
         heartbeat or "", "http://127.0.0.1:8444/benchmark"))
    con.execute(
        "CREATE TABLE iast_events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "app_name TEXT, agent_id TEXT, ingested_at TEXT)")
    con.commit()
    con.close()
    return path


# ---------------------------------------------------------------- resolver
def test_db_is_single_source_of_truth(tmp_path):
    db = make_db(tmp_path)
    r = pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token="")
    assert r.token == DB_TOKEN
    assert r.source == "db" and r.session_id == 1
    assert r.warnings == []


def test_env_db_mismatch_fails_closed(tmp_path):
    db = make_db(tmp_path)
    with pytest.raises(pt.ProbeTokenError) as ei:
        pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token=ENV_TOKEN)
    assert "不对齐" in str(ei.value)
    assert DB_TOKEN[:6] in str(ei.value) and ENV_TOKEN[:6] in str(ei.value)


def test_matching_env_token_is_accepted_from_db(tmp_path):
    db = make_db(tmp_path)
    r = pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token=DB_TOKEN)
    assert r.source == "db" and r.token == DB_TOKEN


def test_non_strict_mismatch_prefers_db_with_warning(tmp_path):
    db = make_db(tmp_path)
    r = pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token=ENV_TOKEN, strict=False)
    assert r.token == DB_TOKEN and r.source == "db"
    assert any("不对齐" in w for w in r.warnings)


def test_wrong_workspace_is_not_silently_matched(tmp_path):
    db = make_db(tmp_path, workspace_id=7)
    with pytest.raises(pt.ProbeTokenError):
        pt.resolve(8, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token="", allow_env_fallback=False)


def test_no_token_no_default(tmp_path):
    db = make_db(tmp_path, token="")
    with pytest.raises(pt.ProbeTokenError) as ei:
        pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token="", allow_env_fallback=False)
    assert "内置凭据" in str(ei.value)


def test_env_fallback_is_flagged_never_silent(tmp_path):
    db = make_db(tmp_path, token="")
    r = pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token=ENV_TOKEN, allow_env_fallback=True)
    assert r.source == "env_fallback" and r.session_id is None
    assert r.warnings


def test_db_unreadable_fails_closed(tmp_path):
    with pytest.raises(pt.ProbeTokenError) as ei:
        pt.resolve(7, "benchmark", "owasp-benchmark-full",
                   db_path=str(tmp_path / "missing.db"), env_token="")
    assert "读取 iast_sessions 失败" in str(ei.value)


def test_resolution_output_is_redacted(tmp_path):
    db = make_db(tmp_path)
    r = pt.resolve(7, "benchmark", "owasp-benchmark-full", db_path=db,
                   env_token="")
    d = r.to_dict()
    assert DB_TOKEN not in str(d)
    assert d["token_prefix"] == DB_TOKEN[:6]
    assert d["token_len"] == len(DB_TOKEN)


def test_assert_token_matches_db_after_takeover(tmp_path):
    db = make_db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("UPDATE iast_sessions SET probe_token=? WHERE id=1", (ENV_TOKEN,))
    con.commit()
    con.close()
    pt.assert_token_matches_db(ENV_TOKEN, 7, "benchmark",
                               "owasp-benchmark-full", db_path=db)
    with pytest.raises(pt.ProbeTokenError):
        pt.assert_token_matches_db(DB_TOKEN, 7, "benchmark",
                                   "owasp-benchmark-full", db_path=db)


# ---------------------------------------------------------------- preflight
def test_preflight_blocks_on_token_mismatch(tmp_path):
    db = make_db(tmp_path)
    report = pp.preflight(7, "benchmark", "owasp-benchmark-full", db_path=db,
                          env_token=ENV_TOKEN, require_online=False)
    assert report["ready"] is False
    assert any("不对齐" in x for x in report["reasons"])


def test_preflight_blocks_env_fallback(tmp_path):
    db = make_db(tmp_path, token="")
    report = pp.preflight(7, "benchmark", "owasp-benchmark-full", db_path=db,
                          env_token=ENV_TOKEN, allow_env_fallback=True,
                          require_online=False)
    assert report["ready"] is False
    assert any("fallback" in x for x in report["reasons"])


def test_preflight_blocks_offline_probe_even_when_token_aligned(tmp_path):
    db = make_db(tmp_path)
    report = pp.preflight(7, "benchmark", "owasp-benchmark-full", db_path=db,
                          env_token="", require_online=True, now=2_000_000_000.0)
    assert report["ready"] is False
    assert any("探针离线" in x for x in report["reasons"])
    # token 本身是对齐的，只是探针没起来
    assert report["token"]["source"] == "db"


def test_preflight_ready_with_fresh_heartbeat_and_handshake(tmp_path):
    now = 2_000_000_000.0
    # 服务端 _now() = datetime.utcnow().isoformat()，落库是无时区的 UTC 串。
    hb = datetime.fromtimestamp(now - 5, timezone.utc).replace(tzinfo=None).isoformat()
    db = make_db(tmp_path, heartbeat=hb)

    class _Resp:
        status = 200

        def read(self):
            return b'{"accepted":0,"rejected":0,"session_id":1,"errors":[]}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Opener:
        def open(self, req, timeout=None):
            return _Resp()

    report = pp.preflight(7, "benchmark", "owasp-benchmark-full", db_path=db,
                          env_token="", require_online=True, do_http=True,
                          now=now, opener=_Opener())
    assert report["ready"] is True, report["reasons"]
    assert report["http_handshake"]["ok"] is True
    assert report["http_handshake"]["accepted"] == 0
    assert report["http_handshake"]["session_id"] == 1


def test_handshake_rejects_auth_failure_body(tmp_path):
    db = make_db(tmp_path)

    class _Resp:
        status = 200

        def read(self):
            return b'{"accepted":0,"rejected":0,"errors":["X-Agent-Token mismatch"]}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Opener:
        def open(self, req, timeout=None):
            return _Resp()

    report = pp.preflight(7, "benchmark", "owasp-benchmark-full", db_path=db,
                          env_token="", require_online=False, do_http=True,
                          opener=_Opener())
    assert report["ready"] is False
    assert report["http_handshake"]["ok"] is False
    assert any("鉴权未通过" in x for x in report["reasons"])


def test_workspace_enumerate_requires_one_ready(tmp_path, monkeypatch):
    """ws4 有两个会话，只要有一个对齐且在线即可；全离线则 fail。"""
    db = make_db(tmp_path, workspace_id=4, app="sec-code", agent="java-sec-code")
    monkeypatch.setattr(pp, "DEFAULT_DB_PATH", db)
    report = pp.preflight_workspace(4, db_path=db, require_online=True,
                                    do_http=False, now=2_000_000_000.0)
    assert report["ready"] is False
    assert len(report["sessions"]) == 1


# ---------------------------------------------------------------- 时区回归锁
def test_utc_naive_heartbeat_is_fresh_not_shifted_by_local_tz(tmp_path):
    """iast_sessions 的 UTC naive 串必须按 UTC 解析。

    UTC+8 机器上裸 datetime.timestamp() 会把 08:54 当本地时间，now - hb 凭空
    多出 8 小时，刚上报心跳的在线探针会被误判离线（发车门禁假拦截）。
    """
    now = datetime(2026, 11, 9, 8, 54, 56, tzinfo=timezone.utc).timestamp()
    db = make_db(tmp_path, heartbeat="2026-11-09T08:54:44.925348")
    s = pp.inspect_session(db, 7, "benchmark", "owasp-benchmark-full", now=now)
    assert s["heartbeat_fresh"] is True
    assert s["probe_online"] is True


def test_utc_naive_stale_heartbeat_still_blocked(tmp_path):
    """修时区不能修成 fail-open：6 天前的心跳仍须判离线。"""
    now = datetime(2026, 11, 9, 8, 54, 56, tzinfo=timezone.utc).timestamp()
    stale = (datetime(2026, 11, 9, 8, 54, 56, tzinfo=timezone.utc)
             - timedelta(days=6)).replace(tzinfo=None).isoformat()
    db = make_db(tmp_path, heartbeat=stale)
    s = pp.inspect_session(db, 7, "benchmark", "owasp-benchmark-full", now=now)
    assert s["heartbeat_fresh"] is False
    assert s["probe_online"] is False


def test_parse_iso_keeps_explicit_timezone_offset():
    """带显式偏移 / Z 的串按原偏移解析，不能被强行钉成 UTC。"""
    z = pp._parse_iso("2026-11-09T08:54:44+08:00")
    u = pp._parse_iso("2026-11-09T08:54:44Z")
    assert z is not None and u is not None
    assert u - z == 8 * 3600


# ---------------------------------------------------------------- 服务端 WARN
def test_auth_reject_is_logged_and_counted(caplog):
    from src.api.routers import agent_bridge as ab
    before = ab.auth_reject_stats()["count"]
    with caplog.at_level("WARNING"):
        n = ab.record_auth_reject("benchmark", "owasp-benchmark-full", "bogus1",
                                  "/api/agent/events", "X-Agent-Token 不匹配")
    assert n == before + 1
    assert "probe-auth" in caplog.text
    assert "bogus1" in caplog.text
    assert DB_TOKEN not in caplog.text  # 只打前缀
    assert ab.auth_reject_stats()["last"]["token_prefix"] == "bogus1"
