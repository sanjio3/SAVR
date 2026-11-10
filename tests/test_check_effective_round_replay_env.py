"""重放层环境一致性回归锁（2026-11-08，本轮被污染轮复盘配套）。

本轮的 A2 contract 与 637 / 639 逐字节一致，但 14:56 起 8080 被另一个
Spring Boot 实例接管：393 条请求落到 ISO 8601 错误体 404，404 率 18.3%、
扩散到 20 个端点，IAST 事件 -21%，最终 ssrf.java/ssrf 少 2 条
oracle:error_reflect 确认、重放 24/24 -> 23/24。只查 A2 contract 会把它
判成有效轮，把环境干扰误读成稳定性退化。本锁保证这类轮次一律 INVALID。

阈值依据（实测）：634/635/637/638/639 的 404 率 1.8~2.2%、2~3 端点、
单一 epoch 错误体、认证态 99.5%；盲化轮 638 同样通过，无需单独豁免。
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from tools import check_effective_round as C


def _info(replay_env=None, **overrides):
    info = {
        "id": 700,
        "name": "jsc-L3-test",
        "status": "completed",
        "phase": "completed",
        "error_message": "",
        "contract": {
            "calls": 95,
            "transport": {
                "timeouts": 0, "retries": 0, "recovered": 0,
                "exhausted": 0, "generation_timeouts": 0,
                "truncated": 3, "circuit_broken": 0,
                "consecutive_exhausted": 0,
            },
            "file_failures": {"failed_files": 0, "files": []},
        },
    }
    if replay_env is not None:
        info["replay_env"] = replay_env
    info.update(overrides)
    return info


def _clean(**kv):
    """本轮实测指纹。"""
    out = {
        "available": True,
        "attempts": 1940,
        "not_found": 35,
        "not_found_ratio": 0.018,
        "not_found_endpoints": 3,
        "error_body_shapes": ["epoch"],
        "other_error_bodies": 0,
        "iast_events": 5182,
        "authenticated_ratio": 0.995,
    }
    out.update(kv)
    return out


def _polluted(**kv):
    """本轮实测指纹。"""
    out = {
        "available": True,
        "attempts": 2336,
        "not_found": 428,
        "not_found_ratio": 0.183,
        "not_found_endpoints": 20,
        "error_body_shapes": ["epoch", "iso"],
        "other_error_bodies": 0,
        "iast_events": 4071,
        "authenticated_ratio": 0.996,
    }
    out.update(kv)
    return out


def test_clean_replay_env_is_effective():
    r = C.evaluate(_info(_clean()))
    assert r["effective"] is True
    assert r["verdict"] == "EFFECTIVE"
    assert r["check_replay_env"] is True
    assert r["failed_checks"] == []


def test_l3_run2_polluted_replay_env_is_invalid():
    r = C.evaluate(_info(_polluted()))
    assert r["effective"] is False
    assert r["verdict"] == "INVALID"
    failed = " | ".join(r["failed_checks"])
    assert "replay_env.not_found_ratio <= 0.10" in failed
    assert "replay_env.not_found_endpoints <= 4" in failed
    assert "replay_env.error_body_shapes <= 1" in failed


@pytest.mark.parametrize("kv", [
    {"error_body_shapes": ["epoch", "iso"]},
    {"not_found_ratio": 0.183},
    {"not_found_endpoints": 20},
    {"iast_events": 0},
    {"authenticated_ratio": 0.42},
])
def test_single_replay_env_signal_invalidates_round(kv):
    r = C.evaluate(_info(_clean(**kv)))
    assert r["effective"] is False
    assert any(x.startswith("replay_env.") for x in r["failed_checks"])


def test_blinded_route_round_638_still_passes():
    """盲化变体 638 实测 404 2.2% / 2 端点 / 单一 epoch，不得被新判据误伤。"""
    r = C.evaluate(_info(_clean(attempts=1077, not_found=24,
                                not_found_ratio=0.022, not_found_endpoints=2,
                                iast_events=3988)))
    assert r["effective"] is True


def test_unavailable_replay_env_is_fail_closed():
    r = C.evaluate(_info({"available": False, "reason": "no replay_attempts for run 700"}))
    assert r["effective"] is False
    assert "replay_env.available" in r["failed_checks"]


def test_absent_replay_env_key_skips_new_checks():
    """--progress / 历史对照没有 DB 上下文时不新增判据，旧调用保持兼容。"""
    r = C.evaluate(_info())
    assert r["effective"] is True
    assert r["check_replay_env"] is False
    assert not any(x.startswith("replay_env.") for x in r["failed_checks"])


@pytest.mark.parametrize("body,expected", [
    ('{"timestamp":1794120134425,"status":404,"error":"Not Found"}', "epoch"),
    ('{"timestamp":"2026-11-08T06:56:37.863+00:00","status":404}', "iso"),
    ("upstream connect failed", "other"),
    ("", "other"),
    (None, "other"),
])
def test_error_body_shape_detects_spring_generations(body, expected):
    assert C._error_body_shape(body) == expected


def test_replay_env_stats_reads_real_sqlite(tmp_path):
    db = tmp_path / "round.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE replay_attempts (task_id INTEGER, status_code INTEGER, "
                "target_endpoint TEXT, resp_body_head TEXT, action_json TEXT)")
    con.execute("CREATE TABLE iast_events (task_id INTEGER)")
    epoch = '{"timestamp":1794120134425,"status":404}'
    iso = '{"timestamp":"2026-11-08T06:56:37.863+00:00","status":404}'
    rows = [(700, 200, "/login", "", '{"auth_state":"authenticated"}')] * 8
    rows += [(700, 404, "/ssrf/a", epoch, '{"auth_state":"authenticated"}'),
             (700, 404, "/ssrf/b", iso, '{"auth_state":"authenticated"}')]
    con.executemany("INSERT INTO replay_attempts VALUES (?,?,?,?,?)", rows)
    con.executemany("INSERT INTO iast_events VALUES (?)", [(700,)] * 10)
    con.commit()
    con.close()

    st = C.replay_env_stats(str(db), 700)
    assert st["available"] is True
    assert st["attempts"] == 10
    assert st["not_found"] == 2
    assert st["not_found_ratio"] == 0.2
    assert st["not_found_endpoints"] == 2
    assert st["error_body_shapes"] == ["epoch", "iso"]
    assert st["iast_events"] == 10
    assert st["authenticated_ratio"] == 1.0
    assert C.evaluate(_info(st))["effective"] is False


def test_replay_env_stats_missing_db_is_fail_closed(tmp_path):
    st = C.replay_env_stats(str(tmp_path / "nope.db"), 700)
    assert st["available"] is False
    assert C.evaluate(_info(st))["effective"] is False


def test_render_prints_replay_env_fingerprint():
    text = C.render(C.evaluate(_info(_polluted())))
    assert "重放层环境指纹" in text
    assert "404 428/2336 (18.3%)" in text
    assert "epoch+iso" in text
    assert "INVALID" in text


def test_cli_task_id_enforces_replay_env(monkeypatch, capsys):
    monkeypatch.setattr(C, "_contract_from_db", lambda tid, db: _info())
    monkeypatch.setattr(C, "replay_env_stats", lambda db, tid: _polluted())
    rc = C.main(["--task-id", "640", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert out["effective"] is False
    assert out["check_replay_env"] is True
    assert out["replay_env"]["not_found"] == 428


def test_cli_no_replay_env_exempts_history_only(monkeypatch, capsys):
    monkeypatch.setattr(C, "_contract_from_db", lambda tid, db: _info())
    called = []
    monkeypatch.setattr(C, "replay_env_stats",
                        lambda db, tid: called.append(tid))
    rc = C.main(["--task-id", "631", "--no-replay-env", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert called == []
    assert out["replay_env_exempt"] is True
    assert out["check_replay_env"] is False
    assert "EXEMPT" in C.render(out)


# ── 2026-11-08（L2 本轮）：404 率按 workspace 分档 ──────────────────────
# jsc 的路由是单段语义路由（/sqli），RuoYi 是多段业务路由，且 A2 会从工具类
# 方法名脑补不存在的路由（exportExcel / loadYaml…）。用 jsc 的 10% 去量 RuoYi
# 只会量出「路由推断质量」，不是这个检查要抓的「靶场身份变了」。

def _ruoyi_645(**kv):
    """本轮实测指纹：13.2% 404 全部落在 5 个脑补路由上。"""
    out = {
        "available": True,
        "workspace_id": 8,
        "attempts": 1043,
        "not_found": 138,
        "not_found_ratio": 0.132,
        "not_found_endpoints": 5,
        "not_found_endpoint_top": [("http://127.0.0.1:8081/exportExcel", 105)],
        "error_body_shapes": ["iso"],
        "other_error_bodies": 0,
        "iast_events": 1949,
        "authenticated_ratio": 1.0,
    }
    out.update(kv)
    return out


def test_profile_selected_by_workspace():
    assert C.replay_profile(4)["name"] == "jsc"
    assert C.replay_profile(8)["name"] == "ruoyi"
    assert C.replay_profile(None)["name"] == "default"
    assert C.replay_profile("not-an-int")["name"] == "default"


def test_ruoyi_profile_tolerates_route_guessing_noise():
    r = C.evaluate(_info(_ruoyi_645()))
    failed = " | ".join(r["failed_checks"])
    assert "replay_env.not_found_ratio" not in failed
    assert "replay_env.not_found_endpoints" not in failed
    assert r["replay_profile"]["name"] == "ruoyi"


def test_same_fingerprint_fails_under_jsc_profile():
    """同一份指纹放到 jsc 档必须仍然失败 —— 分档不是全局放宽。"""
    r = C.evaluate(_info(_ruoyi_645(workspace_id=4)))
    failed = " | ".join(r["failed_checks"])
    assert "replay_env.not_found_ratio <= 0.10 [jsc]" in failed
    assert "replay_env.not_found_endpoints <= 4 [jsc]" in failed


def test_l3_run2_still_invalid_under_its_own_profile():
    """负控：jsc 上的抢占轮在新分档下三条同时命中。"""
    polluted = _clean(workspace_id=4, not_found=428, not_found_ratio=0.183,
                      not_found_endpoints=20, error_body_shapes=["epoch", "iso"],
                      iast_events=4071, attempts=2336)
    r = C.evaluate(_info(polluted))
    assert r["effective"] is False
    failed = " | ".join(r["failed_checks"])
    assert "not_found_ratio <= 0.10 [jsc]" in failed
    assert "not_found_endpoints <= 4 [jsc]" in failed
    assert "error_body_shapes <= 1" in failed


def test_unknown_workspace_falls_back_to_strict_profile():
    """未登记的目标走默认严格档，不能因为不认识就放松。"""
    r = C.evaluate(_info(_ruoyi_645(workspace_id=99)))
    failed = " | ".join(r["failed_checks"])
    assert "replay_env.not_found_ratio <= 0.10 [default]" in failed
