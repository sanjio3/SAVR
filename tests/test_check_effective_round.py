"""Gate 0 有效轮判据回归锁（2026-11-08，本轮无效轮复盘配套）。

防止「LLM 不可用导致假掉点」的轮次被当成泛化验收基线：判据必须 fail-closed，
字段缺失、终态非 completed、任一调用/文件级失败非零，一律判 INVALID。
`truncated` 是首次真实轮后校准的可观测项：必须存在，非零只给
warning，不否决轮次（依据见 tools/check_effective_round.py 模块注释）。
"""
from __future__ import annotations

import json

import pytest

from tools import check_effective_round as C


def _info(**overrides):
    info = {
        "id": 700,
        "name": "jsc-R0prime-test",
        "status": "completed",
        "phase": "completed",
        "error_message": "",
        "contract": {
            "calls": 95,
            "transport": {
                "timeouts": 0, "retries": 0, "recovered": 0,
                "exhausted": 0, "generation_timeouts": 0,
                "truncated": 0, "circuit_broken": 0,
                "consecutive_exhausted": 0,
            },
            "file_failures": {"failed_files": 0, "files": []},
        },
    }
    info.update(overrides)
    return info


def _with_transport(**kv):
    info = _info()
    info["contract"]["transport"].update(kv)
    return info


def test_clean_round_is_effective():
    r = C.evaluate(_info())
    assert r["effective"] is True
    assert r["verdict"] == "EFFECTIVE"
    assert r["failed_checks"] == []


@pytest.mark.parametrize("key", ["exhausted", "generation_timeouts",
                                 "circuit_broken"])
def test_any_transport_failure_invalidates_round(key):
    r = C.evaluate(_with_transport(**{key: 1}))
    assert r["effective"] is False
    assert "transport.%s == 0" % key in r["failed_checks"]


def test_truncated_is_warning_not_veto():
    """截断必须可观测，但不否决轮次；准确性底线由文件/调用失败承担。"""
    r = C.evaluate(_with_transport(truncated=2))
    assert r["effective"] is True
    assert r["verdict"] == "EFFECTIVE"
    assert len(r["warnings"]) == 1
    assert "truncated=2" in r["warnings"][0]
    assert "[WARN]" in C.render(r)


def test_missing_truncated_is_fail_closed():
    info = _info()
    del info["contract"]["transport"]["truncated"]
    r = C.evaluate(info)
    assert r["effective"] is False
    assert "transport.truncated present (observability)" in r["failed_checks"]


def test_file_level_failure_invalidates_round():
    info = _info()
    info["contract"]["file_failures"] = {"failed_files": 2, "files": ["A.java", "B.java"]}
    r = C.evaluate(info)
    assert r["effective"] is False
    assert "file_failures.failed_files == 0" in r["failed_checks"]


def test_missing_transport_is_fail_closed():
    info = _info()
    del info["contract"]["transport"]
    r = C.evaluate(info)
    assert r["effective"] is False
    assert "a2_contract_has_transport_and_file_failures" in r["failed_checks"]


def test_missing_contract_is_fail_closed():
    r = C.evaluate(_info(contract={}))
    assert r["effective"] is False
    assert r["failed_checks"]


def test_legacy_round_shape_is_not_verifiable():
    """本轮/635 的 contract 只有合规率，没有  埋点 ⇒ 不可验证。"""
    legacy = {"calls": 92, "first_pass": 91, "retried": 1,
              "compliance_rate": 0.9891, "invalid_rate": 0.0109}
    r = C.evaluate(_info(contract=legacy))
    assert r["effective"] is False
    assert "a2_contract_has_transport_and_file_failures" in r["failed_checks"]


def test_non_completed_status_invalidates_round():
    r = C.evaluate(_info(status="failed", error_message="aborted"))
    assert r["effective"] is False
    assert "task_completed" in r["failed_checks"]


def test_missing_metric_value_is_fail_closed():
    info = _info()
    del info["contract"]["transport"]["exhausted"]
    r = C.evaluate(info)
    assert r["effective"] is False
    assert "transport.exhausted == 0" in r["failed_checks"]


def test_render_contains_verdict_and_failed_checks():
    text = C.render(C.evaluate(_with_transport(exhausted=3)))
    assert "INVALID" in text
    assert "[NG] transport.exhausted == 0" in text
    assert "不得计入 G0-2 / G0-3" in text


def test_cli_json_exit_code(capsys, monkeypatch):
    monkeypatch.setattr(C, "_contract_from_db", lambda _tid, _db: _with_transport(exhausted=1))
    rc = C.main(["--task-id", "700", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 2
    assert out["effective"] is False
    assert out["verdict"] == "INVALID"


def test_cli_requires_selector():
    with pytest.raises(SystemExit):
        C.main([])
