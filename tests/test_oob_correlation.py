"""OOB 第四层回调回流（收口，2026-09-29）的单元/集成测试。

验证核心：带外回执真实到达（oob_callbacks.kind='callback'）后，_apply_oob_correlation
能把「被 硬闸降级为 confirm-gate:no-arrival 的反序列化 spec」升级回 confirmed_exploitable，
且必须经 _confirm_gate_decide(oob_confirmed=True) 复核；无回执则不升级（铁律：无回执=无证据）。

不依赖整栈，用临时文件 DB 串起 oob_monitor 与 trigger_specs。
"""
import json
import os
import sqlite3
import tempfile

import pytest

import src.iast.oob_monitor as oob_monitor
import src.cli.benchmark_cli as benchmark_cli


class _FakeDB:
    """最小 sdb 替身：与真实 Database.execute 同签名（fetchall/fetchone），返回 dict。"""

    def __init__(self, path):
        self._con = sqlite3.connect(path, timeout=15)
        self._con.row_factory = sqlite3.Row

    def execute(self, sql, params=None, fetchall=False, fetchone=False):
        cur = self._con.execute(sql, params or ())
        if fetchone:
            row = cur.fetchone()
            return dict(row) if row is not None else {}
        if fetchall:
            return [dict(r) for r in cur.fetchall()]
        self._con.commit()
        return cur


@pytest.fixture
def env(tmp_path, monkeypatch):
    db_path = str(tmp_path / "oob_test.db")
    con = sqlite3.connect(db_path)
    con.execute(
        "CREATE TABLE trigger_specs ("
        "id INTEGER PRIMARY KEY, task_id INTEGER, family TEXT, iast_state TEXT, "
        "verification_status TEXT, raw_json TEXT, target_endpoint TEXT)"
    )
    con.execute(oob_monitor._DDL)
    con.commit()
    con.close()

    captured = {}

    def _fake_append(task_id, et, payload):
        captured.setdefault(et, []).append(payload)

    monkeypatch.setattr(benchmark_cli, "_append_scan_task_event", _fake_append)
    sdb = _FakeDB(db_path)
    return {"db_path": db_path, "sdb": sdb, "captured": captured}


def _seed_spec(sdb, spec_id, task_id, iast_state, status="unconfirmed",
               family="deserialization", endpoint="/debug/import"):
    rj = {
        "d2_evidence": {"iast_state": iast_state, "d2_harmful": False,
                        "deserialization_chain_confirmed": False, "matched_event_ids": []},
        "d2_output": {"impact_observed": False},
        "oob": {"token": "", "confirmed": False},
    }
    sdb.execute(
        "INSERT INTO trigger_specs (id, task_id, family, iast_state, verification_status, raw_json, target_endpoint) "
        "VALUES (?,?,?,?,?,?,?)",
        (spec_id, task_id, family, iast_state, status, json.dumps(rj, ensure_ascii=False), endpoint),
    )


def _get_spec(sdb, spec_id):
    return sdb.execute("SELECT * FROM trigger_specs WHERE id=?", (spec_id,), fetchone=True)


def test_oob_callback_upgrades_gated_spec(env):
    """回执到达 ⇒ confirm-gate:no-arrival 的反序列化 spec 升 confirmed_exploitable。"""
    _seed_spec(env["sdb"], 9001, 99, "confirm-gate:no-arrival")
    tok = oob_monitor.new_token()
    oob_monitor.register(tok, task_id=99, family="deserialization",
                         target_endpoint="/debug/import", spec_id=9001, db_path=env["db_path"])
    assert oob_monitor.record_callback(tok, source="http", db_path=env["db_path"])

    n = benchmark_cli._apply_oob_correlation(99, env["sdb"])
    assert n == 1
    sp = _get_spec(env["sdb"], 9001)
    assert sp["verification_status"] == "confirmed_exploitable"
    assert sp["iast_state"] == "oob-reached"
    rj = json.loads(sp["raw_json"])
    assert rj["oob"]["confirmed"] is True
    assert rj["oob"]["token"] == tok[:32]
    assert env["captured"].get("oob_correlation")


def test_no_callback_no_upgrade(env):
    """只登记未回执 ⇒ 不升级（铁律：无回执=无证据）。"""
    _seed_spec(env["sdb"], 9002, 99, "confirm-gate:no-arrival")
    tok = oob_monitor.new_token()
    oob_monitor.register(tok, task_id=99, family="deserialization",
                         target_endpoint="/debug/import", spec_id=9002, db_path=env["db_path"])
    # 故意不 record_callback
    n = benchmark_cli._apply_oob_correlation(99, env["sdb"])
    assert n == 0
    sp = _get_spec(env["sdb"], 9002)
    assert sp["verification_status"] == "unconfirmed"


def test_already_confirmed_not_double_counted(env):
    """已 confirmed 的 spec 不再被回执重复升级。"""
    _seed_spec(env["sdb"], 9003, 99, "sink-reached-probe", status="confirmed_exploitable")
    tok = oob_monitor.new_token()
    oob_monitor.register(tok, task_id=99, family="deserialization",
                         target_endpoint="/debug/import", spec_id=9003, db_path=env["db_path"])
    oob_monitor.record_callback(tok, source="http", db_path=env["db_path"])
    n = benchmark_cli._apply_oob_correlation(99, env["sdb"])
    assert n == 0


def test_fallback_by_family_endpoint_when_no_spec_id(env):
    """旧数据登记行缺 spec_id 时，按 (family, endpoint) 粗收口未确认的反序列化 spec。"""
    _seed_spec(env["sdb"], 9004, 99, "confirm-gate:no-arrival", endpoint="/debug/import")
    _seed_spec(env["sdb"], 9005, 99, "confirm-gate:no-arrival", endpoint="/debug/import")
    tok = oob_monitor.new_token()
    # 旧数据：register 不传 spec_id
    oob_monitor.register(tok, task_id=99, family="deserialization",
                         target_endpoint="/debug/import", db_path=env["db_path"])
    oob_monitor.record_callback(tok, source="http", db_path=env["db_path"])
    n = benchmark_cli._apply_oob_correlation(99, env["sdb"])
    assert n == 2
    assert _get_spec(env["sdb"], 9004)["verification_status"] == "confirmed_exploitable"
    assert _get_spec(env["sdb"], 9005)["verification_status"] == "confirmed_exploitable"


def test_oob_register_records_spec_id(env):
    """register 落 spec_id，回调可追溯精确 spec。"""
    tok = oob_monitor.new_token()
    assert oob_monitor.register(tok, task_id=1, family="deserialization",
                               target_endpoint="/x", spec_id=42, db_path=env["db_path"])
    con = sqlite3.connect(env["db_path"])
    row = con.execute("SELECT spec_id FROM oob_callbacks WHERE token=? AND kind='registered'",
                      (tok,)).fetchone()
    con.close()
    assert row[0] == 42
