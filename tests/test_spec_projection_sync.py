# -*- coding: utf-8 -*-
"""trigger_specs 权威列 → raw_json.exploit_spec.entry 投影同步回归锁。

本轮实测 39/145 处漂移：I1 的 post-pass 只 UPDATE 权威列，报告层读 entry
拿到 A2 旧猜测。全部 post-pass 必须跟一次 sync_entry_projection。
"""
import inspect
import json

from src.iast import spec_projection as sp


class _FakeDB:
    def __init__(self, rows):
        self.rows = {r["id"]: dict(r) for r in rows}
        self.writes = []

    def execute(self, sql, params=(), **kw):
        if sql.strip().startswith("SELECT"):
            sid = params[0]
            r = self.rows.get(sid)
            if not r:
                return None if kw.get("fetchone") else []
            if kw.get("fetchone"):
                return (r["raw_json"],)
            return [r]
        if sql.strip().startswith("UPDATE"):
            payload, sid = params
            self.rows[sid]["raw_json"] = payload
            self.writes.append((sid, payload))
        return None


def _row(sid=1, name="content", loc="body", ct="application/json",
         e_name="content", e_loc="query", e_ct=""):
    return {
        "id": sid, "param_name": name, "param_location": loc, "content_type": ct,
        "raw_json": json.dumps({"exploit_spec": {"entry": {
            "route": "/rce/vuln/yarm", "parameter_name": e_name,
            "parameter_location": e_loc, "content_type": e_ct,
        }}}),
    }


def test_sync_writes_authoritative_values_into_entry():
    db = _FakeDB([_row()])
    assert sp.sync_entry_projection(db, 1, param_name="content",
                                    param_location="body", content_type="application/json")
    entry = json.loads(db.rows[1]["raw_json"])["exploit_spec"]["entry"]
    assert entry["parameter_location"] == "body"
    assert entry["content_type"] == "application/json"
    assert entry["param_authority"] == "trigger_specs"


def test_sync_preserves_a2_intent_once():
    db = _FakeDB([_row()])
    sp.sync_entry_projection(db, 1, param_location="body")
    sp.sync_entry_projection(db, 1, param_location="header")
    entry = json.loads(db.rows[1]["raw_json"])["exploit_spec"]["entry"]
    assert entry["a2_intent"] == {"parameter_name": "content",
                                  "parameter_location": "query"}
    assert entry["parameter_location"] == "header"


def test_sync_is_noop_when_values_already_match():
    db = _FakeDB([_row(e_loc="body", e_ct="application/json")])
    assert sp.sync_entry_projection(db, 1, param_name="content",
                                    param_location="body", content_type="application/json") is False
    assert db.writes == []


def test_sync_skips_missing_or_malformed_raw_json():
    db = _FakeDB([{"id": 2, "param_name": "x", "param_location": "body",
                   "content_type": "", "raw_json": "not-json"},
                  {"id": 3, "param_name": "x", "param_location": "body",
                   "content_type": "", "raw_json": "{}"}])
    assert sp.sync_entry_projection(db, 2, param_location="body") is False
    assert sp.sync_entry_projection(db, 3, param_location="body") is False
    assert db.writes == []


def test_audit_reports_drift_for_dict_and_tuple_rows():
    r = _row()
    d = json.loads(r["raw_json"])
    dict_rows = [{"id": r["id"], "param_name": r["param_name"],
                  "param_location": r["param_location"], "content_type": r["content_type"],
                  "raw_json": r["raw_json"]}]
    tuple_rows = [(r["id"], r["param_name"], r["param_location"],
                   r["content_type"], r["raw_json"])]
    a = sp.audit_entry_projection_rows(dict_rows)
    b = sp.audit_entry_projection_rows(tuple_rows)
    assert len(a) == len(b) == 1
    assert a[0]["spec_id"] == 1
    assert a[0]["diffs"]["param_location"] == {"authoritative": "body", "entry": "query"}
    # 同步后审计应为 0
    sp.sync_entry_projection(_FakeDB([r]), 1, param_location="body",
                             content_type="application/json")


def test_all_authoritative_column_writers_call_sync():
    """四处 UPDATE 必须跟投影同步，漏一处就会重新长出漂移。"""
    from src.cli import benchmark_cli
    from src.agents import i2_feedback
    cli_src = inspect.getsource(benchmark_cli)
    i2_src = inspect.getsource(i2_feedback)
    # import 行不带括号，这里数的是实际调用点
    assert cli_src.count("sync_entry_projection(") >= 3  # src-loc / param-fill / binding
    assert i2_src.count("sync_entry_projection(") >= 1   # I2 switch_param_location
    assert "from src.iast.spec_projection import sync_entry_projection" in cli_src
    assert "from src.iast.spec_projection import sync_entry_projection" in i2_src
