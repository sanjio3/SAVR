"""§3.1-B 末态兜底回归守卫：D2 把空 verification_status 的 trigger_spec 落 'no_evidence'。

根因：trigger_specs 中部分自动登记的 spec 无对应 finding 驱动 run_d2_verify 的 verify()，
导致 per-spec 写回循环永不触发，verification_status / iast_state 恒为空字符串，在召回率指标里
形成幽灵第三类目（empty=8）。

本测试把「8 条空状态 spec」变成可复现的通过用例：finalize_unverified_trigger_specs 必须只扫
本 task 的空状态 spec，置 'no_evidence'，且保持已 verdict 的 spec 与异 task 的 spec 不变；
iast_state 仅在当前为空时才补 'no-iast-evidence'。
"""
import pytest

from src.infrastructure.db import Database
from src.cli.benchmark_cli import finalize_unverified_trigger_specs

TASK = 1
OTHER_TASK = 2
WS = 3
_TS_TS = "2026-09-10T00:00:00"


@pytest.fixture()
def db(tmp_path):
    # Database() 会自动建全量 schema（含 trigger_specs），无需手动建表。
    d = Database(str(tmp_path / "app.db"))
    # trigger_specs 有 FK 指向 workspaces / scan_tasks，先种父行避免 IntegrityError。
    d.execute(
        "INSERT INTO workspaces (id, name, target_path, settings_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (WS, "ws", "/tmp/proj", "{}", _TS_TS, _TS_TS),
    )
    for tid in (TASK, OTHER_TASK):
        d.execute(
            "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, options_json, summary_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (tid, WS, "task{}".format(tid), "completed", "done", "/tmp/out", "{}", "{}", _TS_TS),
        )
    return d


def _seed(db, rows):
    """rows: (id, task_id, workspace_id, family, target_endpoint, verification_status,
    iast_state, business_logic_category, finding_id)"""
    for r in rows:
        # vulnerability_hash_v2 逐条唯一（trigger_specs 的 UNIQUE(task_id, vhash)，upsert 用）
        db.execute(
            "INSERT INTO trigger_specs "
            "(id, task_id, workspace_id, vulnerability_hash_v2, family, target_endpoint,"
            " verification_status, iast_state, business_logic_category, finding_id, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (r[0], r[1], r[2], "h%s" % r[0], r[3], r[4], r[5], r[6], r[7], r[8], _TS_TS),
        )


def _row_map(db):
    out = {}
    for r in (db.execute("SELECT id, verification_status, iast_state FROM trigger_specs", fetchall=True) or []):
        out[r["id"]] = {"vs": r["verification_status"], "state": r["iast_state"]}
    return out


def test_finalize_only_empty_specs_of_current_task(db):
    # task1: 2 条空状态（bola / calculation_logic）+ 2 条已 verdict
    # task2: 1 条空状态（异 task，绝不可被触碰）
    _seed(db, [
        (1, TASK, WS, "idor", "/address/{id}", "", "", "bola", None),
        (2, TASK, WS, "business-logic", "/order/{id}", "", "", "calculation_logic", None),
        (3, TASK, WS, "bola", "/order/{id}", "confirmed_exploitable", "sink-reached-probe", "bola", 10),
        (4, TASK, WS, "race", "/cart/{id}", "unconfirmed", "no-iast-evidence", "race", 11),
        (5, OTHER_TASK, WS, "bola", "/comment/{id}", "", "", "bola", None),
    ])
    n = finalize_unverified_trigger_specs(db, TASK)
    assert n == 2, f"应只清理 task1 的 2 条空状态 spec，实际={n}"

    m = _row_map(db)
    assert m[1]["vs"] == "no_evidence"
    assert m[1]["state"] == "no-iast-evidence"
    assert m[2]["vs"] == "no_evidence"
    assert m[2]["state"] == "no-iast-evidence"
    # 已 verdict 的 spec 必须原样保留
    assert m[3]["vs"] == "confirmed_exploitable"
    assert m[4]["vs"] == "unconfirmed"
    # 异 task 的空状态 spec 不被触碰
    assert m[5]["vs"] == ""


def test_finalize_preserves_non_empty_iast_state(db):
    # 空 verification_status 但有非零 iast_state：保留原 iast_state，不强行覆盖
    _seed(db, [(6, TASK, WS, "bola", "/order/{id}", "", "iast-reached", "bola", None)])
    n = finalize_unverified_trigger_specs(db, TASK)
    assert n == 1
    m = _row_map(db)
    assert m[6]["vs"] == "no_evidence"
    assert m[6]["state"] == "iast-reached"


def test_finalize_empty_string_status_treated_as_empty(db):
    # 真实场景：verification_status 为 NOT NULL default ''，空串即「未写回」。
    # 即便 iast_state 已有观测值（如 no-arrival），verification_status 空仍应被兜底为 no_evidence。
    db.execute(
        "INSERT INTO trigger_specs "
        "(id, task_id, workspace_id, family, target_endpoint, verification_status, iast_state, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (7, TASK, WS, "bola", "/comment", "", "no-arrival", _TS_TS),
    )
    n = finalize_unverified_trigger_specs(db, TASK)
    assert n == 1
    m = _row_map(db)
    assert m[7]["vs"] == "no_evidence"
    # iast_state 非空，保留原观测值
    assert m[7]["state"] == "no-arrival"


def test_finalize_noop_when_clean(db):
    _seed(db, [
        (8, TASK, WS, "bola", "/order/{id}", "confirmed_exploitable", "sink-reached-probe", "bola", 1),
        (9, TASK, WS, "race", "/cart/{id}", "unconfirmed", "no-iast-evidence", "race", 2),
    ])
    n = finalize_unverified_trigger_specs(db, TASK)
    assert n == 0
    m = _row_map(db)
    assert m[8]["vs"] == "confirmed_exploitable"
    assert m[9]["vs"] == "unconfirmed"


def test_finalize_returns_zero_without_task_id(db):
    _seed(db, [(10, TASK, WS, "bola", "/comment", "", "", "bola", None)])
    assert finalize_unverified_trigger_specs(db, None) == 0
    m = _row_map(db)
    assert m[10]["vs"] == ""
