"""R23-2 回归守卫：业务逻辑差分重放的 DB 透传（§6.13 根因二）。

事故：victim_identifiers 两轮全空（0/144、0/167）、victim_resource_id 全为哨兵 VICTIM_FROM_POOL。
根因：``business_logic.verify()`` 无 db 形参，内部 ``D1Service(gateway=...)`` 命中
``D1Service.__init__`` 的 tempfile 兜底 → ``replay_bola`` 末尾的
``IastService(self.db).update_trigger_spec_victim_identifiers(...)`` 把回填写进临时库，
真实 DB 永不落盘；同族问题还包括 bootstrap_accounts 的 accounts_json 回写与
``_load_idor_accounts`` 读账户（无参 D1Service → 恒空）。

修复：verify() 增 db 形参并在三处调用点（d2_facade._verify_business_logic、
D1Service._replay_business_logic、REST /api/business-logic/verify）+ benchmark_cli
_load_idor_accounts 全部透传真实 DB。
"""

from pathlib import Path
from unittest import mock

import pytest

from src.application.d1_service import D1Service
from src.infrastructure.db import Database
from src.iast import business_logic as bl
from src.iast.orchestrator import DastImpact

WORKSPACE_ID = 1


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    database.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (WORKSPACE_ID, "task1", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    return database


def _seed_spec(db: Database, *, spec_id: int = 1) -> int:
    db.execute(
        "INSERT INTO trigger_specs (id, workspace_id, task_id, vulnerability_hash_v2, family, "
        "target_endpoint, http_method, param_name, param_location, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (spec_id, WORKSPACE_ID, 1, "vh1", "bola", "/api/order/{id}", "GET", "id", "path", "2026-01-01T00:00:00"),
    )
    return spec_id


def _read_victim_identifiers(db: Database, spec_id: int):
    row = db.execute("SELECT victim_identifiers FROM trigger_specs WHERE id=?", (spec_id,), fetchone=True)
    return Database.loads(row["victim_identifiers"])


def _spec_payload(spec_id: int) -> dict:
    return {
        "id": spec_id,
        "target_endpoint": "/api/order/{id}",
        "http_method": "GET",
        "param_name": "id",
        "param_location": "path",
        "victim_resource_id": "42",
    }


_ACCOUNTS = {
    "attacker": {"auth_headers": {}, "auth_cookies": {}, "role": "attacker", "username": "bob"},
    "victim": {"auth_headers": {}, "auth_cookies": {}, "role": "victim", "username": "alice",
               "user_id": "42"},
}


# ---------------------------------------------------------------- 形参透传契约


def test_verify_forwards_db_into_d1service(monkeypatch):
    captured = {}

    class _FakeD1:
        def __init__(self, db=None, gateway=None):
            captured["db"] = db
            captured["gateway"] = gateway

        def replay_bola(self, *a, **k):
            return {"confirmed": False}

    monkeypatch.setattr(bl, "D1Service", _FakeD1)
    sentinel = object()
    bl.verify("bola", {}, {}, db=sentinel)
    assert captured["db"] is sentinel, "verify() 必须把 db 透传给 D1Service，否则回填落临时库"


def test_verify_defaults_db_to_none_for_backward_compat(monkeypatch):
    captured = {}

    class _FakeD1:
        def __init__(self, db=None, gateway=None):
            captured["db"] = db
            captured["gateway"] = gateway

        def replay_bola(self, *a, **k):
            return {}

    monkeypatch.setattr(bl, "D1Service", _FakeD1)
    bl.verify("bola", {}, {}, gateway="gw")
    assert captured["db"] is None
    assert captured["gateway"] == "gw"


def test_d2_facade_passes_iast_service_db():
    from src.agents.d2_facade import D2Agent

    sentinel_db = object()
    fake_iast = mock.Mock()
    fake_iast.db = sentinel_db
    fake = {"confirmed": False, "category": "bola", "confidence": "low"}

    with mock.patch("src.iast.business_logic.verify", return_value=fake) as m:
        D2Agent()._verify_business_logic(
            "bola",
            {"business_logic_category": "bola", "target_endpoint": "/api/order/{id}",
             "accounts": _ACCOUNTS},
            {"service_url": "http://x"},
            {"a1_evidence": {"business_logic": True, "category": "bola"}},
            fake_iast,
        )
    assert m.call_args.kwargs.get("db") is sentinel_db, "d2_facade 必须传 iast_service.db"


def test_d1_internal_replay_passes_self_db():
    sentinel_db = object()
    svc = D1Service(db=sentinel_db)  # type: ignore[arg-type]
    with mock.patch("src.iast.business_logic.verify", return_value={"confirmed": False}) as m:
        svc._replay_business_logic("bola", {"id": 1}, {"service_url": "http://x"}, _ACCOUNTS)
    assert m.call_args.kwargs.get("db") is sentinel_db, "D1 内部 replay 必须透传 self.db"


# ---------------------------------------------------------------- 端到端落盘


def test_backfill_lands_in_real_db(db: Database, monkeypatch):
    spec_id = _seed_spec(db)
    monkeypatch.setattr(
        D1Service,
        "_send_one",
        lambda self, *a, **k: DastImpact(reached=True, status_code=200,
                                         body='{"owner":"alice","id":"42"}',
                                         response_summary="200"),
    )

    result = bl.verify("bola", _spec_payload(spec_id), {"service_url": "http://x"},
                       accounts=_ACCOUNTS, db=db)

    assert result["confirmed"] is True
    # victim_markers 由 victim 账户已知属性派生（username + user_id）落库。
    # R23-4(c) 起，"42" 属 3 位以内短数字指纹，会被 src/core/identity_marker 过滤掉——
    # 单位数/两位数 uid 在 JSON 响应体里几乎必然误命中，会让 data_leak 恒真（假确认）。
    # 故此处只剩强指纹 username。
    assert _read_victim_identifiers(db, spec_id) == ["alice"], "victim_identifiers 必须落真实 DB"


def test_backfill_lost_when_db_not_propagated(db: Database, monkeypatch):
    """反证：不传 db（修复前行为）时，回填进临时库，真实 DB 保持为空。"""
    spec_id = _seed_spec(db)
    monkeypatch.setattr(
        D1Service,
        "_send_one",
        lambda self, *a, **k: DastImpact(reached=True, status_code=200,
                                         body='{"owner":"alice"}', response_summary="200"),
    )

    bl.verify("bola", _spec_payload(spec_id), {"service_url": "http://x"}, accounts=_ACCOUNTS)

    assert _read_victim_identifiers(db, spec_id) == [], "这正是修复前 victim_identifiers 全空的机制"
