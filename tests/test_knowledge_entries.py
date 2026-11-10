"""knowledge_entries 模块单测：CRUD / load_knowledge / 种子 / read_for_stage。

全部用临时 DB，不依赖线上 app.db。
"""
import json

from src.core import knowledge_entries as ke
from src.infrastructure.db import Database


def _db(tmp_path):
    return Database(str(tmp_path / "app.db"))


def test_upsert_get_and_get_by_kind(tmp_path):
    db = _db(tmp_path)
    assert ke.upsert(db, 0, ke.KIND_PITFALL, "k1", {"x": 1}, source="s", confidence="high")
    # 同 key 覆盖更新
    assert ke.upsert(db, 0, ke.KIND_PITFALL, "k1", {"x": 2}, source="s2")
    rec = ke.get(db, 0, ke.KIND_PITFALL, "k1")
    assert rec is not None
    assert json.loads(rec["value_json"]) == {"x": 2}
    assert rec["source"] == "s2"
    # 不同 workspace 隔离
    assert ke.get(db, 99, ke.KIND_PITFALL, "k1") is None
    by_kind = ke.get_by_kind(db, 0, ke.KIND_PITFALL)
    assert [r["key"] for r in by_kind] == ["k1"]


def test_load_knowledge_parses_value(tmp_path):
    db = _db(tmp_path)
    ke.upsert(db, 0, ke.KIND_ENV_FACT, "port", {"port": 8092})
    ke.upsert(db, 0, ke.KIND_PITFALL, "h2-drop", {"fact": "x"})
    data = ke.load_knowledge(db, 0)
    assert ke.KIND_ENV_FACT in data
    assert data[ke.KIND_ENV_FACT]["port"]["value"] == {"port": 8092}
    # 按 kind 过滤
    only = ke.load_knowledge(db, 0, kinds=[ke.KIND_PITFALL])
    assert ke.KIND_ENV_FACT not in only
    assert ke.KIND_PITFALL in only
    assert "h2-drop" in only[ke.KIND_PITFALL]


def test_seed_populates_and_read_for_stage(tmp_path):
    db = _db(tmp_path)
    n = ke.seed_target_mall_knowledge(db, workspace_id=0)
    assert n >= 15, f"种子应不少于 15 条，实际 {n}"

    # 全量种类齐全
    data = ke.load_knowledge(db, 0)
    for kind in (ke.KIND_TARGET_PROFILE, ke.KIND_ENV_FACT, ke.KIND_PITFALL,
                 ke.KIND_FAMILY_ALIAS, ke.KIND_VERIFIED_CONCLUSION):
        assert kind in data and data[kind], f"缺少 kind={kind}"

    # read_for_stage：A0 必读 target_profile + pitfall
    a0 = ke.read_for_stage(0, "a0", db=db)
    assert ke.KIND_TARGET_PROFILE in a0
    assert ke.KIND_PITFALL in a0
    assert "h2-file-drop-persists" in a0[ke.KIND_PITFALL]

    # A2 必读 family_alias
    a2 = ke.read_for_stage(0, "a2", db=db)
    assert ke.KIND_FAMILY_ALIAS in a2
    assert "vertical_privesc" in a2[ke.KIND_FAMILY_ALIAS]

    # D1 必读 pitfall
    d1 = ke.read_for_stage(0, "d1", db=db)
    assert ke.KIND_PITFALL in d1

    # 未知 stage 返回空
    assert ke.read_for_stage(0, "zzz", db=db) == {}


def test_read_for_stage_unknown_kind_falls_back(tmp_path):
    db = _db(tmp_path)
    # 仅在全局(0)有数据，传入具体 workspace=None 仍应读到全局兜底
    ke.seed_target_mall_knowledge(db, workspace_id=0)
    res = ke.read_for_stage(None, "a0", db=db)
    assert ke.KIND_PITFALL in res


def test_read_for_stage_db_none_fallback(tmp_path, monkeypatch):
    """回归守卫：db=None 时必须靠 SAST_AI_DB_PATH 自建连接读到知识，而非静默返回空。

    历史 bug：read_for_stage 在 db is None 时误用 Database()（缺 path 参数），
    导致 A0/A2/D1 三处 best-effort 钩子永远读不到知识且不抛异常——静默失效。
    """
    import os

    db_path = str(tmp_path / "app.db")
    # 用一个独立 Database 先灌种子（走同一路径），再让 fallback 用 SAST_AI_DB_PATH 找到它
    seed_db = Database(db_path)
    ke.seed_target_mall_knowledge(seed_db, workspace_id=0)

    monkeypatch.setenv("SAST_AI_DB_PATH", db_path)
    # 关键：不传 db，强制走 fallback 路径
    a0 = ke.read_for_stage(0, "a0")
    assert a0, "db=None fallback 必须读到知识，不能静默返回空"
    assert ke.KIND_PITFALL in a0
    assert "h2-file-drop-persists" in a0[ke.KIND_PITFALL]
    d1 = ke.read_for_stage(0, "d1")
    assert ke.KIND_PITFALL in d1

