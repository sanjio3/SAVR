"""净化器判定九问（Q8）单测：探针织桩清单把 no-arrival 拆三态。"""
from __future__ import annotations

from src.iast.probe_coverage import (
    refine_no_arrival_state, load_coverage_manifest,
    PROBE_NOT_INSTRUMENTED, PROBE_UNAVAILABLE, GENUINE_NO_ARRIVAL,
)


def test_q8_no_manifest_falls_back_to_genuine():
    # 探针未上报清单 → 保守保持原态，不误读
    assert refine_no_arrival_state("Foo.java", None, liveness_canary_reached=True) == GENUINE_NO_ARRIVAL


def test_q8_sink_not_in_manifest_is_probe_not_instrumented():
    manifest = {"com/example/SinkA.java", "com/example/SinkB.java"}
    st = refine_no_arrival_state("com/example/SinkC.java", manifest, liveness_canary_reached=True)
    assert st == PROBE_NOT_INSTRUMENTED


def test_q8_sink_in_manifest_but_probe_down_is_probe_unavailable():
    manifest = {"com/example/SinkA.java"}
    # sink 覆盖到了，但 liveness canary 整体没到 → 探针异常
    st = refine_no_arrival_state("com/example/SinkA.java", manifest, liveness_canary_reached=False)
    assert st == PROBE_UNAVAILABLE


def test_q8_sink_in_manifest_and_alive_is_genuine():
    manifest = {"com/example/SinkA.java"}
    st = refine_no_arrival_state("com/example/SinkA.java", manifest, liveness_canary_reached=True)
    assert st == GENUINE_NO_ARRIVAL


def test_q8_manifest_path_normalization_backslash():
    manifest = {"com/example/SinkA.java"}
    # expected_sink_file 用反斜杠也应命中
    st = refine_no_arrival_state("com\\example\\SinkA.java", manifest, liveness_canary_reached=True)
    assert st == GENUINE_NO_ARRIVAL


def test_q8_load_coverage_manifest_from_session():
    import tempfile, json
    from src.infrastructure.db import Database
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    db.execute("INSERT INTO workspaces (name, target_path, created_at, updated_at) "
               "VALUES (?,?,?,?)", ("ws", ".", "now", "now"))
    db.execute("INSERT INTO iast_sessions (workspace_id, app_name, agent_id, target_url, "
               "registered_at, updated_at, coverage_manifest_json) VALUES (?,?,?,?,?,?,?)",
               (1, "app", "agent", "http://x", "now", "now",
                json.dumps({"sinks": ["a.java", "b.java"]})))
    sid = db.execute("SELECT id FROM iast_sessions WHERE workspace_id=1", fetchone=True)["id"]
    m = load_coverage_manifest(db, sid)
    assert m == {"a.java", "b.java"}


def test_q8_load_coverage_manifest_missing_returns_none():
    import tempfile
    from src.infrastructure.db import Database
    path = tempfile.mktemp(suffix=".db")
    db = Database(path)
    db.execute("INSERT INTO workspaces (name, target_path, created_at, updated_at) "
               "VALUES (?,?,?,?)", ("ws", ".", "now", "now"))
    db.execute("INSERT INTO iast_sessions (workspace_id, app_name, agent_id, target_url, "
               "registered_at, updated_at) VALUES (?,?,?,?,?,?)", (1, "app", "agent", "http://x", "now", "now"))
    sid = db.execute("SELECT id FROM iast_sessions WHERE workspace_id=1", fetchone=True)["id"]
    assert load_coverage_manifest(db, sid) is None
