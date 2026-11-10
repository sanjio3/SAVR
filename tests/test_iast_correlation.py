"""关联聚合（§3.3）与 iast-correlation 报告（§4.5）单测。

验证：
- correlate 按 hash→trigger_spec(taint_marker)→event(canary_state) 查询层 join，取最强态；
- 覆盖率 / confirmed_runtime 占比 / 按资产分布三项统计正确；
- render_markdown / generate_report 产出 report_type=iast-correlation 文件；
- MetricsService.iast_source_stats 复用关联聚合返回统计。

db 用 tmp_path 文件库（Database.execute 每次开新连接，:memory: 无法跨连接持久化）。
"""
from pathlib import Path

import pytest

from src.application.metrics_service import MetricsService
from src.iast.correlation import IastCorrelationService
from src.iast.service import IastService
from src.infrastructure.db import Database


def _seed(tmp_path: Path):
    db = Database(str(tmp_path / "app.db"))
    svc = IastService(db)
    sess = svc.register_session({
        "target_url": "http://app.local", "code_path": "/repo",
        "app_name": "mall", "agent_id": "p1",
    })
    workspace_id = sess["workspace_id"]
    sid = sess["id"]

    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (workspace_id, "task1", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    task_id = int(db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])

    def add_finding(hash_v2, ftype, file_path, line):
        db.execute(
            """INSERT INTO findings
               (task_id, workspace_id, finding_type, severity, file_path, line, title, raw_json, vulnerability_hash_v2, hash_components_json, source, created_at)
               VALUES (?, ?, ?, 'HIGH', ?, ?, ?, '{}', ?, '{}', 'sast', ?)""",
            (task_id, workspace_id, ftype, file_path, line, ftype, hash_v2, now),
        )

    add_finding("H1", "Command Injection", "Ctrl.java", 42)
    add_finding("H2", "SQL Injection", "Dao.java", 10)

    svc.register_trigger_spec({
        "workspace_id": workspace_id, "session_id": sid, "vulnerability_hash_v2": "H1",
        "taint_marker": "s4st41aaaaaaaaaaaaaaaa", "target_endpoint": "/api/exec", "param_name": "cmd", "param_location": "query",
    })
    svc.register_trigger_spec({
        "workspace_id": workspace_id, "session_id": sid, "vulnerability_hash_v2": "H2",
        "taint_marker": "s4st41bbbbbbbbbbbbbbbb", "target_endpoint": "/api/search", "param_name": "q", "param_location": "query",
    })

    def add_event(canary, state, app="mall", agent="p1", sink_file="Ctrl.java", sink_line=42):
        db.execute(
            """INSERT INTO iast_events
               (session_id, workspace_id, app_name, agent_id, event_type, canary, canary_state, sink_file, sink_line, ingested_at, ingest_bucket)
               VALUES (?, ?, ?, ?, 'sink_call', ?, ?, ?, ?, ?, 0)""",
            (sid, workspace_id, app, agent, canary, state, sink_file, sink_line, now),
        )

    add_event("s4st41aaaaaaaaaaaaaaaa", "arrival-sanitized")
    add_event("s4st41aaaaaaaaaaaaaaaa", "sink-reached")  # 更强态，应被取为最强
    # C2 无事件 → no-observation

    return db, workspace_id, task_id


def test_correlate_joins_and_picks_strongest(tmp_path):
    db, workspace_id, _ = _seed(tmp_path)
    result = IastCorrelationService(db).correlate(workspace_id=workspace_id)

    by_hash = {f["vulnerability_hash_v2"]: f for f in result["findings"]}
    assert set(by_hash) == {"H1", "H2"}

    h1 = by_hash["H1"]
    assert h1["iast"]["state"] == "sink-reached"
    assert h1["iast"]["confirmed_runtime"] is True
    assert h1["iast"]["event_count"] == 2
    assert h1["sources"] == ["SAST", "IAST"]

    h2 = by_hash["H2"]
    assert h2["iast"]["state"] is None
    assert h2["iast"]["confirmed_runtime"] is False
    assert h2["sources"] == ["SAST"]


def test_correlate_stats(tmp_path):
    db, workspace_id, _ = _seed(tmp_path)
    stats = IastCorrelationService(db).correlate(workspace_id=workspace_id)["stats"]

    assert stats["total_hypotheses"] == 2
    assert stats["iast_observed"] == 1
    assert stats["confirmed_runtime"] == 1
    assert stats["coverage_ratio"] == pytest.approx(0.5)
    assert stats["confirmed_runtime_ratio"] == pytest.approx(0.5)

    assets = {a["asset"]: a for a in stats["per_asset"]}
    assert assets["mall"]["total"] == 2
    assert assets["mall"]["confirmed_runtime"] == 1


def test_render_markdown_contains_report_type(tmp_path):
    db, workspace_id, _ = _seed(tmp_path)
    md = IastCorrelationService(db).render_markdown(workspace_id=workspace_id)
    assert "iast-correlation" in md
    assert "confirmed_runtime" in md
    assert "Command Injection" in md


def test_generate_report_writes_files(tmp_path):
    db, workspace_id, task_id = _seed(tmp_path)
    out = tmp_path / "reports"
    meta = IastCorrelationService(db).generate_report(workspace_id, task_id=task_id, out_dir=str(out))

    assert meta["report_type"] == "iast-correlation"
    assert Path(meta["file_path"]).exists()
    assert Path(meta["json_file_path"]).exists()
    assert "iast-correlation" in Path(meta["file_path"]).read_text(encoding="utf-8")
    assert meta["stats"]["total_hypotheses"] == 2


def test_metrics_iast_source_stats(tmp_path):
    db, workspace_id, _ = _seed(tmp_path)
    stats = MetricsService(db).iast_source_stats(workspace_id=workspace_id)
    assert stats["total_hypotheses"] == 2
    assert stats["confirmed_runtime"] == 1
    assert "coverage_ratio" in stats and "per_asset" in stats


def _seed_one_finding(tmp_path: Path):
    """隔离种子：单 finding + 单 spec + 无预置事件，供自噪声过滤用例独占 canary。"""
    db = Database(str(tmp_path / "app.db"))
    svc = IastService(db)
    sess = svc.register_session({
        "target_url": "http://app.local", "code_path": "/repo",
        "app_name": "mall", "agent_id": "p1",
    })
    workspace_id = sess["workspace_id"]
    sid = sess["id"]
    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (workspace_id, "t", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    db.execute(
        """INSERT INTO findings
           (task_id, workspace_id, finding_type, severity, file_path, line, title, raw_json, vulnerability_hash_v2, hash_components_json, source, created_at)
           VALUES (?, ?, ?, 'HIGH', ?, ?, ?, '{}', ?, '{}', 'sast', ?)""",
        (1, workspace_id, "Command Injection", "Ctrl.java", 42, "Cmd", "HX", now),
    )
    svc.register_trigger_spec({
        "workspace_id": workspace_id, "session_id": sid, "vulnerability_hash_v2": "HX",
        "taint_marker": "s4st41cccccccccccccccc", "target_endpoint": "/api/exec",
        "param_name": "cmd", "param_location": "query",
    })
    return db, workspace_id, sid


def _add_event_source(db, sid, workspace_id, canary, state, source_value="", now="2026-01-01T00:00:00"):
    """带 source_value 的事件写入，用于验证自噪声过滤（§2026-09-21）。"""
    db.execute(
        """INSERT INTO iast_events
           (session_id, workspace_id, app_name, agent_id, event_type, canary, canary_state,
            sink_file, sink_line, ingested_at, ingest_bucket, source_value)
           VALUES (?, ?, ?, ?, 'taint_flow', ?, ?, ?, ?, ?, 0, ?)""",
        (sid, workspace_id, "mall", "p1", canary, state, "Ctrl.java", 42, now, source_value),
    )


def test_self_noise_event_excluded_from_correlation(tmp_path):
    """探针自写日志噪声（source_value 含 sec-agent.log）不得背书 confirmed_runtime。"""
    db, workspace_id, sid = _seed_one_finding(tmp_path)

    # 仅一条自噪声事件（TAINT_FLOW 主通道，source_value 命中哨兵），无真实应用事件。
    _add_event_source(db, sid, workspace_id, "s4st41cccccccccccccccc",
                      "sink-reached", source_value=r"D:\logs\sec-agent.log [CREATE,APPEND]")

    result = IastCorrelationService(db).correlate(workspace_id=workspace_id)
    hx = {f["vulnerability_hash_v2"]: f for f in result["findings"]}["HX"]
    # 自噪声被排除 → 无真实运行时证据 → 不应判 confirmed_runtime。
    assert hx["iast"]["state"] is None
    assert hx["iast"]["confirmed_runtime"] is False
    assert hx["iast"]["event_count"] == 0
    assert hx["sources"] == ["SAST"]


def test_real_event_passes_self_noise_filter(tmp_path):
    """真实事件与自噪声事件共存时，确认态只取真实事件；自噪声不计入 event_count。"""
    db, workspace_id, sid = _seed_one_finding(tmp_path)

    # 自噪声事件（命中哨兵）。
    _add_event_source(db, sid, workspace_id, "s4st41cccccccccccccccc",
                      "sink-reached", source_value=r"D:\logs\sec-agent.log [CREATE,APPEND]")
    # 与自噪声同 canary 的真实应用事件（source_value 为空，已抵达 sink）。
    _add_event_source(db, sid, workspace_id, "s4st41cccccccccccccccc", "sink-reached")

    result = IastCorrelationService(db).correlate(workspace_id=workspace_id)
    hx = {f["vulnerability_hash_v2"]: f for f in result["findings"]}["HX"]
    assert hx["iast"]["confirmed_runtime"] is True
    # 自噪声被排除，event_count 仅含真实事件（本用例无预置事件）。
    assert hx["iast"]["event_count"] == 1
