"""I2 裁决器（§8.1/§4.7.1/§4.6）单测：覆盖率差集 + 反哺候选。

db 用 tmp_path 文件库（Database.execute 每次开新连接，:memory: 无法跨连接持久化）。
"""
from pathlib import Path

import pytest

from src.application.rule_feedback_service import RuleFeedbackService
from src.iast.adjudicator import (
    FINAL_AMBIGUOUS,
    FINAL_CONFIRMED_ATTRIBUTABLE,
    FINAL_FALSE_POSITIVE_SAST_ONLY,
    FINAL_NO_EVIDENCE,
    FINAL_RUNTIME_CONFIRMED,
    I2Adjudicator,
    parse_stack_frames,
)
from src.iast.orchestrator import (
    STATE_ARRIVAL_SANITIZED,
    STATE_NO_ARRIVAL,
    STATE_SINK_REACHED,
)
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

    def add_finding(hash_v2, ftype="Command Injection", file_path="Ctrl.java", line=42):
        db.execute(
            """INSERT INTO findings
               (task_id, workspace_id, finding_type, severity, file_path, line, title, raw_json, vulnerability_hash_v2, hash_components_json, source, created_at)
               VALUES (?, ?, ?, 'HIGH', ?, ?, ?, '{}', ?, '{}', 'sast', ?)""",
            (task_id, workspace_id, ftype, file_path, line, ftype, hash_v2, now),
        )

    def add_spec(hash_v2, canary):
        svc.register_trigger_spec({
            "workspace_id": workspace_id, "session_id": sid, "vulnerability_hash_v2": hash_v2,
            "taint_marker": canary, "target_endpoint": "/api/x", "param_name": "q", "param_location": "query",
        })

    def add_event(canary, state, sink_method="", stack_trace="", sink_file="Ctrl.java", sink_line=42):
        db.execute(
            """INSERT INTO iast_events
               (session_id, workspace_id, app_name, agent_id, event_type, canary, canary_state, sink_method, sink_file, sink_line, stack_trace, ingested_at, ingest_bucket)
               VALUES (?, ?, ?, ?, 'sink_call', ?, ?, ?, ?, ?, ?, ?, 0)""",
            (sid, workspace_id, "mall", "p1", canary, state, sink_method, sink_file, sink_line, stack_trace, now),
        )

    return db, workspace_id, task_id, add_finding, add_spec, add_event


def test_parse_stack_frames_java_and_python():
    frames = parse_stack_frames(
        "at com.sanjio.mall.Sanitizer.escapeHtml(Sanitizer.java:42)\n"
        'File "x.py", line 7, in clean'
    )
    assert frames[0]["class"] == "com.sanjio.mall.Sanitizer"
    assert frames[0]["method"] == "escapeHtml"
    assert frames[0]["line"] == 42
    assert frames[1]["method"] == "clean"
    assert frames[1]["file"] == "x.py"


def test_adjudicate_final_state_five_states():
    """§8.1 I2 综合裁定：五态 final_state 从 IAST 证据 + DAST 影响证据产出。"""
    adjudicate = I2Adjudicator.adjudicate_final_state
    # sink-reached + 无 DAST → runtime_confirmed
    assert adjudicate(iast_evidence={"state": STATE_SINK_REACHED}, dast_impact_evidence={"impact_observed": False})["final_state"] == FINAL_RUNTIME_CONFIRMED
    # sink-reached + DAST → confirmed_attributable
    assert adjudicate(iast_evidence={"state": STATE_SINK_REACHED}, dast_impact_evidence={"impact_observed": True})["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE
    # arrival-sanitized + 无 DAST → no_evidence
    assert adjudicate(iast_evidence={"state": STATE_ARRIVAL_SANITIZED}, dast_impact_evidence={"impact_observed": False})["final_state"] == FINAL_NO_EVIDENCE
    # arrival-sanitized + DAST → ambiguous
    assert adjudicate(iast_evidence={"state": STATE_ARRIVAL_SANITIZED}, dast_impact_evidence={"impact_observed": True})["final_state"] == FINAL_AMBIGUOUS
    # no-arrival + stable_disproof → false_positive_sast_only
    assert adjudicate(iast_evidence={"state": STATE_NO_ARRIVAL}, dast_impact_evidence={"impact_observed": False, "stable_disproof": True})["final_state"] == FINAL_FALSE_POSITIVE_SAST_ONLY
    # no-arrival + 无 DAST → no_evidence
    assert adjudicate(iast_evidence={"state": STATE_NO_ARRIVAL}, dast_impact_evidence={"impact_observed": False})["final_state"] == FINAL_NO_EVIDENCE
    # no-arrival + DAST → ambiguous
    assert adjudicate(iast_evidence={"state": STATE_NO_ARRIVAL}, dast_impact_evidence={"impact_observed": True})["final_state"] == FINAL_AMBIGUOUS


def test_adjudicate_final_state_confirmed_flag():
    """§8.1：confirmed 仅当 confirmed_attributable / runtime_confirmed 时 True。"""
    adjudicate = I2Adjudicator.adjudicate_final_state
    assert adjudicate(iast_evidence={"state": STATE_SINK_REACHED}, dast_impact_evidence={"impact_observed": True})["confirmed"] is True
    assert adjudicate(iast_evidence={"state": STATE_SINK_REACHED}, dast_impact_evidence={"impact_observed": False})["confirmed"] is True
    assert adjudicate(iast_evidence={"state": STATE_NO_ARRIVAL}, dast_impact_evidence={"impact_observed": False})["confirmed"] is False


def test_audit_coverage_classifies_matched_and_hypothesis_only(tmp_path):
    db, workspace_id, _, add_finding, add_spec, add_event = _seed(tmp_path)
    add_finding("H1")
    add_finding("H2")
    add_spec("H1", "s4st41aaaaaaaaaaaaaaaa")
    add_spec("H2", "s4st41bbbbbbbbbbbbbbbb")
    add_event("s4st41aaaaaaaaaaaaaaaa", "sink-reached")  # H1 有观测
    # H2 无观测

    audit = I2Adjudicator(db).audit_coverage(workspace_id=workspace_id)
    assert audit["stats"]["total_hypotheses"] == 2
    assert audit["stats"]["matched"] == 1
    assert audit["stats"]["hypothesis_only"] == 1
    assert audit["matched"] == ["H1"]
    assert audit["hypothesis_only"] == ["H2"]


def test_audit_coverage_observed_only(tmp_path):
    db, workspace_id, _, add_finding, add_spec, add_event = _seed(tmp_path)
    add_finding("H1")
    add_spec("H1", "s4st41aaaaaaaaaaaaaaaa")
    add_spec("HX", "s4st41cccccccccccccccc")  # HX 不在 findings（SAST 假说集无）
    add_event("s4st41aaaaaaaaaaaaaaaa", "sink-reached")
    add_event("s4st41cccccccccccccccc", "sink-reached", sink_method="com.foo.Sink.run", sink_file="Other.java")

    audit = I2Adjudicator(db).audit_coverage(workspace_id=workspace_id)
    assert audit["stats"]["observed_only"] == 1
    assert audit["observed_only"][0]["canary"] == "s4st41cccccccccccccccc"
    assert audit["observed_only"][0]["sink_method"] == "com.foo.Sink.run"


def test_sanitizer_candidates_two_gates(tmp_path):
    db, workspace_id, _, add_finding, add_spec, add_event = _seed(tmp_path)
    stack = "at com.sanjio.mall.Sanitizer.escapeHtml(Sanitizer.java:42)"
    # 同一净化器方法在两个独立 arrival-sanitized 事件里都出现（门1：多次独立观测一致）
    add_event("s4st41aaaaaaaaaaaaaaaa", "arrival-sanitized", sink_method="com.foo.Ctrl.write", stack_trace=stack)
    add_event("s4st41bbbbbbbbbbbbbbbb", "arrival-sanitized", sink_method="com.foo.Ctrl.write", stack_trace=stack)

    adj = I2Adjudicator(db, min_observations=2)
    cands = adj._sanitizer_candidates(workspace_id)
    assert len(cands) == 1
    assert cands[0]["kind"] == "sanitizer"
    assert cands[0]["pattern"] == "com.sanjio.mall.Sanitizer.escapeHtml"
    assert cands[0]["occurrences"] == 2


def test_sanitizer_candidates_requires_multiple_observations(tmp_path):
    db, workspace_id, _, add_finding, add_spec, add_event = _seed(tmp_path)
    stack = "at com.sanjio.mall.Sanitizer.escapeHtml(Sanitizer.java:42)"
    add_event("s4st41aaaaaaaaaaaaaaaa", "arrival-sanitized", sink_method="com.foo.Ctrl.write", stack_trace=stack)  # 仅 1 次

    adj = I2Adjudicator(db, min_observations=2)
    assert adj._sanitizer_candidates(workspace_id) == []


def test_rule_seed_candidates_from_observed_only(tmp_path):
    db, workspace_id, _, add_finding, add_spec, add_event = _seed(tmp_path)
    add_finding("H1")
    add_spec("H1", "s4st41aaaaaaaaaaaaaaaa")
    add_spec("HX", "s4st41cccccccccccccccc")
    add_event("s4st41aaaaaaaaaaaaaaaa", "sink-reached")
    add_event("s4st41cccccccccccccccc", "sink-reached", sink_method="javax.servlet.HttpServletResponse.getWriter.print", sink_file="Xss.java")

    adj = I2Adjudicator(db)
    seeds = adj._rule_seed_candidates(workspace_id, None)
    assert len(seeds) == 1
    assert seeds[0]["kind"] == "sink"
    assert seeds[0]["pattern"] == "javax.servlet.HttpServletResponse.getWriter.print"


def test_harvest_feedback_records_via_rule_feedback(tmp_path):
    db, workspace_id, _, add_finding, add_spec, add_event = _seed(tmp_path)
    add_finding("H1")
    add_spec("H1", "s4st41aaaaaaaaaaaaaaaa")
    add_spec("HX", "s4st41cccccccccccccccc")
    add_event("s4st41aaaaaaaaaaaaaaaa", "sink-reached")
    add_event("s4st41cccccccccccccccc", "sink-reached", sink_method="com.foo.Sink.run", sink_file="Other.java")

    rule_feedback = RuleFeedbackService(db)
    adj = I2Adjudicator(db, rule_feedback=rule_feedback, min_observations=2)
    result = adj.harvest_feedback(workspace_id)

    assert result["recorded"], "应有反哺候选入库"
    candidates = rule_feedback.list_candidates(workspace_id=workspace_id)
    kinds = {c["kind"] for c in candidates}
    assert "sink" in kinds  # 观测有假说无 → sink 种子

    # 第三门：候选默认 status=candidate，不自动 confirm
    assert all(c["status"] == "candidate" for c in candidates)
