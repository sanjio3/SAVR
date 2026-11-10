"""canary 语义单一真相源回归守卫（2026-09-07 sink_reached 恒 0 事故）。

事故复盘（本测试存在的原因）：
- 现象：task-4 有 39 条 sink 状态 IAST 事件（10 条 sink-reached + 29 条 sink-reached-probe），
  但黑板 / 关联层 / 报告层的 sink_reached 与 confirmed_runtime 全部报 0。
- 根因两类，散落 6 处、每处都自造判据：
  ① 全等比较：trigger_specs.taint_marker 是「身份段 + 元字符段」完整串（如
     s4st41<16hex>PAYLOAD<8hex>），而 iast_events.canary 只有 22 字符身份段。
     `WHERE taint_marker = canary` / `taint_marker in {canary}` 恒 0 命中。
  ② 漏掉探针态：`state == "sink-reached"` 把 sink-reached-probe（探针在 sink 现场
     显式断言，设计上是最强证据）排除在「已抵达」之外，实测丢弃 29/39 条证据。
- 收口：判据收进 src/iast/canary.py 的 is_sink_reached / canary_key / SINK_REACHED_STATES，
  各处一律复用。本文件钉死这些语义，防止再次散落。

另含一项结构性守卫：adjudicator._load_observed_events 的 IN 占位符必须随
_OBSERVED_STATES 长度动态生成（历史实现硬编码 3 个 ?，新增观测态即静默 binding 不匹配）。
"""
from pathlib import Path

import pytest

from src.core.blackboard import derive_counts, sync_blackboard
from src.iast.adjudicator import I2Adjudicator, _OBSERVED_STATES
from src.iast.canary import SINK_REACHED_STATES, CanaryFactory, canary_key, is_sink_reached
from src.iast.correlation import IastCorrelationService
from src.infrastructure.db import Database
from src.iast.service import IastService

NOW = "2026-09-07T00:00:00"

# 完整 taint_marker（身份段 + 元字符段）与其身份段
FULL_MARKER = "s4st41" + "a" * 16 + "PAYLOAD" + "b" * 8
IDENTITY = "s4st41" + "a" * 16


# --------------------------------------------------------------------- 纯函数 #
def test_is_sink_reached_covers_probe_assertion():
    assert is_sink_reached("sink-reached") is True
    assert is_sink_reached("sink-reached-probe") is True, "探针显式断言是最强证据，不能漏"
    assert is_sink_reached("SINK-REACHED") is True, "大小写/空白容错"
    assert is_sink_reached(" arrived ") is False
    assert is_sink_reached("arrival-sanitized") is False
    assert is_sink_reached("no-arrival") is False
    assert is_sink_reached("") is False
    assert is_sink_reached(None) is False


def test_sink_reached_states_constant_matches_states_class():
    assert set(SINK_REACHED_STATES) == {"sink-reached", "sink-reached-probe"}


def test_canary_key_normalizes_full_marker():
    assert canary_key(FULL_MARKER) == IDENTITY
    assert canary_key(IDENTITY) == IDENTITY
    # 抽不出身份段时原样返回，兼容历史脏数据
    assert canary_key("legacy-marker") == "legacy-marker"
    assert canary_key("") == ""


def test_canary_key_roundtrips_factory_output():
    """CanaryFactory.build 产出的完整串，归一后必须仍是 22 字符身份段。"""
    for fam in ("sql-injection", "command-execution", "xss", "path-traversal", "unknown-family"):
        marker = CanaryFactory.build(fam)
        ident = canary_key(marker)
        assert len(ident) == 22 and ident.startswith("s4st41"), f"{fam} 身份段抽取失败: {marker}"


def test_identity_prefix_survives_truncation():
    """探针 maxSampleLength=512 截断尾部时身份段必须还在（身份段置前的设计前提）。"""
    marker = CanaryFactory.build("command-execution")
    truncated = (marker * 40)[:512]
    assert canary_key(truncated).startswith("s4st41")


# --------------------------------------------------------- 结构性守卫（占位符） #
def test_observed_states_placeholders_are_dynamic(tmp_path: Path):
    """_load_observed_events 必须返回 sink-reached-probe 事件（占位符数量动态生成）。

    历史实现 SQL 硬编码 `IN (?, ?, ?)` 而 _OBSERVED_STATES 有 4 项 → binding 不匹配，
    整段查询静默失败、I2 覆盖率审计把已抵达事件判成未观测。
    """
    assert "sink-reached-probe" in _OBSERVED_STATES, "探针断言态必须在观测态集合内"
    db = Database(str(tmp_path / "app.db"))
    svc = IastService(db)
    sess = svc.register_session({"target_url": "http://a", "code_path": "/r", "app_name": "m", "agent_id": "p"})
    db.execute(
        "INSERT INTO iast_events (session_id, workspace_id, app_name, agent_id, event_type, "
        "canary, canary_state, sink_file, sink_line, ingested_at, ingest_bucket) "
        "VALUES (?, ?, 'm', 'p', 'sink_call', ?, 'sink-reached-probe', 'S.java', 1, ?, 0)",
        (sess["id"], sess["workspace_id"], IDENTITY, NOW),
    )
    rows = I2Adjudicator(db=db)._load_observed_events(sess["workspace_id"], None)
    assert len(rows) == 1, "sink-reached-probe 事件未被观测态查询捞到（占位符/状态集不一致）"
    assert rows[0]["canary"] == IDENTITY


# --------------------------------------------------------------- 关联层（口径） #
def _seed_tenant(tmp_path: Path, spec_marker: str, event_canary: str, event_state: str, spec_iast_state: str = ""):
    db = Database(str(tmp_path / "app.db"))
    svc = IastService(db)
    sess = svc.register_session({"target_url": "http://a", "code_path": "/r", "app_name": "m", "agent_id": "p"})
    workspace_id, sid = sess["workspace_id"], sess["id"]
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, "
        "summary_json, error_message, created_at) VALUES (?, 't', 'completed', 'done', '/o', '{}', '{}', '', ?)",
        (workspace_id, NOW),
    )
    task_id = int(db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
    db.execute(
        "INSERT INTO findings (task_id, workspace_id, finding_type, severity, file_path, line, title, "
        "raw_json, vulnerability_hash_v2, hash_components_json, source, created_at) "
        "VALUES (?, ?, 'Command Injection', 'HIGH', 'C.java', 1, 't', '{}', 'H1', '{}', 'sast', ?)",
        (task_id, workspace_id, NOW),
    )
    svc.register_trigger_spec({
        "workspace_id": workspace_id, "session_id": sid, "task_id": task_id,
        "vulnerability_hash_v2": "H1",
        "taint_marker": spec_marker, "target_endpoint": "/api/exec",
        "param_name": "cmd", "param_location": "query",
        # 2026-09-28（测试桩对齐）：F4 修复后黑板 confirm_state 只认
        # verification_status∈{confirmed_exploitable,exploitable} 或 spec.iast_state 含 sink-reached；
        # 旧种子两者皆空 → confirmed 恒 0。种子显式带上 spec 侧 iast_state（由事件侧派生）。
        "iast_state": spec_iast_state,
    })
    db.execute(
        "INSERT INTO iast_events (session_id, workspace_id, app_name, agent_id, event_type, task_id, "
        "canary, canary_state, sink_file, sink_line, ingested_at, ingest_bucket) "
        "VALUES (?, ?, 'm', 'p', 'sink_call', ?, ?, ?, 'C.java', 1, ?, 0)",
        (sid, workspace_id, task_id, event_canary, event_state, NOW),
    )
    return db, workspace_id, task_id


def test_correlation_matches_full_marker_against_event_identity(tmp_path: Path):
    """spec 存完整串、事件存身份段时仍须关联上（历史实现全等比较 → 恒 0）。"""
    db, workspace_id, task_id = _seed_tenant(tmp_path, FULL_MARKER, IDENTITY, "sink-reached")
    stats = IastCorrelationService(db).correlate(workspace_id=workspace_id, task_id=task_id)["stats"]
    assert stats["iast_observed"] == 1, "完整 taint_marker 未与 22 字符事件 canary 关联上"
    assert stats["confirmed_runtime"] == 1


def test_correlation_counts_probe_asserted_as_confirmed_runtime(tmp_path: Path):
    """sink-reached-probe 必须计入 confirmed_runtime（历史实现只认 sink-reached）。"""
    db, workspace_id, task_id = _seed_tenant(tmp_path, FULL_MARKER, IDENTITY, "sink-reached-probe")
    stats = IastCorrelationService(db).correlate(workspace_id=workspace_id, task_id=task_id)["stats"]
    assert stats["confirmed_runtime"] == 1, "探针显式断言态未计入 confirmed_runtime"
    assert stats["sink_reached_count"] == 1


# ----------------------------------------------------------------- 黑板派生 #
def test_blackboard_sink_reached_derives_from_identity(tmp_path: Path):
    """黑板 sink_reached 必须按身份段派生，不能拿完整 taint_marker 全等事件 canary。"""
    db, workspace_id, task_id = _seed_tenant(tmp_path, FULL_MARKER, IDENTITY, "sink-reached-probe", spec_iast_state="sink-reached-probe")
    # 直接给 run_id，绕开 start_run（本用例只验证派生口径）
    db.execute(
        "INSERT INTO scan_runs (workspace_id, task_id, round_no, code_fingerprint, git_revision, "
        "key_files_json, options_json, metrics_json, status, started_at, finished_at, created_at) "
        "VALUES (?, ?, 1, 'fp', '', '[]', '{}', '{}', 'running', ?, '', ?)",
        (workspace_id, task_id, NOW, NOW),
    )
    run_id = int(db.execute("SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1", fetchone=True)["id"])

    sync_blackboard(db, task_id, run_id=run_id, workspace_id=workspace_id)
    counts = derive_counts(db, task_id, run_id=run_id)

    assert counts["blackboard_rows"] == 1
    assert counts["confirmed"] == 1
    assert counts["sink_reached"] == 1, "黑板 sink_reached 仍为 0 → 身份段比对未生效"


def test_blackboard_sink_reached_zero_without_matching_event(tmp_path: Path):
    """反例：事件 canary 与 spec 身份段不同 → sink_reached 必须为 0（防「一律置 1」式作弊）。"""
    db, workspace_id, task_id = _seed_tenant(tmp_path, FULL_MARKER, "s4st41" + "f" * 16, "sink-reached")
    db.execute(
        "INSERT INTO scan_runs (workspace_id, task_id, round_no, code_fingerprint, git_revision, "
        "key_files_json, options_json, metrics_json, status, started_at, finished_at, created_at) "
        "VALUES (?, ?, 1, 'fp', '', '[]', '{}', '{}', 'running', ?, '', ?)",
        (workspace_id, task_id, NOW, NOW),
    )
    run_id = int(db.execute("SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1", fetchone=True)["id"])

    sync_blackboard(db, task_id, run_id=run_id, workspace_id=workspace_id)
    counts = derive_counts(db, task_id, run_id=run_id)
    assert counts["sink_reached"] == 0
