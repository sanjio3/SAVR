"""item 4（IAST 事件 ingest 吞吐）回归测试。

固化两条契约：
1. 批处理落库后，对外语义与原逐条实现完全一致（去重静默丢弃但仍计入 accepted、
   跨调用幂等、canary 命中抬 vulnerability_instances 状态）。
2. 方向 5 指标被正确累加（UI 依赖这些字段做「生产 vs 排空」对比）。

注意 INGEST_METRICS 是进程级单例，跨测试共享，故断言一律用「前后快照差值」而非绝对值。
"""
from pathlib import Path

from src.iast.canary import CanaryFactory
from src.iast.ingest_metrics import INGEST_METRICS, IngestMetrics
from src.iast.service import IastService
from src.infrastructure.db import Database


def _svc(tmp_path: Path) -> IastService:
    return IastService(Database(str(tmp_path / "iast.db")))


def _session(svc: IastService):
    return svc.register_session({
        "target_url": "http://x:11000", "code_path": "/repo/mall",
        "app_name": "mall", "agent_id": "p1",
    })


def test_batch_ingest_writes_all_unique_events(tmp_path):
    """一批 N 条互不重复的事件应全部落库，accepted=N。"""
    svc = _svc(tmp_path)
    sess = _session(svc)
    events = [
        {
            "eventType": "SINK_HIT", "vulnType": "rce", "traceId": f"t-{i}",
            "canary": f"s4st41{i:016x}",
            "sink": {"file": "Ctrl.java", "line": i, "method": "exec"},
            "evidence": {"payload": f"p-{i}"},
        }
        for i in range(50)
    ]
    res = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=events)
    assert res["accepted"] == 50
    assert res["rejected"] == 0
    count = svc.db.execute(
        "SELECT COUNT(*) AS c FROM iast_events WHERE session_id = ?", (sess["id"],), fetchone=True
    )["c"]
    assert count == 50


def test_batch_ingest_dedup_within_batch_and_across_calls(tmp_path):
    """批内重复 + 跨调用重复（同一 10s 时间窗）都幂等：DB 仅 1 行，但都计入 accepted。"""
    svc = _svc(tmp_path)
    sess = _session(svc)
    ev = {
        "eventType": "sink_call", "vulnType": "sqli", "canary": "s4st41abc123def456",
        "sink": {"file": "Ctrl.java", "line": 42}, "evidence": {"payload": "x"},
    }
    # 同一批内 3 条完全相同 → 只落 1 行
    res = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"],
                            events=[ev, ev, ev])
    assert res["accepted"] == 3  # 去重静默丢弃但仍计入 accepted（与原语义一致）
    # 再一次调用（同一时间窗）→ 仍是 1 行
    res2 = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=[ev])
    assert res2["accepted"] == 1
    count = svc.db.execute(
        "SELECT COUNT(*) AS c FROM iast_events WHERE session_id = ?", (sess["id"],), fetchone=True
    )["c"]
    assert count == 1


def test_batch_ingest_still_upgrades_vulnerability_instance(tmp_path):
    """批量落库后副作用不丢：canary 抵达 sink 仍把 vulnerability_instances 抬为 confirmed_runtime。"""
    svc = _svc(tmp_path)
    sess = _session(svc)
    canary = CanaryFactory.build("command-execution")
    svc.register_trigger_spec({
        "workspace_id": sess["workspace_id"], "session_id": sess["id"],
        "family": "command-execution", "taint_marker": canary,
        "target_endpoint": "/api/cmd", "vulnerability_hash_v2": "h-batch-1",
    })
    event = {
        "eventType": "sink_call", "vulnType": "rce", "canary": canary,
        "sink": {"file": "Ctrl.java", "line": 42, "method": "exec"},
        "evidence": {"payload": canary},
    }
    # 同批 3 条相同 canary（批内折叠为 1 行）+ 一批混合的无关事件
    others = [
        {
            "eventType": "SINK_HIT", "vulnType": "noise", "traceId": f"n-{i}",
            "canary": f"s4st41{i:016x}", "sink": {"file": "Other.java", "line": i},
            "evidence": {"payload": "n"},
        }
        for i in range(5)
    ]
    svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"],
                      events=[event, *others, event])
    row = svc.db.execute(
        "SELECT status, family, source FROM vulnerability_instances "
        "WHERE workspace_id = ? AND vulnerability_hash_v2 = ?",
        (sess["workspace_id"], "h-batch-1"), fetchone=True,
    )
    assert row is not None
    assert row["status"] == "confirmed_runtime"
    assert row["family"] == "command_execution"
    assert row["source"] == "iast"


def test_ingest_metrics_accumulate(tmp_path):
    """方向 5：指标按语义累加（received / accepted / written / dup / flushes）。"""
    svc = _svc(tmp_path)
    sess = _session(svc)
    before = INGEST_METRICS.snapshot()

    ev = {
        "eventType": "sink_call", "vulnType": "sqli", "canary": "s4st41metrics01",
        "sink": {"file": "M.java", "line": 7}, "evidence": {"payload": "x"},
    }
    svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"],
                      events=[ev, ev])  # 2 条接收，1 条真正落库（批内去重 1 条）

    after = INGEST_METRICS.snapshot()
    assert after["total_received"] - before["total_received"] == 2
    assert after["total_accepted"] - before["total_accepted"] == 2
    assert after["total_written"] - before["total_written"] == 1
    assert after["total_dup_skipped"] - before["total_dup_skipped"] == 1
    assert after["flushes"] - before["flushes"] == 1
    assert after["last_batch_size"] == 2
    assert after["last_drain_rate"] > 0


def test_drain_rate_counts_processed_not_written():
    """排空速率按「进入流水线的事件数」而非「实际落库行数」。

    实测 target-mall 预热期去重率 95.6%，若按 written 计算，全去重批次会显示 0 条/秒，
    运维会误判吞吐崩溃。故 drain 用 batch_size、write 用 written，两个口径分开。
    """
    m = IngestMetrics()  # 独立实例，不污染进程级单例
    m.record_flush(batch_size=100, written=0, flush_ms=10.0)
    snap = m.snapshot()
    assert snap["last_drain_rate"] == 10000.0
    assert snap["last_write_rate"] == 0.0


def test_ingest_metrics_rejected_on_bad_token(tmp_path):
    """鉴权失败计入 rejected，且不产生任何落库。"""
    svc = _svc(tmp_path)
    _session(svc)
    before = INGEST_METRICS.snapshot()
    res = svc.ingest_events(app_name="mall", agent_id="p1", token="wrong",
                            events=[{"eventType": "sink_call"}])
    after = INGEST_METRICS.snapshot()
    assert res["accepted"] == 0
    assert res["rejected"] == 1
    assert after["total_rejected"] - before["total_rejected"] == 1
    assert after["total_written"] - before["total_written"] == 0
