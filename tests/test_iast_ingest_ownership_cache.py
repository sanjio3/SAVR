"""F2 两项 ingest 侧优化回归测试（2026-09-18 评审「启动」）。

背景（2026-09-15 实测）：真实 GB 级 app.db 上 ingest 端到端仅 78.7 条/秒，而隔离小库
260~404 条/秒；解析阶段占端到端耗时 98.7%，其中每事件 2~5 次「任务归属查询」随表增长变慢。
慢的第二来源是 Database 每次 execute 都新建 sqlite3 连接并跑 4 条 PRAGMA（WAL 库开连接要读
WAL 索引，库越大越慢），用完不关闭也不复用。

本文件固化两项优化的契约：
① IastService._resolve_event_task_id 的归属缓存 —— 命中缓存时查询次数下降，且归属结果与
   未缓存时逐条等价（身份段命中 / 单 task 回退 / 活跃会话回退 / 时间窗回退 / 无法归属→NULL）。
② Database.connect 的按线程连接复用 —— 同线程返回同一连接、不同线程互不共享，且读写行为不变。

注意：缓存 TTL 在 src/iast/service.py 的 _OWNERSHIP_* 常量里，本文件用「过期后再查必
重新查库」来验证时效性，不依赖具体秒数。
"""
import threading
from pathlib import Path

from src.iast.canary import CanaryFactory
from src.iast.ingest_metrics import INGEST_METRICS, IngestMetrics
from src.iast.service import IastService
from src.infrastructure.db import Database


class _CountingDb:
    """Database 代理：统计 execute 次数，用于量化「缓存是否真的减少了查询」。"""

    def __init__(self, db):
        self._db = db
        self.execute_calls = 0

    def execute(self, *args, **kwargs):
        self.execute_calls += 1
        return self._db.execute(*args, **kwargs)

    def reset(self):
        self.execute_calls = 0

    def __getattr__(self, name):
        return getattr(self._db, name)


def _svc(tmp_path: Path):
    real = Database(str(tmp_path / "iast.db"))
    counting = _CountingDb(real)
    return IastService(counting), counting, real


def _register_spec(real_db, workspace_id: int, task_id: int, taint_marker: str):
    real_db.execute(
        "INSERT INTO trigger_specs (workspace_id, session_id, task_id, finding_id, vulnerability_hash_v2, "
        "family, target_endpoint, http_method, param_name, taint_marker, created_at) "
        "VALUES (?, NULL, ?, NULL, 'vh', 'sql-injection', '/x', 'GET', 'id', ?, '2026-09-18T00:00:00')",
        (workspace_id, task_id, taint_marker),
    )


def _bootstrap(tmp_path: Path):
    """建 workspace + session + 一个 task，返回 (svc, counting, real, workspace_id, task_id)。"""
    svc, counting, real = _svc(tmp_path)
    sess = svc.register_session({
        "target_url": "http://x:11000", "code_path": "/repo/mall",
        "app_name": "mall", "agent_id": "p1",
    })
    workspace_id = int(sess["workspace_id"])
    real.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, "
        "error_message, created_at, started_at, finished_at) "
        "VALUES (?, 't', 'completed', 'done', 'out', '{}', '{}', '', ?, '2026-09-01T00:00:00', '')",
        (workspace_id, "2026-09-01T00:00:00"),
    )
    task_id = int(real.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
    return svc, counting, real, workspace_id, task_id


class TestOwnershipCacheReducesQueries:
    def test_identity_owner_is_cached_across_calls(self, tmp_path):
        svc, counting, real, ws, tid = _bootstrap(tmp_path)
        canary = CanaryFactory.build("sql-injection")
        _register_spec(real, ws, tid, canary)

        counting.reset()
        first = svc._resolve_event_task_id(ws, canary, "")
        first_cost = counting.execute_calls
        assert first == tid

        counting.reset()
        for _ in range(20):
            assert svc._resolve_event_task_id(ws, canary, "") == tid
        assert counting.execute_calls == 0, "身份段命中后应全部走缓存，不再查库"
        assert first_cost >= 1

    def test_workspace_fallback_snapshot_is_cached(self, tmp_path):
        """无身份段事件走 workspace 级回退：快照缓存后 N 次调用只查一次库。"""
        svc, counting, real, ws, tid = _bootstrap(tmp_path)
        _register_spec(real, ws, tid, CanaryFactory.build("sql-injection"))

        counting.reset()
        svc._workspace_owner_snapshot(ws)
        build_cost = counting.execute_calls
        # 至少 task 集合 + task 窗口 + 活跃会话三类查询
        assert build_cost >= 3

        counting.reset()
        for _ in range(10):
            svc._workspace_owner_snapshot(ws)
        assert counting.execute_calls == 0

    def test_negative_identity_result_expires_and_requeries(self, tmp_path):
        """身份段查不到时缓存为短 TTL 负结果；过期后必须重新查库（否则会错过刚登记的 spec）。"""
        svc, counting, real, ws, tid = _bootstrap(tmp_path)
        canary = CanaryFactory.build("sql-injection")

        assert svc._resolve_event_task_id(ws, canary, "") is None  # 此时 spec 尚未登记

        # 手工把负缓存置为已过期，模拟 TTL 到期
        key = next(iter(svc._ident_owner))
        _, owner = svc._ident_owner[key]
        svc._ident_owner[key] = (0.0, owner)

        _register_spec(real, ws, tid, canary)  # 登记后应能被重新查到
        counting.reset()
        assert svc._resolve_event_task_id(ws, canary, "") == tid
        assert counting.execute_calls >= 1, "负缓存过期后必须重新查库"


class TestOwnershipResolutionEquivalence:
    """缓存不改判定语义：五条归属路径逐条对齐。"""

    def test_identity_hit_wins(self, tmp_path):
        svc, _, real, ws, tid = _bootstrap(tmp_path)
        canary = CanaryFactory.build("sql-injection")
        _register_spec(real, ws, tid, canary)
        assert svc._resolve_event_task_id(ws, canary, "") == tid
        # 二次调用（命中缓存）结果一致
        assert svc._resolve_event_task_id(ws, canary, "") == tid

    def test_single_task_fallback_without_identity(self, tmp_path):
        svc, _, real, ws, tid = _bootstrap(tmp_path)
        _register_spec(real, ws, tid, CanaryFactory.build("sql-injection"))
        assert svc._resolve_event_task_id(ws, "", "") == tid

    def test_active_session_fallback_when_no_specs(self, tmp_path):
        svc, _, real, ws, tid = _bootstrap(tmp_path)
        real.execute(
            "UPDATE iast_sessions SET current_task_id = ? WHERE workspace_id = ?", (tid, ws)
        )
        assert svc._resolve_event_task_id(ws, "", "") == tid

    def test_no_task_at_all_returns_none(self, tmp_path):
        svc, _, real, ws, tid = _bootstrap(tmp_path)
        assert svc._resolve_event_task_id(ws, "", "") is None

    def test_time_window_fallback_picks_latest_started(self, tmp_path):
        """多 task 共存且无身份段/无活跃会话时，按事件时间落窗、重叠取最晚启动者。"""
        svc, _, real, ws, early = _bootstrap(tmp_path)
        real.execute(
            "UPDATE scan_tasks SET started_at='2026-09-01T00:00:00', finished_at='2026-09-01T01:00:00' WHERE id=?",
            (early,),
        )
        real.execute(
            "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, "
            "error_message, created_at, started_at, finished_at) VALUES (?, 't2', 'running', 'd2', 'out', '{}', '{}', '', ?, "
            "'2026-09-01T00:30:00', '')",
            (ws, "2026-09-01T00:30:00"),
        )
        late = int(real.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"])
        _register_spec(real, ws, early, CanaryFactory.build("sql-injection"))
        _register_spec(real, ws, late, CanaryFactory.build("sql-injection"))

        # 两窗重叠段（00:30~01:00）内 → 归属后启动的 task
        assert svc._resolve_event_task_id(ws, "", "", event_time="2026-09-01T00:45:00") == late
        # 仅早 task 覆盖的时段 → 归属早 task
        assert svc._resolve_event_task_id(ws, "", "", event_time="2026-09-01T00:10:00") == early
        # 落在所有窗之外 → 不臆测
        assert svc._resolve_event_task_id(ws, "", "", event_time="2026-08-01T00:00:00") is None

    def test_trace_id_used_as_canary_fallback(self, tmp_path):
        """canary 为空时用 trace_id 里的身份段（原行为保留）。"""
        svc, _, real, ws, tid = _bootstrap(tmp_path)
        canary = CanaryFactory.build("sql-injection")
        _register_spec(real, ws, tid, canary)
        assert svc._resolve_event_task_id(ws, "", canary) == tid

    def test_ingest_end_to_end_still_attributes_task(self, tmp_path):
        """端到端：带身份段的探针事件在 ingest 后 task_id 正确（缓存路径不影响落库归属）。"""
        svc, _, real, ws, tid = _bootstrap(tmp_path)
        canary = CanaryFactory.build("sql-injection")
        _register_spec(real, ws, tid, canary)
        sess = svc.register_session({
            "target_url": "http://x:11000", "code_path": "/repo/mall",
            "app_name": "mall", "agent_id": "p1",
        })
        events = [
            {
                "eventType": "SINK_HIT", "vulnType": "sqli", "traceId": f"t-{i}",
                "canary": canary,
                "sink": {"file": "Ctrl.java", "line": 10 + i, "method": "exec"},
                "evidence": {"payload": f"p-{i}"},
            }
            for i in range(5)
        ]
        res = svc.ingest_events(app_name="mall", agent_id="p1", token=sess["probe_token"], events=events)
        assert res["accepted"] == 5
        rows = real.execute(
            "SELECT task_id FROM iast_events WHERE session_id = ? ORDER BY id", (sess["id"],), fetchall=True
        )
        assert [r["task_id"] for r in rows] == [tid] * 5


class TestConnectionReuse:
    def test_same_thread_reuses_one_connection(self, tmp_path):
        db = Database(str(tmp_path / "c.db"))
        assert db.connect() is db.connect()

    def test_different_threads_do_not_share_connection(self, tmp_path):
        db = Database(str(tmp_path / "c.db"))
        main_conn = db.connect()
        seen = {}

        def worker():
            seen["conn"] = db.connect()

        t = threading.Thread(target=worker)
        t.start()
        t.join()
        assert seen["conn"] is not main_conn
        assert seen["conn"] is not None

    def test_close_is_idempotent_and_reopens(self, tmp_path):
        db = Database(str(tmp_path / "c.db"))
        first = db.connect()
        db.close()
        db.close()  # 幂等
        second = db.connect()
        assert second is not first

    def test_connection_reusable_for_write_then_read(self, tmp_path):
        """复用连接后读写语义不变（PRAGMA / row_factory 只在该连接建立时设置一次）。"""
        db = Database(str(tmp_path / "c.db"))
        db.execute("CREATE TABLE t (a INTEGER)")
        db.execute("INSERT INTO t (a) VALUES (?)", (7,))
        db.executemany("INSERT INTO t (a) VALUES (?)", [(8,), (9,)])
        rows = db.execute("SELECT a FROM t ORDER BY a", fetchall=True)
        assert [r["a"] for r in rows] == [7, 8, 9]
        assert db.execute("PRAGMA foreign_keys", fetchone=True)["foreign_keys"] == 1


class TestFlushRateNotZeroForTinyBatches:
    """F2 暴露的口径缺陷回归：小批次耗时为 0 时排空速率不得报 0。

    背景：连接复用把单次查询开销从 792µs 降到 5µs 后，小批次真实耗时首次落到时钟可测范围
    以下（time.time() 在 Windows 粒度约 15.6ms），旧式 `if flush_ms > 0 else 0.0` 会输出
    「0 条/秒」→ 运维误判吞吐崩溃。这与 2026-09-15 修过的「全去重批次显示 0」是同一类误判。
    """

    def test_zero_elapsed_still_reports_positive_rate(self):
        m = IngestMetrics()  # 独立实例，不污染进程级单例
        m.record_flush(batch_size=2, written=1, flush_ms=0.0)
        snap = m.snapshot()
        assert snap["last_drain_rate"] > 0
        assert snap["last_write_rate"] > 0
        # 原始耗时如实上报，不掩盖「测得 0」这一事实
        assert snap["last_flush_ms"] == 0.0

    def test_normal_elapsed_rate_unchanged(self):
        """正常耗时下速率算法不变（100 条 / 10ms = 10000 条/秒）。"""
        m = IngestMetrics()
        m.record_flush(batch_size=100, written=0, flush_ms=10.0)
        snap = m.snapshot()
        assert snap["last_drain_rate"] == 10000.0
        assert snap["last_write_rate"] == 0.0

    def test_ingest_uses_high_resolution_timer(self, tmp_path):
        """端到端：真实 ingest 一次后 last_flush_ms 与 rate 均可用（不出现 0 速率）。"""
        svc, _, _real, ws, tid = _bootstrap(tmp_path)
        canary = CanaryFactory.build("sql-injection")
        _register_spec(_real, ws, tid, canary)
        sess = svc.register_session({
            "target_url": "http://x:11000", "code_path": "/repo/mall",
            "app_name": "mall", "agent_id": "p1",
        })
        before = INGEST_METRICS.snapshot()
        svc.ingest_events(
            app_name="mall", agent_id="p1", token=sess["probe_token"],
            events=[{
                "eventType": "sink_call", "vulnType": "sqli", "canary": canary,
                "sink": {"file": "M.java", "line": 7}, "evidence": {"payload": "x"},
            }],
        )
        after = INGEST_METRICS.snapshot()
        assert after["flushes"] - before["flushes"] == 1
        assert after["last_drain_rate"] > 0
