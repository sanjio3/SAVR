"""⑤ HITL 剩余四项：落库 / 批量裁决 / 挂起恢复 的功能测试（临时 DB，不污染生产库）。

覆盖：
- hitl_audit 表落库 + 查询（含 detail_json 解析）。
- attack_context 审计 sink 注入（落库回调 + 进程内缓冲双写）。
- TaskStatus.SUSPENDED 枚举。
- TaskService.resolve_task_hitl_actions_batch（逐条裁决 + 非法项进 failed）。
- TaskService.suspend_task / resume_task（状态机约束 + 恢复重新提交=回填）。
"""

import os
import tempfile

from src.application.hitl_audit import list_guard_events, persist_guard_event
from src.application.task_service import TaskService
from src.domain.models import ScanTask, TaskStatus, Workspace
from src.infrastructure.db import Database


def _temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    db = Database(path)
    db.execute("SELECT 1")  # 触发 _init_schema（含 hitl_audit）
    return db, path


# ── 1. hitl_audit 落库 + 查询 ────────────────────────────────────────────────
def test_hitl_audit_persist_and_list():
    db, path = _temp_db()
    try:
        persist_guard_event(
            db, 7,
            {
                "action": "gated", "category": "data_destroy", "reason": "不可逆动作",
                "route": "/api/order/1", "method": "DELETE", "tool_id": "d2_tool",
                "approval_mode": "ask_on_risky_tools", "stage": "d2_hitl",
                "detail": {"risk": "high"},
            },
        )
        rows = list_guard_events(db, 7)
        assert len(rows) == 1
        r = rows[0]
        assert r["action"] == "gated"
        assert r["category"] == "data_destroy"
        assert r["route"] == "/api/order/1"
        assert r["detail"] == {"risk": "high"}
        # 其它 task_id 不应命中
        assert list_guard_events(db, 999) == []
    finally:
        db.close()
        os.remove(path)


# ── 2. attack_context 审计 sink（落库回调 + 进程内缓冲）─────────────────────
def test_attack_context_guard_sink():
    from src.iast.attack_context import (
        DESTRUCTIVE_GUARD_EVENTS,
        record_destructive_guard_event,
        register_guard_audit_sink,
    )

    captured = []
    register_guard_audit_sink(lambda ev: captured.append(ev))
    try:
        before = len(DESTRUCTIVE_GUARD_EVENTS)
        record_destructive_guard_event(
            {
                "action": "allowed", "category": "none", "route": "/x", "method": "GET",
                "tool_id": "t", "approval_mode": "off", "stage": "d2_hitl",
            }
        )
        assert len(captured) == 1
        assert captured[0]["action"] == "allowed"
        assert len(DESTRUCTIVE_GUARD_EVENTS) == before + 1
    finally:
        register_guard_audit_sink(None)  # 复位，避免影响其它测试


# ── 3. SUSPENDED 枚举 ───────────────────────────────────────────────────────
def test_task_status_suspended():
    assert TaskStatus.SUSPENDED.value == "suspended"
    assert TaskStatus.SUSPENDED not in (TaskStatus.PENDING, TaskStatus.RUNNING,
                                        TaskStatus.COMPLETED, TaskStatus.FAILED)


# ── 4. TaskService 批量裁决 + 挂起/恢复（轻量桩）────────────────────────────
class _FakeTaskRepo:
    def __init__(self):
        self.store = {}

    def create(self, t):
        self.store[t.id] = t
        return t

    def get(self, tid):
        return self.store.get(tid)

    def update(self, tid, **kw):
        t = self.store[tid]
        for k, v in kw.items():
            setattr(t, k, v)
        return t

    def list(self, ws=None):
        return list(self.store.values())

    def delete(self, tid):
        self.store.pop(tid, None)

    def delete_by_workspace(self, ws):
        return None


class _FakeWsRepo:
    def get(self, wid):
        return Workspace(id=wid, name="ws", target_path="/tmp/x")


class _FakeEventRepo:
    def add(self, ev):
        ev.id = 1
        return ev


class _FakeEventBus:
    def publish(self, *a, **k):
        pass

    def subscribe(self, *a, **k):
        pass

    def unsubscribe(self, *a, **k):
        pass


class _FakePreprocess:
    def reset_directory(self, *a, **k):
        pass

    def validate_workspace_path(self, *a, **k):
        return {"status": "ok"}

    def build_output_dir(self, *a, **k):
        return "/tmp/out"


class _FakeRunner:
    def __init__(self):
        self.submitted = []

    def submit(self, task, ws):
        self.submitted.append(task.id)


def _make_service():
    db, path = _temp_db()
    svc = TaskService(
        task_repository=_FakeTaskRepo(),
        workspace_repository=_FakeWsRepo(),
        event_repository=_FakeEventRepo(),
        finding_repository=None,
        report_repository=None,
        event_bus=_FakeEventBus(),
        preprocess=_FakePreprocess(),
        db=db,
    )
    svc.runner = _FakeRunner()
    return svc, db, path


def _seed_task(svc, status=TaskStatus.COMPLETED, pending_actions=None):
    t = ScanTask(
        id=101, workspace_id=1, name="scan", status=status, phase="completed",
        options={"approval_mode": "ask_on_risky_tools", "tool_allowlist": []},
        summary={"hitl": {"approval_mode": "ask_on_risky_tools",
                          "tool_allowlist": [],
                          "pending_actions": pending_actions or []}},
    )
    svc.task_repository.create(t)
    return t


def test_batch_resolve():
    svc, db, path = _make_service()
    try:
        pending = [
            {"id": "a1", "task_id": 0, "tool_id": "t1", "risk_level": "high",
             "reason": "r", "stage": "d2", "status": "pending", "proposed_action": {}},
            {"id": "a2", "task_id": 0, "tool_id": "t2", "risk_level": "high",
             "reason": "r", "stage": "d2", "status": "pending", "proposed_action": {}},
        ]
        _seed_task(svc, pending_actions=pending)
        out = svc.resolve_task_hitl_actions_batch(
            101, [{"action_id": "a1", "decision": "approved"},
                  {"action_id": "a2", "decision": "bogus"}]
        )
        assert len(out["resolved"]) == 1
        assert out["resolved"][0]["id"] == "a1"
        assert out["resolved"][0]["status"] == "approved"
        assert len(out["failed"]) == 1
        assert out["failed"][0]["action_id"] == "a2"
        # allowlist 应追加 t1
        assert "t1" in out["settings"]["tool_allowlist"]
        # 持久化回写：再次读取仍为 approved
        reread = svc.get_task_hitl(101)
        statuses = {a["id"]: a["status"] for a in reread["pending_actions"]}
        assert statuses["a1"] == "approved"
    finally:
        db.close()
        os.remove(path)


def test_suspend_and_resume():
    svc, db, path = _make_service()
    try:
        _seed_task(svc, status=TaskStatus.COMPLETED)
        sus = svc.suspend_task(101)
        assert sus["status"] == "suspended"
        assert svc.get_task(101).status == TaskStatus.SUSPENDED

        res = svc.resume_task(101)
        assert res["status"] == "pending"
        assert svc.runner.submitted == [101]  # 恢复=重新提交（回填）
        assert svc.get_task(101).status == TaskStatus.PENDING

        # 非 SUSPENDED/终态不允许恢复
        _seed_task(svc, status=TaskStatus.RUNNING)
        raised = False
        try:
            svc.resume_task(101)
        except ValueError:
            raised = True
        assert raised
    finally:
        db.close()
        os.remove(path)
