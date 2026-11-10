"""⑤ 批准链路接通：act_allowlist（动作类别级白名单）端到端测试。

背景（2026-09-24 修复的断层）：
闸门 decide_hitl_gate 是「按动作类别」放行的（比对 hitl['act_allowlist']），
但全项目该键只有读取、从未被写入 —— 批准只写了工具级 tool_allowlist，
结果「批准后重跑仍被拦」。同时 failure_classification.category 恒为字面量
"approval_required"，若把该值当类别写进白名单，与闸门算出的 money_out/data_destroy
永远不等，链路依旧不通。本文件锁住这两点。

覆盖：
- 闸门：未放行→拦；放行真实类别→放行；白名单里放 "approval_required"→仍拦（回归守卫）；
  只给 tool_allowlist→仍拦（证明工具级不够）。
- _approval_required_result 必须带出真实 act.category（且 fc.category 恒为 approval_required）。
- TaskService 批准须把真实类别写入 act_allowlist 并回写 options/summary。
"""

import os
import tempfile

import pytest

from src.agents.d2_strategy import _approval_required_result, decide_hitl_gate


def _ctx(act_allowlist=None, tool_allowlist=None, mode="ask_on_risky_tools"):
    return {
        "hitl": {
            "approval_mode": mode,
            "tool_allowlist": list(tool_allowlist or []),
            "act_allowlist": list(act_allowlist or []),
        }
    }


# ── 1. 闸门：只有「真实动作类别」进 act_allowlist 才放行 ────────────────────
def test_gate_blocks_unlisted_category():
    act = decide_hitl_gate(_ctx(), method="DELETE", route="/api/order/1",
                           payload_text="", category_override="money_out")
    assert act["irreversible"] is True
    assert act["gate"] is True


def test_gate_releases_when_true_category_allowlisted():
    act = decide_hitl_gate(_ctx(act_allowlist=["money_out"]), method="DELETE",
                           route="/api/order/1", payload_text="",
                           category_override="money_out")
    assert act["gate"] is False


def test_gate_still_blocks_approval_required_literal():
    """回归守卫：把 failure_classification.category 的 "approval_required" 当类别写进白名单，
    闸门必须仍然判定拦截 —— 否则说明批准链路又退化成「写了等于没写」。
    """
    act = decide_hitl_gate(_ctx(act_allowlist=["approval_required"]), method="DELETE",
                           route="/api/order/1", payload_text="",
                           category_override="money_out")
    assert act["gate"] is True, "字面量 approval_required 不得放行真实不可逆动作"


def test_tool_allowlist_alone_never_releases_gate():
    """证明旧行为（批准只写 tool_allowlist）接通不了链路。"""
    act = decide_hitl_gate(_ctx(tool_allowlist=["d2_replay"]), method="DELETE",
                           route="/api/order/1", payload_text="",
                           category_override="data_destroy")
    assert act["gate"] is True, "工具级白名单不是闸门的放行依据"


# ── 2. 待放行结果必须带出真实 act.category ─────────────────────────────────
def test_approval_required_result_carries_true_act_category():
    res = _approval_required_result(
        exploit_spec={},
        tool_spec={"id": "d2_replay", "risk_level": "high"},
        approval_mode="ask_on_risky_tools",
        allowlist=set(),
        act={"irreversible": True, "category": "money_out",
             "route": "/wallet/withdraw", "method": "POST",
             "reason": "端点语义=money_out"},
    )
    act = (res.verification_decision or {}).get("act") or {}
    assert act.get("category") == "money_out"
    # 同一结果里 failure_classification 是字面量 —— 正是必须取 act 而非 fc 的原因
    assert (res.failure_classification or {}).get("category") == "approval_required"


# ── 3. TaskService 批准写入 act_allowlist（轻量桩，不碰生产库）───────────────
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
        from src.domain.models import Workspace
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
    from src.application.task_service import TaskService
    from src.infrastructure.db import Database

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    db = Database(path)
    db.execute("SELECT 1")
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


def _seed(svc, pending):
    from src.domain.models import ScanTask, TaskStatus

    t = ScanTask(
        id=101, workspace_id=1, name="scan", status=TaskStatus.COMPLETED, phase="completed",
        options={"approval_mode": "ask_on_risky_tools", "tool_allowlist": [], "act_allowlist": []},
        summary={"hitl": {"approval_mode": "ask_on_risky_tools",
                          "tool_allowlist": [], "act_allowlist": [],
                          "pending_actions": pending}},
    )
    svc.task_repository.create(t)
    return t


def test_approve_writes_true_category_into_act_allowlist():
    svc, db, path = _make_service()
    try:
        _seed(svc, [{"id": "a1", "action_id": "a1", "tool_id": "d2_replay",
                     "category": "money_out", "risk_level": "high", "stage": "d2",
                     "status": "pending", "proposed_action": {}}])
        out = svc.resolve_task_hitl_action(101, "a1", "approved")
        assert out["settings"]["act_allowlist"] == ["money_out"]
        assert "d2_replay" in out["settings"]["tool_allowlist"]
        # 回写持久化：options 与 summary 双写，重跑时两者都能取到
        task = svc.get_task(101)
        assert task.options.get("act_allowlist") == ["money_out"]
        assert task.summary["hitl"]["act_allowlist"] == ["money_out"]
    finally:
        db.close()
        os.remove(path)


def test_approve_without_category_keeps_act_allowlist_empty():
    svc, db, path = _make_service()
    try:
        _seed(svc, [{"id": "a2", "action_id": "a2", "tool_id": "d2_replay",
                     "category": "", "risk_level": "high", "stage": "d2",
                     "status": "pending", "proposed_action": {}}])
        out = svc.resolve_task_hitl_action(101, "a2", "approved")
        assert out["settings"]["act_allowlist"] == []
        assert "d2_replay" in out["settings"]["tool_allowlist"]
    finally:
        db.close()
        os.remove(path)


def test_batch_approve_merges_distinct_categories_without_duplicates():
    svc, db, path = _make_service()
    try:
        _seed(svc, [
            {"id": "a1", "action_id": "a1", "tool_id": "d2_replay", "category": "money_out",
             "risk_level": "high", "stage": "d2", "status": "pending", "proposed_action": {}},
            {"id": "a2", "action_id": "a2", "tool_id": "d2_replay", "category": "data_destroy",
             "risk_level": "high", "stage": "d2", "status": "pending", "proposed_action": {}},
            {"id": "a3", "action_id": "a3", "tool_id": "d2_replay", "category": "money_out",
             "risk_level": "high", "stage": "d2", "status": "pending", "proposed_action": {}},
        ])
        svc.resolve_task_hitl_actions_batch(
            101, [{"action_id": i, "decision": "approved"} for i in ("a1", "a2", "a3")]
        )
        cats = svc.get_task_hitl(101)["act_allowlist"]
        assert sorted(cats) == ["data_destroy", "money_out"]  # 去重
    finally:
        db.close()
        os.remove(path)


def test_unknown_action_id_raises():
    svc, db, path = _make_service()
    try:
        _seed(svc, [])
        with pytest.raises(ValueError):
            svc.resolve_task_hitl_action(101, "nope", "approved")
    finally:
        db.close()
        os.remove(path)
