import asyncio
from queue import Empty

from fastapi import APIRouter, HTTPException, Response, WebSocket, WebSocketDisconnect

from src.api.dependencies import container
from src.application.quota_service import QuotaExceededError
from src.api.schemas import (
    HitlActionResolveResponse,
    HitlAuditEntryResponse,
    HitlBatchResolveRequest,
    HitlBatchResolveResponse,
    HitlPendingActionResponse,
    HitlSettingsResponse,
    HitlSettingsUpdate,
    HitlSuspendResponse,
    ScanTaskCreate,
    ScanTaskResponse,
    TaskEventResponse,
)

import json
import logging
import os
import socket
import time
from dataclasses import asdict

logger = logging.getLogger(__name__)

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_STATUS_FILE = os.path.join(_ROOT, "stack_status.json")


router = APIRouter(tags=["tasks"])


@router.get("/api/system/processes")
def system_processes():
    """返回统一看门狗(launch_stack.py)写出的进程状态，并实时复核端口存活。"""
    data = {"updated_at": None, "processes": {}, "stack_manager_running": False}
    try:
        if os.path.exists(_STATUS_FILE):
            with open(_STATUS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            mtime = os.path.getmtime(_STATUS_FILE)
            data["stack_manager_running"] = (time.time() - mtime) < 30
    except Exception:
        pass
    for _name, p in data.get("processes", {}).items():
        port = p.get("port")
        up = False
        if port:
            for host in ("127.0.0.1", "::1"):
                try:
                    with socket.create_connection((host, port), timeout=1):
                        up = True
                        break
                except OSError:
                    continue
        p["live_listening"] = up
    return data


@router.get("/api/scan-tasks", response_model=list[ScanTaskResponse])
def list_tasks(workspace_id: int | None = None):
    return container.task_service.list_tasks(workspace_id)


def _attach_pipeline_tasks(task) -> None:
    """读取时补挂「阶段 → 具体任务清单」。

    attach_stage_tasks 原本只在扫描进程内 _build_pipeline 时执行，因此改造之前跑完的
    用户看不到任何具体任务，等于该功能对历史任务不存在。

    改为读取时按 summary.stage_results 现算挂载、不写库（快照保持原样，可回滚），
    历史任务与在跑任务走同一份口径。
    """
    try:
        summary = getattr(task, "summary", None)
        if not isinstance(summary, dict) or not summary:
            return
        pipeline = summary.get("pipeline")
        if not isinstance(pipeline, dict) or not pipeline:
            return
        stage_results = summary.get("stage_results") or summary.get("results") or {}
        from src.core.pipeline_view import attach_stage_tasks

        summary["pipeline"] = attach_stage_tasks(
            pipeline,
            {"stage_results": stage_results if isinstance(stage_results, dict) else {}},
            getattr(task, "options", None) or {},
        )
    except Exception as exc:  # 展示增强绝不能把 200 变成 500
        logger.warning("[get_task] 阶段任务清单挂载失败（跳过，返回原始 pipeline）：%s", exc)


@router.get("/api/scan-tasks/{task_id}", response_model=ScanTaskResponse)
def get_task(task_id: int):
    task = container.task_service.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    _attach_pipeline_tasks(task)
    return task


@router.post("/api/scan-tasks", response_model=ScanTaskResponse, status_code=201)
def create_task(payload: ScanTaskCreate):
    try:
        return container.task_service.create_task(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except QuotaExceededError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


@router.get("/api/scan-tasks/{task_id}/events", response_model=list[TaskEventResponse])
def list_task_events(task_id: int):
    return container.task_service.list_task_events(task_id)


# 单 task 运行时运维快照。区别于全局 /api/metrics/*（跨任务运营度量，
# 对应前端 /ops 页）：本接口只回答「这一个 task 现在跑得怎么样」——进程锁、进度心跳时间戳
# 与卡死判定、目标端口可达性、最近事件流、AI 调用埋点，供 TaskDetailPage「运维」tab 消费。
# 卡死判定沿用项目铁律：scan_progress.json 连续 > 45 分钟无更新即判卡死（不是靠阶段文案猜）。
_RUNTIME_STUCK_MINUTES = 45


def _task_field(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _probe_port(port: int) -> bool:
    for host in ("127.0.0.1", "::1"):
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            continue
    return False


@router.get("/api/scan-tasks/{task_id}/runtime")
def get_task_runtime(task_id: int, event_limit: int = 40):
    task = container.task_service.get_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")

    # status 在领域模型里是枚举，直接 str 会输出 "TaskStatus.COMPLETED"，前端不好消费。
    _status_raw = _task_field(task, "status")
    status = str(getattr(_status_raw, "value", _status_raw) or "")
    out_dir = str(_task_field(task, "output_dir") or "")
    task_root = os.path.join(_ROOT, out_dir) if out_dir else ""

    # 1) 进度心跳与卡死判定
    progress = {"exists": False, "mtime": None, "age_seconds": None,
                "timestamp": None, "phases": {}, "stuck": False}
    prog_path = os.path.join(task_root, "scan_progress.json") if task_root else ""
    if prog_path and os.path.exists(prog_path):
        try:
            mt = os.path.getmtime(prog_path)
            age = int(time.time() - mt)
            progress.update({
                "exists": True,
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mt)),
                "age_seconds": age,
                "stuck": bool(status == "running" and age > _RUNTIME_STUCK_MINUTES * 60),
            })
            with open(prog_path, "r", encoding="utf-8") as f:
                pj = json.load(f)
            progress["timestamp"] = pj.get("timestamp")
            progress["phases"] = {k: (v or {}).get("status") for k, v in (pj.get("phases") or {}).items()}
        except Exception:
            pass

    # 2) 扫描子进程持有的单例锁（存在即说明该 task 的 runner 进程还活着）
    lock_path = os.path.join(task_root, f"scan_task.{task_id}.lock") if task_root else ""
    subprocess_lock = bool(lock_path and os.path.exists(lock_path))

    ports = {p: _probe_port(p) for p in (8000, 5200, 8080, 8092)}

    # 4) 最近事件流 + AI 调用埋点（两张表都 fail-open，缺表不影响运维视图）
    events = []
    ai_calls = {"total": None, "note": ""}
    try:
        db = getattr(container.task_service, "db", None)
        if db is not None:
            rows = db.execute(
                "SELECT id, event_type, created_at FROM scan_task_events"
                " WHERE task_id=? ORDER BY id DESC LIMIT ?",
                (int(task_id), int(event_limit)), fetchall=True) or []
            events = [{"id": r["id"], "event_type": r["event_type"], "created_at": r["created_at"]} for r in rows]
            # 退而按本 task 运行时间窗统计（created_at 与 started_at 同为 ISO 文本，可直接比较），
            # 口径如实写在 note 里，绝不把「时间窗近似」说成「本任务精确」。
            _start = str(_task_field(task, "started_at") or "")
            _end = str(_task_field(task, "finished_at") or "") or time.strftime("%Y-%m-%dT%H:%M:%S")
            ai_calls["window"] = {"from": _start, "to": _end}
            if _start:
                try:
                    mr = db.execute(
                        "SELECT COUNT(*) AS n, SUM(input_tokens) AS ti, SUM(output_tokens) AS to_tokens,"
                        " SUM(cost_usd) AS cost FROM model_runs WHERE created_at >= ? AND created_at <= ?",
                        (_start, _end), fetchall=True) or []
                    if mr:
                        row = mr[0]
                        ai_calls["total"] = int(row["n"] or 0)
                        ai_calls["input_tokens"] = int(row["ti"] or 0)
                        ai_calls["output_tokens"] = int(row["to_tokens"] or 0)
                        ai_calls["cost_usd"] = round(float(row["cost"] or 0.0), 4)
                    ai_calls["note"] = "按本 task 运行时间窗统计（model_runs 无 task_id 列，非精确归属）"
                except Exception as exc:
                    ai_calls["note"] = f"AI 调用埋点统计失败：{exc}"
            else:
                ai_calls["note"] = "任务尚未开始，无 AI 调用窗口"
    except Exception as exc:
        ai_calls["note"] = f"事件流读取失败：{exc}"

    return {
        "task_id": int(task_id),
        "workspace_id": _task_field(task, "workspace_id"),
        "status": status,
        "phase": str(_task_field(task, "phase") or ""),
        "started_at": _task_field(task, "started_at") or "",
        "finished_at": _task_field(task, "finished_at") or "",
        "output_dir": out_dir,
        "progress": progress,
        "subprocess_lock": subprocess_lock,
        "ports": ports,
        "recent_events": events,
        "ai_calls": ai_calls,
        "stuck_threshold_minutes": _RUNTIME_STUCK_MINUTES,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
    }


@router.get("/api/scan-tasks/{task_id}/hitl", response_model=HitlSettingsResponse)
def get_task_hitl(task_id: int):
    try:
        return container.task_service.get_task_hitl(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/api/scan-tasks/{task_id}/hitl", response_model=HitlSettingsResponse)
def update_task_hitl(task_id: int, payload: HitlSettingsUpdate):
    try:
        return container.task_service.update_task_hitl(task_id, payload.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/scan-tasks/{task_id}/hitl/pending", response_model=list[HitlPendingActionResponse])
def list_task_hitl_pending(task_id: int):
    try:
        return container.task_service.list_task_hitl_pending(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/scan-tasks/{task_id}/hitl/actions/{action_id}/approve", response_model=HitlActionResolveResponse)
def approve_task_hitl_action(task_id: int, action_id: str):
    try:
        return container.task_service.resolve_task_hitl_action(task_id, action_id, "approved")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/scan-tasks/{task_id}/hitl/actions/{action_id}/reject", response_model=HitlActionResolveResponse)
def reject_task_hitl_action(task_id: int, action_id: str):
    try:
        return container.task_service.resolve_task_hitl_action(task_id, action_id, "rejected")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/scan-tasks/{task_id}/hitl/actions/batch", response_model=HitlBatchResolveResponse)
def batch_resolve_task_hitl_actions(task_id: int, payload: HitlBatchResolveRequest):
    try:
        return container.task_service.resolve_task_hitl_actions_batch(
            task_id, [item.model_dump() for item in payload.items]
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/api/scan-tasks/{task_id}/hitl/audit", response_model=list[HitlAuditEntryResponse])
def list_task_hitl_audit(task_id: int):
    try:
        return container.task_service.list_task_hitl_audit(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/scan-tasks/{task_id}/suspend", response_model=HitlSuspendResponse)
def suspend_task(task_id: int):
    try:
        return container.task_service.suspend_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/scan-tasks/{task_id}/resume", response_model=HitlSuspendResponse)
def resume_task(task_id: int):
    try:
        return container.task_service.resume_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/scan-tasks/{task_id}/cancel", status_code=200)
def cancel_task(task_id: int):
    """停掉一个 pending/running 的任务，但保留任务记录与已产出的数据。

    在过去也只删库行、不停线程池里的任务，导致被删任务照样空跑抢资源。
    """
    try:
        return container.task_service.cancel_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/api/scan-tasks/{task_id}", status_code=204)
def delete_task(task_id: int):
    try:
        # 注：task_service.delete_task 内部已先 runner.cancel 再删库行。
        container.task_service.delete_task(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@router.delete("/api/workspaces/{workspace_id}/scan-tasks", status_code=204)
def clear_workspace_tasks(workspace_id: int):
    try:
        container.task_service.clear_workspace_tasks(workspace_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@router.delete("/api/scan-tasks")
def purge_all_tasks(confirm: str = ""):
    """删除全部任务及全部子表残留。

    破坏性操作：必须带 ?confirm=purge-all 才执行，否则 400 拒绝。
    级联范围：trigger_specs / model_runs / hypotheses / vuln_blackboard /
    scan_runs / scan_task_events / findings / reports + scan_tasks 本表，
    另清理 task_id 已无对应任务的孤儿子表行。
    """
    if confirm != "purge-all":
        raise HTTPException(
            status_code=400,
            detail="危险操作：删除全部任务须显式确认，请带 ?confirm=purge-all 重试",
        )
    result = container.task_service.purge_all_tasks()
    return result


@router.websocket("/ws/tasks/{task_id}")
async def task_websocket(websocket: WebSocket, task_id: int):
    await websocket.accept()
    queue = container.event_bus.subscribe(task_id)
    try:
        for event in container.task_service.list_task_events(task_id):
            await websocket.send_json(
                {
                    "id": event.id,
                    "task_id": event.task_id,
                    "event_type": event.event_type,
                    "payload": event.payload,
                    "created_at": event.created_at,
                }
            )
        while True:
            try:
                event = await asyncio.to_thread(queue.get, True, 1)
            except Empty:
                await websocket.send_json({"event_type": "heartbeat", "task_id": task_id})
                continue
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        container.event_bus.unsubscribe(task_id, queue)


@router.websocket("/ws/tasks")
async def tasks_websocket(websocket: WebSocket):
    """全局任务推送通道（取代前端 10s 轮询 /api/scan-tasks）。

    连接即下发全量任务快照（snapshot），之后只回推「状态变更类事件」对应的权威任务行
    （task_update）；其余高频事件（task_progress 等）透传为 event，供详情页各自的
    /ws/tasks/{id} 通道处理。心跳由 queue.get 的 1s 超时兜底（heartbeat）。
    """
    await websocket.accept()
    try:
        tasks = container.task_service.list_tasks(None)
        await websocket.send_json({"type": "snapshot", "tasks": [asdict(t) for t in tasks]})
    except Exception as exc:
        logger.warning("[ws/tasks] 初始快照失败：%s", exc)
    queue = container.event_bus.subscribe_global()
    try:
        while True:
            try:
                event = await asyncio.to_thread(queue.get, True, 1)
            except Empty:
                await websocket.send_json({"type": "heartbeat"})
                continue
            etype = (event or {}).get("event_type")
            if etype in (
                "task_started",
                "task_resumed",
                "task_suspended",
                "task_completed",
                "task_failed",
                "task_cancelled",
            ):
                try:
                    task = container.task_service.get_task(event.get("task_id"))
                    if task is not None:
                        await websocket.send_json({"type": "task_update", "task": asdict(task)})
                        continue
                except Exception as exc:
                    logger.warning("[ws/tasks] 任务回推失败：%s", exc)
            await websocket.send_json({"type": "event", "event": event})
    except WebSocketDisconnect:
        pass
    finally:
        container.event_bus.unsubscribe_global(queue)
