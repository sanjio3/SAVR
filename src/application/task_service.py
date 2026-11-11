import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from src.application.d1_service import D1Service
from src.domain.models import ScanTask, TaskEvent, TaskStatus
from src.infrastructure.db import Database
from src.infrastructure.event_bus import TaskEventBus
from src.infrastructure.repositories import FindingRepository, ReportRepository, TaskEventRepository, TaskRepository, WorkspaceRepository
from src.infrastructure.task_runner import ScanTaskRunner
from src.pipeline.a0.service import A0PreprocessService

logger = logging.getLogger(__name__)


# 落地方式不是「删掉闸门」，而是把缺省与未知值统一收口到 off：
#   - resolve_approval_mode 是唯一解析入口，缺省 off、未知值当 off 并打 warning；
#   - 提交侧仍接受调用方显式传 approval_mode（保留人工收紧的可能），
APPROVAL_MODES = ("off", "ask_on_risky_tools", "strict")
DEFAULT_APPROVAL_MODE = "off"
FULL_APPROVAL_POLICY = "destructive-gate-full-approval"
# progress 事件保留：最近 N 条（细粒度尾迹）。配合 6h 时间窗 + 每 5 分钟采样，
# 审计视角仍能看到「起跑 → 骨架 → 收尾」全过程，而体积从 0.5GB/任务降到 MB 级。
# scan_task_events 膨胀到 9.02GB，占 app.db 的 83%。详见 post-persist 的保留策略注释。
_PROGRESS_KEEP_TAIL = 200


def normalize_approval_mode(raw: Any) -> str:
    """提交侧归一化：非白名单（含空串/None/拼错值）一律收敛到 off，并留痕。"""
    text = str(raw or "").strip()
    if text in APPROVAL_MODES:
        return text
    if raw is not None and str(raw) != "":
        logger.warning("[HITL] 未知 approval_mode=%r，已收敛为 %s（破坏性闸门测试期全批准）",
                       raw, DEFAULT_APPROVAL_MODE)
    return DEFAULT_APPROVAL_MODE


class TaskService:
    def __init__(
        self,
        task_repository: TaskRepository,
        workspace_repository: WorkspaceRepository,
        event_repository: TaskEventRepository,
        finding_repository: FindingRepository,
        report_repository: ReportRepository,
        event_bus: TaskEventBus,
        preprocess: A0PreprocessService,
        runner: Optional[ScanTaskRunner] = None,
        db: Optional[Database] = None,
        d1_service: Optional[D1Service] = None,
    ):
        self.task_repository = task_repository
        self.workspace_repository = workspace_repository
        self.event_repository = event_repository
        self.finding_repository = finding_repository
        self.report_repository = report_repository
        self.event_bus = event_bus
        self.preprocess = preprocess
        self.runner = runner or ScanTaskRunner(self._handle_runner_event, self._handle_runner_result)
        if db is None:
            db_path = os.environ.get("SAST_AI_DB_PATH", "data/app.db")
            db = Database(db_path)
        self.db = db
        self.d1_service = d1_service or D1Service(self.db)

    def list_tasks(self, workspace_id: Optional[int] = None):
        return self.task_repository.list(workspace_id)

    def get_task(self, task_id: int):
        return self.task_repository.get(task_id)

    def delete_task(self, task_id: int):
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if task.output_dir:
            # 抛 PermissionError[WinError 32]，原先未捕获会透传为 HTTP 500。改为 best-effort：
            # 删目录失败也保证库行清除，避免停任务端点 500。
            try:
                self.preprocess.reset_directory(Path(task.output_dir))
            except OSError as _e:
                logger.warning("[delete_task] 输出目录删除失败（best-effort 继续删库行）：%s", _e)
        # 反过来的话 ThreadPoolExecutor 的队列里还留着这个任务，轮到它时照样拉起子进程 ——
        # 实测 历史轮次 被删后仍被依次拉起空跑（CodeQL 建库、占槽位），把快环任务饿死。
        if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
            try:
                self.runner.cancel(task_id)
            except Exception as _ce:  # 取消失败不能挡住删库行
                logger.warning("[delete_task] task=%s 取消运行失败：%s", task_id, _ce)
        self.task_repository.delete(task_id)

    def cancel_task(self, task_id: int) -> Dict[str, Any]:
        """只取消不删除（保留任务记录与已产出的数据）。

        前端此前没有可用的「停我非常跑的任务」入口：DELETE 会把记录一起删掉。
        """
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if task.status not in (TaskStatus.PENDING, TaskStatus.RUNNING):
            raise ValueError(f"仅 pending/running 任务可取消，当前状态={task.status.value}")
        self.runner.cancel(task_id)
        self.task_repository.update(task_id, status=TaskStatus.CANCELLED, phase="cancelled")
        self._emit_event(task_id, "task_cancelled", {"status": "cancelled", "phase": "cancelled"})
        return {"task_id": task_id, "status": "cancelled"}

    def clear_workspace_tasks(self, workspace_id: int):
        workspace = self.workspace_repository.get(workspace_id)
        if workspace is None:
            raise ValueError(f"Workspace {workspace_id} not found")
        tasks = self.task_repository.list(workspace_id)
        for task in tasks:
            # 同 delete_task：先停跑再删，否则被删任务仍会在线程池轮到时空跑。
            if task.status in (TaskStatus.PENDING, TaskStatus.RUNNING):
                try:
                    self.runner.cancel(task.id)
                except Exception as _ce:
                    logger.warning("[clear_workspace_tasks] task=%s 取消运行失败：%s", task.id, _ce)
            if task.output_dir:
                try:
                    self.preprocess.reset_directory(Path(task.output_dir))
                except OSError as _e:
                    logger.warning("[clear_workspace_tasks] 输出目录删除失败（best-effort 继续）：%s", _e)
        self.task_repository.delete_by_workspace(workspace_id)

    def purge_all_tasks(self) -> Dict[str, int]:
        """删除全部任务及其全部子表残留。

        背景：旧 delete 只删 scan_tasks 一行，trigger_specs / model_runs / hypotheses /
        vuln_blackboard / scan_runs / scan_task_events / findings / reports 全部残留
        ，task_id 复用后旧 spec 被当成本轮
        重放目标。级联删已下沉到 TaskRepository；本方法额外清理「task_id 已无对应
        scan_tasks 行」的孤儿残留，并 best-effort 移除各任务输出目录。

        返回 {"deleted_tasks": n, "orphan_rows": m}。
        """
        tasks = self.task_repository.list(None)
        for task in tasks:
            if task.output_dir:
                try:
                    self.preprocess.reset_directory(Path(task.output_dir))
                except OSError as _e:
                    logger.warning("[purge_all_tasks] 输出目录删除失败（best-effort 继续）：%s", _e)
        deleted = self.task_repository.delete_all()
        orphans = self.task_repository.purge_orphans()
        logger.warning("[purge_all_tasks] 已删除 %d 个任务，清理孤儿子表行 %d 条", deleted, orphans)
        return {"deleted_tasks": int(deleted), "orphan_rows": int(orphans)}

    def list_task_events(self, task_id: int):
        return self.event_repository.list(task_id)

    def create_task(self, payload: Dict):
        workspace = self.workspace_repository.get(payload["workspace_id"])
        if workspace is None:
            raise ValueError(f"Workspace {payload['workspace_id']} not found")
        # 不自动杀在跑任务——只在入口拦新任务 + 告警。
        from src.application.quota_service import QuotaExceededError, QuotaService

        try:
            QuotaService(self.db).assert_within_quota(workspace.id)
        except QuotaExceededError:
            raise
        # 创建任务也放宽：路径可暂不存在（strict=False），由实际扫描执行阶段严格校验。
        validation = self.preprocess.validate_workspace_path(workspace, strict=False)
        if validation["status"] != "ok":
            raise ValueError(validation["message"])

        enable_idor = bool(payload.get("enable_idor", False))
        idor_app_id = str(payload.get("idor_app_id", "") or "")
        target_url = str((workspace.settings or {}).get("target_url", "") or "")
        # 如果开启 D1 但未指定 app_id，且 workspace 配置了目标 URL，则自动创建 DAST app
        if enable_idor and not idor_app_id and target_url:
            app_name = f"workspace-{workspace.id}"
            app = self.d1_service.create_app({
                "app_id": app_name,
                "app_name": app_name,
                "base_url": target_url,
            })
            idor_app_id = str(app.get("app_id") or app_name)

        # M11：DAST 配置自检。**不拦截提交**（纯静态扫描不该被 DAST 配置问题挡住），
        # 但把结论写进 options 并推事件——否则「base_url 没填」这件事要等扫完 40 分钟
        # 看一屏 no_evidence 才被发现，而那批 no_evidence 已被当成永久非漏洞写进分母。
        try:
            from src.core import dast_config_check as _dcc
            dast_config_check = _dcc.check_task_dast_config(
                self.db, workspace.id, idor_app_id,
                enable_verification=bool(payload.get("enable_verification", True)))
        except Exception as exc:
            dast_config_check = {"ok": True, "error": str(exc), "warnings": []}

        draft = ScanTask(
            id=None,
            workspace_id=workspace.id,
            name=payload.get("name") or f"Scan {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            status=TaskStatus.PENDING,
            phase="pending",
            options={
                "enable_a1": payload.get("enable_a1", True),
                "enable_a2": payload.get("enable_a2", True),
                "enable_verification": payload.get("enable_verification", True),
                "enable_sca": payload.get("enable_sca", True),
                "enable_ai_review": payload.get("enable_ai_review", True),
                "enable_idor": enable_idor,
                "idor_app_id": idor_app_id,
                "enable_entry_discovery": payload.get("enable_entry_discovery", True),
                "scan_mode": payload.get("scan_mode", "filter_first"),
                "model_profile": payload.get("model_profile", "default"),
                "prompt_version": payload.get("prompt_version", "terminal-first-v1"),
                "sca_tool": payload.get("sca_tool", "auto"),
                "sca_severity_threshold": payload.get("sca_severity_threshold", "LOW"),
                "sca_ignore_unfixed": payload.get("sca_ignore_unfixed", False),
                "output_format": payload.get("output_format", "both"),
                "approval_mode": normalize_approval_mode(payload.get("approval_mode", DEFAULT_APPROVAL_MODE)),
                "tool_allowlist": list(payload.get("tool_allowlist") or []),
                "act_allowlist": list(payload.get("act_allowlist") or []),
                # 只进本任务的 options，不写全局配置 —— 项目是多任务并发的。
                "llm_overrides": dict(payload.get("llm_overrides") or {}),
                # task_runner 会透传给扫描子进程；为空即旧的全量行为。
                "shard_file": str(payload.get("shard_file") or "").strip(),
                # 的 _apply_task_run_env 在子进程启动时注入 os.environ。
                # 只做键/值字符串化（与消费端 str(k)/str(v) 对齐），不在这里改开关语义。
                # 缺了这一行，REST 提交的任务永远丢 run_env。
                "run_env": {str(k): str(v) for k, v in
                            dict(payload.get("run_env") or {}).items()},
                # M11：DAST 配置自检结果（不拦截提交，但随任务留痕并推事件到前端）。
                "dast_config_check": dast_config_check,
            },
            summary=self._build_initial_summary({**payload, "enable_idor": enable_idor, "idor_app_id": idor_app_id}),
        )
        created = self.task_repository.create(draft)
        output_dir = self.preprocess.build_output_dir(workspace, created.id)
        updated = self.task_repository.update(created.id, output_dir=output_dir, phase="queued")
        self._emit_event(created.id, "task_status_changed", {"status": "pending", "phase": "queued", "output_dir": output_dir})
        # M11：配置告警单独走一个事件类型，前端可据此在任务卡上直接标红，
        # 而不是让人从一堆日志里自己找「为什么这轮全是 no-arrival」。
        if dast_config_check and dast_config_check.get("warnings"):
            self._emit_event(created.id, "dast_config_warning", {
                "ok": False,
                "app_id": dast_config_check.get("app_id"),
                "warnings": dast_config_check.get("warnings"),
                "summary": dast_config_check.get("summary"),
            })
        self.runner.submit(updated, workspace)
        return updated

    def get_task_hitl(self, task_id: int) -> Dict[str, Any]:
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        hitl_summary = dict((task.summary or {}).get("hitl") or {})
        return {
            "task_id": task_id,
            "approval_mode": str(task.options.get("approval_mode", hitl_summary.get("approval_mode", "off"))),
            "tool_allowlist": list(task.options.get("tool_allowlist") or hitl_summary.get("tool_allowlist") or []),
            # 闸门实际消费的是 act_allowlist（动作类别级），此前无返回，前端看不到已放行类别。
            "act_allowlist": list(task.options.get("act_allowlist") or hitl_summary.get("act_allowlist") or []),
            "pending_actions": list(hitl_summary.get("pending_actions") or []),
            "approval_policy": str(hitl_summary.get("approval_policy") or FULL_APPROVAL_POLICY),
        }

    def update_task_hitl(self, task_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        options = dict(task.options or {})
        summary = dict(task.summary or {})
        hitl_summary = dict(summary.get("hitl") or {})
        if "approval_mode" in payload and payload.get("approval_mode") is not None:
            options["approval_mode"] = normalize_approval_mode(payload.get("approval_mode"))
            hitl_summary["approval_mode"] = str(options["approval_mode"])
        if "tool_allowlist" in payload and payload.get("tool_allowlist") is not None:
            options["tool_allowlist"] = list(payload.get("tool_allowlist") or [])
            hitl_summary["tool_allowlist"] = list(payload.get("tool_allowlist") or [])
        if "act_allowlist" in payload and payload.get("act_allowlist") is not None:
            options["act_allowlist"] = list(payload.get("act_allowlist") or [])
            hitl_summary["act_allowlist"] = list(payload.get("act_allowlist") or [])
        hitl_summary.setdefault("pending_actions", list(hitl_summary.get("pending_actions") or []))
        summary["hitl"] = hitl_summary
        self.task_repository.update(task_id, options=options, summary=summary)
        return self.get_task_hitl(task_id)

    def list_task_hitl_pending(self, task_id: int) -> list[Dict[str, Any]]:
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        hitl_summary = dict((task.summary or {}).get("hitl") or {})
        return [
            dict(item or {})
            for item in list(hitl_summary.get("pending_actions") or [])
            if str((item or {}).get("status", "pending") or "pending") == "pending"
        ]

    def resolve_task_hitl_action(self, task_id: int, action_id: str, decision: str) -> Dict[str, Any]:
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        options = dict(task.options or {})
        summary = dict(task.summary or {})
        hitl_summary = dict(summary.get("hitl") or {})
        pending_actions = [dict(item or {}) for item in list(hitl_summary.get("pending_actions") or [])]
        selected_action = None
        for item in pending_actions:
            if str(item.get("id", "")) != str(action_id):
                continue
            item["status"] = decision
            item["resolved_at"] = datetime.utcnow().isoformat()
            selected_action = dict(item)
            if decision == "approved":
                tool_id = str(item.get("tool_id", "") or "").strip()
                if tool_id:
                    allowlist = list(options.get("tool_allowlist") or hitl_summary.get("tool_allowlist") or [])
                    if tool_id not in allowlist:
                        allowlist.append(tool_id)
                    options["tool_allowlist"] = allowlist
                    hitl_summary["tool_allowlist"] = allowlist
                # 使 resume/resubmit 重跑到 D2 时同一类别不再被闸门短接。
                act_cat = str(item.get("category") or "").strip()
                if act_cat:
                    act_list = list(options.get("act_allowlist") or hitl_summary.get("act_allowlist") or [])
                    if act_cat not in act_list:
                        act_list.append(act_cat)
                    options["act_allowlist"] = act_list
                    hitl_summary["act_allowlist"] = act_list
            break
        if selected_action is None:
            raise ValueError(f"Pending HITL action {action_id} not found")
        hitl_summary["pending_actions"] = pending_actions
        summary["hitl"] = hitl_summary
        self.task_repository.update(task_id, options=options, summary=summary)
        self._emit_event(task_id, "task_hitl_resolved", {"action": selected_action, "hitl": hitl_summary})
        return {
            "action": selected_action,
            "settings": self.get_task_hitl(task_id),
        }

    def resolve_task_hitl_actions_batch(self, task_id: int, items: list) -> Dict[str, Any]:
        """批量裁决多条 pending action（每条给定 action_id + decision）。

        逐条复用单条裁决逻辑；任一条失败不影响其余（收集 per-item 结果）。
        返回 resolved（成功列表）、failed（失败列表，含原因）。
        """
        resolved: list = []
        failed: list = []
        for entry in list(items or []):
            action_id = str((entry or {}).get("action_id") or "")
            decision = str((entry or {}).get("decision") or "")
            if not action_id or decision not in {"approved", "rejected"}:
                failed.append({"action_id": action_id, "error": "action_id/decision 非法"})
                continue
            try:
                res = self.resolve_task_hitl_action(task_id, action_id, decision)
                resolved.append(res["action"])
            except ValueError as exc:
                failed.append({"action_id": action_id, "error": str(exc)})
        return {"resolved": resolved, "failed": failed, "settings": self.get_task_hitl(task_id)}

    def list_task_hitl_audit(self, task_id: int) -> list:
        """返回某任务全部 HITL 审计事件（破坏性闸门决策的持久化记录）。"""
        from src.application.hitl_audit import list_guard_events

        return list_guard_events(self.db, task_id)

    def suspend_task(self, task_id: int) -> Dict[str, Any]:
        """软挂起：将任务标记为 SUSPENDED（供人工复核期间持有，不杀在跑进程）。

        记录 pending」，任务照常推进到终态。suspend 是对「已完成/排队中」任务的复核持有标记；
        若任务正在运行，状态会在其自身终态事件到达时被改写为终态（挂起不阻断在跑进程）。
        """
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        self.task_repository.update(task_id, status=TaskStatus.SUSPENDED)
        self._emit_event(task_id, "task_suspended", {"status": TaskStatus.SUSPENDED.value})
        return {"task_id": task_id, "status": TaskStatus.SUSPENDED.value}

    def resume_task(self, task_id: int) -> Dict[str, Any]:
        """恢复并回填：重新提交任务（复用既有提交入口）。

        重新提交会开启新一轮 run，D2 阶段按已更新的 allowlist / act_allowlist 重新验证此前
        被拦的不可逆动作——即「审批后回填」。仅允许从 SUSPENDED 或终态恢复。
        """
        task = self.task_repository.get(task_id)
        if task is None:
            raise ValueError(f"Task {task_id} not found")
        if task.status not in (TaskStatus.SUSPENDED, TaskStatus.COMPLETED, TaskStatus.FAILED):
            raise ValueError(f"仅 SUSPENDED/终态任务可恢复，当前状态={task.status.value}")
        workspace = self.workspace_repository.get(task.workspace_id)
        if workspace is None:
            raise ValueError(f"Workspace {task.workspace_id} not found")
        self.task_repository.update(task_id, status=TaskStatus.PENDING, phase="queued")
        self.runner.submit(task, workspace)
        self._emit_event(task_id, "task_resumed", {"status": TaskStatus.PENDING.value})
        return {"task_id": task_id, "status": TaskStatus.PENDING.value}

    def _handle_runner_event(self, task_id: int, event_type: str, payload: Dict):
        task = self.task_repository.get(task_id)
        if task is None:
            return
        merged_summary = self._merge_task_summary(task.summary, payload, task.options, event_type)
        effective_phase = payload.get("current_stage") or payload.get("phase", task.phase)
        if event_type == "task_started":
            self.task_repository.update(
                task_id,
                status=TaskStatus.RUNNING,
                phase=effective_phase,
                started_at=datetime.utcnow().isoformat(),
                summary=merged_summary,
            )
        elif event_type == "task_progress":
            self.task_repository.update(
                task_id,
                status=TaskStatus.RUNNING,
                phase=effective_phase,
                summary=merged_summary,
            )
        elif event_type == "task_failed":
            self._write_terminal(
                task_id, TaskStatus.FAILED, effective_phase, merged_summary, payload,
                error_message=payload.get("error_message", ""),
            )
        elif event_type == "task_completed":
            self._write_terminal(
                task_id, TaskStatus.COMPLETED, "completed", merged_summary, payload,
            )
        self._emit_event(task_id, event_type, payload)

    def _write_terminal(
        self,
        task_id: int,
        status: Any,
        phase: str,
        merged_summary: Dict,
        payload: Dict,
        error_message: Optional[str] = None,
    ) -> None:
        """写任务终态。

        两点修正：
        1. finished_at 优先取事件载荷里的真实结束时刻（孤儿回收会显式带上报告 generated_at
           或 task_result.json 的 mtime），回退当前时刻 —— 避免把「回收时刻」误写成
           「扫描结束时刻」，导致前端耗时展示失真。
        2. 终态写不进去等价于任务永久卡 running、前端停在陈旧态，违反「状态须同步前端」。
           db 层已对锁冲突做退避重试，此处仍失败则显式告警（task_alert + ERROR 日志），
           不再静默吞掉。
        """
        kwargs: Dict[str, Any] = {
            "status": status,
            "phase": phase,
            "finished_at": payload.get("finished_at") or datetime.utcnow().isoformat(),
            "summary": merged_summary,
        }
        if error_message is not None:
            kwargs["error_message"] = error_message
        try:
            self.task_repository.update(task_id, **kwargs)
            # （DB 锁退避用尽后可能静默失败）。终态写不进去等价于任务永久卡 running，
            # 所以这里回读一次；非终态就重试一次，仍失败则显式告警，绝不静默放过。
            _want = str(getattr(status, "value", status)).lower()
            if _want in ("completed", "failed", "cancelled", "skipped"):
                _got = None
                try:
                    _row = self.db.execute(
                        "SELECT status FROM scan_tasks WHERE id = ?", (task_id,), fetchone=True
                    ) if self.db is not None else None
                    _got = str((_row or {}).get("status") or "").lower() if _row else None
                except Exception:
                    _got = None
                if _got != _want:
                    logger.error(
                        "[task-%s] 终态写入未生效（期望=%s 实际=%s），重试一次", task_id, _want, _got,
                    )
                    try:
                        self.task_repository.update(task_id, **kwargs)
                    except Exception as _retry_exc:
                        logger.error("[task-%s] 终态重试写入仍失败：%s", task_id, _retry_exc)
                    self._emit_event(task_id, "task_alert", {
                        "stage": "finalize",
                        "status": "terminal_write_not_effective",
                        "detail": f"终态期望 {_want}，回读为 {_got}（已重试一次）",
                    })
            # 孤儿轮次收口：任务进入终态后，scan_runs 里该 task 所有未收口的 run 必须闭合，
            if str(status).lower() in ("failed", "completed") and self.db is not None:
                try:
                    from src.core.blackboard import close_open_runs
                    closed = close_open_runs(self.db, task_id, status=str(status).lower())
                    if closed:
                        logger.info("[task-%s] 闭合未收口 scan_run %s 条", task_id, closed)
                except Exception as _ce:
                    logger.warning("[task-%s] 闭合孤儿 run 失败（不阻断）：%s", task_id, _ce)
        except Exception as exc:
            logger.error("[task-%s] 终态写入失败，任务将停留在非终态：%s", task_id, exc)
            try:
                self._emit_event(task_id, "task_alert", {
                    "stage": "finalize",
                    "status": "terminal_write_failed",
                    "detail": f"终态({status})写入失败：{exc}",
                })
            except Exception:
                pass

    def _handle_runner_result(self, task_id: int, workspace_id: int, result: Dict):
        _findings = result.get("findings") or []
        # bug④：收尾前把 trigger_specs 的确认态收敛回 findings（仅升级不降级，异常不阻断）。
        try:
            from src.iast.trigger_spec_registry import (
                backfill_verification_status_from_triggers)
            _upgraded = backfill_verification_status_from_triggers(
                self.db, task_id, _findings, logger)
            if _upgraded:
                self._emit_event(task_id, "task_log", {
                    "stage": "finalize",
                    "status": "verification_writeback",
                    "detail": f"trigger_specs 确认态回填 findings：升级 {_upgraded} 条",
                })
        except Exception as _we:
            logger.warning("[task-%s] verification 回填失败（不阻断收尾）：%s", task_id, _we)
        self.finding_repository.replace_for_task(task_id, workspace_id, _findings)
        self.report_repository.replace_for_task(task_id, workspace_id, result.get("reports") or [])
        self._post_persist_finalize(task_id, workspace_id)

    def _post_persist_finalize(self, task_id: int, workspace_id: int) -> None:
        """findings 落库之后的派生步骤。

        根因：所有以 findings 为锚的派生步骤（IAST 事件→finding 关联归因、黑板同步）此前都写在
        benchmark_cli 的报告流程里执行，而 findings 表由本方法在扫描结束之后才写入。于是派生步骤
        执行时 findings 还是空的，导致 iast_events.correlated_finding_id 全为 NULL
        。
        结论：必须把这类派生步骤挪到 findings 落库之后再跑一遍。

        幂等、fail-open：失败只告警，不影响任务终态。
        """
        db = self.db
        if db is None:
            return
        # 0) 重建假说表。以 spec 为假说来源、事件/裁决为观测来源，
        #    收敛到 proposed/confirmed/refuted/open 四态，open 即差集成员。
        try:
            from src.core import hypotheses as _hyp
            counts = _hyp.refresh_hypotheses(db, task_id, workspace_id)
            diff = _hyp.difference_set(db, task_id)
            logger.info("[post-persist] 假说表刷新 task=%s counts=%s 差集条目=%s",
                        task_id, counts, diff.get("open_count"))
        except Exception as _e:
            logger.warning("[post-persist] 假说表刷新失败（不阻断）：%s", _e)
        # 1) IAST 事件 → finding 关联归因
        try:
            from src.iast.service import IastService
            svc = IastService(db)
            bola = svc.correlate_bola_suspect_to_findings(task_id)
            sink = svc.correlate_sink_events_to_findings(task_id)
            logger.info("[post-persist] IAST 关联归因 task=%s bola=%s sink=%s", task_id, bola, sink)
        except Exception as _e:
            logger.warning("[post-persist] IAST 关联归因失败（不阻断）：%s", _e)
        #    沿革与教训（别再退回单条件）：
        #      · 09-14 最初是「每任务只留最近 30 条」——有效，但有人以「30 条会裁光长跑
        #        任务的进度轨迹、事后不可审计」为由改成「最近 6 小时」。
        #      · 单靠 6h 窗等于没窗：OWASP 任务本身只跑 1.5–3.5h，全部事件都落在窗内，
        #        100 个任务把 `scan_task_events` 撑到 9.02GB（占 app.db 的 83%）。
        #    现在三条一起上，才能同时满足「不膨胀」与「可审计」：
        #      a) 6 小时时间窗（兜住跨阶段的粗粒度轨迹）；
        #      b) 每任务最近 200 条硬上限（兜住窗内高频心跳）；
        #      c) 审计采样：保留最早 1 条（起跑状态）+ 每 5 分钟 1 条（进度骨架）。
        #    配合 task_runner 的 payload 瘦身（单字段 > 4KB 折叠成占位）后，
        #    单条 progress 事件从最坏 2.42MB 降到 KB 级。
        try:
            _cutoff = (datetime.utcnow() - timedelta(hours=6)).isoformat()
            db.execute(
                "DELETE FROM scan_task_events WHERE task_id=? AND event_type='task_progress'"
                " AND created_at < ?",
                (int(task_id), _cutoff),
            )
            _rows = db.execute(
                "SELECT id, created_at FROM scan_task_events"
                " WHERE task_id=? AND event_type='task_progress' ORDER BY created_at ASC, id ASC",
                (int(task_id),),
            ).fetchall()
            if len(_rows) > _PROGRESS_KEEP_TAIL:
                _keep = set()
                _keep.add(_rows[0][0])  # 起跑状态
                for _r in _rows[-_PROGRESS_KEEP_TAIL:]:  # 最近 N 条（细粒度尾迹）
                    _keep.add(_r[0])
                _buckets = set()
                for _r in _rows:  # 每 5 分钟 1 条（粗粒度骨架，防中段被裁光）
                    _bucket = str(_r[1])[:15]  # 'YYYY-MM-DDTHH:MM'
                    if _bucket not in _buckets:
                        _buckets.add(_bucket)
                        _keep.add(_r[0])
                _drop = [r[0] for r in _rows if r[0] not in _keep]
                if _drop:
                    for _i in range(0, len(_drop), 400):  # 分批，避开 SQLite 变量上限
                        db.execute(
                            "DELETE FROM scan_task_events WHERE id IN ({})".format(
                                ",".join("?" * len(_drop[_i:_i + 400]))
                            ),
                            _drop[_i:_i + 400],
                        )
                    logger.info("[post-persist] task %s progress 事件裁剪：%d → %d 条",
                                task_id, len(_rows), len(_keep))
        except Exception as _e:
            logger.warning("[post-persist] 事件保留策略执行失败（不阻断）：%s", _e)
        #    根因：sync_blackboard 原先只在 benchmark_cli 报告流程里跑（扫描内），那时 findings
        #    还没写入（findings 由本方法所在的收尾链路写），黑板因此只覆盖 spec 侧
        #    。放在这里后，
        #    黑板 valid_vh（findings ∪ specs）才能覆盖 findings 侧。
        #    并且：失败与不一致不再静默（原先 run_id=None 只 warning、整块 try/except 兜底），
        #    改为写 task_alert 事件（前端可见）+ ERROR 日志，并加「黑板行数 >= findings 去重 vhash 数」断言。
        try:
            from src.core import blackboard as _bb
            _rid = _bb.resolve_run_id(db, task_id)
            if _rid is None:
                _detail = "run_id 无法解析（scan_runs 无对应记录），黑板收口被跳过"
                logger.error("[post-persist] 黑板收口失败：%s", _detail)
                self._emit_event(task_id, "task_alert", {
                    "stage": "blackboard", "status": "blocked", "detail": _detail,
                })
            else:
                _bb.sync_blackboard(db, task_id, _rid)
                _counts = _bb.derive_counts(db, task_id, _rid)
                _bb_rows = int(_counts.get("blackboard_rows", 0) or 0)
                _row = db.execute(
                    "SELECT COUNT(DISTINCT vulnerability_hash_v2) AS n FROM findings WHERE task_id=? AND id NOT IN (SELECT finding_id FROM trigger_specs WHERE COALESCE(suppressed_by_safe_verdict, 0) = 1 AND finding_id > 0)",
                    (int(task_id),), fetchone=True,
                )
                _fv = int((list(_row.values())[0] if _row else 0) or 0)
                _chk = _bb.consistency_check(db, task_id, _rid)
                # 断言：黑板行数应不小于 findings 去重 vhash 数（直接暴露「收口早于落库」这类顺序缺陷）
                if _bb_rows < _fv:
                    _alert = (f"黑板行数({_bb_rows}) < findings 去重 vhash({_fv})："
                              "黑板未覆盖 findings 侧，收口时点或 sync 逻辑有缺陷")
                    logger.error("[post-persist] 黑板一致性断言未通过：%s", _alert)
                    self._emit_event(task_id, "task_alert", {
                        "stage": "blackboard", "status": "mismatch", "detail": _alert,
                        "blackboard_rows": _bb_rows, "findings_vhash": _fv,
                    })
                for _a in (_chk.get("alerts") or []):
                    self._emit_event(task_id, "task_alert", {
                        "stage": "blackboard", "status": "inconsistent", "detail": _a,
                    })
                logger.info(
                    "[post-persist] 黑板收口 task=%s run=%s 黑板行数=%s findings去重vhash=%s 自检告警=%s",
                    task_id, _rid, _bb_rows, _fv, len(_chk.get("alerts") or []),
                )
        except Exception as _e:
            logger.error("[post-persist] 黑板收口异常：%s", _e)
            try:
                self._emit_event(task_id, "task_alert", {
                    "stage": "blackboard", "status": "error", "detail": str(_e),
                })
            except Exception:
                pass
        _post_hoc_sink: int | None = None
        #    根因：benchmark_cli 在 reporting 阶段生成 iast_summary，而 findings 表由本类的
        #    _handle_runner_result 才落库 —— 生成时 findings 尚空，而 IastCorrelationService
        #    以 findings 为根做关联，于是 total_hypotheses 恒 0、各比率恒 0。
        #    实测 历史轮次 连续八轮 iast_summary.stats 全为零，属普遍性时序缺陷而非个别故障。
        #    修法：findings 落库后重算并回写 final_report.json，前端「运行时确认」才显示真实抵达数
        try:
            import json as _json
            from pathlib import Path as _Path

            from src.iast.correlation import IastCorrelationService
            _row = db.execute(
                "SELECT output_dir FROM scan_tasks WHERE id=?", (int(task_id),), fetchone=True
            )
            _out = (_row or {}).get("output_dir") or ""
            if _out:
                _cands = sorted(_Path(_out).glob("final_report_*.json"))
                if _cands:
                    _fp = _cands[-1]
                    _summary = IastCorrelationService(db).correlate(
                        workspace_id=workspace_id, task_id=int(task_id)
                    )
                    _data = _json.loads(_fp.read_text(encoding="utf-8"))
                    _data["iast_summary"] = _summary
                    _fp.write_text(
                        _json.dumps(_data, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                    _post_hoc_sink = int((_summary.get("stats") or {}).get("sink_reached_count") or 0)
                    logger.info(
                        "[post-persist] iast_summary 重算回写 task=%s 文件=%s 假说=%s sink抵达=%s",
                        task_id, _fp.name,
                        _summary.get("stats", {}).get("total_hypotheses"),
                        _summary.get("stats", {}).get("sink_reached_count"),
                    )
        except Exception as _e:
            logger.warning("[post-persist] iast_summary 重算失败（不阻断）：%s", _e)
        #    的 D1/D2 重放窗口正落在该停机+启动区间内 → 重放请求打不到被插桩的应用：
        #    运行期 iast_arrivals 32→1，且收尾重算的 sink 抵达也从 50 掉到 8。
        #    这类轮次的 D2 数字**不可用于对账与差分门禁**，必须显式告警，而不是静默产出低值。
        #    判据：运行期 D1 抵达数显著低于收尾后重算的 sink 抵达数（<60%）。
        try:
            import json as _json5
            if _post_hoc_sink is not None:
                _in_run = None
                _r5 = db.execute(
                    "SELECT summary_json FROM scan_tasks WHERE id=?", (int(task_id),), fetchone=True
                ) or {}
                _sj5 = _r5.get("summary_json") or {}
                if isinstance(_sj5, str):
                    try:
                        _sj5 = _json5.loads(_sj5)
                    except Exception:
                        _sj5 = {}
                _d1m = (((_sj5 or {}).get("results") or {}).get("d1")) or {}
                if isinstance(_d1m, dict):
                    _in_run = _d1m.get("iast_arrivals")
                if isinstance(_in_run, (int, float)) and _post_hoc_sink > 0 and _in_run < _post_hoc_sink * 0.6:
                    _msg5 = (
                        f"运行期 D1 抵达 {int(_in_run)} 条，但收尾后重算的 sink 抵达 {_post_hoc_sink} 条"
                        f"（不足 60%）：重放期靶场很可能不可达或被重启，"
                        f"本轮 D2 指标不可用于对账与差分门禁"
                    )
                    logger.error("[post-persist] D2 可信度守卫未通过：%s", _msg5)
                    self._emit_event(task_id, "task_alert", {
                        "stage": "d2_trust", "status": "suspect", "detail": _msg5,
                        "in_run_arrivals": int(_in_run), "post_hoc_sink_reached": _post_hoc_sink,
                    })
                else:
                    logger.info(
                        "[post-persist] D2 可信度守卫通过 task=%s 运行期抵达=%s 收尾重算抵达=%s",
                        task_id, _in_run, _post_hoc_sink,
                    )
        except Exception as _e:
            logger.warning("[post-persist] D2 可信度守卫异常（不阻断）：%s", _e)

    def _emit_event(self, task_id: int, event_type: str, payload: Dict):
        event = self.event_repository.add(TaskEvent(id=None, task_id=task_id, event_type=event_type, payload=payload))
        self.event_bus.publish(
            task_id,
            {
                "id": event.id,
                "task_id": task_id,
                "event_type": event.event_type,
                "payload": event.payload,
                "created_at": event.created_at,
            },
        )

    @staticmethod
    def _stage(label: str, status: str) -> Dict[str, Any]:
        return {
            "label": label,
            "status": status,
            "message": "",
            "metrics": {},
            "started_at": "",
            "finished_at": "",
        }

    def _build_initial_summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        enable_a1 = payload.get("enable_a1", True)
        enable_a2 = payload.get("enable_a2", True)
        enable_verification = payload.get("enable_verification", True)
        # results / stage_results 共享同一空 dict 引用，与 _merge_task_summary 的合并语义保持一致。
        _empty_results: Dict[str, Any] = {}
        return {
            "pipeline": {
                "preprocess": self._stage("输入与预处理", "pending"),
                "sca": self._stage("SCA 组件扫描", "pending" if payload.get("enable_sca", True) else "skipped"),
                "a1": self._stage("A1 规则扫描", "pending" if enable_a1 else "skipped"),
                "a2": self._stage("A2 语义分析", "pending" if enable_a2 else "skipped"),
                "entry_discovery": self._stage("AI 入口识别", "pending" if payload.get("enable_entry_discovery", True) else "skipped"),
                "ai_review": self._stage("AI 漏洞复核", "pending" if payload.get("enable_ai_review", True) else "skipped"),
                "attack_plan": self._stage("AP 攻击计划", "pending" if enable_a2 else "skipped"),
                # D1 的统一重放已并入 verify 链路（见 benchmark_cli 的 D1 指标聚合），
                # 执行门禁因此与 i1/d2/i2 一致：verify 开启即真实运行。占位状态若只看 enable_idor
                # 会被标成 skipped，导致前端在扫描前 2/3 显示「D1 跳过」而后端实际在重放
                "d1": self._stage("D1 操作器", "pending" if (enable_verification or payload.get("enable_idor", False)) else "skipped"),
                "i1": self._stage("I1 链路监听器", "pending" if (enable_verification or payload.get("enable_idor", False)) else "skipped"),
                "d2": self._stage("D2 验证/裁决器", "pending" if (enable_verification or payload.get("enable_idor", False)) else "skipped"),
                "i2": self._stage("I2 综合裁决器", "pending" if (enable_verification or payload.get("enable_idor", False)) else "skipped"),
                "reporting": self._stage("报告生成", "pending"),
            },
            "current_stage": "queued",
            "results": _empty_results,
            "stage_results": _empty_results,
            "reports": [],
            "finding_count": 0,
            "hitl": {
                "approval_mode": normalize_approval_mode(payload.get("approval_mode", DEFAULT_APPROVAL_MODE)),
                "tool_allowlist": list(payload.get("tool_allowlist") or []),
                "pending_actions": [],
                # M14：闸门策略留痕。对账时靠这一条判断「这轮 D2 有没有被闸门截断」，
                # 而不是去翻 19 条 approval_required 猜。
                "approval_policy": FULL_APPROVAL_POLICY,
                "approval_policy_note": "破坏性闸门测试期持续全批准，不可逆动作直接执行并记 allowed 审计",
            },
        }

    def _merge_task_summary(self, current: Dict[str, Any], payload: Dict[str, Any], options: Dict[str, Any], event_type: str) -> Dict[str, Any]:
        summary = dict(current or {})
        pipeline = dict(summary.get("pipeline") or self._build_initial_summary(options).get("pipeline", {}))
        now = datetime.utcnow().isoformat()

        incoming_pipeline = payload.get("pipeline") or {}
        for stage_name, stage_payload in incoming_pipeline.items():
            existing = dict(pipeline.get(stage_name) or self._stage(stage_name, "pending"))
            merged_stage = {**existing, **stage_payload}
            status = merged_stage.get("status", existing.get("status", "pending"))
            if status == "running" and not merged_stage.get("started_at"):
                merged_stage["started_at"] = now
            if status in {"completed", "failed", "skipped"} and not merged_stage.get("finished_at"):
                merged_stage["finished_at"] = now
            pipeline[stage_name] = merged_stage

        # 顺序门禁：前序阶段未完成则后序不得标 running/completed，改标 blocked（前端显示"未开始"）。
        # 注意：i1/I1 监听与 d1 重放并发、i2/I2 裁决与 d2 校验并发，二者不在顺序门禁内（见下方派生），
        # 它们的依赖由 d1/d2 真实状态派生，避免把"并发进行中"误判为 blocked。
        _STAGE_DEPS = {
            "a2": ["a1"],
            "d1": ["a2"],
            "d2": ["d1"],
            "i2": ["d2"],
            "reporting": ["i2"],
        }
        _STAGE_ORDER = ["preprocess", "sca", "a1", "a2", "entry_discovery", "ai_review", "attack_plan", "d1", "i1", "d2", "i2", "reporting"]
        for _sname, _deps in _STAGE_DEPS.items():
            _stage = pipeline.get(_sname)
            if not _stage:
                continue
            if _stage.get("status") in ("running", "completed"):
                for _dep in _deps:
                    _dep_status = (pipeline.get(_dep) or {}).get("status")
                    if _dep_status not in ("completed", "skipped"):
                        _stage["status"] = "blocked"
                        _stage["message"] = f"等待 {_dep} 完成"
                        break

        # /i1/I1 监听器伴随 D1 重放、i2/I2 裁决伴随 D2 校验，在统一链路里与 d1/d2 并发，
        # 不直接参与顺序门禁；依据 d1/d2 真实状态派生，使预声明的 i1/i2 阶段随进度推进而非卡在 pending。
        # 关键：i1/i2 必须全程跟随 d1/d2 的任何状态（pending/blocked/running/completed/failed/skipped），
        # 否则会出现"d1 还没开始，i1 已显示完成"的错乱。
        def _derive_concurrent_stage(pipeline, derived_key, driver_key):
            _drv = (pipeline.get(driver_key) or {}).get("status")
            _stage = pipeline.get(derived_key)
            if _stage is None or _drv is None:
                return
            _stage["status"] = _drv
            if _drv == "skipped":
                _stage.setdefault("message", f"{driver_key} 未启用")
            elif _drv == "blocked":
                _stage.setdefault("message", f"等待 {driver_key} 开始")
            elif _drv == "running":
                _stage.setdefault("started_at", now)
            elif _drv in ("completed", "failed"):
                _stage.setdefault("finished_at", now)

        _derive_concurrent_stage(pipeline, "i1", "d1")
        _derive_concurrent_stage(pipeline, "i2", "d2")

        if event_type == "task_started":
            preprocess = dict(pipeline.get("preprocess") or self._stage("输入与预处理", "pending"))
            preprocess["status"] = "running"
            preprocess["started_at"] = preprocess.get("started_at") or now
            preprocess["message"] = "任务已启动"
            pipeline["preprocess"] = preprocess

        if event_type == "task_failed":
            stage_name = payload.get("phase") or summary.get("current_stage") or "reporting"
            if stage_name == "failed":
                for candidate in ("reporting", "d2", "i2", "d1", "a2", "a1", "preprocess"):
                    if str((pipeline.get(candidate) or {}).get("status", "")) == "running":
                        stage_name = candidate
                        break
            stage = dict(pipeline.get(stage_name) or self._stage(stage_name, "pending"))
            stage["status"] = "failed"
            stage["finished_at"] = stage.get("finished_at") or now
            stage["message"] = payload.get("error_message", stage.get("message", ""))
            pipeline[stage_name] = stage
            summary["failed_stage"] = stage_name

        if event_type == "task_completed":
            reporting = dict(pipeline.get("reporting") or self._stage("报告生成", "pending"))
            reporting["status"] = "completed"
            reporting["finished_at"] = reporting.get("finished_at") or now
            reporting["message"] = "报告已生成"
            pipeline["reporting"] = reporting

        summary["pipeline"] = pipeline

        # 背景：benchmark_cli 早就把各阶段耗时算好并放进返回值（'phase_times': phase_times），
        # 但 _merge_task_summary 只挑 pipeline/stage_results 等键合并，**phase_times 被丢掉** ⇒
        # 剩下 46.9% 不知道花在哪」这个问题一直无解。
        # 本次只做「搬运」：不改任何阶段的行为、不影响任何判定，纯观测补齐。
        _pt = payload.get("phase_times")
        if isinstance(_pt, dict) and _pt:
            _prev_pt = dict(summary.get("phase_times") or {})
            _prev_pt.update({k: v for k, v in _pt.items() if isinstance(v, (int, float))})
            summary["phase_times"] = _prev_pt

        _first_unfinished = None
        for _s in _STAGE_ORDER:
            _st = (pipeline.get(_s) or {}).get("status")
            # ai_review 等阶段在部分流水线里被标为 "removed"（如 benchmark 路径）
            # 表示「该阶段不适用/已移除」，属已完成语义，不应算作「未完成」去顶替 current_stage。
            # 否则已完成任务会错误地把 current_stage 顶成 ai_review。
            if _st not in ("completed", "skipped", "removed"):
                _first_unfinished = _s
                break
        # 任务已跑完（所有阶段均为 completed/skipped/removed）时，current_stage 必须落到终态
        # "completed"，绝不能顶成某个被 removed 的阶段（如 ai_review）。旧逻辑最后兜底读的是旧
        # summary.current_stage（"ai_review"），导致已完成任务仍展示 ai_review。
        _all_done = all(
            (pipeline.get(_s) or {}).get("status") in ("completed", "skipped", "removed")
            for _s in _STAGE_ORDER
        )
        _terminal = "completed" if _all_done else "queued"
        summary["current_stage"] = (
            _first_unfinished
            or payload.get("current_stage")
            or summary.get("failed_stage")
            or payload.get("phase")
            or _terminal
        )
        # 键名统一（一处修全部）：payload 里的 stage_results 历史上被改名写进 summary["results"]，
        # 导致 summary.stage_results 在库中从未存在，前端所有读 stage_results.*
        # 的面板（A2 漏斗 / SCA / AP）恒为空。现双写同一 dict 对象：
        #   - "results"       保留，兼容既有读取方（reporting / 旧 task 数据 / 外部脚本）
        #   - "stage_results" 规范键名，前端新读法统一用它
        # 二者共享同一对象引用，不存在两份数据漂移的可能；DB 序列化会各写一份，属可接受的冗余换兼容。
        _merged_stage_results = {**dict(summary.get("results") or {}), **dict(payload.get("stage_results") or {})}
        summary["results"] = _merged_stage_results
        summary["stage_results"] = _merged_stage_results
        summary["reports"] = payload.get("reports") or summary.get("reports", [])
        if "hitl" in payload and isinstance(payload.get("hitl"), dict):
            summary["hitl"] = {
                **dict(summary.get("hitl") or {}),
                **dict(payload.get("hitl") or {}),
            }
        if "summary" in payload and isinstance(payload.get("summary"), dict):
            summary["final_report_summary"] = payload.get("summary", {})
        if "finding_count" in payload:
            summary["finding_count"] = payload.get("finding_count", summary.get("finding_count", 0))
        return summary
