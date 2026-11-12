"""孤儿扫描任务回收。

问题：``ScanTaskRunner._run_task`` 在子进程内跑 ``scan_task_runner``，子进程退出后由父进程
（service_server）的轮询线程检测 ``process.poll`` / ``task_result.json`` 并触发 ``task_completed``。
若后端在扫描中途重启，新后端没有该 task 的 watcher 线程，线程既不会读 ``scan_progress.json``
也不会检测退出，task 永久 ``running``，尽管 ``task_result.json`` 早已生成、findings/reports 始终为空。

本模块在后端启动时（或无头脚本中）对「status 非终态 且 output_dir/task_result.json 已落盘」的任务
执行等价回收：``_handle_runner_result`` + ``_handle_runner_event(task_completed)``。
仅当存在 ``task_result.json`` 才回收——该文件只在扫描结束时写入，故存在即表示子进程已结束。
对「仍 running 但无 task_result.json」的真·卡死（watcher 丢失且无结果）只告警、不自动改写状态。

后端活着的时候死的（future 异常被 ThreadPoolExecutor 静默吞），启动自检永远等不到下一次重启，
于是 task 永久 running/d2、findings=0。为此本模块新增：

- ``reconcile_running_tasks``：可在运行期反复调用的增量 reconcile，跳过本进程在跑的任务；
- ``start_periodic_reconciler``：后端启动后常驻的低频守护线程，周期性跑上面这个函数。

判据仍然保守：有结果文件 → 回收为 completed；无结果文件且确认该 task 的 scan_task_runner
子进程已不存在 → 判 failed（否则只告警，绝不自动改写）。
"""
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# 心跳卡死阈值（秒）：与 task_runner.STUCK_HEARTBEAT_SECONDS 同源，用于周期性 reconcile 时
# 判定「子进程存活但 scan_progress.json 长期无更新」的卡死任务并强杀。导入失败时回退默认值。
try:
    from src.infrastructure.task_runner import STUCK_HEARTBEAT_SECONDS
except Exception:
    STUCK_HEARTBEAT_SECONDS = 45 * 60

_TERMINAL_STATUSES = ("completed", "failed", "cancelled", "skipped")

# 周期性 reconcile 的间隔（秒），可用环境变量覆盖。
RECONCILE_INTERVAL_SECONDS = int(float(__import__("os").environ.get("SAST_AI_RECONCILE_INTERVAL", "60")))
# 「启动后多久才允许判死」的宽限（秒）：避免 runner 刚 submit、子进程还没起来时误判。
RECONCILE_GRACE_SECONDS = int(float(__import__("os").environ.get("SAST_AI_RECONCILE_GRACE", "300")))


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def _resolve_finished_at(result_file: Path, payload: Dict[str, Any]) -> Optional[str]:
    """推断任务的真实结束时刻，而不是「本次回收的时刻」。

    datetime.utcnow，finished_at 会偏移到回收时刻，前端「耗时 / 完成时间」展示失真。
    优先取报告自带的 generated_at；缺失时退回 task_result.json 的落盘 mtime ——
    该文件只在扫描结束时写入，故其 mtime 即真实结束时刻。
    """
    # 以 task_result.json 的落盘 mtime 为准：该文件只在扫描结束时写入，mtime 即真实结束时刻，
    # 且不依赖报告内时间字段的口径（项目内 generated_at 存在本地 / UTC 混用）。
    # 必须折算为 UTC：started_at 等既有时间戳是 UTC，若这里写本地时间，
    # finished_at(本地) − started_at(UTC) 会把 1h26m 的真实耗时放大成 9h26m。
    try:
        return datetime.fromtimestamp(
            result_file.stat().st_mtime, tz=timezone.utc
        ).replace(tzinfo=None).isoformat()
    except Exception:
        pass
    for key in ("generated_at", "finished_at", "completed_at"):
        val = payload.get(key)
        if val:
            return str(val)
    return None


def _completion_payload(payload: Dict[str, Any], result_file: Optional[Path] = None) -> Dict[str, Any]:
    """复制 task_runner 正常完成时的 task_completed 事件载荷形状。"""
    return {
        "phase": "completed",
        "summary": payload.get("summary", {}),
        "reports": payload.get("reports", []),
        "finding_count": len(payload.get("findings", []) or []),
        "pipeline": payload.get("pipeline", {}),
        "current_stage": payload.get("current_stage", "reporting"),
        "prepared_runtime": payload.get("prepared_runtime", {}),
        "stage_results": payload.get("stage_results", {}),
        "hitl": payload.get("hitl", {}),
        # 但回收路径此前漏了这一项 ⇒ 直接跑 runner（_wb_submit_local）时任务由本函数收尾，
        # 阶段耗时在 task_result.json 里有、落库后却是空。两路径必须同形。
        "phase_times": payload.get("phase_times", {}) or {},
        # 真实结束时刻。回收场景必须显式带上，否则 task_service 回退成 utcnow（= 回收时刻）。
        "finished_at": _resolve_finished_at(result_file, payload) if result_file else None,
    }


def reconcile_orphaned_tasks(task_service, task_repository, dry_run: bool = False) -> List[int]:
    """回收孤儿任务。返回被回收（或 dry-run 下拟回收）的 task id 列表。

    task_service / task_repository 由调用方通过 app container 注入，确保复用同一 DB 连接与
    同一套 repository 语义（与后端 watcher 完全一致）。
    """
    recovered: List[int] = []
    rows = task_repository.db.execute(
        "SELECT id, workspace_id, status, output_dir FROM scan_tasks "
        "WHERE status NOT IN ('completed','failed','cancelled','skipped')",
        fetchall=True,
    ) or []
    for r in rows:
        task_id = int(r["id"])
        workspace_id = r.get("workspace_id")
        output_dir = r.get("output_dir") or ""
        if not output_dir:
            continue
        result_file = Path(output_dir) / "task_result.json"
        if not result_file.exists():
            # 真·卡死：仍 running 但子进程结果未落盘（watcher 丢失且无产出）。
            # 不自动改状态，仅告警提示人工重跑，避免误标 completed 丢数据。
            logger.warning(
                "[orphan-recovery] task %s 处于 %s 但无 task_result.json，疑似 watcher 丢失且无结果；"
                "未自动回收，请检查后重跑扫描。", task_id, r.get("status")
            )
            continue
        payload = _read_json(result_file)
        if not payload or "findings" not in payload:
            logger.warning("[orphan-recovery] task %s 的 task_result.json 无效，跳过。", task_id)
            continue
        if dry_run:
            logger.info("[orphan-recovery][dry-run] 拟回收 task %s", task_id)
            recovered.append(task_id)
            continue
        try:
            task_service._handle_runner_result(task_id, workspace_id, payload)
            task_service._handle_runner_event(
                task_id, "task_completed", _completion_payload(payload, result_file)
            )
            recovered.append(task_id)
            logger.info("[orphan-recovery] 回收 task %s -> completed（findings=%d）",
                        task_id, len(payload.get("findings", []) or []))
        except Exception as exc:  # 单任务失败不影响其余
            logger.exception("[orphan-recovery] 回收 task %s 失败：%s", task_id, exc)
    return recovered


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def _live_scan_runner_task_ids() -> Optional[Set[int]]:
    """本机当前存活的 ``scan_task_runner --task-id N`` 的 task_id 集合。

    拿不到（psutil 缺失 / 权限不足 / 遍历异常）时返回 None —— 调用方必须当作「未知」，
    此时绝不判死，只告警。宁可漏判，不可误杀正在跑的扫描。
    """
    try:
        import psutil  # 项目依赖，后端进程内可用；缺失时由 except 兜住
    except Exception:
        return None
    ids: Set[int] = set()
    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmd = proc.info.get("cmdline") or []
            except Exception:
                continue
            joined = " ".join(str(x) for x in cmd)
            if "scan_task_runner" not in joined:
                continue
            for i, token in enumerate(cmd):
                if str(token) == "--task-id" and i + 1 < len(cmd):
                    try:
                        ids.add(int(cmd[i + 1]))
                    except (TypeError, ValueError):
                        pass
    except Exception as exc:
        logger.warning("[reconcile] 遍历 scan_task_runner 进程失败（按未知处理，不判死）：%s", exc)
        return None
    return ids


def _progress_stale_seconds(output_dir: str) -> Optional[float]:
    """返回某任务 scan_progress.json 距当前多少秒未更新；文件缺失/不可读返回 None。"""
    if not output_dir:
        return None
    p = Path(output_dir) / "scan_progress.json"
    try:
        if not p.exists():
            return None
        return time.time() - p.stat().st_mtime
    except Exception:
        return None


def _terminate_tree(proc) -> None:
    """终止进程及其子进程树（仅作用于 scan_task_runner 子树，不碰靶场 Java 进程）。"""
    try:
        children = proc.children(recursive=True)
    except Exception:
        children = []
    for child in children:
        try:
            child.terminate()
        except Exception:
            pass
    try:
        proc.terminate()
    except Exception:
        pass


def _kill_scan_runner(task_id: int) -> bool:
    """用 psutil 强杀 ``scan_task_runner --task-id N`` 的进程树（只杀该任务，不碰靶场 Java 进程）。"""
    try:
        import psutil
    except Exception:
        return False
    killed = False
    try:
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmd = proc.info.get("cmdline") or []
            except Exception:
                continue
            joined = " ".join(str(x) for x in cmd)
            if "scan_task_runner" not in joined:
                continue
            for i, tok in enumerate(cmd):
                if str(tok) == "--task-id" and i + 1 < len(cmd):
                    try:
                        if int(cmd[i + 1]) == task_id:
                            _terminate_tree(proc)
                            killed = True
                    except (TypeError, ValueError):
                        pass
    except Exception as exc:
        logger.warning("[reconcile] 遍历进程强杀 task %s 失败：%s", task_id, exc)
    return killed


def reconcile_running_tasks(
    task_service,
    task_repository,
    in_flight: Optional[Set[int]] = None,
    dry_run: bool = False,
) -> Dict[str, List[int]]:
    """运行期增量 reconcile：把「本进程没有 watcher 却仍非终态」的任务收口。

    与启动自检的区别：跳过 ``in_flight``（本进程 runner 正在跑的 task），因此可以安全地
    每分钟跑一次，不必等后端重启。

    两条判据，都保守：
      1. 有 task_result.json → 走与正常完成完全等价的回收（completed）；
      2. 无结果文件，但确认该 task 的 scan_task_runner 子进程已不在（且过了启动宽限）
         → 判 failed 并写明原因。psutil 不可用时只告警、不动状态。
    """
    outcome: Dict[str, List[int]] = {"completed": [], "failed": [], "warned": []}
    in_flight = set(in_flight or ())
    try:
        rows = task_repository.db.execute(
            "SELECT id, workspace_id, status, output_dir, started_at FROM scan_tasks "
            "WHERE status NOT IN ('completed','failed','cancelled','skipped')",
            fetchall=True,
        ) or []
    except Exception as exc:
        logger.warning("[reconcile] 查询非终态任务失败：%s", exc)
        return outcome

    pending_dead: List[int] = []
    for r in rows:
        task_id = int(r["id"])
        if task_id in in_flight:
            continue  # 本进程 watcher 正在跑，交给 runner 自己收尾
        output_dir = r.get("output_dir") or ""
        if not output_dir:
            continue
        result_file = Path(output_dir) / "task_result.json"
        if result_file.exists():
            payload = _read_json(result_file)
            if not payload or "findings" not in payload:
                logger.warning("[reconcile] task %s 的 task_result.json 无效，跳过。", task_id)
                continue
            if dry_run:
                outcome["completed"].append(task_id)
                continue
            try:
                task_service._handle_runner_result(task_id, r.get("workspace_id"), payload)
                task_service._handle_runner_event(
                    task_id, "task_completed", _completion_payload(payload, result_file)
                )
                outcome["completed"].append(task_id)
                logger.warning(
                    "[reconcile] task %s 无 watcher 但有结果文件，已回收为 completed（findings=%d）",
                    task_id, len(payload.get("findings", []) or []),
                )  # warning：后端日志过滤 INFO，回收动作必须留痕
            except Exception as exc:
                logger.exception("[reconcile] 回收 task %s 失败：%s", task_id, exc)
            continue
        pending_dead.append(task_id)

    if not pending_dead:
        return outcome

    # 判死前必须确认「子进程真的没了」。启动宽限内（默认 5 分钟）也不判，避免 runner 刚
    # submit、子进程尚未起来时误杀。
    now = datetime.utcnow()
    grace_ok: List[int] = []
    for task_id in pending_dead:
        started = None
        for r in rows:
            if int(r["id"]) == task_id:
                started = r.get("started_at")
                break
        try:
            if started:
                st = datetime.fromisoformat(str(started).replace("Z", ""))
                if (now - st).total_seconds() < RECONCILE_GRACE_SECONDS:
                    continue
        except Exception:
            pass
        grace_ok.append(task_id)

    if not grace_ok:
        return outcome

    live = _live_scan_runner_task_ids()
    if live is None:
        for task_id in grace_ok:
            outcome["warned"].append(task_id)
            logger.warning(
                "[reconcile] task %s 无 watcher、无结果文件；无法确认子进程存活状态，"
                "按保守策略不改写状态（请人工确认后重跑）。", task_id,
            )
        return outcome

    row_by_id = {int(r["id"]): r for r in rows}
    for task_id in grace_ok:
        if task_id in live:
            # 子进程还活着，但可能卡死（watcher 线程已死、子进程空转不写进度）。
            # 若其 scan_progress.json 超过心跳阈值无更新，判定卡死并强杀，避免永久 running。
            if STUCK_HEARTBEAT_SECONDS > 0:
                _od = (row_by_id.get(task_id) or {}).get("output_dir") or ""
                _stale = _progress_stale_seconds(_od)
                if _stale is not None and _stale > STUCK_HEARTBEAT_SECONDS:
                    if dry_run:
                        outcome["warned"].append(task_id)
                        logger.info("[reconcile][dry-run] 拟卡死强杀 task %s", task_id)
                        continue
                    killed = _kill_scan_runner(task_id)
                    outcome["failed"].append(task_id)
                    try:
                        task_service._handle_runner_event(
                            task_id,
                            "task_failed",
                            {
                                "phase": "failed",
                                "error_message": (
                                    "watcher 丢失且子进程存活但超过心跳阈值无进度（周期性 reconcile 强杀）："
                                    "请重跑扫描。"
                                ),
                                "traceback": None,
                            },
                        )
                        logger.warning(
                            "[reconcile] task %s 子进程存活但心跳卡死（stale=%.0fs，已强杀=%s），已判 failed。",
                            task_id, _stale, killed,
                        )
                    except Exception as exc:
                        logger.exception("[reconcile] 强杀/判死 task %s 失败：%s", task_id, exc)
                    continue
            continue  # 子进程还活着且进度新鲜，交给它的 watcher
        outcome["failed" if not dry_run else "warned"].append(task_id)
        if dry_run:
            logger.info("[reconcile][dry-run] 拟判死 task %s", task_id)
            continue
        try:
            task_service._handle_runner_event(
                task_id,
                "task_failed",
                {
                    "phase": "failed",
                    "error_message": (
                        "watcher 丢失且扫描子进程已不存在（周期性 reconcile 判定）："
                        "结果文件未生成，按失败收口，请重跑扫描。"
                    ),
                    "traceback": None,
                },
            )
            logger.warning("[reconcile] task %s 无 watcher、无结果文件且子进程已消失，已判 failed。", task_id)
        except Exception as exc:
            logger.exception("[reconcile] 判死 task %s 失败：%s", task_id, exc)
    return outcome


def start_periodic_reconciler(task_service, task_repository, interval: Optional[int] = None) -> Optional[threading.Thread]:
    """启动常驻 reconcile 守护线程（后端启动即调用一次即可，重复调用安全）。

    线程永不抛异常打断服务；每轮 reconcile 独立 try，单轮失败只告警。
    """
    global _RECONCILER_THREAD
    with _RECONCILER_LOCK:
        if _RECONCILER_THREAD is not None and _RECONCILER_THREAD.is_alive():
            return _RECONCILER_THREAD
        _gap = int(interval or RECONCILE_INTERVAL_SECONDS)

        def _loop() -> None:
            while True:
                try:
                    time.sleep(_gap)
                except Exception:
                    return
                try:
                    from src.infrastructure.task_runner import in_flight_task_ids
                    inflight = in_flight_task_ids()
                except Exception:
                    inflight = set()
                try:
                    res = reconcile_running_tasks(task_service, task_repository, inflight)
                    if res.get("completed") or res.get("failed"):
                        logger.warning("[reconcile] 本轮收口：completed=%s failed=%s",
                                       res.get("completed"), res.get("failed"))
                except Exception as exc:
                    logger.warning("[reconcile] 本轮 reconcile 异常（下一轮重试）：%s", exc)

        _RECONCILER_THREAD = threading.Thread(target=_loop, name="task-reconciler", daemon=True)
        _RECONCILER_THREAD.start()
        # 用 warning 而非 info：后端日志级别把项目 INFO 过滤掉了，而「reconciler 到底起没起」
        logger.warning("[reconcile] 周期性 reconcile 已启动，间隔 %ss", _gap)
        return _RECONCILER_THREAD


_RECONCILER_THREAD: Optional[threading.Thread] = None
_RECONCILER_LOCK = threading.Lock()
