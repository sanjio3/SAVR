import json
import logging
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set

from src.core.pipeline_view import attach_stage_tasks
from src.domain.models import ScanTask, Workspace

logger = logging.getLogger(__name__)

# 钉死扫描子进程的解释器：无论后端自身用哪个 python 启动（.venv 还是系统
# D:\Python），scan_task_runner 都必须跑在带项目依赖的 .venv 里，否则 A1/A2/
# D1/D2 阶段会因缺依赖而静默失败。用绝对路径钉死，不再依赖 sys.executable。
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENV_PY = os.path.join(_PROJECT_ROOT, ".venv", "Scripts", "python.exe")
if not os.path.exists(VENV_PY):
    VENV_PY = sys.executable  # 兜底：极端情况下退回当前解释器

# 单个扫描子进程的运行时上限（秒），0 表示不限。超时由 runner 主动终止并标记 failed，
# 避免 worker 悬挂让任务永久停在 running。可用 SAST_AI_MAX_SCAN_RUNTIME 覆盖。
#
# 2026-10-07：默认 6h -> 12h。r62 的 hash 分片实测跑满 6h 被强杀
# （"超过运行时上限 21600s"），产出是半成品：697 条 spec 的 D2 从未回写，
# 整片读数报废，还得重跑一遍几小时。全集分片（2740 用例，静态 + D2 + 本地 ollama）
# 在并发分摊下单片 6h 不够用，放宽到 12h；仍可用 SAST_AI_MAX_SCAN_RUNTIME 覆盖。
MAX_SCAN_RUNTIME_SECONDS = int(os.environ.get("SAST_AI_MAX_SCAN_RUNTIME", str(12 * 3600)))

# 同时跑的扫描任务数（= ThreadPoolExecutor 的 worker 数）。可用 SAST_AI_TASK_MAX_WORKERS 覆盖。
# 注意「进程数 ≠ 并发数」——venv 的 python.exe 是 launcher，会再拉真正的解释器，
# 所以一个扫描任务在系统里看到 **两个** python 进程；N 并发在 psutil 里就是 2N 个 pid。
# 曾据此误判并发数，特此留痕。
#
# 2026-10-08：默认 2 → **4**。依据（历史实测）：
#   - 耗时 96~98% 在 D2/D1，而 D2 是**I/O 等待型**（打 HTTP 到靶场 + 有界轮询等探针
#     异步 flush，窗口 12×1.0s），CPU 实测 0% ⇒ 并发提高能直接把等待重叠起来，收益高。
#   - 旧顾虑「4 并发抢 CPU + 单卡 ollama」本次不成立：r65 的 LLM 基本全命中缓存
#     （cmdi 平均 36ms / sqli 141ms，两片 LLM 总耗时仅 0.1min 与 1.6min），ollama 不是瓶颈。
# 若观察到资源争用（内存/CPU 打满或单片被拖慢），用 SAST_AI_TASK_MAX_WORKERS=2 即时回退，
# **无需改代码**。
_DEFAULT_TASK_MAX_WORKERS = int(os.environ.get("SAST_AI_TASK_MAX_WORKERS", "4"))

# 心跳卡死阈值（秒），0 表示不启用。扫描子进程存活但 scan_progress.json 超过该时长无更新，
# 判定卡死并强制终止（run 34 事故：D2 卡 66 分钟无终态、DB 仍 running，根因就是缺少心跳判死）。
# 阈值需远大于任何合法长阶段内部增量心跳间隔（A2/a2_poc 实测约 33 分钟仍逐文件写进度），
# 故默认 45 分钟是「真卡死」而非「慢」的下限。可用 SAST_AI_STUCK_HEARTBEAT 覆盖。
STUCK_HEARTBEAT_SECONDS = int(os.environ.get("SAST_AI_STUCK_HEARTBEAT", str(45 * 60)))

# 扫描子进程的 creationflags 候选（按优先级降级）。含义见 ScanTaskRunner._spawn_runner 注释：
#   0x01000000 CREATE_BREAKAWAY_FROM_JOB —— 脱离后端所在 Job，宿主清理/父进程退出都不再连带它
#   0x00000200 CREATE_NEW_PROCESS_GROUP  —— 独立进程组，便于按组终止
#   0x00000008 DETACHED_PROCESS          —— 不依附后端控制台（stdout 走 PIPE，不受影响）
# 不允许 breakaway 的 Job 下第一项会 ERROR_ACCESS_DENIED，_spawn_runner 会自动降级。
_RUNNER_CREATIONFLAGS = (0x01000000 | 0x00000200 | 0x00000008, 0x00000008)

# ---------------------------------------------------------------------------
# 在跑任务登记表（半截状态根治的配套件）
#
# 事故（run 24，2026-09-28）：扫描子进程 01:01 正常退出、task_result.json（19.9MB）
# 已落盘，但 scan_tasks 至今仍 running/d2、findings=0、reports=0。根因是
# ThreadPoolExecutor.submit() 会把 _run_task 内的异常**静默吞进 future**，既无日志
# 也无终态事件，任务就此永久卡在 running。
# 因此：① 这里登记「本进程正在跑的 task_id」，周期性 reconcile 据此跳过在跑任务，
# 不会与 watcher 抢写；② submit 挂 done_callback 把 future 里的异常显式打出来。
# ---------------------------------------------------------------------------
_IN_FLIGHT_LOCK = threading.Lock()
_IN_FLIGHT: Set[int] = set()


def in_flight_task_ids() -> Set[int]:
    """返回本进程当前仍在 watcher 中的 task_id 集合（供周期性 reconcile 排除）。"""
    with _IN_FLIGHT_LOCK:
        return set(_IN_FLIGHT)


# 每次进度事件都要落库的 SCA 明细字段：工具命令行与 stdout/stderr 体积最大（单轮可达数百 KB），
# 但前端只用 stage 状态与计数展示。2026-09-14 实测：856 条 task_progress 事件 × 平均 0.34 MB
# = 554 MB，是 app.db 存活数据的最大单项，根因就是每条事件把整份流水线快照（含 SCA 工具
# stderr）完整存了一遍。此处只裁剪「体量大且无展示用途」的字段，保留 status/finding_count 等。
_DROP_TOOL_RESULT_KEYS = ("stderr", "stdout", "command", "report_file", "output", "raw", "log")


def _slim_tool_result(node: Any) -> Any:
    """递归剥离 SCA 工具结果里的命令行/日志字段，其余原样返回（不改结构、不改键名）。"""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k in _DROP_TOOL_RESULT_KEYS:
                out[k] = "<trimmed>" if v else v
            else:
                out[k] = _slim_tool_result(v)
        return out
    if isinstance(node, list):
        return [_slim_tool_result(x) for x in node]
    return node


def _slim_stage_map(stage_map: Any) -> Any:
    """对 pipeline / stage_results 做两层瘦身（2026-09-14 SCA 层 + 2026-10-04 明细层）。

    第一层：sca.tool_result 只保留计数与状态（剥 stdout/stderr/command）。
    第二层：任何单字段序列化 > 4KB 就换成带 count/bytes 的占位（见下方 _MAX_FIELD_BYTES
    的实测依据）。两层都只动体积，不改键名语义、不碰标量与前端消费的计数键。
    """
    if not isinstance(stage_map, dict):
        return stage_map
    slimmed = {}
    for name, stage in stage_map.items():
        if not isinstance(stage, dict):
            slimmed[name] = stage
            continue
        stage2 = dict(stage)
        metrics = stage2.get("metrics")
        if isinstance(metrics, dict) and "tool_result" in metrics:
            metrics = dict(metrics)
            metrics["tool_result"] = _slim_tool_result(metrics["tool_result"])
            stage2["metrics"] = metrics
        if "tool_result" in stage2:
            stage2["tool_result"] = _slim_tool_result(stage2["tool_result"])
        # 第二层：明细数组/大对象按体积裁剪（状态、计数、by_family 一律保留）
        stage2 = _trim_bulk_fields(stage2)
        slimmed[name] = stage2
    return slimmed


# 单个字段序列化超过这个字节数就换成紧凑占位（2026-10-04 P0，事件表膨胀 9.02GB 的治本）。
# 背景：`_slim_tool_result` 只解决了 SCA 工具结果（2026-09-14 那轮，载荷降 94.6%），
# 而实测线上单条 progress 事件仍有 2.42MB，构成是明细数组：
#   stage_results.d2.verifications_detail  341.3KB / 421 条
#   stage_results.d2.scheduling            257.4KB（history 300 条）
#   stage_results.attack_plan.entries      427.3KB / 580 条
#   stage_results.d1.replayed_specs_detail 117.3KB / 391 条
#   pipeline（同样含上述 stage 的另一份副本） 1.19MB
# 这些明细前端一个都不消费（`frontend/src/domain/task-view.ts`、`pages/TaskDetailPage.vue`、
# `stores/workspaces.ts` 只读 status / message / 各类 count / by_family）。
#
# 为什么用「字节阈值」而不是「字段名白名单」：明细字段名会随阶段演进而增长
# （今天叫 verifications_detail，明天可能叫 xxx_detail），白名单必然漏。
# 阈值规则对**任何**新增的大字段自动生效，且用体积而不是名字判断，口径稳定。
# 4KB 的取值依据：实测明细条目 300–900B，by_family 这类要展示的小结构远小于 4KB，
# 阈值卡在两者之间不会误伤。
_MAX_FIELD_BYTES = 4096
# 裁剪后仍保留「有多少明细」——占位里带 count / bytes，前端与事后审计才有判据。
_TRIMMED_SUFFIX = "_trimmed"


def _trim_bulk_fields(stage: Dict[str, Any]) -> Dict[str, Any]:
    """把超大字段换成带 count/bytes 的占位；小字段与标量原样保留。"""
    out: Dict[str, Any] = {}
    for key, val in stage.items():
        if isinstance(val, (str, bytes)) and len(val) > _MAX_FIELD_BYTES:
            out[key] = {"count": 1, "bytes": len(val), "trimmed": True}
            continue
        if not isinstance(val, (dict, list, str, bytes)):
            out[key] = val  # 标量（状态、耗时、计数、开关）永远保留
            continue
        try:
            size = len(json.dumps(val, ensure_ascii=False, default=str).encode("utf-8"))
        except Exception:
            size = 0
        if size > _MAX_FIELD_BYTES:
            out[key + _TRIMMED_SUFFIX] = {
                "count": len(val) if isinstance(val, (list, dict)) else 1,
                "bytes": size,
                "trimmed": True,
            }
            # 体积最大的两类（明细数组）额外留一个「有多少条」的扁平计数，
            # 前端列表页常用它显示「421 条明细（已折叠）」。
            if isinstance(val, list):
                out.setdefault(key + "_count", len(val))
            continue
        out[key] = val
    return out


class ScanTaskRunner:
    def __init__(
        self,
        event_callback: Callable[[int, str, Dict[str, Any]], None],
        result_callback: Callable[[int, int, Dict[str, Any]], None],
        max_workers: int = _DEFAULT_TASK_MAX_WORKERS,
    ):
        self.event_callback = event_callback
        self.result_callback = result_callback
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        # 2026-10-04（取消能力）：任务一旦进 ThreadPoolExecutor 的 work_queue，就与 DB 行脱钩。
        # REST DELETE / TaskRepository.delete 只删库里的行，线程池照样在轮到时把它拉起来跑，
        # 于是出现「库里任务已消失、磁盘上却还在建 CodeQL 库」的僵尸扫描——实测 run 80 在被删
        # 之后仍空跑 30 分钟、占 97MB 并在抢CodeQL 槽位，真正要跑的下一任务却被饿着。
        # 这里登记 future 与子进程，让 cancel() 能停掉排队中的和正在跑的两种任务。
        self._lock = threading.RLock()
        self._futures: Dict[int, "Future"] = {}
        self._procs: Dict[int, subprocess.Popen] = {}
        self._cancelled: Set[int] = set()

    def submit(self, task: ScanTask, workspace: Workspace) -> None:
        tid = int(task.id)
        with _IN_FLIGHT_LOCK:
            _IN_FLIGHT.add(tid)
        with self._lock:
            # 同名/同 id 复用时先清掉上一次的取消标记，否则重提的任务会被当场判死。
            self._cancelled.discard(tid)

        future = self.executor.submit(self._run_task, task, workspace)
        with self._lock:
            self._futures[tid] = future

        def _on_done(fut: "Future") -> None:
            # ② 异常不再被 ThreadPoolExecutor 静默吞：显式打日志，让「线程死了但任务还在 running」
            # 这类事故第一次发生就能被看见（run 24 就是靠这条才定位到）。
            try:
                exc = fut.exception()
            except Exception as _ce:  # 取异常本身失败也要留下痕迹
                logger.error("[runner] task=%s 结果取回失败：%s", task.id, _ce)
                return
            if exc is not None:
                logger.exception("[runner] task=%s 的 watcher 线程异常终止：%s", task.id, exc)
            with self._lock:
                self._futures.pop(int(task.id), None)
                self._procs.pop(int(task.id), None)
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT.discard(int(task.id))

        future.add_done_callback(_on_done)

    def cancel(self, task_id: int) -> bool:
        """真正取消一个任务（2026-10-04 补齐）。

        覆盖两种情形：
        1. 还在线程池 work_queue 里没轮到 —— 尝试 future.cancel()，取消成功即不会再拉起子进程；
        2. 已经在跑 —— 终止扫描子进程树并回收，让槽位立刻腾给后面的任务。

        返回是否执行了取消动作（不保证子进程已死透，那由 _terminate_process 三段式负责）。
        """
        tid = int(task_id)
        with self._lock:
            self._cancelled.add(tid)
            fut = self._futures.get(tid)
            proc = self._procs.get(tid)

        queued_cancelled = False
        if fut is not None and not fut.running():
            try:
                queued_cancelled = bool(fut.cancel())
            except Exception as _ce:
                logger.warning("[runner] task=%s future.cancel 失败：%s", tid, _ce)

        if proc is not None:
            self._terminate_process(tid, proc, "任务被取消")

        with _IN_FLIGHT_LOCK:
            _IN_FLIGHT.discard(tid)
        try:
            self.event_callback(tid, "task_cancelled", {
                "phase": "cancelled",
                "message": "任务已被取消（排队中已移除/运行中已终止）"
                if queued_cancelled or proc is None else "任务已被取消（已终止扫描子进程）",
            })
        except Exception:
            pass
        logger.info("[runner] task=%s cancel 已执行（排队future取消=%s，子进程终止=%s）",
                    tid, queued_cancelled, proc is not None)
        return True

    def is_cancelled(self, task_id: int) -> bool:
        with self._lock:
            return int(task_id) in self._cancelled

    def _recover_payload_from_artifacts(self, output_dir: Path, task) -> Optional[Dict[str, Any]]:
        """假失败兜底（2026-10-22）：从磁盘产物重建 result payload。

        触发条件：子进程已产出 final_report_*.json/.md（=全部阶段真的跑完），但
        task_result.json 缺失且非超时终止。run 446 实测就是这种情况（19.7MB 报告齐全，
        仅 result 缺失）——被 returncode!=0 判 failed，污染对账。

        保守边界：①必须有 final_report 才算「跑完」；②超时终止不走本路径（那是真失败）；
        ③重建失败返回 None，仍按原逻辑判 failed。异常一律吞掉，绝不影响终态写入。
        """
        try:
            reports = sorted(output_dir.glob("final_report_*.json"))
            if not reports:
                return None
            report_path = reports[-1]
            report = json.loads(report_path.read_text(encoding="utf-8")) or {}
            md_path = report_path.with_suffix(".md")

            progress: Dict[str, Any] = {}
            progress_path = output_dir / "scan_progress.json"
            if progress_path.exists():
                try:
                    progress = json.loads(progress_path.read_text(encoding="utf-8")) or {}
                except Exception:
                    progress = {}

            options = dict(getattr(task, "options", {}) or {})
            pipeline = {}
            try:
                pipeline = self._build_pipeline(
                    {**progress, "reporting": {"status": "completed",
                                               "final_markdown_file": str(md_path) if md_path.exists() else ""}},
                    options,
                )
            except Exception:
                pipeline = {}

            return {
                "task_id": getattr(task, "id", None),
                "summary": report.get("summary", {}) or {},
                "findings": report.get("vulnerabilities", []) or [],
                "reports": [{"report_type": "FINAL_REPORT",
                             "file_path": str(md_path) if md_path.exists() else ""}],
                "pipeline": pipeline,
                "current_stage": "reporting",
                "prepared_runtime": {},
                "stage_results": progress.get("stage_results") or {},
                "hitl": {},
                "progress_snapshot": {
                    "stage_results": progress.get("stage_results") or {},
                    "timestamp": progress.get("timestamp"),
                },
            }
        except Exception as exc:  # noqa: BLE001
            try:
                logger.warning("[runner] 从产物重建 result 失败（仍按原逻辑判失败）：%s", exc)
            except Exception:
                pass
            return None

    def _terminate_process(self, task_id: int, process: subprocess.Popen, reason: str) -> None:
        """确保扫描子进程被真正回收（孤儿 worker 根治）。

        历史缺陷（task-8 事故）：失败分支直接写 task_failed，却从不终止子进程；runner 一旦
        被打断或后端重启，子进程继续写 scan_progress.json 并持续产生 IAST 事件——
        实测 14:00:25 已标记 failed，阶段却推进到深夜、iast_events 从 0 涨到 540。

        这里用 terminate → 等待 → kill 三段式收口；只回收扫描子进程树，不触碰靶场 Java
        进程（它们是独立进程、独立进程组）。任何一步异常都吞掉，绝不影响终态写入。
        """
        if process is None or process.poll() is not None:
            return
        try:
            self.event_callback(task_id, "task_log", {"message": f"[runner] 终止扫描子进程（{reason}）"})
        except Exception:
            pass
        try:
            process.terminate()
        except Exception:
            pass
        try:
            process.wait(timeout=15)
        except Exception:
            pass
        if process.poll() is None:
            try:
                process.kill()
            except Exception:
                pass
            try:
                process.wait(timeout=10)
            except Exception:
                pass

    def _spawn_runner(self, command):
        """拉起扫描子进程，**尽量让它脱离后端所在的 Job**。

        2026-10-04 实测三次「runner 无声消失」：run 100/102（20:46，连坐后端一起死）、
        run 106（启动后 8 秒）、run 107（reporting 中途）。三次都**没有崩溃栈、没有
        `[runner] 终止扫描子进程` 日志**，锁文件 PID 与进程枚举都确认子进程真的没了，
        内存压力已排除（复现期系统空闲 11–12GB）⇒ 指向「进程仍在后端的 Job 里，
        宿主侧清理时被连带杀掉」。

        `CREATE_BREAKAWAY_FROM_JOB` 让子进程脱离 Job，父进程退出或宿主清理都不再连带它。
        但该标志**要求父所在 Job 允许 breakaway**，不允许时 CreateProcess 直接
        ERROR_ACCESS_DENIED ⇒ 必须带降级：带标志失败就退回无标志再试一次，
        绝不能因为「想更安全」把任务直接堵死。
        """
        base = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace")
        for flags in _RUNNER_CREATIONFLAGS:
            try:
                return subprocess.Popen(command, creationflags=flags, **base)
            except OSError as exc:
                logger.warning("[runner] 以 creationflags=0x%X 拉起失败（%s），降级重试",
                               flags, exc)
        # 最后一招：不带任何标志（与历史行为完全一致）
        return subprocess.Popen(command, **base)

    def _run_task(self, task: ScanTask, workspace: Workspace) -> None:
        tid = int(task.id)
        # 2026-10-04：取消闸门一。任务还在队列里就被 cancel 掉时（删除/暂停），
        # 线程池 pop 出来后必须当场返回，绝不再起子进程。
        if self.is_cancelled(tid):
            logger.info("[runner] task=%s 开跑前已被取消，跳过", tid)
            try:
                self.event_callback(tid, "task_cancelled",
                                    {"phase": "cancelled", "message": "任务已被取消（未启动）"})
            except Exception:
                pass
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT.discard(tid)
            return
        output_dir = Path(task.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        command = [
            VENV_PY,
            "-m",
            "src.cli.scan_task_runner",
            "--task-id",
            str(task.id),
            "--target",
            workspace.target_path,
            "--output-dir",
            str(output_dir),
            "--output-format",
            task.options.get("output_format", "both"),
            "--approval-mode",
            str(task.options.get("approval_mode", "off")),
            "--tool-allowlist",
            ",".join(str(item) for item in (task.options.get("tool_allowlist") or [])),
            # 2026-09-24：把「经批准的动作类别」透传给扫描子进程，供闸门放行判定。
            "--act-allowlist",
            ",".join(str(item) for item in (task.options.get("act_allowlist") or [])),
        ]
        if not task.options.get("enable_a1", True):
            command.append("--no-a1")
        if not task.options.get("enable_a2", True):
            command.append("--no-a2")
        if not task.options.get("enable_verification", True):
            command.append("--no-verification")
        if not task.options.get("enable_sca", True):
            command.append("--no-sca")
        if not task.options.get("enable_ai_review", True):
            command.append("--no-ai-review")
        if not task.options.get("enable_entry_discovery", True):
            command.append("--no-entry-discovery")
        # 2026-10-03（分片作用域）：全集靶场按片扫描时，把分片清单路径下发给扫描子进程
        # （见 src/cli/benchmark_cli 的 SAST_AI_SHARD_FILE 消费点）。未配置则完全不影响原有命令。
        _shard_file = str(task.options.get("shard_file") or "").strip()
        if _shard_file:
            command.extend(["--shard-file", _shard_file])
        if task.options.get("enable_idor", False):
            command.append("--enable-idor")
            if task.options.get("idor_app_id"):
                command.extend(["--idor-app-id", str(task.options.get("idor_app_id"))])
        command.extend(["--scan-mode", str(task.options.get("scan_mode", "filter_first"))])
        command.extend(["--model-profile", str(task.options.get("model_profile", "default"))])
        command.extend(["--prompt-version", str(task.options.get("prompt_version", "terminal-first-v1"))])
        command.extend(["--sca-tool", str(task.options.get("sca_tool", "auto"))])
        command.extend(["--sca-severity-threshold", str(task.options.get("sca_severity_threshold", "LOW"))])
        # 任务级 LLM 扫描强度覆盖：只随本任务的命令行下发，不写全局配置，
        # 因此不会影响同时在跑的其它任务（项目是多任务并发的）。
        _llm_ov = task.options.get("llm_overrides")
        if isinstance(_llm_ov, dict) and _llm_ov:
            command.extend(["--llm-overrides", json.dumps(_llm_ov, ensure_ascii=False)])
        if task.options.get("sca_ignore_unfixed", False):
            command.append("--sca-ignore-unfixed")
        # 把本 workspace 的运行时配置（靶场专属路由/标记/镜像/JDK 覆盖）传给扫描子进程，
        # 由 scan_task_runner 装载为 workspace_runtime 单例（见 src/core/workspace_runtime.py）。
        runtime_cfg = (workspace.settings or {}).get("workspace_runtime_config")
        if runtime_cfg:
            command.extend(["--workspace-runtime-config", json.dumps(runtime_cfg, ensure_ascii=False)])

        self.event_callback(task.id, "task_started", {"phase": "starting"})
        process = self._spawn_runner(command)

        stdout_thread = threading.Thread(target=self._stream_logs, args=(task.id, process), daemon=True)
        stdout_thread.start()
        with self._lock:
            self._procs[tid] = process

        # 取消闸门二：起了子进程之后又被取消（竞态窗口），立刻终止并退出。
        if self.is_cancelled(tid):
            logger.info("[runner] task=%s 启动后收到取消，立即终止子进程", tid)
            self._terminate_process(tid, process, "任务被取消")
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT.discard(tid)
            return

        last_progress = None
        progress_path = output_dir / "scan_progress.json"
        _start_ts = time.time()
        _timed_out = False
        _terminate_reason = ""
        last_mtime = 0.0
        last_heartbeat = time.time()
        heartbeat_active = False
        while process.poll() is None:
            now = time.time()
            # 取消闸门三：运行中收到取消（最常见：用户在前端删除/暂停正在跑的任务）。
            # 没有这道闸门时，DB 状态会被 orchestrator 的 reconcile 覆盖回去，形成
            # 「删了又活」的观感。
            if self.is_cancelled(tid):
                _terminate_reason = "任务被取消"
                self._terminate_process(tid, process, _terminate_reason)
                break
            # 墙钟硬上限看门狗：超时主动终止并标记 failed，避免 worker 悬挂让任务永久停在 running
            # （task-8 曾跑满 12 小时仍未收口）。0 表示不启用。
            if MAX_SCAN_RUNTIME_SECONDS > 0 and (now - _start_ts) > MAX_SCAN_RUNTIME_SECONDS:
                _timed_out = True
                _terminate_reason = f"超过运行时上限 {MAX_SCAN_RUNTIME_SECONDS}s"
                self._terminate_process(task.id, process, _terminate_reason)
                break
            if progress_path.exists():
                try:
                    _mtime = progress_path.stat().st_mtime
                except Exception:
                    _mtime = 0.0
                if _mtime > last_mtime:
                    last_mtime = _mtime
                    last_heartbeat = now
                    heartbeat_active = True
                # 心跳卡死看门狗：子进程存活但 scan_progress.json 超过阈值无更新，判定卡死并终止。
                # 仅在该任务已开始写进度（heartbeat_active）后生效，避免启动早期未产文件被误杀；
                # 阈值（默认 45min）远大于任何合法长阶段内部增量心跳间隔，故只杀真卡死、不杀慢任务。
                if STUCK_HEARTBEAT_SECONDS > 0 and heartbeat_active and (now - last_heartbeat) > STUCK_HEARTBEAT_SECONDS:
                    _timed_out = True
                    _terminate_reason = f"无进度心跳超过 {STUCK_HEARTBEAT_SECONDS}s（疑似卡死）"
                    self._terminate_process(task.id, process, _terminate_reason)
                    break
                try:
                    progress = json.loads(progress_path.read_text(encoding="utf-8"))
                except Exception:
                    progress = None
                if progress and progress != last_progress:
                    last_progress = progress
                    pipeline = self._build_pipeline(progress, task.options)
                    # 2026-09-14 瘦身：去掉 progress 整份副本（前端只消费 pipeline / stage_results，
                    # 不消费 payload.progress），并裁掉 SCA 工具 stdout/stderr。事件体积因此
                    # 从平均 0.34 MB 降到数十 KB 量级，同时不影响前端契约（键名不变）。
                    self.event_callback(
                        task.id,
                        "task_progress",
                        {
                            "phase": self._extract_phase(pipeline),
                            "current_stage": self._extract_phase(pipeline),
                            "pipeline": _slim_stage_map(pipeline),
                            "stage_results": _slim_stage_map(progress.get("stage_results", {}) or {}),
                            "reports": progress.get("reports", []) or [],
                            "finding_count": progress.get("finding_count", 0) or 0,
                            "hitl": progress.get("hitl", {}) or {},
                        },
                    )
            time.sleep(1)

        stdout_thread.join(timeout=2)
        # 孤儿根治：无论成功 / 失败 / 超时，走到此处扫描子进程都不应再存活。
        # 缺失这一步时，runner 被打断后子进程会继续写进度并产生 IAST 事件（task-8 事故根因）。
        self._terminate_process(task.id, process, "流水线收尾")

        result_file = output_dir / "task_result.json"
        # 半截状态根治（run 24 事故）：从「子进程结束」到「终态事件落库」这一段里任何一步
        # 抛异常（19.9MB task_result.json 解析 / findings 落库 / DB 锁 / MemoryError），都会让
        # 任务永久停在 running —— 子进程没了、结果在盘上、DB 里 findings=0，前端还显示跑着。
        # 这里把整段收进 try，捕获后仍强制写 task_failed，保证「非终态」不可能残留。
        try:
            if process.returncode == 0 and result_file.exists():
                payload = json.loads(result_file.read_text(encoding="utf-8"))
                self.result_callback(task.id, workspace.id, payload)
                self.event_callback(
                    task.id,
                    "task_completed",
                    {
                        "phase": "completed",
                        "summary": payload.get("summary", {}),
                        "reports": payload.get("reports", []),
                        "finding_count": len(payload.get("findings", [])),
                        "pipeline": payload.get("pipeline", {}),
                        "current_stage": payload.get("current_stage", "reporting"),
                        "prepared_runtime": payload.get("prepared_runtime", {}),
                        "stage_results": payload.get("stage_results", {}),
                        "hitl": payload.get("hitl", {}),
                        # 2026-10-25（20.3.4 阶段耗时埋点）：把各阶段耗时透传给 service，
                        # 由 _merge_task_summary 落到 summary["phase_times"]。
                        # 此前 CLI 已算出 phase_times 但事件里没带 ⇒ 库中查不到任何阶段耗时。
                        "phase_times": payload.get("phase_times", {}),
                    },
                )
                return

            # 2026-10-22（假失败兜底）：子进程已把 final_report 落盘（=全部阶段真的跑完了），
            # 但 task_result.json 因内存尖峰 / 被硬杀而缺失时，returncode 非 0 会被判 failed。
            # run 446 实测：final_report 1.0MB + 19.7MB JSON 齐全、pipeline 全 completed，
            # 仅缺 task_result.json → 被标 failed，污染对账。这里从产物重建 payload 按已完成收口。
            if (not result_file.exists()) and (not _timed_out):
                _recovered = self._recover_payload_from_artifacts(output_dir, task)
                if _recovered is not None:
                    self.event_callback(task.id, "task_log", {
                        "message": (f"[runner] 子进程退出码 {process.returncode}，但 final_report 齐全、"
                                    f"pipeline 已完成 → 从产物重建结果按「已完成」收口（假失败兜底）"),
                    })
                    payload = _recovered
                    self.result_callback(task.id, workspace.id, payload)
                    self.event_callback(
                        task.id,
                        "task_completed",
                        {
                            "phase": "completed",
                            "summary": payload.get("summary", {}),
                            "reports": payload.get("reports", []),
                            "finding_count": len(payload.get("findings", [])),
                            "pipeline": payload.get("pipeline", {}),
                            "current_stage": payload.get("current_stage", "reporting"),
                            "prepared_runtime": payload.get("prepared_runtime", {}),
                            "stage_results": payload.get("stage_results", {}),
                            "hitl": payload.get("hitl", {}),
                            "phase_times": payload.get("phase_times", {}),
                            "recovered": True,
                        },
                    )
                    return

            if _timed_out:
                error_message = f"Scan task terminated: {_terminate_reason}（任务已强制终止）"
            else:
                error_message = f"Scan task exited with code {process.returncode}"
            traceback_text = None
            if result_file.exists():
                try:
                    payload = json.loads(result_file.read_text(encoding="utf-8"))
                    error_message = payload.get("error", error_message)
                    traceback_text = payload.get("traceback")
                except Exception:
                    pass
            self.event_callback(
                task.id,
                "task_failed",
                {"phase": "failed", "error_message": error_message, "traceback": traceback_text},
            )
        except Exception as _finalize_exc:
            logger.exception(
                "[runner] task=%s 收尾写入终态失败（子进程已退出，returncode=%s）：%s",
                task.id, process.returncode, _finalize_exc,
            )
            try:
                self.event_callback(
                    task.id,
                    "task_failed",
                    {
                        "phase": "failed",
                        "error_message": f"收尾写终态异常：{type(_finalize_exc).__name__}: {_finalize_exc}",
                        "traceback": None,
                    },
                )
            except Exception as _emit_exc:
                logger.error("[runner] task=%s 连 task_failed 都写不进去：%s", task.id, _emit_exc)
        finally:
            with _IN_FLIGHT_LOCK:
                _IN_FLIGHT.discard(int(task.id))

    def _stream_logs(self, task_id: int, process: subprocess.Popen) -> None:
        if process.stdout is None:
            return
        for line in process.stdout:
            text = line.rstrip()
            if text:
                self.event_callback(task_id, "task_log", {"message": text})

    @staticmethod
    def _build_pipeline(progress: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        phases = progress.get("phases", {}) or {}
        stage_results = progress.get("stage_results", {}) or {}

        def normalize(status: str) -> str:
            return "failed" if status == "error" else status

        def stage(status: str, message: str = "", metrics: Dict[str, Any] | None = None) -> Dict[str, Any]:
            return {"status": status, "message": message, "metrics": metrics or {}}

        phase1 = normalize(str((phases.get("phase1") or {}).get("status", "pending")))
        phase3 = "skipped" if not options.get("enable_a2", True) else normalize(str((phases.get("phase3") or {}).get("status", "pending")))
        preprocess_states = [phase1] + ([phase3] if phase3 != "skipped" else [])
        # #5 (2026-09-13)：把 D1/D2 重放增量心跳并入 D2 阶段文案，使前端在重放期间显示
        # 「已重放 N/M」「当前端点」「confirmed/sink 计数」，不再把长时间 running 误判为卡死。
        _rp = progress.get("replay_progress") or {}
        _rp_msg = ""
        if _rp:
            _rp_status = str(_rp.get("status", ""))
            # replay_reconciled（2026-09-16 新增）：迟到证据补捞升级后回写的纠正心跳。
            # 它覆盖了 scan_progress.json 里的 replay_done，若此处不认该状态，补捞后前端
            # 反而什么都不显示——必须和 replaying/replay_done 一并接受。
            if _rp_status in ("replaying", "replay_done", "replay_reconciled"):
                _rp_msg = f"已重放 {_rp.get('replayed', 0)}/{_rp.get('total', 0)}" \
                          f"（confirmed={_rp.get('confirmed', 0)}, sink_reached={_rp.get('sink_reached', 0)}）"
                if _rp_status == "replay_reconciled":
                    _rp_msg += " · 含迟到证据补捞"
                _cur = str(_rp.get("current_endpoint") or "")
                if _cur:
                    _rp_msg += f" · 当前 {_cur}"

        def _live_d1_status() -> str:
            """D1 阶段的**运行期**状态。

            2026-09-22 走查实证的缺陷：D1 与 D2 已并入同一条 verify 链路，``stage_results.d1``
            只在 D1 收尾时才写；运行期该键不存在，于是 D1 恒为 ``pending``。连锁后果有两个，
            都在 run 32 真实运行期被拍到：
              ① 前端「运行监控」在重放 189 条的同时把 D1 显示成「未开始」；
              ② 阶段依赖门禁见 D1 未完成，把**真的在跑**的 D2 改写成 ``blocked`` 并覆盖其文案为
                 「等待 d1 完成」——把「已重放 189/…（confirmed=…）」这条唯一的心跳抹掉，
                 同一屏上于是出现「运行中 · D2 校验器」与「D2 等待上游」并存。
            这与本函数上方 D1 门禁注释（"只看 enable_idor 会把真实运行的 D1 显示成 skipped，
            前端状态与后端事实不符"）是同一类问题，此处按同一原则收敛：运行期以**实时进度**为准，
            收尾后（``stage_results.d1`` 落盘）以其为最终真值。
            """
            _sr = str((stage_results.get("d1") or {}).get("status") or "")
            if _sr:
                return _sr
            if not (options.get("enable_verification", True) or options.get("enable_idor", False)):
                return "skipped"
            _rps = str(_rp.get("status", ""))
            if _rps in ("replay_done", "replay_reconciled"):
                return "completed"
            if _rps == "replaying":
                return "running"
            # 没有 replay 心跳但 verify 阶段已在跑：D1 至少已进入链路，不能显示成「未开始」
            if normalize(str((phases.get("phase5") or {}).get("status", "pending"))) in ("running", "completed"):
                return "running"
            return "pending"

        _d1_status = _live_d1_status()
        # 2026-09-16（待请示 6 项 #5）：A2 / a2_poc 长耗时阶段增量心跳并入阶段文案，
        # 使前端在 A2（本轮 33.4 分钟）/ a2_poc（33.9 分钟）期间能看到真实进度，不再误判卡死。
        _a2p = progress.get("a2_progress") or {}
        _a2_msg = ""
        if _a2p:
            _a2_msg = f"已分析 {_a2p.get('done', 0)}/{_a2p.get('total', 0)} 文件"
        _a2pp = progress.get("a2_poc_progress") or {}
        _a2_poc_msg = ""
        if _a2pp:
            _a2_poc_msg = f"PoC 规划 {_a2pp.get('done', 0)}/{_a2pp.get('total', 0)}"
        # 2026-09-16（#4② 待请示批准）：闭环重跑轮次 i2_rerun 折入 a2 阶段文案与 metrics，
        # 使前端在闭环期显示「闭环第 N 轮 / 重跑中」，闭合「运行状态须同步前端」铁律。
        _i2r = progress.get("i2_rerun") or {}
        _i2_msg = ""
        if _i2r:
            _i2_status = str(_i2r.get("status", ""))
            if _i2_status in ("running", "done"):
                _i2_msg = f"闭环第 {_i2r.get('iteration', 0)}/{_i2r.get('max_iterations', 0)} 轮"
                if _i2_status == "running":
                    _i2_msg += " / 重跑中"
        # 2026-09-16（#4② 待请示批准）：D2 验证迭代进度 d2_verify_progress 折入 d2 阶段文案与 metrics。
        _d2vp = progress.get("d2_verify_progress") or {}
        _d2vp_msg = ""
        if _d2vp:
            _d2vp_status = str(_d2vp.get("status", ""))
            if _d2vp_status in ("running", "done"):
                _d2vp_msg = f"D2 验证第 {_d2vp.get('iteration', 0)} 轮"
                if _d2vp_status == "running":
                    _d2vp_msg += "（进行中）"
        # 把进度指标并入各阶段 metrics（前端进度条本轮不做，先落 metrics 供下一轮渲染）。
        _a2_metrics = dict(stage_results.get("a2", {}) or {})
        if _a2p:
            _a2_metrics["progress_done"] = _a2p.get("done", 0)
            _a2_metrics["progress_total"] = _a2p.get("total", 0)
        if _i2r:
            _a2_metrics["closed_loop_iteration"] = _i2r.get("iteration", 0)
            _a2_metrics["closed_loop_max_iterations"] = _i2r.get("max_iterations", 0)
            _a2_metrics["closed_loop_status"] = _i2r.get("status", "")
        _a2_parts = [p for p in (_a2_msg, _i2_msg) if p]
        _a2_full_msg = "；".join(_a2_parts)
        if (phases.get("phase4") or {}).get("details"):
            _a2_full_msg = (_a2_full_msg + "；" if _a2_full_msg else "") + str((phases.get("phase4") or {}).get("details", ""))
        _d2_metrics = dict(stage_results.get("d2", {}) or {})
        if _rp:
            _d2_metrics["replay_total"] = _rp.get("total", 0)
            _d2_metrics["replay_replayed"] = _rp.get("replayed", 0)
            _d2_metrics["replay_confirmed"] = _rp.get("confirmed", 0)
            _d2_metrics["replay_sink_reached"] = _rp.get("sink_reached", 0)
        if _d2vp:
            _d2_metrics["d2_verify_iteration"] = _d2vp.get("iteration", 0)
            _d2_metrics["d2_verify_exploitable_count"] = _d2vp.get("exploitable_count", 0)
            _d2_metrics["d2_verify_status"] = _d2vp.get("status", "")
        # 重放心跳归还给 D1 行：D1 恢复成可显示「进行中」之后，把「已重放 N/M」留在 D2 会造成
        # 两行同时播报同一件事（001 走查已见到的「同屏矛盾」）。D1 说自己重放到哪，D2 说自己核验到哪。
        _d2_parts = [p for p in (_d2vp_msg,) if p]
        _d2_full_msg = "；".join(_d2_parts)
        if (phases.get("phase5") or {}).get("details"):
            _d2_full_msg = (_d2_full_msg + "；" if _d2_full_msg else "") + str((phases.get("phase5") or {}).get("details", ""))
        if any(status == "failed" for status in preprocess_states):
            preprocess_status = "failed"
        elif any(status == "running" for status in preprocess_states):
            preprocess_status = "running"
        elif preprocess_states and all(status in {"completed", "skipped"} for status in preprocess_states):
            preprocess_status = "completed"
        else:
            preprocess_status = "pending"

        # 2026-09-17（待请示批准）：挂「阶段 -> 具体任务清单」并补齐 i1/i2 并发阶段，
        # 使前端能把空壳阶段卡片换成可展开的任务列表。
        return attach_stage_tasks({
            "preprocess": stage(preprocess_status, str((phases.get("phase3") or {}).get("details", "") or (phases.get("phase1") or {}).get("details", "")), stage_results.get("preprocess", {})),
            "a1": stage(normalize(str((phases.get("phase2") or {}).get("status", "pending"))) if options.get("enable_a1", True) else "skipped", str((phases.get("phase2") or {}).get("details", "")), stage_results.get("a1", {})),
            "a2": stage(normalize(str((phases.get("phase4") or {}).get("status", "pending"))) if options.get("enable_a2", True) else "skipped", _a2_full_msg, _a2_metrics),
            "sca": stage(str(stage_results.get("sca", {}).get("status", "completed" if stage_results.get("sca") else "pending")) if options.get("enable_sca", True) else "skipped", str(stage_results.get("sca", {}).get("message", "")), stage_results.get("sca", {})),
            "entry_discovery": stage(str(stage_results.get("entry_discovery", {}).get("status", "completed" if stage_results.get("entry_discovery") else "pending")) if options.get("enable_entry_discovery", True) else "skipped", str(stage_results.get("entry_discovery", {}).get("message", "")), stage_results.get("entry_discovery", {})),
            "ai_review": stage(str(stage_results.get("ai_review", {}).get("status", "completed" if stage_results.get("ai_review") else "pending")) if options.get("enable_ai_review", True) else "skipped", str(stage_results.get("ai_review", {}).get("message", "")), stage_results.get("ai_review", {})),
            # AP 攻击计划：透明可视化层，介於 A2 与 D1 之间。与 sca/ai_review 同模式——直接读 stage_results
            # 状态（benchmark_cli 在阶段起止各写一次 status），不进顺序门禁（失败不影响后续阶段）。
            "attack_plan": stage(str(stage_results.get("attack_plan", {}).get("status", "completed" if stage_results.get("attack_plan") else "pending")) if options.get("enable_a2", True) else "skipped", str(stage_results.get("attack_plan", {}).get("message", "")), stage_results.get("attack_plan", {})),
            # D1 已并入 verify 链路：门禁与 d2 保持一致，只看 enable_idor 会把真实运行的
            # D1 显示成 skipped（前端状态与后端事实不符）。
            # 运行期文案用 replay 心跳；D1 收尾后 stage_results.d1 落盘，其 message 才是终态结论。
            "d1": stage(
                _d1_status,
                str((stage_results.get("d1") or {}).get("message") or "") or _rp_msg,
                stage_results.get("d1", {}),
            ),
            "d2": stage(normalize(str((phases.get("phase5") or {}).get("status", "pending"))) if options.get("enable_verification", True) else "skipped", _d2_full_msg, _d2_metrics),
            # 2026-09-16（待请示 6 项 #5）：a2_poc 提升为前端可见阶段。原只在 stage_results 出现，
            # 不在 pipeline 阶段列表，前端在 33.9 分钟里只能显示「进行中」。读 stage_results.a2_poc.status，
            # 与 sca/ai_review 同模式（不进顺序门禁，失败不影响后续阶段）。
            "a2_poc": stage(str(stage_results.get("a2_poc", {}).get("status", "completed" if stage_results.get("a2_poc") else "pending")) if options.get("enable_a2", True) else "skipped", (_a2_poc_msg + ("；" if _a2_poc_msg and stage_results.get("a2_poc", {}).get("message") else "") + str(stage_results.get("a2_poc", {}).get("message", ""))).strip(), stage_results.get("a2_poc", {})),
            "reporting": stage(str((progress.get("reporting") or {}).get("status", "pending")), str((progress.get("reporting") or {}).get("final_markdown_file", "")), stage_results.get("reporting", {})),
        }, progress, options)

    @staticmethod
    def _extract_phase(pipeline: Dict[str, Any]) -> str:
        for key in ("reporting", "d2", "d1", "ai_review", "entry_discovery", "a2_poc", "a2", "a1", "sca", "preprocess"):
            if (pipeline.get(key) or {}).get("status") == "failed":
                return key
        for key in ("preprocess", "sca", "a1", "a2", "a2_poc", "entry_discovery", "ai_review", "d1", "d2", "reporting"):
            if (pipeline.get(key) or {}).get("status") == "running":
                return key
        for key in ("reporting", "d2", "d1", "ai_review", "entry_discovery", "a2_poc", "a2", "a1", "sca", "preprocess"):
            if (pipeline.get(key) or {}).get("status") == "completed":
                return key
        return "running"
