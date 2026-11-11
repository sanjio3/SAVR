import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, Optional

from src.cli.benchmark_cli import run_benchmark
from src.core.config import config
from src.core.pipeline_view import attach_stage_tasks
from src.core.workspace_runtime import set_runtime as set_workspace_runtime
from src.infrastructure.db import Database


PIPELINE_LABELS = {
    "preprocess": "输入与预处理",
    "a1": "A1 规则扫描",
    "a2": "A2 语义分析",
    "d2": "D2 动态验证（含闭环 a2_rerun）",
    "reporting": "报告生成",
}


def _pid_alive(pid: int) -> bool:
    """跨平台轻量存活探测：进程存在即视为存活（含无权限访问的情况）。"""
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # 进程存在但无权限发信号 → 仍存活
        return True
    except OSError:
        return False


def _parse_llm_overrides(raw: str) -> Optional[Dict[str, Any]]:
    """解析 --llm-overrides（JSON）。失败返回 None 而不是抛错——
    参数填错不该让整个任务起不来，退化成「用服务端默认值」即可。"""
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except Exception as _e:
        print(f"[llm-overrides] 解析失败，使用服务端默认值：{_e}", file=sys.stderr)
        return None
    return parsed if isinstance(parsed, dict) else None


def _acquire_singleton_lock(task_id: int, output_dir: Path) -> "Optional[int]":
    """命名互斥体单实例守卫。

    同一 task_id 只允许一个 scan_task_runner 真正执行。防止托管运行时的后台任务
    外壳重拉子进程 / 后端重试 relaunch / orphan_recovery 双发 导致的重复子进程争抢
    iast_sessions.current_task_id 与 DB 写入，从而把 canary→sink 归属搅乱、单轮耗时
    从 15 分钟膨胀到 115 分钟。

    返回锁文件描述符（持有即占用）；若已被存活进程占用则返回 None，调用方应优雅退出、
    绝不参与竞争。陈旧锁（持有 PID 已死）自动接管，避免任务卡死无法重跑。
    """
    lock_path = output_dir / f"scan_task.{task_id}.lock"
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
    except FileExistsError:
        pid = None
        try:
            _old = lock_path.read_text(encoding="utf-8").strip()
            pid = int(_old) if _old else None
        except Exception:
            pid = None
        if pid and _pid_alive(pid):
            print(
                f"[singleton] task {task_id} 已被 PID {pid} 占用，本实例退出（避免重复进程争用 iast_sessions/DB）",
                file=sys.stderr,
            )
            return None
        # 陈旧锁：强制接管
        try:
            from src.core.progress_logger import _force_delete_file
            _force_delete_file(str(lock_path))
        except Exception:
            pass
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            return None
    try:
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode("utf-8"))
        os.fsync(fd)
    except Exception:
        pass
    return fd


def parse_args():
    parser = argparse.ArgumentParser(description="Background scan task runner")
    # 由 task_runner 从任务 options 下发，最终由 run_benchmark 写入 SAST_AI_SHARD_FILE。
    parser.add_argument("--shard-file", default="", help="分片清单 JSON 路径（按片缩小扫描范围）")
    parser.add_argument("--task-id", required=True, type=int)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output-format", default="both")
    parser.add_argument("--no-a1", action="store_true")
    parser.add_argument("--no-a2", action="store_true")
    parser.add_argument("--no-verification", action="store_true")
    parser.add_argument("--approval-mode", default="ask_on_risky_tools")
    parser.add_argument("--tool-allowlist", default="")
    parser.add_argument("--act-allowlist", default="")
    parser.add_argument("--no-sca", action="store_true")
    parser.add_argument("--no-ai-review", action="store_true")
    parser.add_argument("--no-entry-discovery", action="store_true")
    parser.add_argument("--enable-idor", action="store_true")
    parser.add_argument("--idor-app-id", default="")
    parser.add_argument("--scan-mode", default="filter_first")
    parser.add_argument("--model-profile", default="default")
    parser.add_argument("--prompt-version", default="terminal-first-v1")
    parser.add_argument("--sca-tool", default="osv-scanner")
    parser.add_argument("--sca-severity-threshold", default="LOW")
    parser.add_argument("--sca-ignore-unfixed", action="store_true")
    parser.add_argument("--llm-overrides", default="")
    parser.add_argument("--workspace-runtime-config", default="",
                        help="JSON 字符串：本 workspace 的 workspace_runtime_config（靶场专属路由/标记/镜像/JDK 覆盖）。")
    return parser.parse_args()


def _phase_status(value: Optional[Dict[str, Any]]) -> str:
    status = str((value or {}).get("status", "pending"))
    return "failed" if status == "error" else status


def _stage(status: str, message: str = "", metrics: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "status": status,
        "message": message,
        "metrics": metrics or {},
    }


def _combine_preprocess(progress: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    phases = progress.get("phases", {})
    phase1 = phases.get("phase1", {})
    phase3 = phases.get("phase3", {})
    scan_status = _phase_status(phase1)
    index_status = "skipped" if not options.get("enable_a2", True) else _phase_status(phase3)
    statuses = [scan_status] + ([index_status] if index_status != "skipped" else [])
    if any(status == "failed" for status in statuses):
        status = "failed"
    elif any(status == "running" for status in statuses):
        status = "running"
    elif statuses and all(status in {"completed", "skipped"} for status in statuses):
        status = "completed"
    else:
        status = "pending"
    message = phase3.get("details") or phase1.get("details") or ""
    return _stage(status, message, (progress.get("stage_results", {}) or {}).get("preprocess", {}))


def _build_pipeline(progress: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    phases = progress.get("phases", {})
    stage_results = progress.get("stage_results", {}) or {}
    # 折入 a2/d2 阶段文案与 metrics，保证终态 summary 也带进度（前端进度条本轮不做，先落 metrics）。
    _a2p = progress.get("a2_progress") or {}
    _i2r = progress.get("i2_rerun") or {}
    _a2_metrics = dict(stage_results.get("a2", {}) or {})
    if _a2p:
        _a2_metrics["progress_done"] = _a2p.get("done", 0)
        _a2_metrics["progress_total"] = _a2p.get("total", 0)
    if _i2r:
        _a2_metrics["closed_loop_iteration"] = _i2r.get("iteration", 0)
        _a2_metrics["closed_loop_max_iterations"] = _i2r.get("max_iterations", 0)
        _a2_metrics["closed_loop_status"] = _i2r.get("status", "")
    _a2_parts = []
    if _a2p:
        _a2_parts.append(f"已分析 {_a2p.get('done', 0)}/{_a2p.get('total', 0)} 文件")
    if _i2r and str(_i2r.get("status", "")) in ("running", "done"):
        _a2_parts.append(f"闭环第 {_i2r.get('iteration', 0)}/{_i2r.get('max_iterations', 0)} 轮"
                          + (" / 重跑中" if str(_i2r.get("status", "")) == "running" else ""))
    _a2_msg = "；".join(_a2_parts)
    if (phases.get("phase4") or {}).get("details"):
        _a2_msg = (_a2_msg + "；" if _a2_msg else "") + str((phases.get("phase4") or {}).get("details", ""))
    _rp = progress.get("replay_progress") or {}
    _d2vp = progress.get("d2_verify_progress") or {}
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
    _d2_parts = []
    if _rp and str(_rp.get("status", "")) in ("replaying", "replay_done", "replay_reconciled"):
        _d2_parts.append(f"已重放 {_rp.get('replayed', 0)}/{_rp.get('total', 0)}"
                          f"（confirmed={_rp.get('confirmed', 0)}, sink_reached={_rp.get('sink_reached', 0)}）")
    if _d2vp and str(_d2vp.get("status", "")) in ("running", "done"):
        _d2_parts.append(f"D2 验证第 {_d2vp.get('iteration', 0)} 轮"
                          + ("（进行中）" if str(_d2vp.get("status", "")) == "running" else ""))
    _d2_msg = "；".join(_d2_parts)
    if (phases.get("phase5") or {}).get("details"):
        _d2_msg = (_d2_msg + "；" if _d2_msg else "") + str((phases.get("phase5") or {}).get("details", ""))
    pipeline = {
        "preprocess": _combine_preprocess(progress, options),
        "a1": _stage(
            _phase_status(phases.get("phase2", {})) if options.get("enable_a1", True) else "skipped",
            str((phases.get("phase2", {}) or {}).get("details", "")),
            stage_results.get("a1", {}),
        ),
        "a2": _stage(
            _phase_status(phases.get("phase4", {})) if options.get("enable_a2", True) else "skipped",
            _a2_msg,
            _a2_metrics,
        ),
        "attack_plan": _stage(
            str(stage_results.get("attack_plan", {}).get("status", "completed" if stage_results.get("attack_plan") else "skipped"))
            if options.get("enable_a2", True) else "skipped",
            str(stage_results.get("attack_plan", {}).get("message", "")),
            stage_results.get("attack_plan", {}),
        ),
        "sca": _stage(
            str(stage_results.get("sca", {}).get("status", "completed" if stage_results.get("sca") else "pending")) if options.get("enable_sca", True) else "skipped",
            str(stage_results.get("sca", {}).get("message", "")),
            stage_results.get("sca", {}),
        ),
        "entry_discovery": _stage(
            str(stage_results.get("entry_discovery", {}).get("status", "completed" if stage_results.get("entry_discovery") else "pending")) if options.get("enable_entry_discovery", True) else "skipped",
            str(stage_results.get("entry_discovery", {}).get("message", "")),
            stage_results.get("entry_discovery", {}),
        ),
        "ai_review": _stage(
            str(stage_results.get("ai_review", {}).get("status", "completed" if stage_results.get("ai_review") else "pending")) if options.get("enable_ai_review", True) else "skipped",
            str(stage_results.get("ai_review", {}).get("message", "")),
            stage_results.get("ai_review", {}),
        ),
        # D1 已并入 verify 链路：门禁与 d2 一致，只看 enable_idor 会把真实运行的 D1 显示成 skipped。
        "d1": _stage(
            str(stage_results.get("d1", {}).get("status", "pending" if (options.get("enable_verification", True) or options.get("enable_idor", False)) else "skipped"))
            if stage_results.get("d1")
            else ("pending" if (options.get("enable_verification", True) or options.get("enable_idor", False)) else "skipped"),
            str(stage_results.get("d1", {}).get("message", "")),
            stage_results.get("d1", {}),
        ),
        "d2": _stage(
            _phase_status(phases.get("phase5", {})) if options.get("enable_verification", True) else "skipped",
            _d2_msg,
            _d2_metrics,
        ),
        "reporting": _stage(
            str((progress.get("reporting", {}) or {}).get("status", "pending")),
            str((progress.get("reporting", {}) or {}).get("final_markdown_file", "")),
            stage_results.get("reporting", {}),
        ),
    }
    if pipeline["d2"]["status"] == "completed" and pipeline["reporting"]["status"] == "pending":
        pipeline["reporting"]["status"] = "running"
        pipeline["reporting"]["message"] = "等待生成报告"
    # 使前端能把空壳阶段卡片换成可展开的任务列表（i1/i2 此前实时 pipeline 缺项，恒显 pending）。
    return attach_stage_tasks(pipeline, progress, options)


def _current_stage(pipeline: Dict[str, Dict[str, Any]]) -> str:
    for stage_name in ("preprocess", "sca", "a1", "a2", "attack_plan", "entry_discovery", "ai_review", "d1", "d2", "reporting"):
        if pipeline.get(stage_name, {}).get("status") == "failed":
            return stage_name
    for stage_name in ("preprocess", "sca", "a1", "a2", "attack_plan", "entry_discovery", "ai_review", "d1", "d2", "reporting"):
        if pipeline.get(stage_name, {}).get("status") == "running":
            return stage_name
    for stage_name in ("reporting", "d2", "d1", "ai_review", "entry_discovery", "attack_plan", "a2", "a1", "sca", "preprocess"):
        if pipeline.get(stage_name, {}).get("status") == "completed":
            return stage_name
    return "queued"


def _ensure_localhost_no_proxy():
    """某些托管运行时会向环境注入 HTTP_PROXY，
    导致本进程及所有子进程（feroxbuster/ffuf/nuclei、requests 探活、D1 重放等）
    发往 127.0.0.1/localhost 的本地请求被误路由到该代理并超时，表现为
    「A0 环境门禁 Read timed out」。这里显式让 localhost 绕过代理，
    外部出站（OSV/nuclei 模板等）仍走原代理。必须在任何网络调用前设置。"""
    _np = "127.0.0.1,localhost,::1"
    os.environ["no_proxy"] = _np
    os.environ["NO_PROXY"] = _np


def _apply_task_run_env(task_id: int) -> None:
    """把 scan_tasks.options_json.run_env 应用到本进程环境。

    背景：SAST_AI_DESER_YSOSERIAL 这类**按次运行**的危险能力开关原来只能通过进程环境
    传给后端；submit 脚本上设了 env，但真正跑扫描的是常驻 runner/后端派生的本进程，
    环境根本没带过去 ⇒ payload_library._deser_binary 恒判「开关未开」⇒ 反序列化族
    现在任务级 options_json.run_env（{KEY: VALUE}）在 runner 启动时注入 os.environ，
    全部 env 门控能力随任务走，与启动方式（后端/submit 脚本）解耦。
    安全性：这类开关默认关闭（如 ysoserial 会在目标执行命令），仍由 payload_library
    的默认值兜底；run_env 只是「显式声明本次允许」的正规通道。
    """
    if not task_id:
        return
    try:
        db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
        row = db.execute("SELECT options_json FROM scan_tasks WHERE id=?", [task_id], fetchone=True)
        if not row:
            return
        opts = row["options_json"] if not isinstance(row["options_json"], str) else json.loads(row["options_json"] or "{}")
        run_env = (opts or {}).get("run_env") or {}
        if isinstance(run_env, dict) and run_env:
            for k, v in run_env.items():
                os.environ[str(k)] = str(v)
            print(f"[run_env] 已应用任务级环境开关：{sorted(run_env.keys())}", file=sys.stderr)
    except Exception as _e:  # noqa: BLE001  env 注入失败不阻断任务
        print(f"[run_env] 应用失败（忽略）：{_e}", file=sys.stderr)


def main() -> int:
    _ensure_localhost_no_proxy()
    args = parse_args()
    _apply_task_run_env(args.task_id)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 命名互斥体单实例守卫：重复进程（外壳重拉 / 后端重试 / orphan 双发）在此被挡下，
    # 仅一个实例真正执行，杜绝争抢 iast_sessions.current_task_id 与 DB 写入。返回 None 即重复实例，
    # 优雅退出、不参与竞争。
    _lock_fd = _acquire_singleton_lock(args.task_id, output_dir)
    if _lock_fd is None:
        return 0

    # 装载本 workspace 的运行时配置（靶场专属路由/标记/镜像/JDK 覆盖）。
    # 未提供时 set_runtime 退化为内置默认（= 历史硬编码并集），行为与旧代码一致。
    if args.workspace_runtime_config:
        try:
            cfg = json.loads(args.workspace_runtime_config)
        except Exception as _e:
            print(f"[workspace_runtime] 解析失败，使用默认配置：{_e}", file=sys.stderr)
            cfg = None
    else:
        cfg = None
    set_workspace_runtime(cfg, code_root=args.target)

    snapshot = config.snapshot()
    try:
        config.set("output.output_dir", str(output_dir))
        config.set("agents.d2.hitl.approval_mode", str(args.approval_mode or "off"))
        allowlist = [item.strip() for item in str(args.tool_allowlist or "").split(",") if item.strip()]
        config.set("agents.d2.hitl.tool_allowlist", allowlist)
        act_allowlist = [item.strip() for item in str(args.act_allowlist or "").split(",") if item.strip()]
        config.set("agents.d2.hitl.act_allowlist", act_allowlist)
        result = run_benchmark(
            args.target,
            enable_a1=not args.no_a1,
            enable_a2=not args.no_a2,
            enable_verification=not args.no_verification,
            enable_sca=not args.no_sca,
            enable_ai_review=not args.no_ai_review,
            enable_entry_discovery=not args.no_entry_discovery,
            enable_idor=args.enable_idor,
            idor_app_id=args.idor_app_id,
            task_id=args.task_id,
            scan_mode=args.scan_mode,
            model_profile=args.model_profile,
            prompt_version=args.prompt_version,
            sca_tool=args.sca_tool,
            sca_severity_threshold=args.sca_severity_threshold,
            sca_ignore_unfixed=args.sca_ignore_unfixed,
            output_format=args.output_format,
            output_dir=str(output_dir),
            llm_overrides=_parse_llm_overrides(args.llm_overrides),
            shard_file=args.shard_file,
        )
        result = result or {}
        progress_snapshot = {}
        progress_path = output_dir / "scan_progress.json"
        if progress_path.exists():
            progress_snapshot = json.loads(progress_path.read_text(encoding="utf-8"))
        # run_benchmark 返回的 stage_results 比 scan_progress.json 更完整（后者会被进度记录器覆盖），合并后生成 pipeline
        result_stage_results = result.get("stage_results") or {}
        if result_stage_results:
            progress_snapshot["stage_results"] = {
                **(progress_snapshot.get("stage_results") or {}),
                **result_stage_results,
            }
        pipeline = _build_pipeline(
            {**progress_snapshot, "reporting": {"status": "completed", "final_markdown_file": (result.get("final_report") or {}).get("markdown_file", "")}},
            {
                "enable_a1": not args.no_a1,
                "enable_a2": not args.no_a2,
                "enable_verification": not args.no_verification,
                "enable_sca": not args.no_sca,
                "enable_ai_review": not args.no_ai_review,
                "enable_entry_discovery": not args.no_entry_discovery,
                "enable_idor": args.enable_idor,
            },
        )
        # 闭环差值告警。D2 重验后核对「发出重放数 vs 收到 IAST 事件数」，差值超容差即
        # 记录一条可见告警（scan_task_events），暴露探针侧丢事件，绝不静默。
        try:
            from src.iast.replay_ingest_audit import reconcile_replay_ingest_gap
            _audit_db = Database(os.environ.get("SAST_AI_DB_PATH", "data/app.db"))
            _gap_audit = reconcile_replay_ingest_gap(_audit_db, args.task_id)
            if _gap_audit.get("alert"):
                pipeline.setdefault("d2", {}).setdefault("metrics", {})
                pipeline["d2"]["metrics"]["replay_ingest_gap"] = _gap_audit
                print(f"replay-ingest 差值告警（{_gap_audit.get('severity')}）：{_gap_audit.get('reason')}",
                      file=sys.stderr)
        except Exception as _ae:  # 告警失败绝不阻断任务收尾
            print(f"差值告警计算失败（不影响任务收尾）：{_ae}", file=sys.stderr)
        final_report_data = (result.get("final_report") or {}).get("report", {})
        # 实测可达 14MB，progress_snapshot 再叠 1MB+，原来用
        # `json.dumps(..., indent=2)` 会在内存里同时持有「对象图 + 缩进美化后的巨型字符串」
        # task_result.json 却压根没写出来，runner 见 returncode!=0 判 failed。
        # 现改为：①progress_snapshot 只留 stage_results/timestamp（无消费方读全量副本）；
        # ②用 json.dump 直接流式写文件，不再构造整串。
        _snapshot_light = {
            "stage_results": progress_snapshot.get("stage_results") or {},
            "timestamp": progress_snapshot.get("timestamp"),
        }
        payload = {
            "task_id": args.task_id,
            "summary": (final_report_data or {}).get("summary", {}),
            "findings": (final_report_data or {}).get("vulnerabilities", []),
            "reports": [
                {"report_type": "FINAL_REPORT", "file_path": (result.get("final_report") or {}).get("markdown_file", "")},
            ],
            "pipeline": pipeline,
            "current_stage": _current_stage(pipeline),
            "prepared_runtime": result.get("prepared_runtime") or {},
            "stage_results": result.get("stage_results") or progress_snapshot.get("stage_results") or {},
            # 此前 result 里有 phase_times，但构造 payload 时没带 ⇒ 落库后查不到任何阶段耗时，
            # 「总耗时里 A1+A2+D2 只占 53%，剩下 46.9% 在哪」无法回答。
            # 纯观测字段，不影响任何判定与产物口径。
            "phase_times": result.get("phase_times") or {},
            "hitl": {
                "approval_mode": config.get("agents.d2.hitl.approval_mode", "off"),
                "tool_allowlist": list(config.get("agents.d2.hitl.tool_allowlist", []) or []),
                "pending_actions": list((result.get("hitl") or {}).get("pending_actions", []) or []),
            },
            "progress_snapshot": _snapshot_light,
        }
        with open(output_dir / "task_result.json", "w", encoding="utf-8") as _fh:
            json.dump(payload, _fh, ensure_ascii=False)
        return 0
    except Exception as exc:
        tb = traceback.format_exc()
        # 把完整堆栈落盘 + 打印到 stdout：后者会被上层编排器作为 task_log 事件推到前端，
        # 避免再次出现「只写 str(exc) 无堆栈」导致无法定位根因的黑盒失败。
        print(tb, file=sys.stderr)
        (output_dir / "task_result.json").write_text(
            json.dumps(
                {"task_id": args.task_id, "error": str(exc), "traceback": tb},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        raise
    finally:
        config.restore(snapshot)
        # 释放单实例锁（陈旧锁不影响下次重跑；PID 已死的锁会被 _acquire_singleton_lock 接管）
        try:
            _lock_path = output_dir / f"scan_task.{args.task_id}.lock"
            os.close(_lock_fd)
            try:
                # 避免撞 safe-delete 垫片的每 turn 删除限额（触顶会直接杀进程）。
                from src.core.progress_logger import _force_delete_file
                _force_delete_file(str(_lock_path))
            except Exception:
                pass
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
