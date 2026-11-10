# -*- coding: utf-8 -*-
"""单轮验证执行器：GPU 闸门等待 → 提交全量扫描 → 监控 → 四档对账 → 状态外置。

闸门规则（用户约定，不能只看 Ollama 有没有常驻模型）：同时看 nvidia-smi 空闲显存、
利用率和 /api/ps；要求空闲显存 >= --min-free-mib（默认 6200，覆盖 qwen3:8b 约
6215 MiB 峰值）、利用率 < --max-util-pct（默认 40；本机桌面 WDDM 常态 20-35%，
真正的 LLM 推理是 90%+）、且无常驻模型，连续 3 次采样都满足才提交。
任何一项不满足就继续等，不与别的项目抢卡。8 GiB 卡物理上留不出约 3 GiB 给对方，
这条限制已如实记在执行计划里，靠「无常驻模型 + 无别的计算任务」把关。

提交后立刻核对落库 options_json.run_env；为空说明服务端又把任务级环境开关丢了，
立即取消该任务并报错退出，绝不让一轮缺 run_env 的扫描跑完再发现。

用法（由编排层调用，也可单独跑一轮）：
    python tools/run_validation_round.py --name jsc-R0-redline-zero-20261106b \
        --env SAST_AI_DESER_YSOSERIAL=1 ...
    python tools/run_validation_round.py --name jsc-R1 --profile jsc   # 6 项展开
    python tools/run_validation_round.py --name probe --no-submit   # 只测闸门

--profile 从 config/run_profiles.yaml 纯展开 6 项 run_env（与 --env 互斥），
B 区调优值不注入；发车前跑探针握手 preflight，不 ready 直接拒绝发车。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)  # #545：`from tools import run_profiles` 在直接运行时可用
DB = os.path.join(ROOT, "data", "app.db")
RUNS = os.path.join(ROOT, "data", "validation_runs")
STATE = os.path.join(ROOT, "docs", "validation_run_state_20261106.md")


def project_python() -> str:
    """子进程一律用项目 .venv 解释器，避免四档口径静默降级。

    2026-11-08 本轮实测：发车用系统 Python 3.13（无 PyYAML），
    ``jsc_four_tier.py`` 的降级分支丢掉族名归一与「动态可重放族」判定，
    静态·文件+族 30/31→29/31、动态分母 24→31、重放 23/24→23/31，
    落盘四档与权威口径不一致。四档读数必须绑定装齐依赖的解释器。
    """
    for parts in ((".venv", "Scripts", "python.exe"), (".venv", "bin", "python")):
        cand = os.path.join(ROOT, *parts)
        if os.path.isfile(cand):
            return cand
    return sys.executable


PY = project_python()


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _log(msg: str) -> None:
    print("[%s] %s" % (_ts(), msg), flush=True)


def gpu_state() -> dict:
    out = subprocess.run(
        ["nvidia-smi", "--query-gpu=memory.used,memory.total,utilization.gpu",
         "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=15)
    parts = [p.strip() for p in (out.stdout or "").strip().splitlines()[0].split(",")]
    used, total, util = int(parts[0]), int(parts[1]), int(parts[2])
    return {"used_mib": used, "total_mib": total, "free_mib": total - used,
            "util_pct": util}


def ollama_models() -> list[str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:11434/api/ps", timeout=6) as resp:
        data = json.load(resp)
    return [str(m.get("name") or "") for m in (data.get("models") or [])]


def gate_check(min_free: int, max_util: int) -> tuple[bool, dict]:
    try:
        g = gpu_state()
        models = ollama_models()
    except Exception as exc:  # noqa: BLE001
        return False, {"error": str(exc)}
    g["models"] = models
    # 利用率阈值不能设成「桌面级」：本机 WDDM 桌面进程常态就有 20-35%，
    # 真正的 LLM 推理是 90%+。40% 用来区分「没有别的计算任务」，而不是要求 GPU 空闲。
    ok = g["free_mib"] >= min_free and g["util_pct"] < max_util and not models
    return ok, g


def wait_gate(min_free: int, max_util: int, max_minutes: int, poll: int) -> dict | None:
    deadline = time.time() + max_minutes * 60
    streak = 0
    while time.time() < deadline:
        ok, g = gate_check(min_free, max_util)
        _log("gate ok=%s free=%s MiB util=%s%% models=%s"
             % (ok, g.get("free_mib"), g.get("util_pct"), g.get("models") or g.get("error")))
        streak = streak + 1 if ok else 0
        if streak >= 3:
            return g
        time.sleep(poll)
    return None


def _db_ro():
    return sqlite3.connect("file:%s?mode=ro" % DB.replace("\\", "/"), uri=True)


def submit(name: str, ws: int, app: str, envs: list[str]) -> int:
    cmd = [PY, "scripts/submit_scan_task.py", "--name", name,
           "--workspace-id", str(ws), "--idor-app-id", app,
           "--no-sca", "--no-idor"]
    for kv in envs:
        cmd += ["--env", kv]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=90)
    _log("submit stdout: %s" % (out.stdout or "").strip()[-300:])
    if out.returncode != 0:
        raise RuntimeError("submit failed rc=%s stderr=%s" % (out.returncode, out.stderr[-500:]))
    m = re.search(r"created task_id=(\d+)", out.stdout or "")
    if not m:
        raise RuntimeError("no task_id in submit output")
    return int(m.group(1))


def cancel(task_id: int) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/scan-tasks/%d/cancel" % task_id, data=b"", method="POST")
    try:
        with opener.open(req, timeout=15) as resp:
            _log("cancelled task %d: %s" % (task_id, resp.read()[:120]))
    except Exception as exc:  # noqa: BLE001
        _log("cancel failed task %d: %s" % (task_id, exc))


def task_options(task_id: int) -> dict:
    con = _db_ro()
    row = con.execute("SELECT options_json FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
    con.close()
    return json.loads(row[0] or "{}") if row else {}


def task_status(task_id: int) -> str:
    con = _db_ro()
    row = con.execute("SELECT status FROM scan_tasks WHERE id=?", (task_id,)).fetchone()
    con.close()
    return str(row[0]) if row else "missing"


def monitor(task_id: int, timeout_minutes: int, poll: int) -> str:
    deadline = time.time() + timeout_minutes * 60
    last = ""
    while time.time() < deadline:
        st = task_status(task_id)
        if st != last:
            _log("task %d status=%s" % (task_id, st))
            last = st
        if st in ("completed", "failed", "cancelled"):
            return st
        time.sleep(poll)
    return "timeout"


def four_tier(task_id: int, name: str, truth: str = "") -> str:
    """四档对账。jsc 走默认真值表；L2/RuoYi 必须显式传 --truth，
    否则会把 jsc 的 31 点真值套到 RuoYi 结果上，四档数字全无意义。"""
    cmd = [PY, "tools/jsc_four_tier.py", "--task-id", str(task_id)]
    if truth:
        cmd += ["--truth", truth]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=180)
    os.makedirs(RUNS, exist_ok=True)
    path = os.path.join(RUNS, "%s.four_tier.txt" % name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out.stdout or "")
        if out.stderr:
            fh.write("\n[stderr]\n" + out.stderr)
    # 缺依赖 / 真值表不存在 / 数据库异常时四档脚本会 exit != 0，此时 stdout 要么是
    # 降级读数要么是空串。旧实现忽略 returncode，会把错误读数当正式产物落盘。
    if out.returncode != 0:
        raise RuntimeError("four-tier failed rc=%s, see %s: %s" %
                           (out.returncode, path,
                            (out.stderr or out.stdout or "")[-500:]))
    redline = [ln.strip() for ln in (out.stdout or "").splitlines() if "红线口径" in ln]
    _log("four-tier: %s" % (redline[0] if redline else "no redline line"))
    return path


def append_state(line: str) -> None:
    try:
        with open(STATE, "a", encoding="utf-8") as fh:
            fh.write("\n- %s %s\n" % (_ts(), line))
    except OSError as exc:
        _log("state append failed: %s" % exc)


def run_probe_preflight(profile: dict | None, ws: int, *,
                        app_name: str = "", agent_id: str = "",
                        do_http: bool = True) -> dict:
    """发车前握手。返回脱敏报告；ready=False 时调用方必须停止发车。"""
    from tools import probe_preflight as pp

    if profile:
        probe = profile.get("probe") or {}
        app_name = app_name or str(probe.get("app_name") or "")
        agent_id = agent_id or str(probe.get("agent_id") or "")
    # 未显式给三元组时按 workspace 枚举全部会话，要求至少一个对齐且在线。
    # 不猜 token、不凭空造会话行。
    return pp.preflight_workspace(ws, app_name=app_name, agent_id=agent_id,
                                  do_http=do_http, require_online=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--workspace-id", type=int, default=None,
                    help="不传时取 profile 的 workspace_id，无 profile 则回落 4")
    ap.add_argument("--idor-app-id", default="")
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("--profile", default="",
                    help="从 config/run_profiles.yaml 纯展开 6 项 run_env；与 --env 互斥")
    ap.add_argument("--probe-app-name", default="")
    ap.add_argument("--probe-agent-id", default="")
    ap.add_argument("--no-probe-http", action="store_true",
                    help="preflight 只做本地 DB 体检，不发后端鉴权空批次")
    ap.add_argument("--no-probe-preflight", action="store_true",
                    help="显式豁免发车前探针握手（结果里留痕，仅供离线自检）")
    # qwen3:8b Q4_K_M 峰值约 6.07 GiB（6215 MiB）；8 GiB 卡物理上留不出 3 GiB
    # 余量，故用「覆盖模型峰值 + 无常驻模型 + 无别的计算任务」三条同时把关。
    ap.add_argument("--min-free-mib", type=int, default=6200)
    ap.add_argument("--max-util-pct", type=int, default=40)
    ap.add_argument("--gate-wait-minutes", type=int, default=60)
    ap.add_argument("--task-timeout-minutes", type=int, default=120)
    ap.add_argument("--poll-sec", type=int, default=30)
    ap.add_argument("--truth", default="",
                    help="四档对账真值表；jsc 留空用默认，L2/RuoYi 必须传 data/ruoyi_451_truth.csv")
    ap.add_argument("--no-submit", action="store_true", help="只测闸门，不提交任何任务")
    args = ap.parse_args()

    # ---- profile 纯展开（不推断、不合并） ----
    profile = None
    expanded: list[str] = []
    if args.profile:
        from tools import run_profiles as rp
        try:
            profile = rp.load_profile(args.profile)
            expanded = rp.expand_run_env(profile, args.name)
            for drift in rp.check_tuning_drift(profile):
                _log("[profile][WARN] tuning drift: %s" % drift)
        except rp.ProfileError as exc:
            _log("[profile][FATAL] %s" % exc)
            return 5
        if args.env:
            _log("[profile][FATAL] --profile 与 --env 互斥（禁止合并/覆盖），"
                 "请二选一：要么用 profile 的 6 项，要么显式逐项 --env")
            return 5
        if args.workspace_id is not None and args.workspace_id != int(profile["workspace_id"]):
            _log("[profile][FATAL] --workspace-id=%s 与 profile %r 的 workspace_id=%s 冲突"
                 % (args.workspace_id, args.profile, profile["workspace_id"]))
            return 5
        min_free, max_util = rp.gpu_args(profile)
        min_free = min_free if min_free is not None else args.min_free_mib
        max_util = max_util if max_util is not None else args.max_util_pct
        truth = args.truth or str(profile.get("truth") or "")
        ws = int(profile["workspace_id"])
        _log("[profile] %r 展开 6 项 run_env（来源 %s）：%s"
             % (args.profile, profile["_source"], sorted(k.split("=", 1)[0] for k in expanded)))
    else:
        expanded = list(args.env)
        min_free, max_util = args.min_free_mib, args.max_util_pct
        truth = args.truth
        ws = args.workspace_id if args.workspace_id is not None else 4
    idor_app = args.idor_app_id or ("workspace-%d" % ws)

    # ---- 发车前探针握手，fail-closed ----
    preflight_report = None
    if not args.no_submit and not args.no_probe_preflight:
        preflight_report = run_probe_preflight(
            profile, ws, app_name=args.probe_app_name,
            agent_id=args.probe_agent_id, do_http=not args.no_probe_http)
        if not preflight_report.get("ready"):
            _log("[probe-preflight][FATAL] 发车前握手未通过，拒绝提交任务：")
            for reason in preflight_report.get("reasons") or []:
                _log("  - %s" % reason)
            for sub in preflight_report.get("sessions") or []:
                if not sub.get("ready"):
                    _log("  - %s/%s: %s" % (sub.get("app_name"), sub.get("agent_id"),
                                            "; ".join(sub.get("reasons") or [])))
            append_state("[%s] 发车前探针握手未通过，未提交任务" % args.name)
            return 6
        _log("[probe-preflight] READY: %s" % json.dumps(
            preflight_report.get("ready_sessions") or [preflight_report.get("token")],
            ensure_ascii=False))
    elif args.no_probe_preflight and not args.no_submit:
        _log("[probe-preflight][EXEMPT] 显式豁免发车前握手，结果留痕")

    _log("round=%s interpreter=%s gate: free>=%d MiB, util<%d%%, no resident models, 3 consecutive samples"
         % (args.name, PY, min_free, max_util))
    gate = wait_gate(min_free, max_util,
                     args.gate_wait_minutes, args.poll_sec)
    if gate is None:
        _log("GATE TIMEOUT after %d min, no task submitted" % args.gate_wait_minutes)
        append_state("[%s] 闸门等待超时，未提交（对方仍占用 GPU）" % args.name)
        return 3
    _log("GATE PASSED: %s" % json.dumps(gate, ensure_ascii=False))
    if args.no_submit:
        _log("--no-submit，结束")
        return 0

    task_id = submit(args.name, ws, idor_app, expanded)
    _log("submitted task_id=%d" % task_id)
    append_state("[%s] 闸门通过并提交 task_id=%d，提交前显存 %s" %
                 (args.name, task_id, json.dumps(gate, ensure_ascii=False)))

    opts = task_options(task_id)
    if not opts.get("run_env"):
        cancel(task_id)
        _log("FATAL: options_json.run_env 为空，已取消 task %d" % task_id)
        append_state("[%s] task_id=%d 已取消：run_env 未落库" % (args.name, task_id))
        return 4
    _log("run_env ok: %s" % sorted(opts["run_env"].keys()))
    if args.profile:
        # 纯展开必须逐项落库，键集合与基线 6 项严格一致（含 STAGE_CACHE=0）。
        from tools import run_profiles as rp
        want = set(rp.BASELINE_RUN_ENV_KEYS)
        got = set(opts["run_env"])
        if got != want:
            cancel(task_id)
            _log("[profile][FATAL] 落库 run_env 与基线 6 项不一致，已取消 task %d：缺少=%s 多出=%s"
                 % (task_id, sorted(want - got), sorted(got - want)))
            return 4
        if str(opts["run_env"].get("SAST_AI_STAGE_CACHE")) != "0":
            cancel(task_id)
            _log("[profile][FATAL] SAST_AI_STAGE_CACHE 落库非 0，已取消 task %d" % task_id)
            return 4

    status = monitor(task_id, args.task_timeout_minutes, args.poll_sec)
    _log("final status=%s" % status)
    result = {"name": args.name, "task_id": task_id, "status": status,
              "gate": gate, "run_env": opts.get("run_env"),
              "workspace_id": ws, "finished_at": _ts()}
    if args.profile:
        result["profile_name"] = args.profile
        result["profile_source"] = profile["_source"]
        # 只落键与值的哈希前缀，不落 Shiro key 等敏感明文
        result["expanded_run_env"] = [
            {"key": kv.split("=", 1)[0], "value_sha256_prefix":
             __import__("hashlib").sha256(kv.split("=", 1)[1].encode()).hexdigest()[:12]}
            for kv in expanded]
    if preflight_report is not None:
        result["probe_preflight"] = preflight_report
    elif args.no_probe_preflight:
        result["probe_preflight"] = {"exempt": True, "reason": "--no-probe-preflight"}
    if status == "completed":
        result["four_tier_path"] = four_tier(task_id, args.name, truth)
        if truth:
            result["truth"] = truth
    os.makedirs(RUNS, exist_ok=True)
    jpath = os.path.join(RUNS, "%s.json" % args.name)
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    append_state("[%s] task_id=%d 终态=%s，结果 %s" %
                 (args.name, task_id, status, jpath))
    _log("result written: %s" % jpath)
    return 0 if status == "completed" else 2


if __name__ == "__main__":
    sys.exit(main())
