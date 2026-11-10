"""r88 串行批次下发器：幂等、可断点续跑、显式排除 ab-mix。

为什么不用 tools/owasp_run_shards.py --submit 直接下发
----------------------------------------------------------
1. index.json 的 shards 列表有 18 项，其中 **ab-mix 是独立对照分片**（204 例，用例
   与其余 17 片重叠）。submit_batch.cmd 不带 --shards 时会连它一起交，全集读数变成
   2944 例，Reconcile 重复计数。这里写死 17 片。
2. 原生 --submit 不检查「本片是否已经提交过」。批次被 Ctrl+C 后重跑会把已完成的分片
   再跑一遍（同名任务重复创建），本脚本跳过已存在的片。
3. 后端的 TaskRunner 是 ThreadPoolExecutor(max_workers=SAST_AI_TASK_MAX_WORKERS，
   默认 4)。一旦一次性把 17 片提交进去，就会 4 片并发跑：D2 运行窗重叠，空 canary 的
   collateral sink 事件会被时间窗错归到后启动的那片（r79 实证 312 的 0 事件根因）。
   所以必须由下发器端做「真串行」：一片终态 + 排空 drain 秒后才交下一片。

用法（由 tools/run_r88.cmd 调用，也可手敲）
------------------------------------------
    .venv/Scripts/python.exe tools/submit_r88_serial.py --run-tag r88 --wave all
    .venv/Scripts/python.exe tools/submit_r88_serial.py --run-tag r88 --wave signal
    .venv/Scripts/python.exe tools/submit_r88_serial.py --run-tag r88 --dry-run

Ctrl+C 之后重跑同一条命令即可：已提交/已完成的片自动跳过，从断点继续。
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sqlite3
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import importlib.util as _ilu

_ORS_PATH = os.path.join(HERE, "tools", "owasp_run_shards.py")
_spec = _ilu.spec_from_file_location("_ors", _ORS_PATH)
_ORS = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_ORS)

SHARDS_DIR = _ORS.SHARDS
DB = _ORS.DB
TERMINAL = _ORS.TERMINAL

# ---- 17 片全集（ab-mix 不在内；它是对照片，与其他片用例重叠） ----
# 顺序是刻意排的：前 6 片是 dataflow 通道（与已验收的 xss 同源），跑完约 2 小时就能
# 先拿到「跨族泛化是否成立」的核心读数，不必等整批。
WAVE_SIGNAL = [
    "sqli-1", "cmdi-1", "pathtraver-1", "ldapi", "xpathi", "trustbound",
]
WAVE_ALGO = [
    "crypto", "hash", "weakrand-1", "securecookie",
]
WAVE_REST = [
    "cmdi-2", "pathtraver-2", "sqli-2", "sqli-3", "weakrand-2", "xss-1", "xss-2",
]
WAVES = {
    "signal": WAVE_SIGNAL,
    "algo": WAVE_ALGO,
    "rest": WAVE_REST,
    "all": WAVE_SIGNAL + WAVE_ALGO + WAVE_REST,
}


def _log(msg: str, fh=None) -> None:
    stamp = _dt.datetime.now().strftime("%H:%M:%S")
    line = f"[r88 {stamp}] {msg}"
    print(line, flush=True)
    if fh:
        fh.write(line + "\n")
        fh.flush()


def _existing(con, task_name: str):
    return con.execute(
        "SELECT id, status, phase FROM scan_tasks WHERE name = ? ORDER BY id DESC LIMIT 1",
        (task_name,)).fetchone()


def _wait_terminal(con, task_name: str, tid: int, max_wait: float, log) -> str:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        row = con.execute(
            "SELECT status, phase FROM scan_tasks WHERE id = ?", (tid,)).fetchone()
        if row and row[0] in TERMINAL:
            return row[0]
        time.sleep(15)
    log(f"  [WAIT] {task_name} 超过 {int(max_wait)}s 仍未终态，放弃等待继续下一片")
    return "timeout"


def _submit_one(name: str, run_tag: str, log) -> int:
    shard_file = os.path.join(SHARDS_DIR, f"{name}.json")
    if not os.path.isfile(shard_file):
        log(f"  [SKIP] {name}: 分片清单不存在 {shard_file}")
        return 1
    cmd = [
        sys.executable, os.path.join(HERE, "scripts", "submit_scan_task.py"),
        "--name", f"shard-{name}-{run_tag}",
        "--workspace-id", str(_ORS.FULL_WORKSPACE_ID),
        "--idor-app-id", _ORS._idor_app_id(),
        "--no-sca", "--no-idor",
        "--shard", os.path.abspath(shard_file),
    ]
    if not _ORS._verify_on():
        cmd.append("--no-verification")
    proc = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)
    tail = ((proc.stdout or "").strip().splitlines() or ["(no output)"])[-1]
    log(f"  exit={proc.returncode} {tail.strip()[:160]}")
    return proc.returncode


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-tag", default="r88")
    ap.add_argument("--wave", choices=sorted(WAVES), default="all")
    ap.add_argument("--shards", default="",
                    help="自定义分片清单（逗号分隔），给出时覆盖 --wave；"
                         "用于断点续跑：把当前正在跑的片放首位，下发器会先等它终态再串行后续")
    ap.add_argument("--drain", type=float, default=300.0,
                    help="每片终态后排空秒数，等探针把迟到事件 flush 完")
    ap.add_argument("--max-wait", type=float, default=7200.0,
                    help="单片等终态的最长秒数")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.shards.strip():
        names = [s.strip() for s in args.shards.split(",") if s.strip()]
    else:
        names = WAVES[args.wave]
    mode = "STATIC + D2 动态验证" if _ORS._verify_on() else "STATIC ONLY"
    log_path = os.path.join(HERE, "tools", f"{args.run_tag}_submit.log")
    fh = open(log_path, "a", encoding="utf-8", errors="replace")

    def log(m):
        _log(m, fh)

    log("=" * 64)
    log(f"run-tag={args.run_tag} wave={args.wave} ({len(names)} 片) mode={mode}")
    log(f"target app_id={_ORS._idor_app_id()} drain={int(args.drain)}s")

    if not args.dry_run and _ORS._verify_on():
        _ORS.preflight_verify()

    con = sqlite3.connect(DB, timeout=20)
    t_start = time.time()
    done_n, skip_n, fail_n = 0, 0, 0
    try:
        for idx, name in enumerate(names, 1):
            task_name = f"shard-{name}-{args.run_tag}"
            row = _existing(con, task_name)
            if row:
                tid, status, phase = row
                log(f"[{idx}/{len(names)}] {name:<14} 已存在 task={tid} status={status} phase={phase}")
                if status in TERMINAL:
                    skip_n += 1
                    continue
                if args.dry_run:
                    skip_n += 1
                    continue
                st = _wait_terminal(con, task_name, tid, args.max_wait, log)
                if st in TERMINAL:
                    done_n += 1
                    log(f"  [DRAIN] {name} 终态({st})，排空 {int(args.drain)}s")
                    time.sleep(args.drain)
                continue

            est = ""
            if idx > 1:
                per = (time.time() - t_start) / max(done_n, 1)
                left = per * (len(names) - idx + 1)
                est = f" 剩余估算 {left/3600:.1f}h"
            log(f"[{idx}/{len(names)}] {name:<14} {'[dry-run] ' if args.dry_run else ''}提交中...{est}")
            if args.dry_run:
                continue
            rc = _submit_one(name, args.run_tag, log)
            if rc != 0:
                fail_n += 1
                log(f"  [FAIL] {name} 提交返回 {rc}，继续下一片")
                continue
            time.sleep(5)
            row = _existing(con, task_name)
            if not row:
                fail_n += 1
                log(f"  [FAIL] {name} 提交后查不到任务")
                continue
            st = _wait_terminal(con, task_name, row[0], args.max_wait, log)
            if st in TERMINAL:
                done_n += 1
                log(f"  [DRAIN] {name} 终态({st})，排空 {int(args.drain)}s")
                time.sleep(args.drain)

        total = time.time() - t_start
        log(f"完成：跑完 {done_n} / 跳过已有 {skip_n} / 失败 {fail_n}，耗时 {total/3600:.1f}h")
        log("=" * 64)
    finally:
        con.close()
        fh.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
