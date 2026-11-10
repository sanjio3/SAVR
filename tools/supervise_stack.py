#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""栈常驻守护：拉起后端 + 前端，并在它们掉线时自动重启，自身**永不主动退出**。

背景（2026-10-05 两轮实测）
---------------------------
- 把服务挂在会话后台任务里：会话一旦退出，8000/5200 连带在跑的任务一起终止。
- 想让子进程"脱离"也不行：本环境后台任务一结束，它派生的子进程（带
  DETACHED_PROCESS / CREATE_NEW_PROCESS_GROUP 都一样）会被系统回收
  （psutil 查 NoSuchProcess，裸 socket ConnectionRefused）。
- 所以本脚本走**两级保活**：服务进程由本脚本 spawn；本脚本自己常驻不退，
  盯住服务进程，掉了就重新 spawn。只要本脚本进程活着，服务就在。
- 若要脱离会话托管（推荐），用 tools/install_stack_task.cmd 装成 Windows 计划任务
  （系统托管，任何会话死了都不影响）。本脚本只是过渡方案。

用法
----
    python tools/supervise_stack.py               # 常驻守护（推荐前台跑，Ctrl+C 停）
    python tools/supervise_stack.py --once        # 只拉起一次就开始盯（与上面等价，别名）
    python tools/supervise_stack.py --no-wait     # 拉起后立即返回（配合外部 cron/计划任务）
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.request

#项目根从本文件位置反推（tools/ 的上一级），不写死盘符。
# 为什么要反推：本脚本会被 Windows 计划任务（tools/install_stack_task.cmd）
# 在系统层拉起，那时 CWD 不保证是项目根；写死路径换机器/换目录就失效。
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENV_PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")


def _find_node() -> str:
    """定位 node：优先项目内，其次 PATH 上能找到的 managed 运行时。

    写死版本号会在 managed 运行时升级后失效，故做一次候选探测。
    """
    override = os.environ.get("SASTAI_NODE")
    if override and os.path.isfile(override):
        return override
    base = os.path.expanduser(
        r"~\.workbuddy\binaries\node\versions")
    if os.path.isdir(base):
        cands = sorted(
            (os.path.join(base, d, "node.exe") for d in os.listdir(base)),
            reverse=True)
        for c in cands:
            if os.path.isfile(c):
                return c
    found = shutil.which("node")
    if found:
        return found
    raise SystemExit("[supervise] 找不到 node：请设环境变量 SASTAI_NODE 指向 node.exe")


NODE = _find_node()

ENV = dict(os.environ)
ENV["NO_PROXY"] = "127.0.0.1,localhost"
ENV["no_proxy"] = "127.0.0.1,localhost"
# 2026-10-28：**不要禁用周期 reconcile**。它是「runner 写完 task_result.json → 标记任务
# completed + 回填 findings」的收口者；禁掉后任务会永远 pending、findings=0（本轮/491/492
# 实测）。此前怀疑它卡死，真凶其实是 async 端点同步写库堵住事件循环（已在 agent_bridge 修）。
ENV.setdefault("SAST_AI_RECONCILE_INTERVAL", "60")

SERVICES = {
    "backend": {
        "label": "后端 API 8000",
        "cmd": [VENV_PY, "-m", "src.cli.service_server"],
        "cwd": ROOT,
        "log": os.path.join(ROOT, "stack-backend.log"),
    },
    "frontend": {
        "label": "前端 vite 5200",
        "cmd": [NODE, os.path.join(ROOT, "frontend", "node_modules", "vite", "bin", "vite.js"),
                "--host", "--port", "5200"],
        "cwd": os.path.join(ROOT, "frontend"),
        "log": os.path.join(ROOT, "stack-frontend.log"),
    },
}

RESTART_LIMIT = 20  # 同一服务连续重启上限，防死循环刷日志

# 2026-10-27 修：后端最常见的退化形态是「进程活着、端口在听、HTTP 请求全超时」
# （线程死锁/单线程被占）。此时 p.poll() 仍是 None，旧逻辑永远不会重启它，
# 表现为「后端一挂就是几小时」。改为：连续 N 次健康检查失败即强制重启。
HEALTH_URLS = {
    # 用不碰 DB 的 /ping：db 层全局锁在扫描期会被长期占用，走 DB 的 /health 会排队超时，
    # 导致 supervisor 误杀正在干活的 backend（本轮/486/488 实测）。
    "backend": "http://127.0.0.1:8000/api/system/ping",
}
HEALTH_FAIL_LIMIT = int(os.environ.get("SAST_AI_SUPERVISE_HEALTH_FAILS", "24"))
HEALTH_TIMEOUT = float(os.environ.get("SAST_AI_SUPERVISE_HEALTH_TIMEOUT", "10"))


def _health_ok(url: str, timeout: float) -> bool:
    # 2026-10-28：绕过系统代理。本机 HTTP_PROXY=127.0.0.1:15512，后端启动中代理会返回
    # 502「upstream connect failed」，被当成健康检查失败 → 反复强杀正在启动的后端。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as resp:
            return 200 <= resp.status < 400
    except Exception:
        return False


def _spawn(key: str, starts: dict):
    d = SERVICES[key]
    logf = open(d["log"], "a", buffering=1, encoding="utf-8", errors="replace")
    logf.write(f"[{time.strftime('%H:%M:%S')}] supervise: 拉起 {d['label']}\n")
    logf.flush()
    p = subprocess.Popen(d["cmd"], cwd=d["cwd"], env=ENV,
                         stdin=subprocess.DEVNULL,
                         stdout=logf, stderr=subprocess.STDOUT)
    logf.close()
    starts[key] = starts.get(key, 0) + 1
    print(f"[supervise] {d['label']} pid={p.pid}", flush=True)
    return p


def _shutdown(procs: dict) -> None:
    """停掉所有子进程，让「关窗口 = 真的全停」。

    不这样做的话 Ctrl+C 只退守护本身，后端/前端/runner 会变悬空留在后台，
    既占端口又可能和新拉起的实例打架。TERM/INT 两种信号都要接，
    因为双击 cmd 窗口的关闭按钮走的是 TERM 而不是 INT。
    """
    for key, p in list(procs.items()):
        if p.poll() is not None:
            continue
        label = SERVICES[key]["label"]
        print(f"[supervise] 停止 {label} (pid={p.pid})", flush=True)
        try:
            p.terminate()
        except Exception:
            continue
    deadline = time.time() + 10
    for key, p in list(procs.items()):
        if p.poll() is not None:
            continue
        try:
            p.wait(timeout=max(0.5, deadline - time.time()))
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    print("[supervise] 全部子进程已停止", flush=True)


def _install_signal_handlers() -> None:
    def handler(signum, frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handler)
        except Exception:
            pass  # 非主线程或平台不支持时忽略


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-wait", action="store_true", help="拉起后立即返回（不常驻）")
    args = ap.parse_args()

    procs: dict[str, subprocess.Popen] = {}
    starts: dict[str, int] = {}
    for key in SERVICES:
        procs[key] = _spawn(key, starts)

    if args.no_wait:
        print("[supervise] --no-wait：已拉起后立即返回", flush=True)
        return 0

    _install_signal_handlers()
    health_fails: dict[str, int] = {}
    print("[supervise] 常驻守护中（Ctrl+C 或直接关窗口 = 全部停止）…", flush=True)
    try:
        while True:
            time.sleep(5)
            for key, p in list(procs.items()):
                if p.poll() is not None:
                    label = SERVICES[key]["label"]
                    print(f"[supervise] {label} 退出（rc={p.returncode}），准备重启", flush=True)
                    if starts.get(key, 0) >= RESTART_LIMIT:
                        print(f"[supervise] {label} 重启已达上限 {RESTART_LIMIT}，停止盯它", flush=True)
                        procs.pop(key, None)
                        continue
                    procs[key] = _spawn(key, starts)
                    # 关键：重启后必须清零健康失败计数，否则计数跨进程残留，
                    # 会让新起的后端「几次失败就被杀」，形成越杀越快的抖动循环。
                    health_fails[key] = 0
                    continue
                url = HEALTH_URLS.get(key)
                if not url:
                    continue
                if _health_ok(url, HEALTH_TIMEOUT):
                    health_fails[key] = 0
                    starts[key] = 0  # 健康即清零，使 RESTART_LIMIT 成为「连续」上限
                    continue
                health_fails[key] = health_fails.get(key, 0) + 1
                if health_fails[key] >= HEALTH_FAIL_LIMIT:
                    label = SERVICES[key]["label"]
                    print(f"[supervise] {label} 进程在但 HTTP 连续 {health_fails[key]} 次不响应，"
                          f"强制重启", flush=True)
                    health_fails[key] = 0
                    try:
                        p.terminate()
                    except Exception:
                        pass
    except KeyboardInterrupt:
        print("\n[supervise] 收到中断信号，正在停止全部服务…", flush=True)
        _shutdown(procs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
