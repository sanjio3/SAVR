"""OWASP 跑批进度查看器（只读、可随时运行）。

## 为什么单独成一个 .py

上一版把逻辑塞进 watch_batch.cmd 的 `python -c "..."` 里，两处踩死：
  1. cmd 会先展开 %VAR%，`%-26s` / `%.2f` 到了 python 手里已经残缺 → SyntaxError；
  2. 引号嵌套（`"` 里套 `'`，再套 SQL 的 `LIKE 'shard-%'`）在 cmd 下无法可靠转义。
所以逻辑全部搬到这里，cmd 只负责调用。

## 输出纪律

cmd 跑在 chcp 936 (GBK) 下，**所有输出必须纯 ASCII**，否则中文/符号变乱码。

## 它回答什么

  - 栈活着吗（端口 + 按 cmdline 打标签的进程，不用 taskkill /IM python.exe）
  - 当前这一代（run-tag）跑到哪一片了 —— 自动识别最新 run-tag，不再硬编码 r58
  - **生产路径真的在抑制吗**（[safe_verdict] 段）—— 这是 r59 最关键的观测点：
    抑制数若为 0，说明 register_trigger_spec 没拿到代码根目录，跑完也是白跑

用法：
    .venv/Scripts/python.exe tools/watch_batch.py
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import sqlite3
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DB = ROOT / "data" / "app.db"

# 分片任务名形如 shard-sqli-1-r58 → 取末尾 -rNN 作为世代号
TAG_RE = re.compile(r"-r(\d+)$")


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def show_stack() -> None:
    print()
    print("[stack ports]")
    for label, p in (("backend  8000", 8000), ("frontend 5200", 5200)):
        print(f"   [{'UP' if port_open(p) else 'DOWN'}] {label}")

    print()
    print("[stack processes]")
    # 按 cmdline 打标签而不是按映像名：venv python 只是 launcher
    # (venv -> D:\Python -> venv -> 真进程)，每个服务两个 pid，
    # taskkill /IM python.exe 会误杀托管运行时自己的 python。
    try:
        import psutil
    except ImportError:
        print("   (psutil missing, skipped)")
        return
    tags = (
        ("supervise_stack", "SUPERVISOR"),
        ("service_server", "BACKEND"),
        ("vite.js", "FRONTEND"),
        ("scan_task_runner", "RUNNER"),
        ("owasp_run_shards", "SUBMITTER"),
    )
    found = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        try:
            cl = " ".join(p.info["cmdline"] or [])
        except Exception:
            continue
        for needle, tag in tags:
            if needle in cl:
                found.append((tag, p.info["pid"]))
                break
    if not found:
        print("   [NONE] no stack process alive - start tools\\up_stack.cmd first")
    for tag, pid in sorted(found):
        print(f"   {tag:<10} pid={pid}")


def latest_tag(con: sqlite3.Connection) -> str:
    rows = con.execute(
        "SELECT name FROM scan_tasks WHERE name LIKE 'shard-%' ORDER BY id DESC LIMIT 400"
    ).fetchall()
    best, num = "", -1
    for (name,) in rows:
        m = TAG_RE.search(name or "")
        if m and int(m.group(1)) > num:
            num, best = int(m.group(1)), "r" + m.group(1)
    return best


def show_progress(con: sqlite3.Connection) -> str:
    print()
    print("[progress - whole DB]")
    cnt = Counter()
    for st, n in con.execute("SELECT status, COUNT(*) FROM scan_tasks GROUP BY status"):
        cnt[st] = n
    print(f"   completed={cnt['completed']} failed={cnt['failed']} "
          f"pending={cnt['pending']} running={cnt['running']}")

    tag = latest_tag(con)
    print()
    print(f"[progress - current generation: {tag or '(none)'}]")
    if not tag:
        return ""
    rows = con.execute(
        "SELECT id, name, status, phase FROM scan_tasks "
        "WHERE name LIKE ? ORDER BY id",
        (f"shard-%-{tag}",),
    ).fetchall()
    st = Counter(r["status"] for r in rows)
    print(f"   total={len(rows)}  completed={st['completed']} failed={st['failed']} "
          f"running={st['running']} pending={st['pending']}")
    print(f"   {'id':>5}  {'name':<24} {'status':<10} phase")
    for r in rows:
        print(f"   {r['id']:>5}  {r['name']:<24} {r['status']:<10} {r['phase'] or ''}")
    return tag


def show_safe_verdict(con: sqlite3.Connection, tag: str) -> None:
    """生产路径是否真的在抑制 —— r59 的核心观测点。

    抑制数恒为 0 = register_trigger_spec 没拿到代码根目录（相对路径拼不出绝对路径，
    类级窗口为空，规则一条都不命中）。这种故障要等 4~6 小时跑完才发现，所以这里
    提前暴露：前几片跑完就能看出来。
    """
    print()
    print(f"[safe_verdict - suppression by production path ({tag})]")
    if not tag:
        print("   (no generation found)")
        return
    ids = [r[0] for r in con.execute(
        "SELECT id FROM scan_tasks WHERE name LIKE ?", (f"shard-%-{tag}",)).fetchall()]
    if not ids:
        print("   (no tasks in this generation yet)")
        return
    ph = ",".join("?" * len(ids))
    rows = con.execute(
        f"SELECT suppress_rule, COUNT(*) n FROM trigger_specs "
        f"WHERE task_id IN ({ph}) AND COALESCE(suppressed_by_safe_verdict,0)=1 "
        f"GROUP BY suppress_rule ORDER BY n DESC", ids).fetchall()
    tot = sum(r["n"] for r in rows)
    if tot == 0:
        done = con.execute(
            f"SELECT COUNT(*) FROM scan_tasks WHERE name LIKE ? AND status='completed'",
            (f"shard-%-{tag}",)).fetchone()[0]
        if done == 0:
            print("   no completed shard yet - check again after the first one finishes")
        else:
            print(f"   [ALARM] {done} shards completed but ZERO suppression.")
            print("           production path is not suppressing -> code_root missing.")
            print("           STOP the batch (close up_stack window) and report this.")
        return
    for r in rows:
        print(f"   {str(r['suppress_rule'] or '(empty)'):<24} {r['n']}")
    print(f"   {'TOTAL':<24} {tot}")


def show_verdict(con: sqlite3.Connection, tag: str) -> None:
    print()
    print("[verdict]")
    if not tag:
        print("   [UNKNOWN] no shard generation found")
        return
    rows = con.execute(
        "SELECT status, COUNT(*) n FROM scan_tasks WHERE name LIKE ? GROUP BY status",
        (f"shard-%-{tag}",)).fetchall()
    st = {r["status"]: r["n"] for r in rows}
    inflight = st.get("running", 0) + st.get("pending", 0)
    print(f"   generation={tag}  completed={st.get('completed',0)} "
          f"failed={st.get('failed',0)}  inflight={inflight}")
    if inflight == 0:
        print("   [DONE] every shard is terminal.")
        print("          next: .venv\\Scripts\\python.exe tools\\owasp_run_shards.py "
              "--reconcile --run-tag " + tag)
    else:
        print("   [RUNNING] shards still in flight - DO NOT close the up_stack window.")


def show_disk() -> None:
    print()
    print("[disk]")
    try:
        gb = os.path.getsize(str(DB)) / 1e9
        print(f"   app.db GB = {gb:.2f}")
    except OSError:
        print("   app.db not readable")
    try:
        free = shutil.disk_usage(str(ROOT.drive))[2] / 1e9
        print(f"   {ROOT.drive} free GB = {free:.1f}")
    except Exception:
        pass


def tag_is_free(tag: str) -> bool:
    """该 run-tag 是否还没被用过（防止新一代并进旧一代，对账会撒谎）。"""
    if not DB.is_file():
        return True
    con = sqlite3.connect(str(DB))
    try:
        n = con.execute(
            "SELECT COUNT(*) FROM scan_tasks WHERE name LIKE ?",
            (f"shard-%-{tag}",)).fetchone()[0]
    finally:
        con.close()
    return n == 0


def next_tag() -> str:
    """下一个空闲世代号（r58 → r59）。

    给双击场景用：双击 cmd 传不了参数，让脚本自己算出安全的下一代，
    而不是硬编码一个可能已被占用的 tag。
    """
    con = sqlite3.connect(str(DB))
    try:
        rows = con.execute(
            "SELECT name FROM scan_tasks WHERE name LIKE 'shard-%' "
            "ORDER BY id DESC LIMIT 400").fetchall()
    finally:
        con.close()
    best = 0
    for (name,) in rows:
        m = TAG_RE.search(name or "")
        if m:
            best = max(best, int(m.group(1)))
    return f"r{best + 1}"


def main() -> int:
    # 供 submit_batch.cmd 调用（cmd 里写 python -c 会因为 %VAR% 展开和
    # 引号嵌套炸掉，所以宁可多一个入口也不内联）。
    if len(sys.argv) >= 2 and sys.argv[1] == "--next-tag":
        print(next_tag())
        return 0

    # 2026-10-06：cmd 的 for /f 在捕获 stdout 时会把整条命令行连同引号一起吃进来
    # （usebackq+反引号直接语法报错；usebackq+单引号能跑但引号不脱）。
    # 写文件再让 cmd 读文件，彻底绕开引号转义。文件只写一个 tag，无注入面。
    if len(sys.argv) >= 3 and sys.argv[1] == "--next-tag-out":
        out = sys.argv[2]
        tag = next_tag()
        with open(out, "w", encoding="ascii", errors="replace") as fh:
            fh.write(tag + "\n")
        return 0

    if len(sys.argv) >= 3 and sys.argv[1] == "--tag-free":
        tag = sys.argv[2]
        free = tag_is_free(tag)
        if not free:
            print(f"[FATAL] run-tag {tag} already has tasks in the DB.")
            print("        pick a fresh tag (e.g. r60). refusing to merge generations.")
        return 0 if free else 1

    print("=" * 74)
    print("  SAVR batch status (read only)")
    print("=" * 74)
    if not DB.is_file():
        print(f"[FATAL] db not found: {DB}")
        return 1
    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row
    try:
        show_stack()
        tag = show_progress(con)
        show_safe_verdict(con, tag)
        show_verdict(con, tag)
        show_disk()
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
