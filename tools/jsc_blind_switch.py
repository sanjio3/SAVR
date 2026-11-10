# -*- coding: utf-8 -*-
"""L1 盲化验证的靶场 + 扫描源码根可逆切换。

L1 只换靶场 jar 是不够的：workspace 4 的 target_path 若仍指向原仓库，
A1/A2 读到的仍是带 /sqli、/spel 等族语义的原始路由（先验没去掉），
D1 还会按旧路由发包，结果全是 404。两侧必须同步切，跑完再 restore。

切换方式刻意不动看门狗：launch_java_seccode.py 的 find_jar() 每次重启都从
CODE_PATH/target/*.jar 里挑最重的 fat jar。把原 jar 改名、把盲化 jar 复制成
同名文件，再让 java 退出一次，看门狗 5s 后自动加载新 jar。这样不碰 7813
单实例哨兵、不新起进程、恢复只需把文件改回来。

用法（blind / restore 默认 dry-run，必须显式 --apply）：
    python tools/jsc_blind_switch.py status
    python tools/jsc_blind_switch.py blind
    python tools/jsc_blind_switch.py blind --apply
    python tools/jsc_blind_switch.py restore --apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)  # #544：支持 `python tools/jsc_blind_switch.py` 直接运行
DB = os.path.join(ROOT, "data", "app.db")
STATE = os.path.join(ROOT, "data", "blind_variants", "jsc_l1_state.json")
JSC_ROOT = os.environ.get(
    "SAST_AI_JSC_SRC", os.path.normpath(os.path.join(ROOT, "..", "java-sec-code")))
BLIND_ROOT = os.path.join(ROOT, "data", "blind_variants", "jsc-blind")
JAR_NAME = "java-sec-code-1.0.0.jar"
ORIG_JAR = os.path.join(JSC_ROOT, "target", JAR_NAME)
BACKUP_SUFFIX = ".orig-L1"
STAGED_JAR = os.path.join(JSC_ROOT, "target", ".blind-L1-staged.jar")
BLIND_JAR = os.path.join(BLIND_ROOT, "target", JAR_NAME)
WS_ID = 4
LOGIN_URL = "http://127.0.0.1:8080/login"


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _log(msg: str) -> None:
    print("[%s] %s" % (_ts(), msg), flush=True)


def _state() -> dict:
    if os.path.isfile(STATE):
        with open(STATE, encoding="utf-8") as fh:
            return json.load(fh)
    return {"mode": "original"}


def _save(st: dict) -> None:
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, STATE)


def _db():
    return sqlite3.connect(DB, timeout=30)


def _target_path(con) -> str:
    row = con.execute("SELECT target_path FROM workspaces WHERE id=?", (WS_ID,)).fetchone()
    return str(row[0]) if row else ""


def _set_target_path(con, value: str) -> None:
    con.execute("UPDATE workspaces SET target_path=?, updated_at=? WHERE id=?",
                (value, _ts(), WS_ID))
    con.commit()


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _listener_pid(port: int) -> int | None:
    # 中文 Windows 的 netstat 输出是 GBK；text=True 会按 UTF-8 解码并抛
    # UnicodeDecodeError，reader thread 挂掉后 stdout 直接变 None。这里手动解码。
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"], capture_output=True,
                         timeout=30)
    text = (out.stdout or b"").decode("gbk", "replace")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "TCP" or parts[3] != "LISTENING":
            continue
        if parts[1].rsplit(":", 1)[-1] == str(port):
            return int(parts[-1])
    return None


def _kill(pid: int) -> None:
    # 同为 GBK 输出，不能用 text=True
    out = subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                         capture_output=True, timeout=30)
    msg = ((out.stdout or b"") + (out.stderr or b"")).decode("gbk", "replace").strip()
    _log("taskkill %d rc=%s %s" % (pid, out.returncode, msg[:160]))


def _http_ok(url: str, timeout: float = 3.0) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as resp:
            return resp.status < 500
    except Exception:  # noqa: BLE001
        return False


def _wait_healthy(old_pid: int | None, timeout_sec: int = 150) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        pid = _listener_pid(8080)
        if pid and pid != old_pid and _http_ok(LOGIN_URL):
            _log("8080 healthy: pid=%s /login 200" % pid)
            return True
        time.sleep(3)
    _log("8080 did not come back healthy within %ds" % timeout_sec)
    return False


def _wait_port_free(port: int, timeout_sec: float = 8.0) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if _listener_pid(port) is None:
            return True
        time.sleep(0.2)
    return False


def _stop_target_for_swap() -> None:
    """杀掉 8080 上的 JVM 以释放 jar 文件锁；看门狗 5s 后会自动重启。"""
    pid = _listener_pid(8080)
    if pid:
        _kill(pid)
    _wait_port_free(8080)


def _install_blind_jar() -> None:
    """幂等：ORIG_JAR = 盲化 jar，BACKUP = 原 jar。

    原 jar 被运行中的 JVM 锁住时 Windows 不允许 rename，所以调用方必须先停 JVM。
    98MB 的复制提前预置到 STAGED_JAR，这里只做两次同盘 os.replace（元数据操作）。
    若看门狗抢先带着旧 jar 重启，ORIG_JAR 会重新被锁，抛错交给调用方重试。
    """
    backup = ORIG_JAR + BACKUP_SUFFIX
    if not os.path.isfile(backup):
        os.replace(ORIG_JAR, backup)
    if not os.path.isfile(ORIG_JAR):
        if os.path.isfile(STAGED_JAR):
            os.replace(STAGED_JAR, ORIG_JAR)
        else:
            shutil.copy2(BLIND_JAR, ORIG_JAR)
    elif _md5(ORIG_JAR) != _md5(BLIND_JAR):
        raise PermissionError("ORIG_JAR relocked by an old JVM")


def _restore_original_jar() -> None:
    backup = ORIG_JAR + BACKUP_SUFFIX
    if not os.path.isfile(backup):
        raise SystemExit("[FATAL] 备份 jar 缺失，无法自动还原：%s" % backup)
    os.replace(backup, ORIG_JAR)


def _rebind_iast_session(ws_id: int, code_path: str) -> dict:
    """把看门狗重启时误建的孤儿 IAST session 归位到扫描任务所在 workspace。

    根因：launch_java_seccode.resolve_token() 调 register_session(workspace_id=None)，
    IastService._resolve_workspace() 按 code_path 找 workspace。切了 workspace 4 的
    target_path 后，CODE_PATH（原仓库）不再匹配任何 workspace，于是自动新建 workspace 9
    和 session 9。ingest_events 用 session.workspace_id 写事件、correlation 也按它过滤，
    不修的话 L1 的探针事件全部落到孤儿 workspace，D2 拿不到任何证据。
    """
    con = _db()
    orphan = con.execute(
        "SELECT id, workspace_id, probe_token FROM iast_sessions "
        "WHERE app_name='sec-code' AND agent_id='java-sec-code' AND workspace_id != ? "
        "ORDER BY id DESC LIMIT 1", (ws_id,)).fetchone()
    if not orphan:
        con.close()
        return {"rebinding": "not_needed"}
    oid, old_ws, orphan_token = int(orphan[0]), int(orphan[1]), str(orphan[2])
    canonical = con.execute(
        "SELECT id, probe_token FROM iast_sessions "
        "WHERE workspace_id=? AND app_name='sec-code' AND agent_id='java-sec-code' "
        "ORDER BY id LIMIT 1", (ws_id,)).fetchone()
    if not canonical:
        # 没有既有 session 时，直接改 workspace_id 不会撞唯一约束
        con.execute("UPDATE iast_sessions SET workspace_id=?, code_path=?, updated_at=? WHERE id=?",
                    (ws_id, code_path, _ts(), oid))
        con.commit()
        con.close()
        return {"strategy": "move_session", "session_id": oid,
                "from_workspace": old_ws, "to_workspace": ws_id, "code_path": code_path}

    # UNIQUE(workspace_id, app_name, agent_id) 不允许把孤儿直接搬到 ws_id。
    # 改为让 ws 上的既有 session 接管探针当前 token：authenticate() 按
    # (app_name, agent_id, token) 反查，命中 canonical 后事件就落在正确的 workspace。
    cid, prev_token = int(canonical[0]), str(canonical[1])
    con.execute("UPDATE iast_sessions SET probe_token=?, code_path=?, status='ready', updated_at=? "
                "WHERE id=?", (orphan_token, code_path, _ts(), cid))
    merged = con.execute("UPDATE iast_events SET session_id=?, workspace_id=? WHERE session_id=?",
                         (cid, ws_id, oid)).rowcount
    con.execute("DELETE FROM iast_sessions WHERE id=?", (oid,))
    con.commit()
    con.close()
    # 改完 DB token 立刻自检，确认注入侧将要读到的值与 DB 真值一致。
    # 过去改完不验，任何仍持有 prev_token 的进程都会继续被后端静默拒绝。
    from src.iast.probe_token import assert_token_matches_db
    assert_token_matches_db(orphan_token, ws_id, "sec-code", "java-sec-code",
                            db_path=DB)
    return {"strategy": "token_takeover", "canonical_session_id": cid,
            "removed_orphan_session": oid, "orphan_workspace": old_ws,
            "merged_orphan_events": merged,
            "previous_token_prefix": prev_token[:8],
            "active_token_prefix": orphan_token[:8], "code_path": code_path,
            "token_alignment": "verified"}


def _swap_with_retry(installer, label: str) -> bool:
    for attempt in range(1, 5):
        _stop_target_for_swap()
        try:
            installer()
            _log("%s jar swap ok (attempt %d)" % (label, attempt))
            return True
        except (PermissionError, FileNotFoundError) as exc:
            _log("%s attempt %d failed: %s（看门狗可能抢先重启，重试）"
                 % (label, attempt, exc))
            time.sleep(1)
    return False


def _preflight_blind() -> None:
    for label, path in (("blind source tree", BLIND_ROOT),
                        ("blind jar", BLIND_JAR), ("original jar", ORIG_JAR)):
        if not os.path.exists(path):
            raise SystemExit("[FATAL] %s missing: %s" % (label, path))
    blind_map = os.path.join(BLIND_ROOT, "blind_map.json")
    with open(blind_map, encoding="utf-8") as fh:
        mapping = json.load(fh)
    for seg in ("/login", "/logout"):
        if seg in mapping["segments"]:
            raise SystemExit("[FATAL] %s 仍被盲化，先修 PROTECTED_SEGMENTS" % seg)
    if mapping["coverage"]["percent"] < 95.0:
        raise SystemExit("[FATAL] 注解覆盖率不足 95%，拒绝部署半盲化变体")
    scan_files = sum(1 for _, _, fs in os.walk(os.path.join(BLIND_ROOT, "src"))
                     for f in fs if f.endswith(".java"))
    _log("preflight ok: %d blind segments, %d java files, auth literals preserved"
         % (len(mapping["segments"]), scan_files))


def _iast_sessions() -> list[dict]:
    con = _db()
    rows = con.execute(
        "SELECT id, workspace_id, agent_id, code_path, status, probe_token "
        "FROM iast_sessions WHERE target_url='http://127.0.0.1:8080' ORDER BY id").fetchall()
    con.close()
    return [{"id": r[0], "workspace_id": r[1], "agent_id": r[2],
             "code_path": r[3], "status": r[4],
             "token_prefix": str(r[5] or "")[:8]} for r in rows]


def status() -> int:
    con = _db()
    tp = _target_path(con)
    con.close()
    st = _state()
    print(json.dumps({
        "mode": st.get("mode", "original"),
        "workspace_4_target_path": tp,
        "expected_original": JSC_ROOT,
        "expected_blind": BLIND_ROOT,
        "original_jar": ORIG_JAR,
        "original_jar_md5": _md5(ORIG_JAR) if os.path.isfile(ORIG_JAR) else None,
        "backup_jar_exists": os.path.isfile(ORIG_JAR + BACKUP_SUFFIX),
        "staged_jar_exists": os.path.isfile(STAGED_JAR),
        "blind_jar": BLIND_JAR,
        "blind_jar_md5": _md5(BLIND_JAR) if os.path.isfile(BLIND_JAR) else None,
        "active_jar_matches_blind": (
            os.path.isfile(ORIG_JAR) and os.path.isfile(BLIND_JAR)
            and _md5(ORIG_JAR) == _md5(BLIND_JAR)),
        "listener_8080_pid": _listener_pid(8080),
        "login_200": _http_ok(LOGIN_URL),
        "iast_sessions_8080": _iast_sessions(),
        "state_file": st,
    }, ensure_ascii=False, indent=2))
    return 0


def blind(apply: bool) -> int:
    _preflight_blind()
    st = _state()
    if st.get("mode") == "blind":
        raise SystemExit("[FATAL] 已是 blind 模式，先 restore")
    con = _db()
    original_tp = _target_path(con)
    con.close()
    if not original_tp:
        raise SystemExit("[FATAL] workspace 4 不存在")
    if os.path.exists(ORIG_JAR + BACKUP_SUFFIX):
        raise SystemExit("[FATAL] 备份 jar 已存在，疑似上次未 restore：%s"
                         % (ORIG_JAR + BACKUP_SUFFIX))
    plan = {
        "original_target_path": original_tp,
        "blind_target_path": BLIND_ROOT,
        "jar_swap": "%s -> %s%s" % (ORIG_JAR, ORIG_JAR, BACKUP_SUFFIX),
        "blind_jar_md5": _md5(BLIND_JAR),
        "restart": "kill 8080 java, watchdog reloads in ~5s",
    }
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    if not apply:
        _log("dry-run only; pass --apply to execute")
        return 0

    old_pid = _listener_pid(8080)
    # 预置：java 仍在跑时就能复制，不与 jar 文件锁冲突
    shutil.copy2(BLIND_JAR, STAGED_JAR)
    _log("staged blind jar at %s" % STAGED_JAR)
    if not _swap_with_retry(_install_blind_jar, "blind"):
        _log("[FATAL] jar 交换失败；未改动 workspace，执行 restore --apply 可回滚")
        return 2
    _log("jar swapped, md5=%s" % _md5(ORIG_JAR))
    con = _db()
    _set_target_path(con, BLIND_ROOT)
    con.close()
    _log("workspace 4 target_path -> %s" % BLIND_ROOT)
    if not _wait_healthy(old_pid):
        _log("[FATAL] 靶场未恢复，立即执行 restore --apply 回滚")
        return 2
    rebind = _rebind_iast_session(WS_ID, BLIND_ROOT)
    _log("IAST session rebind: %s" % json.dumps(rebind, ensure_ascii=False))
    _save({"mode": "blind", "ts": _ts(), **plan,
           "original_jar_md5": _md5(ORIG_JAR + BACKUP_SUFFIX),
           "iast_session_rebind": rebind})
    _log("blind mode active")
    return 0


def restore(apply: bool) -> int:
    st = _state()
    original_tp = st.get("original_target_path") or JSC_ROOT
    backup = ORIG_JAR + BACKUP_SUFFIX
    print(json.dumps({
        "restore_target_path": original_tp,
        "jar_restore": "%s -> %s" % (backup, ORIG_JAR),
        "backup_jar_exists": os.path.isfile(backup),
    }, ensure_ascii=False, indent=2))
    if not apply:
        _log("dry-run only; pass --apply to execute")
        return 0
    if not os.path.isfile(backup):
        raise SystemExit("[FATAL] 备份 jar 缺失，无法自动还原：%s" % backup)
    old_pid = _listener_pid(8080)
    if not _swap_with_retry(_restore_original_jar, "restore"):
        _log("[FATAL] jar 还原失败，请人工把 %s 改回 %s" % (backup, ORIG_JAR))
        return 2
    if os.path.isfile(STAGED_JAR):
        os.remove(STAGED_JAR)
    con = _db()
    _set_target_path(con, original_tp)
    # 探针源码根也还原，保证 L3 两轮与 R0 的 session 形状一致
    con.execute("UPDATE iast_sessions SET code_path=?, updated_at=? "
                "WHERE app_name='sec-code' AND agent_id='java-sec-code' AND workspace_id=?",
                (original_tp, _ts(), WS_ID))
    con.commit()
    con.close()
    _log("jar + target_path restored, md5=%s" % _md5(ORIG_JAR))
    if not _wait_healthy(old_pid):
        _log("[FATAL] 原靶场未恢复健康，请人工检查 launch_java_seccode.py")
        return 2
    _save({"mode": "original", "restored_ts": _ts(),
           "restored_target_path": original_tp,
           "restored_jar_md5": _md5(ORIG_JAR)})
    _log("original mode restored")
    return 0


def rebind(apply: bool) -> int:
    """补做 session 归位：用于 blind 已生效、但当时脚本还没有归位逻辑的情况。"""
    st = _state()
    if st.get("mode") != "blind":
        raise SystemExit("[FATAL] 仅 blind 模式需要 rebind")
    con = _db()
    cp = _target_path(con)
    con.close()
    print(json.dumps({"mode": "blind", "target_workspace": WS_ID,
                      "current_target_path": cp, "sessions": _iast_sessions()},
                     ensure_ascii=False, indent=2))
    if not apply:
        _log("dry-run only; pass --apply to execute")
        return 0
    result = _rebind_iast_session(WS_ID, cp)
    _log("rebind: %s" % json.dumps(result, ensure_ascii=False))
    st["iast_session_rebind"] = result
    _save(st)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=("status", "blind", "restore", "rebind"))
    ap.add_argument("--apply", action="store_true",
                    help="blind / restore / rebind 必须显式给出才会真正改动")
    args = ap.parse_args()
    if args.action == "status":
        return status()
    return {"blind": blind, "restore": restore,
            "rebind": rebind}[args.action](args.apply)


if __name__ == "__main__":
    sys.exit(main())
