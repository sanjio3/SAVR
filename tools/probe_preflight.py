# -*- coding: utf-8 -*-
"""发车前探针握手 preflight——fail-closed，不给「静默 accepted=0」留门。

历史故障：注入侧 token 与 DB ``iast_sessions`` 不对齐时，探针心跳/事件被后端
``authenticate_by_token`` 全量拒绝，但响应是 **HTTP 200 + accepted=0**，探针侧
``ProbeHttpClient.sendEvents`` 只 post 不解析响应体，于是整轮扫描直到 D2 才发现
IAST 事件恒 0。用户侧观感就是「扫描又断链了」。

本工具在提交扫描任务前把这条链路提前走一遍：

1. :func:`src.iast.probe_token.resolve` 按三元组拿唯一权威 token，并对
   ``SAST_AI_PROBE_TOKEN`` 做一致性断言（不一致直接 fail）；
2. 只读核对 session 行的 status / version_status / 心跳新鲜度 / 近期事件，
   探针离线也直接 fail（token 对齐但探针已死，同样会打空门）；
3. 可选 ``--http``：向 ``/api/agent/events`` 发**空事件批次**走完整鉴权链路，
   断言返回 ``session_id`` 非空且 ``errors`` 为空。空批次不写事件、不刷心跳，
   不会把死会话「探测成假在线」。这一步还能抓出「后端连了另一个 DB」。

退出码：0=ready；2=preflight 判定不 ready（调用方必须停止发车）；3=运行异常。
任何输出都不含完整 token，只打前缀。

用法：
    python tools/probe_preflight.py --workspace-id 7 --app-name benchmark \
        --agent-id owasp-benchmark-full --http
    python tools/probe_preflight.py --workspace-id 4 --http
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.iast.probe_token import (  # noqa: E402
    DEFAULT_DB_PATH, ProbeTokenError, resolve)

API_BASE = os.environ.get("SAST_AI_API_BASE", "http://127.0.0.1:8000")


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _parse_iso(s: Any) -> Optional[float]:
    """把 iast_sessions / iast_events 的 ISO 时间戳解析成 epoch 秒。

    服务端 `src/iast/service.py::_now` 用 `datetime.utcnow.isoformat` 落库，
    是**无时区的 UTC 字符串**；`env_readiness.py` 的 now 也取 utcnow，偏移互相抵消，
    但本模块的 now 是 `time.time`（真 epoch）。若用裸 `datetime.timestamp`，
    naive 串会被按本地时区解释，UTC+8 机器上 `now - hb` 凭空多出 8 小时，
    刚上报心跳的在线探针也会被判离线。这里与 `target_epoch.py` 保持同一口径：
    naive 一律按 UTC，带时区的串保留原偏移。
    """
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:  # noqa: BLE001
        return None


def open_ro(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"),
                           uri=True, timeout=10)


def inspect_session(db_path: str, workspace_id: int, app_name: str,
                    agent_id: str, *, heartbeat_ttl: float = 120.0,
                    event_ttl: float = 180.0,
                    now: Optional[float] = None) -> Dict[str, Any]:
    """只读体检 session 行 + 探针活性，不产生任何写动作。"""
    now = now if now is not None else time.time()
    con = open_ro(db_path)
    try:
        row = con.execute(
            "SELECT id, status, version_status, last_heartbeat_at, target_url "
            "FROM iast_sessions WHERE workspace_id=? AND app_name=? AND agent_id=? "
            "ORDER BY id DESC LIMIT 1",
            (workspace_id, app_name, agent_id)).fetchone()
        if not row:
            return {"exists": False}
        sid, status, vstatus, hb_raw, target_url = row
        hb = _parse_iso(hb_raw)
        hb_fresh = hb is not None and (now - hb) <= heartbeat_ttl
        ev = con.execute(
            "SELECT MAX(ingested_at) FROM iast_events WHERE app_name=? AND agent_id=?",
            (app_name, agent_id)).fetchone()
        last_ev = ev[0] if ev else None
        ev_ts = _parse_iso(last_ev)
        ev_fresh = ev_ts is not None and (now - ev_ts) <= event_ttl
        return {
            "exists": True,
            "session_id": int(sid),
            "status": str(status or ""),
            "version_status": str(vstatus or ""),
            "target_url": str(target_url or ""),
            "last_heartbeat_at": str(hb_raw or ""),
            "heartbeat_fresh": hb_fresh,
            "last_event_at": str(last_ev or ""),
            "event_fresh": ev_fresh,
            "probe_online": hb_fresh or ev_fresh,
        }
    finally:
        con.close()


def http_handshake(token: str, app_name: str, agent_id: str, *,
                   api_base: str = API_BASE, timeout: float = 8.0,
                   opener=None) -> Dict[str, Any]:
    """空事件批次走完整鉴权链路；不写事件、不刷心跳。"""
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    body = json.dumps({"appName": app_name, "agentId": agent_id,
                       "events": []}).encode("utf-8")
    req = urllib.request.Request(
        api_base.rstrip("/") + "/api/agent/events", data=body,
        headers={"Content-Type": "application/json", "X-Agent-Token": token},
        method="POST")
    with opener.open(req, timeout=timeout) as resp:
        status_code = int(getattr(resp, "status", 200) or 200)
        payload = json.loads(resp.read().decode("utf-8", "replace") or "{}")
    if not isinstance(payload, dict):
        payload = {}
    errors = payload.get("errors") or []
    if payload.get("error"):
        errors = list(errors) + [str(payload["error"])]
    session_id = payload.get("session_id")
    ok = (200 <= status_code < 300 and session_id not in (None, "", 0)
          and not errors)
    return {
        "ok": ok,
        "http_status": status_code,
        "session_id": session_id,
        "accepted": payload.get("accepted"),
        "errors": errors,
        "reason": "" if ok else (
            "后端鉴权未通过（session_id 为空或 errors 非空）：token 与后端 DB 不一致，"
            "或后端连了另一个数据库"),
    }


def preflight(workspace_id: int, app_name: str, agent_id: str, *,
              db_path: str = DEFAULT_DB_PATH,
              env_token: Any = None,
              allow_env_fallback: bool = False,
              require_online: bool = True,
              do_http: bool = False,
              api_base: str = API_BASE,
              heartbeat_ttl: float = 120.0,
              event_ttl: float = 180.0,
              now: Optional[float] = None,
              opener=None) -> Dict[str, Any]:
    """返回脱敏的 preflight 报告；``ready=False`` 时调用方必须停止发车。"""
    report: Dict[str, Any] = {
        "checked_at": _ts(),
        "workspace_id": workspace_id, "app_name": app_name, "agent_id": agent_id,
        "ready": False, "reasons": [], "token": None, "session": None,
        "http_handshake": None, "db_path": db_path,
    }
    # env_token=None 表示「沿用 os.environ」，显式传 "" 表示「禁用环境变量」。
    kwargs = {} if env_token is None else {"env_token": env_token}
    try:
        resolution = resolve(workspace_id, app_name, agent_id,
                             db_path=db_path,
                             allow_env_fallback=allow_env_fallback,
                             strict=True, **kwargs)
    except ProbeTokenError as exc:
        report["reasons"].append("token 解析失败：%s" % exc)
        return report
    report["token"] = resolution.to_dict()
    report["reasons"].extend(resolution.warnings)
    if resolution.source != "db":
        report["reasons"].append(
            "token 来自环境变量 fallback 而非 DB 会话；后端鉴权仍可能拒绝，"
            "本轮按 fail-closed 处理")
        return report

    sess = inspect_session(db_path, workspace_id, app_name, agent_id,
                           heartbeat_ttl=heartbeat_ttl, event_ttl=event_ttl,
                           now=now)
    report["session"] = sess
    if not sess.get("exists"):
        report["reasons"].append("DB 中无该三元组会话行")
        return report
    if str(sess.get("status")) not in ("ready", "active", ""):
        report["reasons"].append("会话 status=%s 非 ready" % sess.get("status"))
    if str(sess.get("version_status")) == "mismatch":
        report["reasons"].append("探针/分析代码版本 mismatch")
    if require_online and not sess.get("probe_online"):
        report["reasons"].append(
            "探针离线：无新鲜心跳且无近期事件（心跳 TTL %.0fs / 事件 TTL %.0fs）"
            % (heartbeat_ttl, event_ttl))

    if do_http:
        try:
            hs = http_handshake(resolution.token, app_name, agent_id,
                                api_base=api_base, opener=opener)
        except Exception as exc:  # noqa: BLE001
            hs = {"ok": False, "reason": "握手请求异常：%s" % exc}
        report["http_handshake"] = hs
        if not hs.get("ok"):
            report["reasons"].append(str(hs.get("reason") or "HTTP 握手失败"))

    report["ready"] = not report["reasons"]
    return report


def preflight_workspace(workspace_id: int, *, db_path: str = DEFAULT_DB_PATH,
                        app_name: str = "", agent_id: str = "",
                        do_http: bool = True,
                        require_online: bool = True,
                        api_base: str = API_BASE,
                        now: Optional[float] = None,
                        opener=None) -> Dict[str, Any]:
    """未显式给三元组时，按 workspace 枚举已注册会话并要求至少一个 ready。

    不能武断挑一个；这里逐个体检，只要有一个对齐且在线就放行，并把全部结果
    写进 ``sessions`` 供审计。仍然不猜 token —— 每个会话都走 resolve + 一致性断言。
    """
    report: Dict[str, Any] = {
        "checked_at": _ts(), "workspace_id": workspace_id,
        "ready": False, "reasons": [], "sessions": [], "mode": "workspace_enumerate",
    }
    con = open_ro(db_path)
    try:
        rows = con.execute(
            "SELECT app_name, agent_id FROM iast_sessions WHERE workspace_id=? "
            "ORDER BY id", (workspace_id,)).fetchall()
    finally:
        con.close()
    if app_name and agent_id:
        rows = [(app_name, agent_id)]
    if not rows:
        report["reasons"].append(
            "workspace %s 下没有任何 iast_sessions 会话行，无法确认探针 token"
            % workspace_id)
        return report
    for a, g in rows:
        sub = preflight(workspace_id, str(a), str(g), db_path=db_path,
                        require_online=require_online, do_http=do_http,
                        api_base=api_base, now=now, opener=opener)
        report["sessions"].append(sub)
    ready = [s for s in report["sessions"] if s.get("ready")]
    report["ready"] = bool(ready)
    if not ready:
        report["reasons"].append(
            "workspace %s 的 %d 个会话无一通过（对齐 + 在线 + 握手），"
            "详见 sessions[].reasons" % (workspace_id, len(report["sessions"])))
    report["ready_sessions"] = [
        {"app_name": s["app_name"], "agent_id": s["agent_id"]} for s in ready]
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace-id", type=int)
    ap.add_argument("--app-name", default="")
    ap.add_argument("--agent-id", default="")
    ap.add_argument("--db", default=DEFAULT_DB_PATH)
    ap.add_argument("--http", action="store_true", help="额外做后端鉴权空批次握手")
    ap.add_argument("--api-base", default=API_BASE)
    ap.add_argument("--allow-env-fallback", action="store_true",
                    help="允许 DB 无会话时用环境变量（默认禁止，保持 fail-closed）")
    ap.add_argument("--no-require-online", action="store_true",
                    help="不要求探针在线（仅用于离线自检，发车时不得使用）")
    ap.add_argument("--heartbeat-ttl", type=float, default=120.0)
    ap.add_argument("--event-ttl", type=float, default=180.0)
    args = ap.parse_args()

    ws, app, agent = args.workspace_id, args.app_name, args.agent_id
    if ws is None:
        print(json.dumps({"ready": False, "reasons": ["缺少 --workspace-id"]},
                         ensure_ascii=False, indent=2))
        return 2

    try:
        if app and agent:
            report = preflight(
                ws, app, agent, db_path=args.db,
                allow_env_fallback=args.allow_env_fallback,
                require_online=not args.no_require_online,
                do_http=args.http, api_base=args.api_base,
                heartbeat_ttl=args.heartbeat_ttl, event_ttl=args.event_ttl)
        else:
            # 只给 workspace：枚举该 workspace 全部会话，要求至少一个 ready
            report = preflight_workspace(
                ws, db_path=args.db, do_http=args.http,
                require_online=not args.no_require_online,
                api_base=args.api_base)
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ready": False, "reasons": ["preflight 异常：%s" % exc]},
                         ensure_ascii=False, indent=2))
        return 3
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    sys.exit(main())
