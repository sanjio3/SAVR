# -*- coding: utf-8 -*-
"""探针 token 单一真值解析器。

真值源只有一个：``iast_sessions`` 表按 ``(workspace_id, app_name, agent_id)``
唯一键查出的 ``probe_token``。历史上注入侧存在两套互相冲突的优先级：

- ``launch_ruoyi_full.py``：``SAST_AI_PROBE_TOKEN`` 环境变量优先，DB 兜底；
- ``launch_java_quote.py``：DB 优先，但查询**不带 workspace_id**，可能命中别的
  workspace 下的同名会话；
- ``launch_owasp*.py``：按 ``CODE_PATH`` 反推 workspace 再查 DB；
- ``launch_stack.py``：只读环境变量。

再加上「原地改 DB token 的运维操作」会与探针手里的旧 token 冲突
（token takeover），结果是「探针手里拿着旧 token、DB 里已经是新 token」。
探针 ingest 鉴权失败时后端返回 HTTP 200 + ``accepted=0``，探针侧不解析响应体，
于是整轮扫描静默丢光 IAST 事件，直到 D2 才发现，表现为「扫描断链」。

本模块把所有注入点收敛到一条规则：

1. DB 按三元组查出的 token 是唯一权威值；
2. 环境变量只能作为**显式 fallback**，且当它与 DB 值不一致时直接 fail-closed
   报错（这正是「不对齐」本身，绝不能悄悄选一个继续跑）；
3. token 无默认值、无内置凭据；缺任何一个都抛 :class:`ProbeTokenError`；
4. 返回结构只暴露 token 前缀，不打印完整凭据。

模块只依赖标准库，可被顶层 ``launch_*.py`` 独立进程直接 import。
"""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "app.db")

_UNSET = object()


class ProbeTokenError(RuntimeError):
    """token 缺失或与 DB 真值不对齐。调用方必须 fail-closed，不得降级继续发车。"""


@dataclass
class ProbeTokenResolution:
    token: str
    workspace_id: int
    app_name: str
    agent_id: str
    source: str                      # "db" | "env_fallback"
    session_id: Optional[int] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def token_prefix(self) -> str:
        return self.token[:6] if self.token else ""

    def to_dict(self) -> Dict[str, Any]:
        """脱敏输出，供日志 / result.json 落盘。绝不写全量 token。"""
        return {
            "workspace_id": self.workspace_id,
            "app_name": self.app_name,
            "agent_id": self.agent_id,
            "source": self.source,
            "session_id": self.session_id,
            "token_prefix": self.token_prefix,
            "token_len": len(self.token),
            "warnings": list(self.warnings),
        }


def _connect_ro(db_path: str) -> sqlite3.Connection:
    """只读连接；DB 不存在时也必须抛错，不能静默当成「无会话」。"""
    uri = "file:%s?mode=ro" % db_path.replace("\\", "/")
    return sqlite3.connect(uri, uri=True, timeout=10)


def lookup_db_token(workspace_id: int, app_name: str, agent_id: str,
                    db_path: str) -> tuple[Optional[int], str]:
    """返回 ``(session_id, probe_token)``；无匹配行时 ``(None, "")``。"""
    con = _connect_ro(db_path)
    try:
        row = con.execute(
            "SELECT id, probe_token FROM iast_sessions "
            "WHERE workspace_id=? AND app_name=? AND agent_id=? "
            "ORDER BY id DESC LIMIT 1",
            (workspace_id, app_name, agent_id),
        ).fetchone()
    finally:
        con.close()
    if not row:
        return None, ""
    return int(row[0]), str(row[1] or "").strip()


def resolve(workspace_id: int, app_name: str, agent_id: str, *,
            db_path: Optional[str] = None,
            env_token: Any = _UNSET,
            allow_env_fallback: bool = True,
            strict: bool = True) -> ProbeTokenResolution:
    """解析该三元组应当注入探针的 token。

    :param env_token: 显式传入的环境变量 token；默认（``_UNSET``）从
        ``SAST_AI_PROBE_TOKEN`` 读取。传 ``""`` 等价于「环境变量没配」。
    :param allow_env_fallback: DB 无会话行时是否允许用环境变量顶上。为 True 时
        仍会带 warning，且发车握手 preflight 会再验一次后端是否认这个 token。
    :param strict: DB 与环境变量**都有值但不一致**时是否 fail-closed。正常路径
        必须保持 True；仅为兼容个别遗留调用方保留 False（此时取 DB 值并记 warning）。
    """
    for label, value in (("workspace_id", workspace_id),
                         ("app_name", app_name), ("agent_id", agent_id)):
        if value in (None, ""):
            raise ProbeTokenError("resolve() 缺少必要参数 %s" % label)

    db_path = db_path or os.environ.get("SAST_AI_DB_PATH") or DEFAULT_DB_PATH
    if env_token is _UNSET:
        env_token = os.environ.get("SAST_AI_PROBE_TOKEN", "")
    env_token = str(env_token or "").strip()

    try:
        sid, db_token = lookup_db_token(workspace_id, app_name, agent_id, db_path)
    except Exception as exc:  # noqa: BLE001 - DB 不可读必须 fail-closed
        raise ProbeTokenError(
            "读取 iast_sessions 失败（%s）：%s" % (db_path, exc)) from exc

    warnings: List[str] = []

    if db_token and env_token and db_token != env_token:
        # 这就是「token / session 不对齐」的本体：环境里是旧 token，DB 里是新 token
        # （或反之）。过去各 launcher 各自挑一个，探针拿错的那个去注册，
        # 后端 HTTP 200 + accepted=0 静默拒绝。现在直接拦下。
        msg = ("探针 token 不对齐：DB session_id=%s 的 token 前缀 %s… 与环境变量 "
               "SAST_AI_PROBE_TOKEN 前缀 %s… 不一致（workspace=%s app=%s agent=%s）。"
               "请清掉旧环境变量或让 DB 会话重新颁发，不要二选一继续跑。"
               % (sid, db_token[:6], env_token[:6],
                  workspace_id, app_name, agent_id))
        if strict:
            raise ProbeTokenError(msg)
        warnings.append(msg + " [strict=False，已强制采用 DB 值]")

    if db_token:
        return ProbeTokenResolution(
            token=db_token, workspace_id=workspace_id, app_name=app_name,
            agent_id=agent_id, source="db", session_id=sid, warnings=warnings)

    if env_token and allow_env_fallback:
        warnings.append(
            "DB 中无 workspace=%s app=%s agent=%s 的会话行，改用环境变量 token；"
            "后端 authenticate_by_token 只认 DB 行，发车前必须由 preflight 握手确认。"
            % (workspace_id, app_name, agent_id))
        return ProbeTokenResolution(
            token=env_token, workspace_id=workspace_id, app_name=app_name,
            agent_id=agent_id, source="env_fallback", session_id=None,
            warnings=warnings)

    raise ProbeTokenError(
        "未取得探针 token：iast_sessions 无 workspace=%s app=%s agent=%s 的会话，"
        "且未设置 SAST_AI_PROBE_TOKEN。请先在 Workspace → IAST 注册会话；"
        "本模块不提供任何内置凭据。" % (workspace_id, app_name, agent_id))


def assert_token_matches_db(token: str, workspace_id: int, app_name: str,
                            agent_id: str, *, db_path: Optional[str] = None) -> None:
    """原地改过 ``iast_sessions.probe_token`` 后调用，确认注入侧与 DB 仍对齐。

    原地改过 ``iast_sessions.probe_token`` 的 token takeover 会更新 DB token，任何还在
    持有旧 token 的进程都必须失效重拉；本断言用于切换完成后自检。
    """
    db_path = db_path or os.environ.get("SAST_AI_DB_PATH") or DEFAULT_DB_PATH
    sid, db_token = lookup_db_token(workspace_id, app_name, agent_id, db_path)
    if not db_token:
        raise ProbeTokenError("自检失败：DB 中已无该三元组的会话行")
    if str(token or "").strip() != db_token:
        raise ProbeTokenError(
            "自检失败：注入侧 token 前缀 %s… 与 DB session_id=%s 前缀 %s… 不对齐"
            % (str(token or "")[:6], sid, db_token[:6]))
