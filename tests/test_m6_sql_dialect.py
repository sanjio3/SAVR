"""M6 SQL 方言 sleep 弹药：补弹 + 先判后投 + 时延 ≥3s。

三条设计红线各有用例守着（见 src/core/sql_dialect.py 文件头）：
  - PG 的 pg_sleep() 返回 void，绝不能写成 `OR pg_sleep(3)`；
  - MSSQL 的 WAITFOR DELAY 是语句，必须先分号；
  - 内嵌库没有便携 sleep，明确不投，不浪费预算。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core import sql_dialect as sqld  # noqa: E402
from src.iast.attack_context import parse_sleep_seconds, neutralize_sleep_payload  # noqa: E402

# ── 方言归一 ──

def test_normalize_db_type():
    assert sqld.normalize_db_type("MySQL") == "mysql"
    assert sqld.normalize_db_type("mariadb") == "mysql"
    assert sqld.normalize_db_type("PostgreSQL") == "postgresql"
    assert sqld.normalize_db_type("sqlserver") == "mssql"
    assert sqld.normalize_db_type("") == ""


def test_supports_sleep():
    assert sqld.supports_sleep("mysql") is True
    assert sqld.supports_sleep("postgresql") is True
    assert sqld.supports_sleep("h2") is False
    assert sqld.supports_sleep("hsqldb") is False
    assert sqld.supports_sleep("sqlite") is False
    assert sqld.supports_sleep("") is True   # 未知 fail-open


# ── 弹药形态 ──

def test_mysql_payload_is_parsable():
    p = sqld.build_sleep_payload("mysql", "1'", 3, "sqli")
    assert "SLEEP(3)" in p
    assert parse_sleep_seconds(p) == 3.0


def test_postgresql_is_statement_not_boolean_expression():
    """pg_sleep() 返回 void，`OR pg_sleep(3)` 在 PG 里直接报类型错。"""
    p = sqld.build_sleep_payload("postgresql", "1", 3, "sqli")
    assert "pg_sleep(3)" in p
    assert " OR pg_sleep" not in p
    assert ";" in p
    assert parse_sleep_seconds(p) == 3.0


def test_mssql_uses_waitfor_with_statement_separator():
    p = sqld.build_sleep_payload("mssql", "1", 3, "sqli")
    assert "WAITFOR DELAY '0:0:3'" in p
    assert ";" in p
    assert parse_sleep_seconds(p) == 3.0


def test_oracle_uses_boolean_wrapper():
    p = sqld.build_sleep_payload("oracle", "1", 3, "sqli")
    assert "dbms_pipe.receive_message" in p
    assert parse_sleep_seconds(p) == 3.0


def test_embedded_db_yields_no_payload():
    """内嵌库没有便携 sleep：投了也不生效，必须明确返回 None 让通道早退。"""
    for db in ("h2", "hsqldb", "derby", "sqlite"):
        assert sqld.build_sleep_payload(db, "1", 3, "sqli") is None, db


def test_command_family_gets_shell_sleep():
    p = sqld.build_sleep_payload("", "id", 3, "command_injection")
    assert "sleep 3" in p
    assert parse_sleep_seconds(p) == 3.0


def test_sleep_seconds_default_is_at_least_three():
    """D2 时延门把 <1.5s 一律判不可采信，SLEEP(1) 投了也白投。"""
    assert sqld.SLEEP_SECONDS_DEFAULT >= 3
    assert parse_sleep_seconds(sqld.build_sleep_payload("mysql", "1", 0, "sqli")) >= 1.5


def test_unknown_dialect_falls_back_to_mysql_and_says_so():
    """事实缺失时 fail-open 退 MySQL，但 reason 必须写明是猜的。"""
    p = sqld.build_sleep_payload("", "1", 3, "sqli")
    assert "SLEEP(3)" in p
    assert "猜测" in sqld.dialect_reason("", "sqli")


# ── 与既有基线采集链路同源 ──

def test_baseline_neutralization_works_on_synthesized_payloads():
    """合成弹必须能被 neutralize_sleep_payload 归零，否则基线对照做不出来。"""
    for db in ("mysql", "postgresql", "mssql", "oracle"):
        p = sqld.build_sleep_payload(db, "1", 3, "sqli")
        zeroed = neutralize_sleep_payload(p)
        assert parse_sleep_seconds(zeroed) == 0.0, db


def test_only_one_group_per_db_type():
    """先判后投：一个 db_type 只产一条弹，不穷举方言。"""
    for db in ("mysql", "postgresql", "mssql", "oracle"):
        p = sqld.build_sleep_payload(db, "1", 3, "sqli")
        assert isinstance(p, str) and p
        assert parse_sleep_seconds(p) == 3.0
