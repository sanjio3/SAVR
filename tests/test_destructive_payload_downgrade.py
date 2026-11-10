"""3.4-C 破坏性 SQL payload 降级回归守卫。

背景：target-mall 的 H2 文件库被 D2 重放真执行过 DROP TABLE t_product ×72 / users ×87，数据被
永久破坏（真实环境不自愈、只能人工回滚），并污染其后所有轮次的业务逻辑确认。修法：D1 投放前把
破坏性 SQL 降级为语法错误型探针（未闭合引号），证明注入可达但不改数据。

本测试钉死：
  - 破坏性 SQL（DROP/TRUNCATE/ALTER/无 WHERE 的 DELETE·UPDATE/URL 编码变形）被识别并降级；
  - 非破坏性 payload（UNION、布尔盲注、sleep 时间盲注）原样保留（不得误伤时间盲注承接）；
  - 有 WHERE 的 DELETE/UPDATE 不算破坏性（不降级）。
"""
from src.iast.attack_context import (
    is_destructive_sql_payload,
    downgrade_destructive_payload,
)


def test_drop_table_is_destructive():
    assert is_destructive_sql_payload("1'; DROP TABLE users--")
    assert is_destructive_sql_payload("1; drop table t_product")
    assert is_destructive_sql_payload("DROP DATABASE malldb")


def test_truncate_and_alter_are_destructive():
    assert is_destructive_sql_payload("1; TRUNCATE TABLE t_product")
    assert is_destructive_sql_payload("1; truncate t_product")
    assert is_destructive_sql_payload("1; ALTER TABLE users ADD COLUMN x INT")


def test_delete_update_without_where_is_destructive():
    assert is_destructive_sql_payload("1; DELETE FROM users")
    assert is_destructive_sql_payload("1; UPDATE users SET role='admin'")
    # 有 WHERE 的不算破坏性（定向修改，非全表摧毁）——不降级
    assert not is_destructive_sql_payload("1; DELETE FROM users WHERE id=1")
    assert not is_destructive_sql_payload("1; UPDATE users SET role='admin' WHERE id=1")


def test_url_encoded_destructive_is_detected():
    # %44ROP = DROP；防编码绕过
    assert is_destructive_sql_payload("1%3B%20%44ROP%20TABLE%20users")
    assert is_destructive_sql_payload("1%3B%20truncate%20table%20t_product")


def test_benign_injection_is_not_destructive():
    # UNION / 布尔盲注 / 报错型 / 时间盲注都不是破坏性，不得误伤
    assert not is_destructive_sql_payload("1' OR '1'='1")
    assert not is_destructive_sql_payload("1 UNION SELECT username,password FROM users")
    assert not is_destructive_sql_payload("1 AND SLEEP(5)")
    assert not is_destructive_sql_payload("1'; WAITFOR DELAY '0:0:5'--")
    assert not is_destructive_sql_payload("")


def test_downgrade_replaces_destructive_with_syntax_error_probe():
    probe = downgrade_destructive_payload("1; DROP TABLE users--", "sqli")
    assert probe == "'"
    assert downgrade_destructive_payload("TRUNCATE TABLE t_product", "sqli") == "'"


def test_downgrade_keeps_benign_payloads():
    assert downgrade_destructive_payload("1' OR '1'='1", "sqli") == "1' OR '1'='1"
    assert downgrade_destructive_payload("1 AND SLEEP(5)", "sqli") == "1 AND SLEEP(5)"
    assert downgrade_destructive_payload("", "sqli") == ""


def test_downgrade_custom_probe():
    assert downgrade_destructive_payload("DROP TABLE x", "sqli", probe="')") == "')"
