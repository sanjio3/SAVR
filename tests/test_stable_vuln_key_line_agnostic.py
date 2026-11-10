"""②-4 单元守卫：stable_vuln_key 行号无关弱键变体。

背景（memory §4 / 评审文档）：强键把行号算进哈希，整条关联链对「行号来源变化」敏感，
一侧改从别处取行号 → 两端算出不同键 → D2 关联成批失配，症状只是「验证数骤降」，极难反查。
修复：stable_vuln_keys 同时返回 [强键(file+line+code), 弱键(file+code, 行号置 0)]，
D2 关联 / 孤儿清理都接受双键并集，强键未命中时再走弱键兜底。

本测试断言：
1. 弱键 ≠ 强键（变体确实生效）。
2. 弱键对行号漂移免疫（同文件同类型不同行 → 弱键恒等），强键对行号漂移敏感。
3. 弱键不抢强键：行号不同 + 代码不同的两条漏洞，弱键也互不相同（避免把无关漏洞并到一起）。
4. stable_vuln_keys 始终返回 [强键, 弱键] 顺序，且不含空串。
5. 孤儿清理（trigger_spec_registry._stable_variants）接受双键并集：行号漂移的合法 spec 不被判孤儿。
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.core.vuln_hash import stable_vuln_key, stable_vuln_keys
from src.iast.trigger_spec_registry import reconcile_orphan_specs


def _vuln(line, code="Runtime.getRuntime().exec(a);", ftype="command_execution"):
    return {
        "file": "src/main/java/com/sanjio/mall/web/OrderController.java",
        "line": line,
        "type": ftype,
        "code_snippet": code,
    }


def test_weak_key_differs_from_strong():
    v = _vuln(42)
    s, w = stable_vuln_keys(v)
    assert s != w, "弱键应把行号置 0，故与强键不同"
    assert stable_vuln_key(v) == s, "stable_vuln_key 默认应等于强键"
    assert stable_vuln_key(v, line_agnostic=True) == w, "line_agnostic=True 应等于弱键"


def test_weak_key_immune_to_line_drift():
    v = _vuln(42)
    w = stable_vuln_key(v, line_agnostic=True)
    drifted = _vuln(99)  # 仅行号不同，文件/类型/代码相同
    w2 = stable_vuln_key(drifted, line_agnostic=True)
    assert w == w2, "弱键必须对行号漂移免疫（②-4 兜底根基）"
    # 强键对行号漂移敏感（反向验证：强键确实会因行号变化失配，才需要弱键兜底）
    assert stable_vuln_key(v) != stable_vuln_key(drifted), "强键应对行号漂移敏感"


def test_weak_key_does_not_steal_strong():
    # 行号不同且代码不同 → 弱键也应不同，避免把无关漏洞误并
    a = _vuln(10, code="Runtime.exec(cmd);")
    b = _vuln(11, code="ProcessBuilder.start();")
    wa, wb = stable_vuln_key(a, line_agnostic=True), stable_vuln_key(b, line_agnostic=True)
    assert wa != wb, "弱键含 code_block，行号/代码都不同时应互不命中（不抢强键）"


def test_stable_vuln_keys_shape():
    keys = stable_vuln_keys(_vuln(42))
    assert isinstance(keys, list) and len(keys) == 2, "应返回 [强键, 弱键]"
    assert keys[0] != keys[1]
    assert all(k for k in keys), "不应含空串"


def test_orphan_reconcile_accepts_weak_key_on_line_drift(tmp_path):
    # 构造一个最小 SQLite，spec 侧行号与 findings 侧行号漂移，但文件/类型/code 相同。
    # 预期：双键并集下该 spec 不被判孤儿（弱键兜底命中）。
    import sqlite3

    dbp = tmp_path / "app.db"
    con = sqlite3.connect(str(dbp))
    con.execute(
        "CREATE TABLE findings(id INTEGER, vulnerability_hash_v2 TEXT, finding_type TEXT, "
        "file_path TEXT, line INTEGER, raw_json TEXT)"
    )
    con.execute(
        "CREATE TABLE trigger_specs(id INTEGER, task_id INTEGER, vulnerability_hash_v2 TEXT, "
        "raw_json TEXT, expected_sink_file TEXT, expected_sink_line INTEGER)"
    )
    # findings 侧：行号 100
    f_raw = '{"file":"src/main/java/com/sanjio/mall/web/OrderController.java","line":100,' \
            '"type":"command_execution","code_snippet":"Runtime.getRuntime().exec(a);"}'
    con.execute(
        "INSERT INTO findings VALUES(1,'vh_f','command_execution',"
        "'src/main/java/com/sanjio/mall/web/OrderController.java',100,?)", (f_raw,),
    )
    # spec 侧：行号 200（漂移），vhash 故意不同，但文件/类型/code 与 findings 一致
    s_raw = '{"file":"src/main/java/com/sanjio/mall/web/OrderController.java","line":200,' \
            '"type":"command_execution","code_snippet":"Runtime.getRuntime().exec(a);"}'
    con.execute(
        "INSERT INTO trigger_specs VALUES(1,4,'vh_s_diff',?,NULL,200)", (s_raw,),
    )
    con.commit()
    con.close()

    os.environ["SAST_AI_DB_PATH"] = str(dbp)
    try:
        n = reconcile_orphan_specs(task_id=4, dry_run=True)
    finally:
        os.environ.pop("SAST_AI_DB_PATH", None)
    assert n == 0, "行号漂移的合法 spec 应被弱键兜底保住，不可判孤儿（实测删除数=%s）" % n


if __name__ == "__main__":
    test_weak_key_differs_from_strong()
    test_weak_key_immune_to_line_drift()
    test_weak_key_does_not_steal_strong()
    test_stable_vuln_keys_shape()
    print("\nALL ②-4 UNIT TESTS PASSED")
