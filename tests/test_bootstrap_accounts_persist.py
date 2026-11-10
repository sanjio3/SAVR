"""回归测试：bootstrap_accounts 出的双账号必须回写 dast_accounts（含陈旧行去重）。

背景（2026-10-03 live 验证 java-sec-code）：dast_accounts 此前只由 import_accounts 写入，
bootstrap 只在内存里返回会话、从不落盘。于是 ws4 修好双凭据（attacker=joychou / victim=admin）
之后，库里留的仍是上一次 import 的旧行（同 subject、同一条早已失效的 JSESSIONID），
M11 的 dual_account_same_subject 永远报红——已修好的配置在闸门上看还是红的。

本测试锁三条防呆约束（双账号齐全才写 / 定位不到 app_id 就不写 / 每 stance 只留最新一条），
不依赖外部网络、不依赖靶场存活。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from src.application.d1_service import D1Service  # noqa: E402
from src.infrastructure.db import Database  # noqa: E402


def _tmp_db(tmp_path):
    db = Database(str(tmp_path / "persist.db"))
    db.connect()
    return db


def _rows(db, app_id="workspace-4"):
    rows = db.execute(
        "SELECT id, account_id, role, subject, auth_cookies_json FROM dast_accounts "
        "WHERE app_id = ? ORDER BY id",
        (app_id,), fetchall=True) or []
    return [dict(r) for r in rows]


def _out(attacker_subject="joychou", victim_subject="admin"):
    return {
        "attacker": {"role": "user", "username": attacker_subject,
                     "auth_cookies": {"JSESSIONID": "AAA"}},
        "victim": {"role": "admin", "username": victim_subject,
                   "auth_cookies": {"JSESSIONID": "BBB"}},
    }


def _target(app_id="workspace-4"):
    return {"app_id": app_id, "service_url": "http://127.0.0.1:8080",
            "login": {"url": "/login"}}


def test_persist_writes_both_stances(tmp_path):
    db = _tmp_db(tmp_path)
    D1Service(db=db)._persist_bootstrap_accounts(_target(), None, _out())
    rows = _rows(db)
    assert len(rows) == 2
    by = {r["account_id"]: r for r in rows}
    assert by["attacker"]["subject"] == "joychou"
    assert by["victim"]["subject"] == "admin"
    assert '"JSESSIONID": "AAA"' in by["attacker"]["auth_cookies_json"]
    assert '"JSESSIONID": "BBB"' in by["victim"]["auth_cookies_json"]


def test_persist_skips_when_only_one_stance(tmp_path):
    """登录失败导致只出一个账户时绝不落盘——否则双账号名册被自己缩成单条。"""
    db = _tmp_db(tmp_path)
    D1Service(db=db)._persist_bootstrap_accounts(_target(), None, {"attacker": _out()["attacker"]})
    assert _rows(db) == []


def test_persist_skips_without_app_id(tmp_path):
    db = _tmp_db(tmp_path)
    D1Service(db=db)._persist_bootstrap_accounts({"service_url": "http://x"}, None, _out())
    assert _rows(db) == []


def test_persist_dedupes_stale_duplicates(tmp_path):
    """历史 import 的陈旧行（同主体、死会话）必须被顶掉，否则闸门继续报红。"""
    db = _tmp_db(tmp_path)
    now = "2026-01-01T00:00:00"
    for stance, sub in (("attacker", "joychou"), ("victim", "joychou")):
        db.execute(
            "INSERT INTO dast_accounts (app_id, account_id, role, subject, auth_cookies_json, "
            "auth_headers_json, token_ref, metadata_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            ("workspace-4", stance, "user", sub, '{"JSESSIONID": "STALE"}', "{}", "", "{}", now))
    assert len(_rows(db)) == 2

    D1Service(db=db)._persist_bootstrap_accounts(_target(), None, _out())

    rows = _rows(db)
    assert len(rows) == 2, "每个 stance 只应保留最新一条"
    by = {r["account_id"]: r for r in rows}
    assert by["victim"]["subject"] == "admin"
    assert "STALE" not in "".join(r["auth_cookies_json"] for r in rows)


def test_persist_keeps_honest_warning_when_same_subject(tmp_path):
    """双账号同主体时照样落盘：闸门必须继续报红，不能因为写了盘就把缺陷洗白。"""
    db = _tmp_db(tmp_path)
    D1Service(db=db)._persist_bootstrap_accounts(_target(), None, _out("joychou", "joychou"))
    rows = _rows(db)
    assert len(rows) == 2
    assert {r["subject"] for r in rows} == {"joychou"}


def test_persist_survives_db_failure(tmp_path):
    """落盘异常只告警不抛出——重放用的是内存里的 out，绝不能被落盘拖死。"""
    db = _tmp_db(tmp_path)

    class _Boom(Database):
        def execute(self, *a, **k):
            raise RuntimeError("disk on fire")

    boom = _Boom(str(tmp_path / "boom.db"))
    boom.connect()
    svc = D1Service(db=object())
    svc.db = boom
    # 不抛异常即可
    svc._persist_bootstrap_accounts(_target(), None, _out())


def test_persist_end_to_end_false_confirm_gate_clears(tmp_path):
    """端到端：真会话回写后，dual_account_same_subject 告警必须消失。"""
    from src.core.dast_config_check import check_dast_config

    db = _tmp_db(tmp_path)
    db.execute(
        "INSERT INTO dast_apps (app_id, app_name, base_url, auth_type, role_boundaries_json, "
        "settings_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        ("workspace-4", "sec-code", "http://127.0.0.1:8080", "", "{}", "{}", "2026-01-01", "2026-01-01"))
    # 先埋陈旧同主体行，模拟修复前状态
    for stance in ("attacker", "victim"):
        db.execute(
            "INSERT INTO dast_accounts (app_id, account_id, role, subject, auth_cookies_json, "
            "auth_headers_json, token_ref, metadata_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("workspace-4", stance, "user", "joychou", '{"JSESSIONID": "STALE"}', "{}", "", "{}",
             "2026-01-01T00:00:00"))
    before = check_dast_config(db, "workspace-4", 4, enable_verification=True)
    codes_before = {w["code"] for w in before["warnings"]}
    assert "dual_account_same_subject" in codes_before, "修复前的陈旧配置应当报双账号同主体"

    D1Service(db=db)._persist_bootstrap_accounts(_target(), None, _out())

    after = check_dast_config(db, "workspace-4", 4, enable_verification=True)
    codes_after = {w["code"] for w in after["warnings"]}
    assert "dual_account_same_subject" not in codes_after, "真实双账号回写后告警应消失"
    assert after["summary"]["accounts"] == 2


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-p", "no:randomly"]))
