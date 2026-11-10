"""M11 DAST 配置自检闸门测试（2026-10-03）。

两类要抓的洞：
  1. base_url 为空 → 运行时重放全部发不出去，整片 no_evidence，且报告无法区分
     「没配地址」与「无漏洞」（后者会被当成永久非漏洞写进确认口径分母）。
  2. 双账号同一主体 → 越权判据被自己的数据满足，产出**假确认**。这比缺配置更危险，
     因为它不是让结论缺失，而是让结论错误。

还有一条：账号没有登记任何 cookie/header → 以未认证身份打，判据必然不成立。
"""


class _Rows(list):
    """sqlite3 的 fetchall() 返回值语义：可迭代 + 有 fetchall()。"""

    def fetchall(self):
        return list(self)


class _FakeDB:
    """最小 DB 桩：只实现 dast_apps / dast_accounts 两个查询。

    接口对齐真实 Database.execute（src/infrastructure/db.py）：查询靠 fetchone /
    fetchall 关键字开关决定，而不是「execute 后再调 .fetchall()」—— 后者在真实库上
    会返回 None 再取 .fetchall() 抛 AttributeError，被 except 吞成「查不到行」，
    于是配置闸门的告警全部静默失效（这条坑就是这么发现的）。
    """

    def __init__(self, apps=None, accounts=None):
        self._apps = apps or {}
        self._accs = accounts or {}

    def execute(self, sql, params=(), fetchone=False, fetchall=False):
        low = " ".join(str(sql).lower().split())
        if "from dast_apps" in low:
            row = self._apps.get(str(params[0]))
            if fetchone:
                return row
            return _Rows([row] if row else [])
        if "from dast_accounts" in low:
            return _Rows(self._accs.get(str(params[0]), []))
        if fetchone:
            return None
        return _Rows()


def _app(app_id, base_url, auth_type="cookie"):
    return {"app_id": app_id, "app_name": app_id, "base_url": base_url,
            "auth_type": auth_type, "role_boundaries_json": "[]"}


def _acc(account_id, role, subject, cookies='{"JSESSIONID": "x"}'):
    return {"account_id": account_id, "role": role, "subject": subject,
            "tenant": "", "auth_cookies_json": cookies, "auth_headers_json": "{}"}


def test_missing_app_is_blocking():
    res = _check(_FakeDB(), 9)
    assert res["ok"] is False
    assert res["warnings"][0]["code"] == "app_not_found"
    assert res["summary"]["app_found"] is False


def test_empty_base_url_is_blocking():
    db = _FakeDB(apps={"workspace-5": _app("workspace-5", "")},
                 accounts={"workspace-5": [_acc("a", "attacker", "alice")]})
    res = _check(db, 5)
    codes = {w["code"] for w in res["warnings"]}
    assert "base_url_empty" in codes
    assert res["ok"] is False


def test_malformed_base_url_is_blocking():
    db = _FakeDB(apps={"workspace-5": _app("workspace-5", "127.0.0.1:8080")})
    res = _check(db, 5)
    assert "base_url_malformed" in {w["code"] for w in res["warnings"]}


def test_same_subject_dual_account_is_false_confirm_risk():
    """双账号同主体 → 假确认风险（severity 不同于缺配置，且要标出来）。"""
    db = _FakeDB(
        apps={"workspace-4": _app("workspace-4", "http://127.0.0.1:8080")},
        accounts={"workspace-4": [_acc("attacker", "attacker", "joychou"),
                                  _acc("victim", "victim", "joychou")]})
    res = _check(db, 4)
    warn = [w for w in res["warnings"] if w["code"] == "dual_account_same_subject"]
    assert warn, "同主体双账号必须被抓出来"
    assert warn[0]["severity"] == "false_confirm"
    assert res["summary"]["has_false_confirm_risk"] is True


def test_different_subject_dual_account_passes():
    db = _FakeDB(
        apps={"workspace-3": _app("workspace-3", "http://127.0.0.1:8092")},
        accounts={"workspace-3": [_acc("attacker", "attacker", "alice"),
                                  _acc("victim", "victim", "bob")]})
    res = _check(db, 3)
    assert res["ok"] is True
    assert res["warnings"] == []


def test_same_subject_detected_when_role_column_is_privilege_not_test_role():
    """防回归：role 列装的是权限角色（user）时也必须判出假确认。

    workspace-4 真实数据就是 role='user' 的 attacker/victim 两条记录
    （attacker/victim 只写在 account_id 上）。按 role 标签分组会取空、
    整个告警静默失效 —— 这条用例把它钉死。
    """
    db = _FakeDB(
        apps={"workspace-4": _app("workspace-4", "http://127.0.0.1:8080")},
        accounts={"workspace-4": [_acc("attacker", "user", "joychou"),
                                  _acc("victim", "user", "joychou")]})
    res = _check(db, 4)
    codes = {w["code"] for w in res["warnings"]}
    assert "dual_account_same_subject" in codes
    assert res["summary"]["has_false_confirm_risk"] is True


def test_identical_credential_strings_are_called_out():
    """两条账号凭据串完全相同 → 消息里要点明「同一个会话登记了两次」。"""
    cookie = '{"JSESSIONID": "ABC"}'
    db = _FakeDB(
        apps={"workspace-4": _app("workspace-4", "http://127.0.0.1:8080")},
        accounts={"workspace-4": [_acc("attacker", "attacker", "joychou", cookies=cookie),
                                  _acc("victim", "victim", "joychou", cookies=cookie)]})
    res = _check(db, 4)
    warn = [w for w in res["warnings"] if w["code"] == "dual_account_same_subject"][0]
    assert "同一个会话" in warn["message"]


def test_same_subject_only_matters_when_both_roles_present():
    """只有一个角色时不判同主体（没有对照就没有越权判据）。"""
    db = _FakeDB(
        apps={"workspace-4": _app("workspace-4", "http://127.0.0.1:8080")},
        accounts={"workspace-4": [_acc("attacker", "attacker", "alice")]})
    res = _check(db, 4)
    assert "dual_account_same_subject" not in {w["code"] for w in res["warnings"]}


def test_account_without_credential_is_blocking():
    db = _FakeDB(
        apps={"workspace-6": _app("workspace-6", "http://127.0.0.1:9001")},
        accounts={"workspace-6": [_acc("attacker", "attacker", "alice", cookies="{}")]})
    res = _check(db, 6)
    assert "account_without_credential" in {w["code"] for w in res["warnings"]}


def test_headers_credential_also_counts():
    db = _FakeDB(
        apps={"workspace-6": _app("workspace-6", "http://127.0.0.1:9001")},
        accounts={"workspace-6": [
            {"account_id": "attacker", "role": "attacker", "subject": "alice", "tenant": "",
             "auth_cookies_json": "{}", "auth_headers_json": '{"Authorization": "Bearer x"}'}]})
    res = _check(db, 6)
    assert "account_without_credential" not in {w["code"] for w in res["warnings"]}


def test_each_warning_carries_fix_hint():
    """每条告警都要带可执行的修复指引 —— 告警本身不解决问题，指引才解决。"""
    db = _FakeDB(apps={"workspace-5": _app("workspace-5", "")})
    res = _check(db, 5)
    for w in res["warnings"]:
        assert w.get("fix"), w["code"]
        assert w.get("message")


def test_task_level_check_skips_when_verification_disabled():
    """纯静态扫描不该被 DAST 配置问题拦住。"""
    res = _check(_FakeDB(), 5, app_id="", enable_verification=False)
    assert res["ok"] is True and res["skipped"] is True


def test_task_level_check_resolves_workspace_app_id():
    res = _check(_FakeDB(), 5, app_id="")
    assert res["app_id"] == "workspace-5"


import json as _json


class _FakeDBWithWorkspace(_FakeDB):
    """在 _FakeDB 之上加 workspaces.settings_json —— 重放真用的是这里面的 service_url。

    行形状对齐真实 DB 层：select 单行返回 dict，字段值 settings_json 是**字符串**（JSON 文本），
    不是已解析的 dict（见 src/infrastructure/db.py 的 dict 行封装）。
    """

    def __init__(self, apps=None, accounts=None, ws_settings=None):
        super().__init__(apps=apps, accounts=accounts)
        self._ws = ws_settings or {}

    def execute(self, sql, params=(), fetchone=False, fetchall=False):
        low = " ".join(str(sql).lower().split())
        if "from workspaces" in low and fetchone:
            settings = self._ws.get(str(params[0]))
            if settings is None:
                return None
            return {"settings_json": _json.dumps(settings)}
        return super().execute(sql, params, fetchone)


def test_base_url_falls_back_to_workspace_service_url():
    """workspace 配了 service_url 但 DAST 应用登记漏填 → 不算缺地址（否则会误报 blocking）。"""
    db = _FakeDBWithWorkspace(
        apps={"workspace-5": _app("workspace-5", "")},
        ws_settings={"5": {"service_url": "http://127.0.0.1:8443/benchmark"}})
    res = _check(db, 5)
    assert "base_url_empty" not in {w["code"] for w in res["warnings"]}
    assert res["base_url"] == "http://127.0.0.1:8443/benchmark"


def test_workspace_target_url_is_also_accepted():
    db = _FakeDBWithWorkspace(
        apps={"workspace-4": _app("workspace-4", "")},
        ws_settings={"4": {"target_url": "http://127.0.0.1:8080"}})
    res = _check(db, 4)
    assert res["base_url"] == "http://127.0.0.1:8080"


def test_app_base_url_wins_over_workspace_setting():
    db = _FakeDBWithWorkspace(
        apps={"workspace-3": _app("workspace-3", "http://127.0.0.1:8092")},
        ws_settings={"3": {"service_url": "http://127.0.0.1:9999"}})
    res = _check(db, 3)
    assert res["base_url"] == "http://127.0.0.1:8092"


def test_both_empty_still_blocking():
    db = _FakeDBWithWorkspace(apps={"workspace-6": _app("workspace-6", "")},
                              ws_settings={"6": {}})
    res = _check(db, 6)
    assert "base_url_empty" in {w["code"] for w in res["warnings"]}


def test_every_warning_has_severity():
    db = _FakeDB(apps={"workspace-5": _app("workspace-5", "")},
                 accounts={"workspace-5": [_acc("a", "attacker", "a", cookies="{}")]})
    res = _check(db, 5)
    sev = {w["severity"] for w in res["warnings"]}
    assert sev <= {"blocking", "false_confirm"}
    assert sev  # 至少有一条


def _check(db, workspace_id, app_id="", enable_verification=True):
    from src.core.dast_config_check import check_dast_config, check_task_dast_config
    if app_id == "" and enable_verification is False:
        return check_task_dast_config(db, workspace_id, "", enable_verification=False)
    if app_id == "":
        return check_task_dast_config(db, workspace_id, "", enable_verification=True)
    return check_dast_config(db, app_id, workspace_id, enable_verification)


def test_missing_app_with_workspace_url_downgrades_to_info():
    """2026-10-08 M11 降噪：app 未登记但 workspace 配了生效地址 → 不再判 blocking。

    OWASP 分片跑批实证：重放走 workspace.settings_json.service_url 打得通
    （55 条 confirmed），旧实现却在 app_not_found 分支短路返回 blocking，
    每片背一条假告警。降级后 ok=True、severity=info、summary 标 ws_fallback。
    """

    class _WsDB(_FakeDB):
        def __init__(self, settings):
            super().__init__()
            self._settings = settings

        def execute(self, sql, params=(), fetchone=False, fetchall=False):
            low = " ".join(str(sql).lower().split())
            if "from workspaces" in low and fetchone:
                return {"settings_json": self._settings}
            return super().execute(sql, params, fetchone=fetchone, fetchall=fetchall)

    db = _WsDB(_json.dumps({"service_url": "http://127.0.0.1:8444/benchmark"}))
    res = _check(db, 7)
    assert res["ok"] is True
    assert res["warnings"][0]["code"] == "app_not_found_ws_fallback"
    assert res["warnings"][0]["severity"] == "info"
    assert res["summary"]["ws_fallback"] is True
    assert res["base_url"] == "http://127.0.0.1:8444/benchmark"
