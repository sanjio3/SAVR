"""R23-4 回归守卫：VICTIM_FROM_POOL 哨兵在重放期必须落成可解析的具体值。

事故（task-8）：bola 族 confirmed 从 task-7 的 12 掉到 3，业务族 confirmed 合计 18→11。
真因链：
  1. R23-3 让 A1 对业务族统一写 `prerequisites.victim_resource_id = "VICTIM_FROM_POOL"`
     （登记期「就绪标记」，使 spec 能进 D2 主线）。task-8 该列哨兵从 15 条涨到 94 条。
  2. `bootstrap_accounts` 在 acct 里写入 `user_id`（d1_service.py:493），但输出白名单
     `("auth_headers","auth_cookies","role","username")` 又把它过滤掉。
  3. `replay_bola` 的哨兵解析读 victim/attacker 的 `user_id` → 恒 None → `victim_id` 残留
     字面量 "VICTIM_FROM_POOL" → `_inject` 拼出 `/order/VICTIM_FROM_POOL/pay` → 靶场类型
     绑定失败（400/404）→ 探针 findById / AuthzDecision 钩子永不命中 → iast_state 从
     iast-authz-confirmed 退化为 no-iast-evidence。
  4. 对照：task-7 同族 spec 的 victim_resource_id 为空 → 走 `_resolve_object_id` 现场枚举
     真实对象 id → 探针命中 → 确认（12 条里 11 条是该路径）。

修复：白名单保留 user_id；哨兵按资源语义分档解析（path 型交枚举、非 path 型用池 uid、
都取不到则置空走既有枚举/回退 "1"）；`_account_row` 从持久化凭据解出 uid。
"""

import base64
import json
from typing import Any, Dict, List
from unittest import mock

import pytest

from src.application.d1_service import D1Service
from src.infrastructure.db import Database
from src.iast.orchestrator import DastImpact

SENTINEL = "VICTIM_FROM_POOL"


def _jwt(uid: Any = 2) -> str:
    """构造一个含 uid 声明的未签名 JWT（仅用于解析路径测试，不做签名校验）。"""
    def _seg(obj: Any) -> str:
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_seg({'alg': 'HS256', 'typ': 'JWT'})}.{_seg({'uid': uid, 'role': 'user'})}.sig"


class _Recorder:
    """替换 `_send_one`，记录每次请求并返回预设响应。"""

    def __init__(self, responses: List[DastImpact] | None = None) -> None:
        self.calls: List[Dict[str, Any]] = []
        self._responses = list(responses or [])

    def __call__(self, method, url, query, headers, cookies, body, content_type, *a, **k):
        self.calls.append({"method": method, "url": url, "query": dict(query or {}),
                           "headers": dict(headers or {}), "cookies": dict(cookies or {}),
                           "body": body})
        if self._responses:
            return self._responses.pop(0)
        return DastImpact(reached=True, status_code=200, body="{}", response_summary="200")

    @property
    def urls(self) -> List[str]:
        return [c["url"] for c in self.calls]


# ------------------------------------------------------------------ 白名单保 user_id


def test_bootstrap_output_retains_user_id():
    """bootstrap_accounts 必须把从真实 token 解出的 uid 透出，否则哨兵永远解析不出。"""
    svc = D1Service(db=None)
    token = _jwt(uid=2)
    resp = mock.Mock()
    resp.cookies.get.return_value = token
    resp.headers = {"Set-Cookie": f"mall_token={token}; Path=/"}
    resp.text = ""

    target = {"service_url": "http://x",
              "login": {"url": "/login", "method": "POST", "cookie_name": "mall_token",
                        "content_type": "form",
                        "credentials": [{"role": "user", "username": "alice", "password": "p"},
                                        {"role": "user", "username": "bob", "password": "p"}]}}
    with mock.patch("src.application.d1_service.requests.request", return_value=resp):
        out = svc.bootstrap_accounts(target, {"id": 1})

    assert out is not None
    for stance in ("attacker", "victim"):
        assert out[stance].get("user_id") == "2", (
            f"{stance} 缺少 user_id：白名单又把 uid 过滤掉了（R23-4 事故回归）"
        )
        assert out[stance].get("auth_cookies") == {"mall_token": token}


def test_account_row_derives_user_id_from_persisted_jwt():
    """dast_accounts 来源的账户也要能从持久化 cookie JWT 解出 uid（此前只有 subject/username）。"""
    row = {"id": 4, "app_id": "workspace-3", "account_id": "attacker", "role": "user",
           "tenant": "", "subject": "alice", "auth_headers_json": "{}",
           "auth_cookies_json": json.dumps({"mall_token": _jwt(uid=11)}),
           "token_ref": "", "metadata_json": json.dumps({"username": "alice"}),
           "created_at": "2026-01-01T00:00:00"}
    acct = D1Service._account_row(row)
    assert acct["user_id"] == "11"


def test_account_row_omits_user_id_when_token_is_opaque():
    row = {"id": 4, "app_id": "workspace-3", "account_id": "attacker", "role": "user",
           "tenant": "", "subject": "alice", "auth_headers_json": "{}",
           "auth_cookies_json": json.dumps({"sid": "opaque-not-a-jwt"}),
           "token_ref": "", "metadata_json": "{}", "created_at": "2026-01-01T00:00:00"}
    assert "user_id" not in D1Service._account_row(row), "绝不猜测 uid"


# ------------------------------------------------------------------ 哨兵不再字面量入 URL


def _accounts(victim_uid: Any = "42") -> Dict[str, Any]:
    victim = {"auth_headers": {}, "auth_cookies": {}, "role": "user", "username": "bob"}
    if victim_uid is not None:
        victim["user_id"] = victim_uid
    return {"attacker": {"auth_headers": {}, "auth_cookies": {}, "role": "user", "username": "alice"},
            "victim": victim}


def test_path_shaped_sentinel_enumerates_real_object_id(monkeypatch):
    """path 型（/order/{id}）：资源 id ≠ 账户 uid，必须现场枚举真实对象 id，绝不发字面哨兵。"""
    svc = D1Service(db=None)
    rec = _Recorder([
        DastImpact(reached=True, status_code=200, body='[{"id": 7}]', response_summary="200"),
        DastImpact(reached=True, status_code=200, body='{"owner":"bob"}', response_summary="200"),
    ])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    svc.replay_bola({"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
                     "param_location": "path", "victim_resource_id": SENTINEL},
                    {"service_url": "http://x"}, accounts=_accounts())

    assert not any(SENTINEL in u for u in rec.urls), f"哨兵字面量进了 URL：{rec.urls}"
    assert rec.urls[-1] == "http://x/order/7", f"应以枚举出的真实 id 重放，实得 {rec.urls}"


def test_path_param_without_placeholder_also_enumerates(monkeypatch):
    """/comment/delete（param_location=path 但无占位符）：同样不得发字面哨兵。"""
    svc = D1Service(db=None)
    rec = _Recorder([
        DastImpact(reached=True, status_code=200, body='[{"id": 9}]', response_summary="200"),
        DastImpact(reached=True, status_code=200, body="{}", response_summary="200"),
    ])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    svc.replay_bola({"target_endpoint": "/comment/delete", "http_method": "GET",
                     "param_name": "id", "param_location": "path",
                     "victim_resource_id": SENTINEL},
                    {"service_url": "http://x"}, accounts=_accounts())

    assert not any(SENTINEL in u for u in rec.urls), f"哨兵字面量进了 URL：{rec.urls}"


def test_non_path_sentinel_uses_pool_uid(monkeypatch):
    """非 path 型（query/cookie 传参）且拿到池 uid：直接用 uid，优于盲投 "1"。"""
    svc = D1Service(db=None)
    rec = _Recorder()
    monkeypatch.setattr(D1Service, "_send_one", rec)

    svc.replay_bola({"target_endpoint": "/wallet/balance", "http_method": "GET",
                     "param_name": "uid", "param_location": "query",
                     "victim_resource_id": SENTINEL},
                    {"service_url": "http://x"}, accounts=_accounts(victim_uid="42"))

    assert rec.calls[-1]["query"] == {"uid": "42"}, rec.calls[-1]


def test_non_path_sentinel_without_uid_degrades_to_default(monkeypatch):
    """非 path 型且账户池无 uid：退化为既有兜底 "1"，仍不发字面哨兵。"""
    svc = D1Service(db=None)
    rec = _Recorder()
    monkeypatch.setattr(D1Service, "_send_one", rec)

    svc.replay_bola({"target_endpoint": "/wallet/balance", "http_method": "GET",
                     "param_name": "uid", "param_location": "query",
                     "victim_resource_id": SENTINEL},
                    {"service_url": "http://x"}, accounts=_accounts(victim_uid=None))

    assert rec.calls[-1]["query"] == {"uid": "1"}, rec.calls[-1]


def test_concrete_id_is_never_overridden(monkeypatch):
    """A2 LLM 给出的具体 id 优先，任何修复都不得覆盖。"""
    svc = D1Service(db=None)
    rec = _Recorder()
    monkeypatch.setattr(D1Service, "_send_one", rec)

    svc.replay_bola({"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
                     "param_location": "path", "victim_resource_id": "888"},
                    {"service_url": "http://x"}, accounts=_accounts())

    assert rec.urls == ["http://x/order/888"], rec.urls


@pytest.mark.parametrize("sentinel", [SENTINEL, "VICTIM_FROM_POOL "])
def test_sentinel_variants_are_never_emitted(monkeypatch, sentinel):
    """哨兵（含尾部空格形态）一律不得以字面量进入请求。"""
    svc = D1Service(db=None)
    rec = _Recorder([
        DastImpact(reached=True, status_code=200, body='[{"id": 3}]', response_summary="200"),
        DastImpact(reached=True, status_code=200, body="{}", response_summary="200"),
    ])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    svc.replay_bola({"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
                     "param_location": "path", "victim_resource_id": sentinel},
                    {"service_url": "http://x"}, accounts=_accounts())

    assert not any("VICTIM_FROM_POOL" in u for u in rec.urls), rec.urls


# ------------------------------------------------------------------ 数据库账户读取


def test_list_accounts_exposes_uid_end_to_end(tmp_path):
    """落库 → list_accounts → 解出 uid 的端到端链路（哨兵解析的上游依赖）。"""
    db = Database(str(tmp_path / "app.db"))
    token = _jwt(uid=5)
    db.execute(
        "INSERT INTO dast_accounts (app_id, account_id, role, tenant, subject, "
        "auth_headers_json, auth_cookies_json, token_ref, metadata_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("workspace-9", "victim", "user", "", "bob", "{}",
         json.dumps({"mall_token": token}), "", "{}", "2026-01-01T00:00:00"),
    )
    accounts = D1Service(db=db).list_accounts("workspace-9")
    assert len(accounts) == 1
    assert accounts[0]["user_id"] == "5"


# ------------------------------------------------------------------ 登记期归一（咽喉点）


def test_registry_normalization_keeps_concrete_value():
    from src.iast.trigger_spec_registry import _normalize_victim_resource_id

    assert _normalize_victim_resource_id("42", "bola") == "42"
    assert _normalize_victim_resource_id(42, "bola") == "42"


@pytest.mark.parametrize("family", [
    "bola", "idor", "vertical_privesc", "cross_module_privesc", "state_machine",
    "race", "calculation_logic", "auth_session", "abuse_dos",
])
def test_registry_normalization_fills_sentinel_for_differential_families(family):
    """所有差分证明族缺值都必须补哨兵——契约规划器路径此前漏写（task-8 16 条空值）。"""
    from src.iast.trigger_spec_registry import _normalize_victim_resource_id

    assert _normalize_victim_resource_id("", family) == SENTINEL
    assert _normalize_victim_resource_id("   ", family) == SENTINEL
    assert _normalize_victim_resource_id(None, family) == SENTINEL


@pytest.mark.parametrize("family", ["sqli", "xss", "deserialization", "generic", "", "template-injection"])
def test_registry_normalization_leaves_non_differential_empty(family):
    """非差分族保持为空：注入族走 canary 重放，绝不被塞入差分就绪哨兵。"""
    from src.iast.trigger_spec_registry import _normalize_victim_resource_id

    assert _normalize_victim_resource_id("", family) == ""


# ---------------------------------------------------- 身份指纹强度（R23-4(c) 假确认防线）


@pytest.mark.parametrize("value,expected", [
    ("3", False), ("1", False), ("12", False), ("999", False), (" 7 ", False),
    ("", False), (None, False), ("   ", False),
    ("1000", True), ("bob", True), ("alice@example.com", True),
    ("550e8400-e29b-41d4-a716-446655440000", True),
])
def test_is_strong_identity_marker(value, expected):
    from src.core.identity_marker import is_strong_identity_marker

    assert is_strong_identity_marker(value) is expected


def test_filter_identity_markers_dedupes_and_drops_weak():
    from src.core.identity_marker import filter_identity_markers

    assert filter_identity_markers(["bob", "3", "bob", "", None, "alice@x.com"]) == ["bob", "alice@x.com"]
    assert filter_identity_markers("bob") == ["bob"]
    assert filter_identity_markers(None) == []
    assert filter_identity_markers({"unexpected": "dict"}) == []


def test_replay_bola_does_not_leak_on_short_numeric_uid(monkeypatch):
    """反证：bob 的 uid 是单位数 3，响应体含数字 3 不得被判为数据泄露（R23-4(c) 事故场景）。"""
    svc = D1Service(db=None)
    rec = _Recorder([DastImpact(reached=True, status_code=200,
                                body='{"amount": 3, "qty": 3, "page": 3}', response_summary="200")])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    result = svc.replay_bola(
        {"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
         "param_location": "path", "victim_resource_id": "7"},
        {"service_url": "http://x"},
        accounts={"attacker": {"role": "user", "username": "alice"},
                  "victim": {"role": "user", "username": "bob", "user_id": "3"}},
    )

    assert result["leaked_victim_identifiers"] == [], "短数字 uid 不得作为泄露指纹"
    assert result["data_leak_confirmed"] is False
    assert result["confirmed"] is False


def test_replay_bola_still_leaks_on_real_username(monkeypatch):
    """正例对照：强指纹（username）仍能判定泄露，防线未把正确判定一起挡掉。"""
    svc = D1Service(db=None)
    rec = _Recorder([DastImpact(reached=True, status_code=200,
                                body='{"owner": "bob", "amount": 3}', response_summary="200")])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    result = svc.replay_bola(
        {"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
         "param_location": "path", "victim_resource_id": "7"},
        {"service_url": "http://x"},
        accounts={"attacker": {"role": "user", "username": "alice"},
                  "victim": {"role": "user", "username": "bob", "user_id": "3"}},
    )

    assert result["leaked_victim_identifiers"] == ["bob"]
    assert result["data_leak_confirmed"] is True


def test_replay_bola_filters_weak_markers_from_spec_list(monkeypatch):
    """spec 自带标识列表里的短数字同样被过滤（来源双检）。"""
    svc = D1Service(db=None)
    rec = _Recorder([DastImpact(reached=True, status_code=200,
                                body='{"amount": 3}', response_summary="200")])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    result = svc.replay_bola(
        {"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
         "param_location": "path", "victim_resource_id": "7",
         "victim_identifiers": ["3", "bob"]},
        {"service_url": "http://x"}, accounts=_accounts(),
    )

    assert result["leaked_victim_identifiers"] == []
    assert result["data_leak_confirmed"] is False


def test_registry_account_identifiers_drop_short_uid():
    from src.iast.trigger_spec_registry import _account_identifiers

    acc = {"role": "user", "subject": "bob", "metadata": {"username": "bob", "uid": 3, "id": 3}}
    assert _account_identifiers(acc) == ["bob"]


def test_register_trigger_spec_filters_weak_markers_at_persistence(tmp_path):
    """落库咽喉点：短数字 uid 不得进入 trigger_specs.victim_identifiers。"""
    from src.iast.service import IastService

    db = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    db.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, "
        "summary_json, error_message, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (1, "task1", "completed", "done", "/tmp/out", "{}", "{}", "", now),
    )
    svc = IastService(db)
    svc.register_trigger_spec({
        "workspace_id": 1, "task_id": 1, "family": "bola", "target_endpoint": "/order/{id}",
        "http_method": "GET", "param_name": "id", "param_location": "path",
        "category": "bola", "business_logic_category": "bola",
        "victim_identifiers": ["3", "bob"],
    })
    row = db.execute("SELECT victim_identifiers FROM trigger_specs", fetchone=True)
    assert Database.loads(row["victim_identifiers"]) == ["bob"]


def test_replay_bola_keeps_long_numeric_uid(monkeypatch):
    """长数字 uid（如 100023）区分度足够，仍可作为泄露指纹——防线只拦明显无区分度的值。"""
    svc = D1Service(db=None)
    rec = _Recorder([DastImpact(reached=True, status_code=200,
                                body='{"ownerId": 100023}', response_summary="200")])
    monkeypatch.setattr(D1Service, "_send_one", rec)

    result = svc.replay_bola(
        {"target_endpoint": "/order/{id}", "http_method": "GET", "param_name": "id",
         "param_location": "path", "victim_resource_id": "7"},
        {"service_url": "http://x"},
        accounts={"attacker": {"role": "user", "username": "alice"},
                  "victim": {"role": "user", "username": "bob", "user_id": "100023"}},
    )

    assert result["leaked_victim_identifiers"] == ["100023"]
    assert result["data_leak_confirmed"] is True
