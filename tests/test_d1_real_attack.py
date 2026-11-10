"""D1 真实攻击链路测试（2026-08-29 统一链路落地）。

覆盖三件事：
1. payload 构造归 A2 —— D1 只挑选、不生成；A2 没产出就显式降级。
2. canary 走请求头（I1 请求级关联），真实 payload 走参数位（真攻击）。
3. 账户发现是「机制通用 + 实例发现」，不套模板。
"""

import json
import os
import tempfile

import pytest

from src.iast import attack_context
from src.iast import account_discovery


# ------------------------------------------------------------------ attack_context

def test_normalize_category_maps_business_families():
    assert attack_context.normalize_category("idor") == "bola"
    assert attack_context.normalize_category("race-condition") == "race"
    assert attack_context.normalize_category("workflow-bypass") == "state_machine"
    assert attack_context.normalize_category("privilege-escalation") == "vertical_privesc"


def test_normalize_category_keeps_ordinary_vulns_out_of_business_channel():
    """普通漏洞绝不能被误判成业务族 —— 否则会被送去差分通道而拿不到账户。"""
    for fam in ("sql-injection", "deserialization", "template-injection", "ssrf", "xss"):
        cat = attack_context.normalize_category(fam)
        assert not attack_context.is_business_logic(cat), f"{fam} 被误判为业务族：{cat}"


def test_normalize_category_infers_from_text_when_family_generic():
    vuln = {"type": "越权访问", "title": "平行越权读取他人订单", "description": ""}
    assert attack_context.normalize_category("generic", {}, vuln) == "bola"


def test_select_attack_payloads_prefers_high_impact():
    """真打就要最大威力：high_impact 优先于验证级探测串。"""
    exploit_spec = {
        "payload": {
            "payload_family": "template-injection",
            "verification_payloads": ["{{7*7}}"],
            "high_impact_payloads": ["<#exec cmd>", "${T(java.lang.Runtime).getRuntime().exec(...)}"],
            "candidate_payloads": ["{{7*7}}", "<#exec cmd>"],
        }
    }
    got = attack_context.select_attack_payloads(exploit_spec, "template-injection")
    assert got[0] == "<#exec cmd>"          # 高影响排在最前
    assert "{{7*7}}" in got                  # 探测串保留在后（验证级证据）
    assert got.index("<#exec cmd>") < got.index("{{7*7}}")


def test_select_attack_payloads_filters_placeholders():
    """A2 的占位串不能当攻击载荷投放（否则等于没打）。"""
    exploit_spec = {
        "payload": {
            "payload_family": "deserialization",
            "candidate_payloads": ["base64(serialized_object)"],
            "high_impact_payloads": [],
        }
    }
    assert attack_context.select_attack_payloads(exploit_spec, "deserialization") == []


def test_select_attack_payloads_returns_empty_when_a2_produced_nothing():
    assert attack_context.select_attack_payloads({}, "sql-injection") == []
    assert attack_context.select_attack_payloads({"payload": {"payload_family": "xss"}}, "xss") == []


def test_spec_attack_payloads_reads_both_list_and_db_json():
    """D1 在 DB 回放路径上读到的是 attack_payloads_json 字符串，内存路径是 list，两种都要支持。"""
    assert attack_context.spec_attack_payloads({"attack_payloads": ["p1", "p2"]}) == ["p1", "p2"]
    assert attack_context.spec_attack_payloads(
        {"attack_payloads_json": json.dumps(["p1", "p2"])}
    ) == ["p1", "p2"]
    assert attack_context.spec_attack_payloads({}) == []
    # 损坏的 JSON 不能抛异常，按无 payload 处理（走降级路径）
    assert attack_context.spec_attack_payloads({"attack_payloads_json": "{bad json"}) == []


def test_build_attack_context_carries_payloads_and_category():
    vuln = {
        "type": "sql-injection",
        "exploit_spec": {
            "payload": {
                "payload_family": "sql-injection",
                "high_impact_payloads": ["' UNION SELECT @@version--"],
            }
        },
    }
    ctx = attack_context.build_attack_context(vuln)
    assert ctx["category"] == ""
    assert ctx["attack_payloads"] == ["' UNION SELECT @@version--"]


# ------------------------------------------------------------------ D1 路由

def test_business_logic_category_routes_to_differential_replay(monkeypatch):
    """业务族 + 有账户 → 走 business_logic.verify 的双账户差分，不走 canary 通道。"""
    from src.application.d1_service import D1Service

    called = {}

    def fake_verify(category, spec, target, accounts=None, concurrency=5, gateway=None, db=None):
        called.update({"category": category, "accounts": accounts})
        return {"confirmed": True, "status_code": 200, "response_summary": "leaked victim data"}

    import src.iast.business_logic as bl
    monkeypatch.setattr(bl, "verify", fake_verify)

    spec = {
        "target_endpoint": "/api/order/{id}", "http_method": "GET", "param_name": "id",
        "category": "bola", "victim_resource_id": "1001",
        "taint_marker": "s4st41abcd",
    }
    accounts = {"attacker": {"auth_headers": {"Authorization": "Bearer A"}},
                "victim": {"auth_headers": {"Authorization": "Bearer B"}}}
    target = {"service_url": "http://app.local", "accounts": accounts}

    imp = D1Service().replay(spec, target)
    assert called.get("category") == "bola"
    assert imp.business_logic.get("confirmed") is True
    # 差分结果挂专用字段，不污染 slices
    assert imp.slices == {}


def test_business_logic_without_accounts_falls_back_to_canary_channel(monkeypatch):
    """业务族但拿不到账户时，不能假装差分验证过 —— 回落到普通通道并标记降级。"""
    from src.application.d1_service import D1Service
    import requests

    captured = {}

    def fake_request(method, url, params=None, headers=None, **kw):
        captured.update(params=params or {}, headers=headers or {})
        # 2026-09-28（测试桩对齐）：补 headers，与真实 requests.Response 对齐。
        return type("R", (), {"status_code": 200, "text": "ok", "headers": {}})()

    monkeypatch.setattr(requests, "request", fake_request)
    spec = {"target_endpoint": "/api/order/{id}", "http_method": "GET", "param_name": "id",
            "param_location": "query", "category": "bola", "taint_marker": "s4st41abcd"}
    imp = D1Service().replay(spec, {"service_url": "http://app.local"})
    # 没有账户 → 不进差分通道，走 canary 探针且明确降级
    assert imp.attack_degraded is True
    assert captured["headers"].get("X-SASTAI-Trace") == "s4st41abcd"


# ------------------------------------------------------------------ 账户发现

def test_infer_ownership_detects_missing_check():
    """代码里只有资源字段、没有归属比较 → 判为「无归属校验」（BOLA 假说）。"""
    code = "Order o = repo.findById(id); return o;"
    got = account_discovery.infer_ownership_binding(
        {"param_name": "id", "target_endpoint": "/api/order/{id}"}, source_text=code, param_name="id")
    assert got["has_ownership_check"] is False
    assert got["resource_id_param"] == "id"


def test_infer_ownership_detects_real_check():
    """出现「资源所有者 与 当前用户 的比较」→ 判为已做归属校验，不应报 BOLA。"""
    code = """
    Order o = repo.findById(id);
    if (!o.getOwnerId().equals(currentUser.getId())) { throw new AccessDeniedException(); }
    return o;
    """
    got = account_discovery.infer_ownership_binding(
        {"param_name": "id"}, source_text=code, param_name="id")
    assert got["has_ownership_check"] is True
    assert got["confidence"] in ("high", "medium")
    assert any("getOwnerId" in f for f in got["ownership_fields"])


def test_learn_auth_binding_extracts_bearer_from_login_response():
    got = account_discovery.learn_auth_binding(
        login_response_body='{"access_token":"eyJhbGciOi.abc.def","user":"u1"}')
    assert got["type"] == "bearer"
    assert got["header_name"] == "Authorization"
    assert got["header_value"].startswith("Bearer ")


def test_learn_auth_binding_extracts_cookie_session():
    got = account_discovery.learn_auth_binding(observed_cookies={"JSESSIONID": "abc123"})
    assert got["type"] == "cookie"


def test_learn_auth_binding_never_invents_when_nothing_observed():
    got = account_discovery.learn_auth_binding()
    assert got["type"] == "unknown"
    assert got["learned"] is False


def test_account_spec_is_structured_not_templated():
    """account spec 每应用一份：schema 固定，内容完全是这个应用自己的。"""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({
            "accounts": [
                {"id": "u-low", "role": "attacker", "auth_headers": {"Authorization": "Bearer LOW"}},
                {"id": "u-victim", "role": "victim", "auth_headers": {"Authorization": "Bearer VIC"}},
            ],
            "victim_resource_id": "1001",
        }, fh)
    try:
        got = account_discovery.load_account_spec(path)
        assert len(got["accounts"]) == 2
        assert got["victim_resource_id"] == "1001"
    finally:
        os.unlink(path)


def test_resolve_accounts_merges_spec_and_sast_inference():
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({
            "accounts": [
                {"id": "u-low", "role": "attacker", "token": "LOWTOKEN"},
                {"id": "u-victim", "role": "victim", "token": "VICTOKEN"},
            ],
            "victim_resource_id": "1001",
        }, fh)
    try:
        binding = account_discovery.resolve_accounts(
            vuln={"param_name": "orderId", "target_endpoint": "/api/order/{id}"},
            source_text="Order o = repo.findById(orderId); return o;",
            account_spec_path=path,
        )
        assert binding.ready is True
        assert binding.attacker["auth_headers"]["Authorization"] == "Bearer LOWTOKEN"
        assert binding.victim_resource_id == "1001"
        assert binding.ownership["has_ownership_check"] is False
        assert "account_spec" in binding.sources
        assert "sast_ownership_inference" in binding.sources
    finally:
        os.unlink(path)


def test_resolve_accounts_not_ready_without_spec():
    """拿不到账户就明确不 ready —— 绝不拿假账户假装差分验证过。"""
    binding = account_discovery.resolve_accounts(vuln={"param_name": "id"})
    assert binding.ready is False
    assert binding.sources == []


def test_account_binding_to_trigger_spec_payload():
    binding = account_discovery.AccountBinding(
        attacker={"id": "a", "role": "attacker"},
        victim={"id": "b", "role": "victim"},
        victim_resource_id="42", auth_binding={"type": "bearer"},
    )
    payload = binding.to_trigger_spec_payload()
    assert payload["victim_resource_id"] == "42"
    assert len(payload["accounts"]) == 2
    assert payload["auth_binding"]["type"] == "bearer"


# ------------------------------------------------------------------ 迁移防回归

def test_trigger_specs_new_columns_survive_schema_init():
    """回归防护：trigger_specs 的 5 个攻击列必须在建表后存在。

    历史 bug：迁移块每次初始化都 DROP/RENAME 重建表，新加的列会被永久抹掉，
    导致 register_trigger_spec 插入失败且被调用方 except 吞成 warning（极难排查）。
    """
    import sqlite3
    tmpdir = tempfile.mkdtemp()
    dbpath = os.path.join(tmpdir, "t.db")
    from src.infrastructure.db import Database
    Database(dbpath).connect()
    cols = {r[1] for r in sqlite3.connect(dbpath).execute("PRAGMA table_info(trigger_specs)")}
    for col in ("category", "attack_payloads_json", "accounts_json",
                "victim_resource_id", "auth_binding_json"):
        assert col in cols, f"trigger_specs 缺失列 {col}（迁移块抹列 bug 复发）"


def test_trigger_specs_columns_survive_legacy_rebuild():
    """旧库（session_id NOT NULL）走重建路径时，新列不能丢。"""
    import sqlite3
    tmpdir = tempfile.mkdtemp()
    dbpath = os.path.join(tmpdir, "legacy.db")
    conn = sqlite3.connect(dbpath)
    conn.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "workspace_id INTEGER NOT NULL, session_id INTEGER NOT NULL, task_id INTEGER, "
        "finding_id INTEGER, vulnerability_hash_v2 TEXT NOT NULL DEFAULT '', "
        "family TEXT NOT NULL DEFAULT '', target_endpoint TEXT NOT NULL DEFAULT '', "
        "http_method TEXT NOT NULL DEFAULT 'GET', param_name TEXT NOT NULL DEFAULT '', "
        "param_name_source TEXT NOT NULL DEFAULT 'unknown', param_location TEXT NOT NULL DEFAULT 'query', "
        "content_type TEXT NOT NULL DEFAULT '', principal TEXT NOT NULL DEFAULT '', "
        "taint_marker TEXT NOT NULL DEFAULT '', expected_sink_file TEXT NOT NULL DEFAULT '', "
        "expected_sink_line INTEGER NOT NULL DEFAULT 0, "
        "representative_request_params_json TEXT NOT NULL DEFAULT '{}', "
        "raw_json TEXT NOT NULL DEFAULT '{}', poc_chain_json TEXT NOT NULL DEFAULT '{}', "
        "created_at TEXT NOT NULL, category TEXT NOT NULL DEFAULT '', "
        "attack_payloads_json TEXT NOT NULL DEFAULT '[]')"
    )
    conn.commit()
    conn.close()

    from src.infrastructure.db import Database
    Database(dbpath).connect()
    cols = {r[1] for r in sqlite3.connect(dbpath).execute("PRAGMA table_info(trigger_specs)")}
    for col in ("category", "attack_payloads_json", "accounts_json",
                "victim_resource_id", "auth_binding_json"):
        assert col in cols, f"旧库重建后缺失列 {col}"
