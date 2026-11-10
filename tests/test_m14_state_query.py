"""M14 单测：破坏性闸门持续全批准 + state_query 协议与配置位置。

两张半场，各自的关键纪律：

A. 闸门 —— 「持续全批准」不是删掉闸门，而是**缺省与未知值 fail-open 到 off**。
   旧缺省是 ask_on_risky_tools：hitl 键写了但漏填 approval_mode 就把闸门静默打开，
   真实库里历史累计 19 条 approval_required 全是这个路径造成的。
   显式收紧（ask_on_risky_tools / strict）的语义必须原样保留，只动缺省。

B. state_query —— 业务逻辑族的确认判据是「投攻击前后受害者状态差分」。
   此前全项目只有读侧解析、没有写侧产出，三源全空 → 快照恒 None → 差分恒空，
   那批 unconfirmed 的真因在这。本轮补的是：协议定死、配置位置定死、
   写端点启发式推导（**只出候选，不下结论**，候选必须真发 GET 验过才采信）。
"""
import sys
import os
import types

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.agents import d2_strategy
from src.application import task_service
from src.application import d1_service as d1_service_mod
from src.core.state_query import (
    DEFAULT_DERIVED_CANDIDATE_BUDGET,
    derive_state_query_candidates,
    extract_state_fields,
    normalize_state_query,
    resolve_state_query,
    state_query_applicable,
)


# ───────────────────────── A. 破坏性闸门持续全批准 ─────────────────────────

def test_resolve_default_mode_is_off():
    assert d2_strategy.resolve_approval_mode({}) == "off"
    assert d2_strategy.resolve_approval_mode(None) == "off"
    assert d2_strategy.resolve_approval_mode({"approval_mode": ""}) == "off"
    assert d2_strategy.resolve_approval_mode({"approval_mode": "ASK-HUMAN"}) == "off"


def test_resolve_keeps_explicit_modes():
    assert d2_strategy.resolve_approval_mode({"approval_mode": "off"}) == "off"
    assert d2_strategy.resolve_approval_mode({"approval_mode": "ask_on_risky_tools"}) == "ask_on_risky_tools"
    assert d2_strategy.resolve_approval_mode({"approval_mode": "strict"}) == "strict"


def test_resolve_warns_on_unknown_mode(caplog):
    import logging
    with caplog.at_level(logging.WARNING):
        assert d2_strategy.resolve_approval_mode({"approval_mode": "whatever"},
                                                 logger=d2_strategy.logger) == "off"
    assert "未知 approval_mode" in caplog.text


def test_normalize_approval_mode_on_submit_side():
    # 提交侧同样收敛：None / 空串 / 拼错值都不许漏成「拦」。
    assert task_service.normalize_approval_mode(None) == "off"
    assert task_service.normalize_approval_mode("") == "off"
    assert task_service.normalize_approval_mode("strict") == "strict"
    assert task_service.normalize_approval_mode("ask") == "off"


def test_initial_summary_records_full_approval_policy():
    class _StubService:
        """只补 _build_initial_summary 会调到的 _stage，其余走真实实现。"""
        _build_initial_summary = task_service.TaskService._build_initial_summary

        def _stage(self, name, status):
            return {"name": name, "status": status}

    summary = _StubService()._build_initial_summary({"approval_mode": "off"})
    hitl = summary["hitl"]
    assert hitl["approval_mode"] == "off"
    assert hitl["approval_policy"] == task_service.FULL_APPROVAL_POLICY
    assert "approval_policy_note" in hitl


# ───────────────────────── B. state_query 协议 ─────────────────────────

def test_normalize_str_shape():
    cfg = normalize_state_query("/wallet/balance")
    assert cfg["endpoint"] == "wallet/balance"
    assert cfg["method"] == "GET"
    assert cfg["json_paths"] == []


def test_normalize_dict_shape_and_aliases():
    cfg = normalize_state_query({"url": "/a", "method": "post", "fields": ["x"]})
    assert cfg["endpoint"] == "a"
    assert cfg["method"] == "POST"
    assert cfg["json_paths"] == ["x"]
    assert normalize_state_query({"nope": 1}) is None
    assert normalize_state_query(None) is None
    assert normalize_state_query(123) is None


def test_dict_without_endpoint_is_rejected():
    assert normalize_state_query({"method": "GET"}) is None


def test_extract_json_paths():
    cfg = {"endpoint": "/a", "json_paths": ["data.balance"]}
    assert extract_state_fields('{"data": {"balance": 100}}', cfg) == {"data.balance": 100}


def test_extract_non_json_needs_text_paths():
    cfg = {"endpoint": "/a", "text_paths": [r'"balance":\s*([0-9]+)']}
    assert extract_state_fields('{"balance": 42}', cfg) == {'text:"balance":\\s*([0-9]+)': "42"}


def test_extract_without_paths_on_non_json_returns_none_not_fake():
    # 整段正文做差分会被时间戳/token 淹没，宁可 None 也不猜。
    assert extract_state_fields("<html>2026-10-03</html>", {"endpoint": "/a"}) is None


def test_extract_json_paths_on_non_json_returns_none():
    cfg = {"endpoint": "/a", "json_paths": ["balance"]}
    assert extract_state_fields("<html>x</html>", cfg) is None


def test_applicability_requires_endpoint():
    assert state_query_applicable({"endpoint": "/a"}) is True
    assert state_query_applicable({"endpoint": ""}) is False
    assert state_query_applicable(None) is False
    assert state_query_applicable("str") is False


# ───────────────────────── B2. 配置位置（优先级） ─────────────────────────

def test_priority_spec_top_level():
    spec = {"state_query": {"endpoint": "/top"}}
    cfg, src = resolve_state_query(spec=spec)
    assert src == "spec"
    assert cfg["endpoint"] == "top"


def test_target_beats_raw_json():
    # 既有契约（test_time_blind_latency 已钉）：target 优先于 raw_json 内嵌的 exploit_spec。
    spec = {"raw_json": '{"exploit_spec": {"state_query": {"endpoint": "/x"}}}'}
    target = {"state_query": {"endpoint": "/tgt"}}
    cfg, src = resolve_state_query(spec=spec, target=target)
    assert src == "target"
    assert cfg["endpoint"] == "tgt"


def test_raw_json_exploit_spec_is_read():
    spec = {"raw_json": '{"exploit_spec": {"state_query": {"endpoint": "/deep"}}}'}
    cfg, src = resolve_state_query(spec=spec)
    assert src == "spec_raw_json"
    assert cfg["endpoint"] == "deep"


def test_read_endpoint_is_used_as_state_source():
    spec = {"target_endpoint": "/a"}
    cfg, src = resolve_state_query(spec=spec, read_endpoint="/me")
    assert src == "read_endpoint"
    assert cfg["endpoint"] == "me"


def test_no_config_falls_back_to_derive():
    spec = {"target_endpoint": "/wallet/withdraw", "http_method": "POST"}
    cfg, src = resolve_state_query(spec=spec)
    assert src == "derived"
    assert cfg["endpoint"] in cfg["candidates"]


def test_derive_can_be_disabled():
    cfg, src = resolve_state_query(spec={"target_endpoint": "/wallet/withdraw"}, derive=False)
    assert cfg is None
    assert src == "none"


def test_str_shaped_config_survives_resolve():
    cfg, src = resolve_state_query(spec={"state_query": "/wallet"})
    assert src == "spec"
    assert isinstance(cfg, dict)
    assert cfg["endpoint"] == "wallet"


# ───────────────────────── B3. 写端点启发式（只出候选） ─────────────────────────

@pytest.mark.parametrize("route,expected_in", [
    ("/order/{id}/refund", "/order/{id}"),
    ("/ops/user/delete", "/ops/user"),
    ("/address/delete", "/address"),
    ("/cart/remove", "/cart"),
    ("/wallet/withdraw", "/wallet"),
    ("/profile/update", "/profile"),
])
def test_derive_produces_parent_candidates(route, expected_in):
    cands = derive_state_query_candidates(route)
    assert expected_in in cands
    assert cands[0].startswith("/")


def test_derive_emits_sibling_balance_for_wallet_verbs():
    cands = derive_state_query_candidates("/wallet/withdraw")
    assert "/wallet/balance" in cands


def test_derive_is_deduped_ordered_and_bounded():
    cands = derive_state_query_candidates("/order/123/delete")
    assert len(cands) == len(set(cands))
    assert len(cands) <= 4
    # 顺序稳定：首次出现位置即最终位置
    assert cands == list(dict.fromkeys(cands))


def test_derive_empty_route_returns_empty():
    assert derive_state_query_candidates("") == []
    assert derive_state_query_candidates(None) == []


def test_derive_ranks_explicit_balance_read_first():
    # derived 时候选验证只给 2 次预算，排第三的候选等于不存在。
    # 真实库 /wallet/withdraw 原本排成 ['/wallet', '/balance', '/wallet/balance', ...]，
    # 预算内探的是 /wallet 和几乎必 404 的 /balance —— 这条是那条 bug 的防回归。
    assert derive_state_query_candidates("/wallet/withdraw")[0] == "/wallet/balance"


def test_derive_skips_noise_for_param_paths():
    # /order/{id}/list 这种组合几乎必 404，带参数路径时不该挂读尾白占预算。
    cands = derive_state_query_candidates("/order/{id}/refund")
    assert "/order/{id}" in cands
    assert not any(c.startswith("/order/{id}/") and c != "/order/{id}" for c in cands[:2])


def test_derive_puts_write_route_itself_as_last_resort():
    assert "/seckill" in derive_state_query_candidates("/seckill")


def test_derive_never_invents_endpoint_out_of_nowhere():
    # /foo/bar 这种无从推断的写法，只给父路径，不许编出 /foo/bar/exists
    cands = derive_state_query_candidates("/foo/bar")
    assert "/foo" in cands
    assert all(c.startswith("/foo") for c in cands)


# ───────────────────────── B4. 代价纪律 ─────────────────────────

def test_derived_candidate_budget_is_declared():
    # 候选验证算在 5 次重放预算内，上限必须显式存在且不是 0/放开。
    assert 0 < DEFAULT_DERIVED_CANDIDATE_BUDGET <= 2


def test_d1_service_declares_candidate_budget():
    from src.application.d1_service import _STATE_QUERY_CANDIDATE_BUDGET
    assert 0 < _STATE_QUERY_CANDIDATE_BUDGET <= 2


# ───────────────────────── B5. 快照链路：候选验证必须在真请求上过 ─────────────────────────

class _Resp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text


@pytest.fixture()
def d1():
    from src.application.d1_service import D1Service
    return D1Service.__new__(D1Service)


# 快照链路里 D1Service 调的是模块级 requests.request（不是 self.*），monkeypatch 打这个点。
d1_service_requests = d1_service_mod.requests


def test_snapshot_picks_first_candidate_that_answers(monkeypatch, d1):
    calls = []

    def _req(method, url, **kw):
        calls.append(url)
        if url.endswith("/wallet"):
            return _Resp(404, "")
        return _Resp(200, '{"balance": 100, "orders": 3}')

    monkeypatch.setattr(d1_service_requests, "request", _req)
    cfg = {"endpoint": "wallet", "candidates": ["wallet", "wallet/balance"],
           "method": "GET", "json_paths": []}
    snap = d1._snapshot_observable_state({"auth_cookies": {"a": "1"}}, cfg,
                                         {"service_url": "http://t"}, candidate_budget=2)
    assert snap == {"balance": 100, "orders": 3}
    assert len(calls) == 2  # 第一个 404 被换掉，第二个才采信


def test_snapshot_returns_none_when_all_candidates_fail(monkeypatch, d1):
    monkeypatch.setattr(d1_service_requests, "request",
                        lambda *a, **kw: _Resp(401, "unauthorized"))
    cfg = {"endpoint": "wallet", "candidates": ["wallet", "wallet/balance"],
           "method": "GET", "json_paths": []}
    assert d1._snapshot_observable_state({"auth_cookies": {}}, cfg,
                                         {"service_url": "http://t"}, candidate_budget=2) is None


def test_snapshot_respects_candidate_budget(monkeypatch, d1):
    calls = []

    def _req(method, url, **kw):
        calls.append(url)
        return _Resp(404, "")

    monkeypatch.setattr(d1_service_requests, "request", _req)
    cfg = {"endpoint": "a", "candidates": ["a", "b", "c", "d"], "method": "GET"}
    assert d1._snapshot_observable_state({"auth_cookies": {}}, cfg,
                                         {"service_url": "http://t"}, candidate_budget=2) is None
    assert len(calls) == 2


def test_snapshot_does_not_fake_on_non_json_without_text_paths(monkeypatch, d1):
    monkeypatch.setattr(d1_service_requests, "request",
                        lambda *a, **kw: _Resp(200, "<html>2026-10-03</html>"))
    cfg = {"endpoint": "a", "candidates": ["a"], "method": "GET"}
    assert d1._snapshot_observable_state({"auth_cookies": {}}, cfg,
                                         {"service_url": "http://t"}, candidate_budget=1) is None


def test_snapshot_reads_text_paths_from_html(monkeypatch, d1):
    monkeypatch.setattr(d1_service_requests, "request",
                        lambda *a, **kw: _Resp(200, '{"balance": 42}'))
    cfg = {"endpoint": "a", "candidates": ["a"], "method": "GET",
           "json_paths": [], "text_paths": [r'"balance":\s*([0-9]+)']}
    snap = d1._snapshot_observable_state({"auth_cookies": {}}, cfg,
                                         {"service_url": "http://t"}, candidate_budget=1)
    assert snap == {'text:"balance":\\s*([0-9]+)': "42"}


def test_snapshot_uses_account_credentials(monkeypatch, d1):
    seen = {}

    def _req(method, url, **kw):
        seen.update(kw.get("cookies") or {})
        return _Resp(200, '{"balance": 1}')

    monkeypatch.setattr(d1_service_requests, "request", _req)
    cfg = {"endpoint": "a", "method": "GET"}
    d1._snapshot_observable_state({"auth_cookies": {"sid": "victim"},
                                   "auth_headers": {}}, cfg, {"service_url": "http://t"})
    # 受害者状态必须**用受害者自己的会话**读，否则读到自己的余额等于没差分
    assert seen == {"sid": "victim"}
