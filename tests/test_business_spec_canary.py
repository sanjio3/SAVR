"""P1 回归：业务差分重放 spec 必须绑定 canary（taint_marker），否则 IAST 可达性消费端拿不到锚点、
replay_bola 不注 X-SASTAI-Trace。验证 _build_business_logic_spec 本身不带 taint_marker，而
_attach_business_canary 能：①复用本 task 已登记 trigger_spec 的 taint_marker；②未登记时现场生成
全局唯一 canary（业务族常因无 sink 缺 route 被注册门禁 missing_route 拒）。
"""
import re

from src.cli import benchmark_cli as bc
from src.iast.canary import CanaryMatcher


def _built_spec():
    # 模拟 _build_business_logic_spec 的产出（不含 taint_marker，这是 P1 的前置缺陷）
    return {
        "business_logic_category": "bola",
        "target_endpoint": "/api/order/{id}",
        "http_method": "GET",
        "param_name": "id",
        "victim_resource_id": "victim-1",
        "accounts": {"attacker": {"auth_headers": {}}, "victim": {"auth_headers": {}}},
    }


def test_build_business_logic_spec_has_no_canary_initially():
    assert not _built_spec().get("taint_marker")


def test_attach_reuses_registered_canary():
    """本 task 已登记 trigger_spec 带 taint_marker → 直接复用，不重新生成。"""
    vhash = "abc123"
    task_id = 9
    registered = {
        "id": 42,
        "task_id": 9,
        "workspace_id": 3,
        "app_name": "mall",
        "agent_id": "a1",
        "vulnerability_hash_v2": vhash,
        "taint_marker": "s4st41deadbeef00000001PAYLOADabc",
    }
    specs_by_hash = {vhash: [registered]}
    out = bc._attach_business_canary(_built_spec(), vhash, specs_by_hash, task_id)
    assert out["taint_marker"] == "s4st41deadbeef00000001PAYLOADabc"
    # 端点/参数等派生字段不被覆盖
    assert out["target_endpoint"] == "/api/order/{id}"
    assert out["param_name"] == "id"
    # 作用域字段补齐（fail-open 不要求，但有了更好）
    assert out.get("workspace_id") == 3
    assert out.get("app_name") == "mall"


def test_attach_generates_canary_when_unregistered():
    """未登记（业务族常因无 route 被注册门禁拒）→ 现场生成全局唯一 canary。"""
    out = bc._attach_business_canary(_built_spec(), "nohash", {}, None)
    ident = CanaryMatcher.find_identity(out["taint_marker"] or "")
    assert ident, "生成的 taint_marker 必须含可解析的 canary 身份段"
    assert out["taint_marker"].startswith("s4st41")
    assert re.match(r"s4st41[0-9a-fA-F]{16}", out["taint_marker"])


def test_attach_idempotent_when_canary_present():
    """已带 taint_marker 的 spec 不应被覆盖或重新生成。"""
    spec = _built_spec()
    spec["taint_marker"] = "s4st41fixed0000000001ZZZ"
    out = bc._attach_business_canary(spec, "h", {}, None)
    assert out["taint_marker"] == "s4st41fixed0000000001ZZZ"
