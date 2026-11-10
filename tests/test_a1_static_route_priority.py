"""静态路由 vs A2 LLM 推断路由的优先级守卫（Q1/Q2，2026-09-11）。

设计约定（round-21-design-plan.md 一、Q1 第 3 条）：
    「A2 不再做首检，改为分析+路由+证明：从 findings 表消费候选，**路由绑定优先走静态
    resolver**（见二），仅歧义情形回落 LLM 推断。」

落地前的实际顺序相反：`resolve_trigger_endpoint` 的候选 ① 是 `exploit_spec.entry.route`
（A2 LLM 假说），候选 ⑤ 才是 `a1_evidence.target_endpoint`（A1 静态事实），且候选按加入
顺序优先 → LLM 猜的路由会盖掉静态确定的路由。

本文件守卫：A1 阶段由 `bind_static_routes` 写入（`route_status == 'static'`）的静态路由，
必须高于 A2 LLM 写的 `entry.route`；未经过静态绑定（无 route_status / static-failed）的
finding 保持原行为，不改变既有优先级。
"""
from src.core.param_resolver import resolve_trigger_endpoint

ORDER_CTRL = "D:/proj/src/main/java/com/demo/OrderController.java"
# 无源码注解可解析、无 entry_discovery 路由 → 只考验候选顺序本身
NO_SOURCE_DIR = "D:/nonexistent-project"


def _vuln(entry_route: str = "", method: str = "POST", param: str = "id"):
    """构造一条 A2 假说：entry 带 route + parameter_name（Tier 2 的触发条件）。"""
    return {
        "type": "IDOR",
        "severity": "HIGH",
        "file": ORDER_CTRL,
        "line": 81,
        "description": "仅凭 id 查询订单，不校验归属",
        "exploit_spec": {
            "entry": {
                "route": entry_route,
                "method": method,
                "parameter_name": param,
                "parameter_location": "query",
            },
            "payload": {},
        },
    }


def _static_evidence(route: str, method: str, status: str = "static"):
    return {
        "business_logic": True,
        "category": "水平越权",
        "family": "idor",
        "target_endpoint": route,
        "http_method": method,
        "vulnerable_param": "id",
        "route_status": status,
    }


def test_static_route_outranks_llm_route():
    """A1 静态路由（/order/{id}）应压过 A2 LLM 猜的 /order/{id}/pay。"""
    res = resolve_trigger_endpoint(
        _vuln(entry_route="/order/{id}/pay", method="POST"),
        _static_evidence("/order/{id}", "GET"),
        code_root=NO_SOURCE_DIR,
    )
    assert res.get("route") == "/order/{id}", res
    assert res.get("method") == "GET", res


def test_llm_route_still_wins_without_static_binding():
    """未经静态绑定的 finding 保持既有行为：A2 结构化 entry 仍作候选 ①。"""
    ev = _static_evidence("/order/{id}", "GET", status="static-failed")
    ev.pop("target_endpoint", None)
    res = resolve_trigger_endpoint(
        _vuln(entry_route="/order/{id}/pay", method="POST"),
        ev,
        code_root=NO_SOURCE_DIR,
    )
    assert res.get("route") == "/order/{id}/pay", res


def test_static_failed_evidence_not_prioritized():
    """route_status='static-failed'（未命中静态路由）不得被提权。"""
    res = resolve_trigger_endpoint(
        _vuln(entry_route="/order/{id}/pay", method="POST"),
        _static_evidence("/order/{id}", "GET", status="static-failed"),
        code_root=NO_SOURCE_DIR,
    )
    assert res.get("route") == "/order/{id}/pay", res


def test_static_evidence_without_status_not_prioritized():
    """历史数据里 a1_evidence.target_endpoint 可能由 LLM 写入，无 route_status 标记时不提权。"""
    ev = _static_evidence("/order/{id}", "GET")
    ev.pop("route_status")
    res = resolve_trigger_endpoint(
        _vuln(entry_route="/order/{id}/pay", method="POST"),
        ev,
        code_root=NO_SOURCE_DIR,
    )
    assert res.get("route") == "/order/{id}/pay", res
