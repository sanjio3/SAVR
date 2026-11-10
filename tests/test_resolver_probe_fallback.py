"""回归测试：探针归因误报 + 源码路经当路由 的修复（#2 / Q1）。

覆盖：
- A2 把 xxe/ssrf/command-execution/deserialization 误归到 IAST 探针控制器
  (FrameworkProbeController) 时，resolve_trigger_endpoint 必须按 family 回退到真实业务入口，
  而非锁到 /api/fw/dubbo、/api/fw/redis 等探针调试端点。
- is_valid_route 必须拒绝源码路经（OrderService.java:118 之类），使注册 gate 能据此跳过。
"""
import pytest

from src.core.param_resolver import resolve_trigger_endpoint, is_valid_route

PROBE = "src/main/java/com/sanjio/mall/web/FrameworkProbeController.java"


def _vuln(fam, eroute, pname):
    return {
        "type": fam,
        "file": PROBE,
        "line": 58,
        "exploit_spec": {
            "entry": {"route": eroute, "parameter_name": pname, "method": "GET"},
            "payload": {"payload_family": fam},
        },
    }


@pytest.mark.parametrize("fam,eroute,pname,expect_route,expect_param", [
    ("xxe", "/api/fw/dubbo", "name", "/order/import-xml", "xml"),
    ("ssrf", "/api/fw/dubbo", "name", "/profile/avatar-from-url", "url"),
    ("command-execution", "/api/fw/redis", "key", "/admin/ping", "host"),
    ("deserialization", "/api/fw/dubbo", "data", "/profile/import", "data"),
])
def test_probe_attributed_resolves_to_real_route(fam, eroute, pname, expect_route, expect_param):
    r = resolve_trigger_endpoint(_vuln(fam, eroute, pname), {}, code_root=None, discovered_routes=None)
    assert r.get("resolvable") is True
    assert r.get("route") == expect_route, r
    assert r.get("param_name") == expect_param, r
    assert "probe" not in r.get("route", "")


def test_is_valid_route_rejects_source_path():
    assert is_valid_route("/order/import-xml") is True
    assert is_valid_route("OrderService.java:118") is False
    assert is_valid_route("d:\\x\\y\\orderservice.java:131") is False
    # /api/fw/* 是合法 HTTP 路径但属探针端点：is_valid_route 只判格式，探针判定由 _is_probe_route 负责
    assert is_valid_route("/api/fw/dubbo") is True
