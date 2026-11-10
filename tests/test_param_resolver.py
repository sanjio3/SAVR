"""param_resolver 回归测试。

核心守护点：resolve_trigger_endpoint 在最高优先级（entry_discovery 真实路由）
未命中时，应回退到 Tier1(源码注解)/Tier2(A2 结构化 entry)，都解析不出则返回空字段由调用方跳过。

历史背景：本函数曾有一档「探针实观测请求面（iast_request_params）」，且当时存在
「A2 假说路由匹配不到任何观测路由就静默折叠到观测面第一个端点」的缺陷（会把 20 条 spec
折叠到 /debug/list+limit）。该观测面一档已于 2026-09-01 全链路移除（探针从不发送
request_observed，表内仅扫描器字典盲打噪声，恒为空且已被 Tier0 真实路由取代）。
下列用例保留"不得折叠 / 不得静默兜底"的守护语义，但不再构造观测面输入。
"""

from src.core.param_resolver import (
    build_discovered_route_index,
    is_valid_route,
    resolve_trigger_endpoint,
)


def _vuln(route, param, family="sql"):
    return {
        "exploit_spec": {
            "entry": {
                "route": route,
                "parameter_name": param,
                "method": "GET",
                "parameter_location": "query",
            },
            "payload": {"payload_family": family},
        }
    }


def test_no_silent_fold_when_tier0_misses():
    """A2 路由 /api/quote 未被 entry_discovery 真实路由覆盖时，应使用 A2 自己的端点+参数，
    而非静默折叠到任何无关端点。"""
    # code_root 空、discovered_routes 空 → 走 Tier2（A2 结构化 entry）
    res = resolve_trigger_endpoint(
        _vuln("/api/quote", "id"), code_root=None
    )
    assert res["route"] == "/api/quote", res
    assert res["param_name"] == "id", res
    assert res["param_name_source"] == "a2", res


def test_unmatched_a2_route_not_folded_when_a2_route_present():
    """未命中的 A2 路由不应落到任何其它端点；A2 自带完整端点信息时原样解析。"""
    res = resolve_trigger_endpoint(
        _vuln("/api/secret", "token"), code_root=None
    )
    assert res["route"] == "/api/secret", res
    assert res["param_name"] == "token", res


def test_empty_a2_route_resolves_empty_not_folded():
    """A2 路由为空且无源码可解析时，返回空字段（调用方据此跳过），不静默构造端点。"""
    res = resolve_trigger_endpoint(
        _vuln("", ""), code_root=None
    )
    assert res["route"] == "", res
    assert res["param_name"] == "", res
    assert res.get("resolvable") is False, res


def _entry(sig, params, etype="web_route"):
    return {"entry_type": etype, "signature": sig, "request_params": params}


def test_build_discovered_route_index_normalizes():
    """entry_discovery 实体被规整为归一化路由 + 参数名（Flask <id> → {id}）。"""
    entries = [
        _entry('@GetMapping("/api/order/{id}")', [{"param_name": "id", "param_location": "path"}]),
        _entry('@app.route("/users/<int:uid>")', [{"param_name": "uid", "param_location": "query"}]),
        {"entry_type": "mq_consumer", "signature": "@KafkaListener", "request_params": []},  # 非 web_route 应被忽略
    ]
    idx = build_discovered_route_index(entries)
    assert len(idx) == 2, idx
    routes = {d["route"] for d in idx}
    assert "/api/order/{id}" in routes, routes
    assert "/users/{uid}" in routes, routes  # Flask <int:uid> 已转 {uid}
    by_route = {d["route"]: d for d in idx}
    assert by_route["/users/{uid}"]["method"] == "", by_route  # 无显式 method 时留空


def test_discovered_routes_tier0_precedence():
    """Q1：entry_discovery 真实路由作为 Tier0 优先命中，且取真实参数名。"""
    # A2 假说路由 /api/order/{id} 命中 discovered(/api/order/{id})
    discovered = [
        _entry('@GetMapping("/api/order/{id}")', [{"param_name": "id", "param_location": "path"}]),
    ]
    res = resolve_trigger_endpoint(
        _vuln("/api/order/{id}", "id"),
        code_root=None,
        discovered_routes=discovered,
    )
    assert res["route"] == "/api/order/{id}", res
    assert res["param_name"] == "id", res
    assert res["param_location"] == "path", res
    assert res["param_name_source"] == "a2+discovered", res
    assert res["resolvable"] is True, res


def test_discovered_a2_param_not_in_catalog_falls_to_catalog_first_param():
    """Q1：A2 参数名不在 discovered 参数清单时，取 discovered 真实参数。"""
    discovered = [
        _entry('@GetMapping("/api/order/{id}")', [{"param_name": "orderId", "param_location": "path"}]),
    ]
    # A2 给的参数名 'zzz' 非法 → 应取 discovered 的 orderId
    res = resolve_trigger_endpoint(
        {"exploit_spec": {"entry": {"route": "/api/order/{id}", "parameter_name": "zzz", "method": "GET"},
                          "payload": {"payload_family": "idor"}}},
        code_root=None,
        discovered_routes=discovered,
    )
    assert res["route"] == "/api/order/{id}", res
    assert res["param_name"] == "orderId", res
    assert res["param_name_source"] == "discovered", res


def test_discovered_routes_none_falls_back_to_a2_entry():
    """Q1：未传 discovered_routes 时，回退到 Tier1(源码)/Tier2(A2 结构化 entry) 兜底。"""
    res = resolve_trigger_endpoint(
        _vuln("/api/quote", "id"), code_root=None
    )
    assert res["route"] == "/api/quote", res
    assert res["param_name"] == "id", res


def test_q3b_top_level_entry_route_recovers_unresolvable():
    """Q3(b)：exploit_spec.entry.route 为空，但 top-level entry_route/trigger_route/entry_point
    携带真实入口时，resolve 必须纳入候选，不能再误判 skipped_unresolved。"""
    vuln = {
        "entry_route": "/debug/import",
        "trigger_route": "/api/quote/random",
        "exploit_spec": {
            "entry": {"route": "", "trigger_route": "", "parameter_name": "", "method": ""},
            "payload": {"payload_family": "deserialization"},
        },
    }
    discovered = [_entry('@PostMapping("/debug/import")', [{"param_name": "data", "param_location": "body"}])]
    res = resolve_trigger_endpoint(
        vuln, code_root=None, discovered_routes=discovered
    )
    assert res["resolvable"] is True, res
    assert res["route"] == "/debug/import", res
    assert res["method"] == "POST", res
    assert res["param_name"] == "data", res


def test_q3b_entry_point_string_parsed():
    """Q3(b)：top-level entry_point 形如 'METHOD /path' 应解析为 (route, method) 候选。"""
    vuln = {
        "entry_point": "GET /api/status",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                          "payload": {"payload_family": "path"}},
    }
    discovered = [_entry('@GetMapping("/status")', [{"param_name": "filePath", "param_location": "query"}])]
    res = resolve_trigger_endpoint(
        vuln, code_root=None, discovered_routes=discovered
    )
    assert res["resolvable"] is True, res
    assert res["route"] == "/status", res
    assert res["param_name"] == "filePath", res


def test_q3b_loose_api_prefix_matches():
    """Q3(b)：A2 假说 /api/status 必须能匹配真实路由 /status（Spring 类级 /api 前缀归一化）。"""
    vuln = {
        "entry_point": "GET /api/status",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "filePath", "method": ""},
                          "payload": {"payload_family": "path"}},
    }
    discovered = [_entry('@GetMapping("/status")', [{"param_name": "filePath", "param_location": "query"}])]
    res = resolve_trigger_endpoint(
        vuln, code_root=None, discovered_routes=discovered
    )
    assert res["resolvable"] is True, res
    assert res["route"] == "/status", res
    assert res["param_name"] == "filePath", res


def test_q3b_entry_route_precedes_trigger_route():
    """Q3(b)：多跳漏洞（反序列化链）应以 HTTP 入口点 /debug/import 为重放目标，而非污点触发点
    /api/quote/random——入口优先于触发点。"""
    vuln = {
        "entry_route": "/debug/import",
        "trigger_route": "/api/quote/random",
        "exploit_spec": {"entry": {"route": "", "trigger_route": "/api/quote/random",
                                    "parameter_name": "", "method": ""},
                          "payload": {"payload_family": "deserialization"}},
    }
    discovered = [
        _entry('@PostMapping("/debug/import")', [{"param_name": "data", "param_location": "body"}]),
        _entry('@GetMapping("/api/quote/random")', [{"param_name": "id", "param_location": "query"}]),
    ]
    res = resolve_trigger_endpoint(
        vuln, code_root=None, discovered_routes=discovered
    )
    assert res["route"] == "/debug/import", res
    assert res["param_name"] == "data", res


def test_q3b_no_route_anywhere_stays_unresolved():
    """Q3(b)：A2 任何层级都没有路由/参数信息时，应保持 skipped_unresolved（不注入无效 spec）。"""
    vuln = {
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                          "payload": {"payload_family": "xss"}},
    }
    res = resolve_trigger_endpoint(
        vuln, code_root=None, discovered_routes=[]
    )
    assert res["resolvable"] is False, res
    assert res["route"] == "", res
    assert res["param_name"] == "", res


def test_is_valid_route_rejects_source_paths():
    """is_valid_route 必须拒绝源码路径（.java:118 / D:\\... / com/...），只放行真实 HTTP 路由。"""
    assert is_valid_route("D:\\Users\\x\\OrderService.java:118") is False
    assert is_valid_route("/src/main/java/com/sanjio/mall/OrderService.java") is False
    assert is_valid_route("com/sanjio/mall/controller/AddressController.java") is False
    assert is_valid_route("/Users/x/AddressController.java:34") is False
    assert is_valid_route("/api/order/{id}") is True
    assert is_valid_route("/status") is True


def test_file_basename_recovers_controller_finding():
    """#2 落地：A2 entry 是源码路径（被 is_valid_route 拒掉、candidate 里无真实路由）时，
    用漏洞 file 的 basename 对齐 entry_discovery 的 web_route.file（同控制器），
    回收为可按真实路由重放的 spec（命中/已观测，而非永远 not_hit）。
    这正是 run 23 里 8/9 条 BOLA/IDOR 垃圾 spec（endpoint=file:line）的回收路径。"""
    vuln = {
        "file": "<sdl-root>/target-mall/src/main/java/com/sanjio/mall/controller/AddressController.java",
        "line": 34,
        "exploit_spec": {
            # A2 把源码路径误当 route（run 23 的真实失败形态）
            "entry": {"route": "<sdl-root>/target-mall/src/main/java/com/sanjio/mall/controller/AddressController.java:34",
                      "parameter_name": "", "method": "GET"},
            "payload": {"payload_family": "idor"},
        },
    }
    discovered = [
        {"entry_type": "web_route",
         "signature": '@GetMapping("/api/address/{id}")',
         "request_params": [{"param_name": "id", "param_location": "path"}],
         "file": "src/main/java/com/sanjio/mall/controller/AddressController.java",
         "line": 30},
    ]
    res = resolve_trigger_endpoint(vuln, code_root=None, discovered_routes=discovered)
    assert res["resolvable"] is True, res
    assert res["route"] == "/api/address/{id}", res
    assert res["param_name"] == "id", res
    assert res["param_name_source"] == "discovered-file", res


def test_file_basename_prefers_matching_method():
    """#2：同文件多 web_route 时，优先选 HTTP 方法与 A2 method 一致者（而非盲取第一个）。"""
    vuln = {
        "file": "controller/AddressController.java",
        "line": 34,
        "exploit_spec": {
            "entry": {"route": "controller/AddressController.java:34", "parameter_name": "", "method": "POST"},
            "payload": {"payload_family": "idor"},
        },
    }
    discovered = [
        {"entry_type": "web_route", "signature": '@GetMapping("/api/address/{id}")',
         "request_params": [{"param_name": "id", "param_location": "path"}],
         "file": "controller/AddressController.java", "line": 30},
        {"entry_type": "web_route", "signature": '@PostMapping("/api/address")',
         "request_params": [{"param_name": "body", "param_location": "body"}],
         "file": "controller/AddressController.java", "line": 60},
    ]
    res = resolve_trigger_endpoint(vuln, code_root=None, discovered_routes=discovered)
    assert res["resolvable"] is True, res
    assert res["route"] == "/api/address", res
    assert res["method"] == "POST", res
    assert res["param_name"] == "body", res


# ---------------------------------------------------------------------------
# 路由大小写保真（2026-09-13 事故回归守护）
#
# 事故：build_discovered_route_index 经 _norm_route 把路由全小写化，Tier0 又把该小写值
# 直接写进 trigger_specs.target_endpoint。Spring 的 PathPattern 大小写敏感，于是
# /rce/processbuilder（spec）≠ /rce/ProcessBuilder（真实）→ D1 重放 404 → 永久 no-arrival。
# java-sec-code run 31 实测 22 个端点中 8 个因此 404。
#
# 守护点：route 保真（可直接作 HTTP 路径），route_key 小写（仅供匹配），
# 且 A2 给的小写假说路由必须仍能命中真实路由、并回写为保真大小写。
# ---------------------------------------------------------------------------
def test_route_case_preserved_but_match_is_case_insensitive():
    entries = [
        {"entry_type": "web_route",
         "file": "controller/Rce.java",
         "signature": '@GetMapping("/rce/ProcessBuilder")',
         "request_params": [{"param_name": "code", "param_location": "query"}]},
        {"entry_type": "web_route",
         "file": "controller/XXE.java",
         "signature": '@PostMapping("/xxe/SAXParser/vuln")',
         "request_params": [{"param_name": "xml", "param_location": "body"}]},
    ]
    idx = build_discovered_route_index(entries)
    routes = {d["route"] for d in idx}
    assert "/rce/ProcessBuilder" in routes, routes
    assert "/xxe/SAXParser/vuln" in routes, routes
    # route_key 必须是小写键，供大小写不敏感匹配
    assert {d["route_key"] for d in idx} == {"/rce/processbuilder", "/xxe/saxparser/vuln"}, idx

    # A2 假说给全小写路由：必须命中真实路由，且回写为保真的 /rce/ProcessBuilder
    vuln = _vuln("/rce/processbuilder", "code", family="command")
    res = resolve_trigger_endpoint(vuln, code_root=None, discovered_routes=entries)
    assert res["resolvable"] is True, res
    assert res["route"] == "/rce/ProcessBuilder", res
    assert res["param_name"] == "code", res


def test_route_case_preserved_when_discovered_is_authoritative():
    """保真路由不得因上游大小写差异而被改写；索引 route 必须等于源码注解里的原文。"""
    entries = [
        {"entry_type": "web_route",
         "file": "controller/Deserialize.java",
         "signature": '@RequestMapping("/deserialize/rememberMe/vuln")',
         "request_params": []},
    ]
    idx = build_discovered_route_index(entries)
    assert len(idx) == 1, idx
    assert idx[0]["route"] == "/deserialize/rememberMe/vuln", idx
    assert idx[0]["route_key"] == "/deserialize/rememberme/vuln", idx


# —— 2026-10-01 修复回归守卫 ——
# 根因：方法声明正则要求 `)` 后紧跟 `{`/行尾，导致带 `throws IOException` 的方法（命令注入等靶场几乎全是）
# 无法被识别为方法声明 → method_decl 恒为 None → 兜底②.5 读不到签名 → 参数名解析失败；旧兜底③又把方法体里的
# `process.getInputStream()`（进程输出流）误判为请求体 → 参数回退成 `_body` → D1 把 canary 注入到应用不读取的
# body 位置 → 端点永久 no-arrival、waf_blocked 永不被求值。修复后：方法声明正则容忍 throws；②.5 直接扫描方法体找
# 签名行；③ 锚定到请求对象。下列用例锁定这两条事实。
_JAVA_SEC_CODE_ROOT = "<sdl-root>/java-sec-code/src/main/java"


def _have_java_sec_code():
    import os
    return os.path.isdir(_JAVA_SEC_CODE_ROOT)


def test_command_inject_sec_recovers_param_from_signature_with_throws():
    """/codeinject/sec 的方法签名 `public String codeInjectSec(String filepath) throws IOException`
    带 throws 子句：修复后必须解析出 param_name=filepath / query（而非回退 _body 或留空）。"""
    if not _have_java_sec_code():
        import pytest
        pytest.skip("java-sec-code 源码不在默认路径，跳过")
    vuln = {
        "file": "org/joychou/controller/CommandInject.java",
        "line": 52,
        "family": "command-execution",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                          "payload": {"payload_family": "command"}},
    }
    res = resolve_trigger_endpoint(vuln, code_root=_JAVA_SEC_CODE_ROOT, discovered_routes=None)
    assert res["resolvable"] is True, res
    assert res["route"].endswith("/codeinject/sec"), res
    assert res["param_name"] == "filepath", res
    assert res["param_location"] == "query", res
    assert res["param_name_source"] == "source-recovered", res


def test_command_inject_recovers_param_without_throws_confounder():
    """/codeinject（同样带 throws）也应解析出 filepath，验证修复对整类命令注入生效。"""
    if not _have_java_sec_code():
        import pytest
        pytest.skip("java-sec-code 源码不在默认路径，跳过")
    vuln = {
        "file": "org/joychou/controller/CommandInject.java",
        "line": 25,
        "family": "command-execution",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                          "payload": {"payload_family": "command"}},
    }
    res = resolve_trigger_endpoint(vuln, code_root=_JAVA_SEC_CODE_ROOT, discovered_routes=None)
    assert res["route"].endswith("/codeinject"), res
    assert res["param_name"] == "filepath", res
    assert res["param_location"] == "query", res


def test_saxparser_vuln_still_resolves_request_body():
    """回归守卫：真请求体端点（WebUtils.getRequestBody(request)）必须仍解析为 _body / body，
    不能被「跳过 throws 的方法声明」改动误伤——其签名是 `HttpServletRequest request`，②.5 会跳过 request 入参，
    ③ 命中 getRequestBody 兜底为 _body。"""
    if not _have_java_sec_code():
        import pytest
        pytest.skip("java-sec-code 源码不在默认路径，跳过")
    vuln = {
        "file": "org/joychou/controller/XXE.java",
        "line": 163,
        "family": "xxe",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                          "payload": {"payload_family": "xxe"}},
    }
    res = resolve_trigger_endpoint(vuln, code_root=_JAVA_SEC_CODE_ROOT, discovered_routes=None)
    assert res["route"].endswith("/SAXParser/vuln"), res
    assert res["param_name"] == "_body", res
    assert res["param_location"] == "body", res
