"""本轮（2026-11-04）三层修复的回归锁。

覆盖三组改动：

1. **D2 判据层**
   - `expr_eval`：SpEL / QLExpress 算术求值（结果出现 + 原表达式不出现）
   - `jsonp_reflect`：JSONP callback 非法标识符反射
   - `cmd_script`：脚本引擎（JS/Groovy）形态的命令执行
   - `csrf_statechange` 收紧：必须含「状态变更被接受」的语义证据
     （否则任何 POST 端点返回 200 都会被误判成 CSRF）
2. **D2 归属校验**：sink 文件不拥有该端点 ⇒ 判据命中也不确认
3. **A2 载荷层**：spel_injection / expression_injection / jsonp_referer 三族
   从「无内置载荷生成器」变成有弹药（此前恒零重放）
"""
from __future__ import annotations

import os

from src.iast.payload_library import build_family_payloads
from src.iast.technique_oracle import detect_technique, judge_attempts


def _att(payload, body="", headers="", status=200, method="GET"):
    return {"attempt_no": 1, "payload": payload, "resp_body_head": body,
            "resp_headers_digest": headers, "status_code": status,
            "http_method": method, "elapsed_ms": 20}


# ── 1. D2 判据层 ─────────────────────────────────────────────────────────

def test_expr_eval_confirms_arithmetic_result():
    """SpEL 裸表达式求值 ⇒ 响应出现 49 且不含原表达式。"""
    ok, tech, _ = judge_attempts("spel_injection", [_att("7*7", "49")])
    assert ok and tech == "expr_eval"


def test_expr_eval_confirms_template_form():
    """SpEL 模板模式（#{7*7}）同样能求值。"""
    ok, tech, _ = judge_attempts("spel_injection", [_att("#{7*7}", "49")])
    assert ok and tech == "expr_eval"


def test_expr_eval_rejects_pure_reflection():
    """只是把载荷反射回来（原文还在）⇒ 不算求值，不确认。"""
    ok, _tech, _ = judge_attempts("spel_injection", [_att("7*7", "7*7")])
    assert not ok


def test_expr_eval_works_for_expression_injection():
    """QLExpress 同形态：表达式引擎族共用 expr_eval 判据。"""
    ok, tech, _ = judge_attempts("expression_injection", [_att("7*7", "49")])
    assert ok and tech == "expr_eval"


def test_jsonp_reflect_confirms_illegal_callback():
    """非法 JSONP 标识符被原样写进响应开头 ⇒ callback 注入成立。"""
    pay = "<sastaijsonpabc>("
    ok, tech, _ = judge_attempts(
        "jsonp_referer", [_att(pay, pay + '{"a":1}')])
    assert ok and tech == "jsonp_reflect"


def test_jsonp_reflect_rejects_normal_response():
    """callback 未被反射（响应以 null( 开头）⇒ 不确认。"""
    ok, _tech, _ = judge_attempts(
        "jsonp_referer", [_att("<sastaijsonpabc>(", 'null({"a":1})')])
    assert not ok


def test_cmd_script_confirms_script_eval_result():
    """脚本引擎求值结果回显 ⇒ 命令执行成立。"""
    pay = "java.lang.System.getProperty('java.version')+'sastai_cmd_abc123'"
    ok, tech, _ = judge_attempts("command_execution", [_att(pay, "11.0.16sastai_cmd_abc123")])
    assert ok and tech == "cmd_script"


def test_cmd_script_confirms_script_engine_exception():
    """脚本引擎编译异常 ⇒ 「确实进了脚本引擎」也是硬观测。"""
    pay = "java.lang.System.getProperty('x')+'sastai_cmd_abc123'"
    body = "org.codehaus.groovy.control.MultipleCompilationErrorsException"
    ok, tech, _ = judge_attempts("command_execution", [_att(pay, body)])
    assert ok and tech == "cmd_script"


def test_cmd_script_not_confused_with_shell_marker():
    """脚本形态与 shell 形态必须走不同判据。"""
    assert detect_technique("command_execution", "echo sastai_cmd_abc123") == "cmd_echo"
    assert detect_technique(
        "command_execution",
        "java.lang.System.getProperty('x')+'sastai_cmd_abc123'") == "cmd_script"


def test_csrf_requires_state_change_semantics():
    """CSRF 判据收紧：响应须含「状态变更被接受」的语义证据。"""
    ok, tech, _ = judge_attempts(
        "csrf", [_att("", "CSRF passed.", method="POST")])
    assert ok and tech == "csrf_statechange"


def test_csrf_rejects_unrelated_post_endpoint():
    """反证（jsc 617 spec 237752）：XXE 端点 POST 返回 200 不等于 CSRF 漏洞。"""
    ok, _tech, _ = judge_attempts(
        "csrf", [_att("", "xxe except", method="POST")])
    assert not ok


def test_csrf_rejects_plain_2xx_without_semantics():
    """无任何语义证据的 2xx ⇒ 不确认（2xx 只说明没被拦，不说明状态被改）。"""
    ok, _tech, _ = judge_attempts(
        "csrf", [_att("", '{"some":"json"}', method="POST")])
    assert not ok


def test_csrf_still_rejects_guard_pages():
    """防护拦截页（403 语义）仍不确认。"""
    ok, _tech, _ = judge_attempts(
        "csrf", [_att("", "Access denied", method="POST")])
    assert not ok


# ── 2. D2 归属校验 ───────────────────────────────────────────────────────

def test_ownership_rejects_sink_file_not_owning_endpoint():
    """sink 文件不拥有该端点 ⇒ 判据命中也不得确认（归属错误）。"""
    from src.cli.benchmark_cli import _endpoint_owner_matches
    owners = {"/cors/vuln/origin": {"cors.java"}}
    assert _endpoint_owner_matches(
        owners, "/cors/vuln/origin", "org/joychou/filter/OriginFilter.java") is False
    assert _endpoint_owner_matches(
        owners, "/cors/vuln/origin", "org/joychou/controller/Cors.java") is True


def test_ownership_fails_open_when_endpoint_unknown():
    """端点不在索引里 ⇒ 无法判定 ⇒ fail-open 放行（不误杀）。"""
    from src.cli.benchmark_cli import _endpoint_owner_matches
    assert _endpoint_owner_matches({}, "/x/y", "A.java") is None
    assert _endpoint_owner_matches(
        {"/a/b": {"a.java"}}, "/unknown", "a.java") is None


def test_ownership_ignores_path_prefix_difference():
    """归属校验只比 basename（绝对/相对路径前缀不一致是常态）。"""
    from src.cli.benchmark_cli import _endpoint_owner_matches
    owners = {"/x": {"cors.java"}}
    assert _endpoint_owner_matches(
        owners, "/x", "D:\\abs\\path\\CORS.java") is True


def test_family_sink_line_rejects_wrong_family_line():
    """族-行一致性：xss 族登记在 logger 行（L20）⇒ 明确冲突 ⇒ 否决。

    jsc 617 spec 237715：token 同时喂给 logger.error（L20，JNDI sink）与
    return token（L21，XSS sink），A1 把 xss 族登记在 L20。
    """
    from src.cli.benchmark_cli import _family_sink_line_consistent
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    fake = os.path.join(root, "data", "_wb_fake_src", "Log4j.java")
    os.makedirs(os.path.dirname(fake), exist_ok=True)
    with open(fake, "w", encoding="utf-8") as fh:
        fh.write("public class Log4j {\n"
                 "    public String log4j(String token) {\n"
                 "        logger.error(token);\n"
                 "        return token;\n"
                 "    }\n"
                 "}\n")
    try:
        assert _family_sink_line_consistent(
            "xss", fake, 3, root) is False        # logger 行 → 与 xss 冲突
        assert _family_sink_line_consistent(
            "jndi_injection", fake, 3, root) is True   # logger 行 → 匹配 jndi
        assert _family_sink_line_consistent(
            "xss", fake, 4, root) is True        # return 行 → 匹配 xss
    finally:
        try:
            os.remove(fake)
            os.rmdir(os.path.dirname(fake))
        except OSError:
            pass


def test_family_sink_line_fails_open_on_unknown():
    """读不到源码 / 族无规则 ⇒ None（fail-open，不误杀）。"""
    from src.cli.benchmark_cli import _family_sink_line_consistent
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert _family_sink_line_consistent(
        "xss", "no/such/File.java", 10, root) is None
    assert _family_sink_line_consistent(
        "some_unknown_family", "no/such/File.java", 10, root) is None


# ── 3. A2 载荷层 ─────────────────────────────────────────────────────────

def test_new_families_have_payload_generators():
    """这三族此前「无内置载荷生成器」⇒ 恒零重放（jsc 617 layer1 实测）。"""
    for fam in ("spel_injection", "expression_injection", "jsonp_referer"):
        out = build_family_payloads(fam, {"param_name": "value",
                                          "param_location": "query"})
        assert out["provider"] not in ("none", "error"), (fam, out)
        assert out["payloads"], (fam, out)


def test_spel_payloads_are_side_effect_free():
    """表达式族不得投会执行命令的载荷。"""
    out = build_family_payloads("spel_injection", {"param_name": "value"})
    for p in out["payloads"]:
        low = p.lower()
        assert "runtime" not in low and "exec" not in low, p


def test_command_execution_keeps_script_engine_variants():
    """脚本引擎形态的弹不能被 MAX_PAYLOADS_PER_SPEC 截掉。"""
    out = build_family_payloads("command_execution", {"param_name": "cmd"})
    techs = [detect_technique("command_execution", p) for p in out["payloads"]]
    assert "cmd_script" in techs, techs


def test_cors_ssti_xss_have_family_payload_generators():
    """cors / ssti / xss 三族此前「无内置载荷生成器」⇒ 只能投 canary。

    后果是判据拿不到「真载荷形态」的证据：`xss_reflected` 要求响应体含**原始标签载荷**，
    而 canary 不是标签 ⇒ 恒不命中（jsc 619 日志：
    `[no-send:no_payload] GET /xss/reflect ... 载荷库=该族无内置载荷生成器：xss`）。
    """
    for fam in ("cors", "ssti", "xss"):
        out = build_family_payloads(fam, {"param_name": "value"})
        assert out["provider"] not in ("none", "error", "unsupported"), (fam, out)
        assert out["payloads"], (fam, out)


def test_xss_payloads_are_real_tags():
    """XSS 载荷必须是真标签（应用转义 `<` 时判据才认得出来）。"""
    out = build_family_payloads("xss", {"param_name": "xss"})
    for p in out["payloads"]:
        assert "<" in p and ">" in p, p


def test_cors_payload_carries_identifiable_marker():
    """CORS 载荷必须带可辨识片段，才能在 ACAO 头里被确定性识别。"""
    out = build_family_payloads("cors", {"param_name": "origin"})
    assert any("sastai" in p for p in out["payloads"]), out


def test_ssti_payloads_cover_multiple_template_syntaxes():
    """不同模板引擎语法不同，算术求值探针要覆盖多种形态。"""
    out = build_family_payloads("ssti", {"param_name": "template"})
    joined = " ".join(out["payloads"])
    assert "7*7" in joined, out
    assert "${" in joined or "{{" in joined or "#{" in joined, out


# ── 4. 后续环节不得推翻技术判据 ───────────────────────────────────────────

def test_technique_proven_is_an_arrived_state():
    """`technique-proven` 必须算到达态，否则族路由会把它当非到达态改写标签。

    jsc 619 spec 237863：technique-oracle postpass 写了 `iast_state='technique-proven'`，
    但 `technique-proven` 不在 `_ARRIVED_IAST_STATES` 里 ⇒ 后续轮的族路由 postpass
    走 else 分支把标签改写成 `family-route:*`，把刚确认的结果覆盖掉。
    """
    from src.cli.benchmark_cli import _ARRIVED_IAST_STATES
    assert "technique-proven" in _ARRIVED_IAST_STATES


def test_family_route_must_not_override_technique_verdict():
    """族路由遇到「技术判据已确认」的 spec 必须跳过，不得改判。

    事故链（jsc 619 spec 237863）：A1 把 XSS 端点标了 capability_family='secure_cookie'
    （该端点从 Cookie 读值 ⇒ 命中「样板 Cookie」误标）⇒ 它进了族路由的 capability 候选
    ⇒ 族路由按 secure_cookie 判定，把技术判据已确认的 spec 改判成 unconfirmed。
    """
    import inspect
    from src.cli import benchmark_cli as B
    src = inspect.getsource(B._apply_family_route_postpass)
    assert "technique_evidence" in src, "族路由必须检查 technique_evidence"
    assert "族路由不改判" in src or "不得改判" in src or "无权改判" in src


def test_confirmation_gate_must_not_downgrade_technique_verdict():
    """确认态硬闸遇到技术判据已确认的 spec 必须放行（保护已前移到闸门判定之前）。"""
    import inspect
    from src.cli import benchmark_cli as B
    src = inspect.getsource(B._apply_confirmation_gate)
    # 保护必须出现在 _confirm_gate_decide 调用**之前**
    idx_tech = src.find('technique_evidence')
    idx_decide = src.find("_confirm_gate_decide(")
    assert idx_tech != -1, src[:400]
    assert idx_tech < idx_decide, (
        "技术判据的放行必须前移到 _confirm_gate_decide 之前，"
        "否则硬闸判 False 时走不到放行分支")
