"""2026-11-03 三项修复的回归守卫。

覆盖：
1. `scan_scope.is_vendor_asset` —— 第三方库/构建产物判定（若依 51 条 js 噪声的根因）
2. `payload_library._cmd_injection` + `technique_oracle` 的 cmd_echo 判据
3. `jndi_probe` 的本地回连 + 按 spec 归账（jndi 响应回显不可用，只能靠回连）
"""
from __future__ import annotations

import time

import pytest


# ── 1. 第三方库判定 ────────────────────────────────────────────────────────
@pytest.mark.parametrize("path,expected", [
    # 若依实测的噪声源
    ("ruoyi-admin/src/main/resources/static/ajax/libs/bootstrap-table/bootstrap-table.min.js", True),
    ("ruoyi-admin/src/main/resources/static/ajax/libs/jquery-ztree/3.5/js/jquery.ztree.all-3.5.js", True),
    ("ruoyi-admin/src/main/resources/static/js/jquery.tmpl.js", True),
    ("ruoyi-admin/src/main/resources/static/js/jquery-ui-1.10.4.min.js", True),
    # 业务代码不能被误伤
    ("ruoyi-admin/src/main/resources/static/ruoyi/js/ry-ui.js", False),
    ("ruoyi-system/src/main/resources/mapper/system/SysUserMapper.xml", False),
    ("src/main/java/org/joychou/controller/XSS.java", False),
    ("ruoyi-common/src/main/java/com/ruoyi/common/utils/poi/ExcelUtil.java", False),
    # 相对路径也要能命中（前导斜杠归一）
    ("node_modules/foo/index.js", True),
    ("vendor/lib/x.js", True),
])
def test_is_vendor_asset(path, expected):
    from src.core.scan_scope import is_vendor_asset
    assert is_vendor_asset(path) is expected


def test_filter_vendor_files_accepts_dict_items():
    from src.core.scan_scope import filter_vendor_files
    items = [
        {"rel_path": "src/main/java/A.java"},
        {"rel_path": "static/ajax/libs/x/y.min.js"},
        {"path": "/abs/node_modules/z.js"},
    ]
    kept, dropped = filter_vendor_files(items)
    assert dropped == 2
    assert [k.get("rel_path") or k.get("path") for k in kept] == ["src/main/java/A.java"]


def test_vendor_filter_can_be_disabled(monkeypatch):
    from src.core.scan_scope import is_vendor_asset
    monkeypatch.setenv("SAST_AI_SCAN_VENDOR", "1")
    assert is_vendor_asset("static/ajax/libs/x/y.min.js") is False


# ── 2. 命令执行载荷与判据 ──────────────────────────────────────────────────
def test_cmd_payloads_have_marker_and_full_command_first():
    from src.iast.payload_library import build_family_payloads
    out = build_family_payloads("command_execution", {"param_name": "cmd"})
    assert out["provider"] == "cmd_marker"
    ps = out["payloads"]
    assert ps, "必须产出载荷，否则 D1 仍会 degraded_no_synthesis"
    # 第一发必须是「完整命令」：Runtime.exec(String) 不经过 shell，分隔符变体对它无效
    assert ps[0].startswith("echo sastai_cmd_")
    assert all("sastai_cmd_" in p for p in ps)


def test_cmd_judge_requires_execution_not_reflection():
    from src.iast.payload_library import build_family_payloads
    from src.iast.technique_oracle import detect_technique, judge_attempts

    p = build_family_payloads("command_execution")["payloads"][0]
    marker = p.split("echo ", 1)[1]
    assert detect_technique("command_execution", p) == "cmd_echo"

    # 执行：响应只有命令 stdout
    ok, tech, _ = judge_attempts("command_execution",
                                 [{"attempt_no": 1, "payload": p,
                                   "resp_body_head": "uid=0\n" + marker + "\n"}])
    assert ok and tech == "cmd_echo"

    # 反射：响应是「你输入了 <完整载荷>」——不能算执行
    ok2, _, _ = judge_attempts("command_execution",
                               [{"attempt_no": 1, "payload": p,
                                 "resp_body_head": "you said: " + p}])
    assert not ok2

    # 无回显
    ok3, _, _ = judge_attempts("command_execution",
                               [{"attempt_no": 1, "payload": p, "resp_body_head": "error"}])
    assert not ok3


def test_jndi_payload_points_at_local_listener():
    from src.iast.payload_library import build_family_payloads
    out = build_family_payloads("jndi_injection", {"param_name": "token"})
    if out["provider"] == "unsupported":
        pytest.skip("本地监听不可用（环境限制）")
    assert out["provider"] == "jndi_local"
    assert all("${jndi:" in p or "ndi" in p for p in out["payloads"])
    assert any("127.0.0.1" in p for p in out["payloads"])


# ── 3. jndi 回连按 spec 归账 ───────────────────────────────────────────────
def test_jndi_probe_attributes_hits_per_spec():
    import socket

    from src.iast import jndi_probe
    from src.iast.technique_oracle import judge_attempts

    port = jndi_probe.ensure_listener()
    if not port:
        pytest.skip("无法绑定本地监听")

    jndi_probe.begin_spec(111)
    with socket.create_connection(("127.0.0.1", port), timeout=3):
        pass
    deadline = time.time() + 3
    while time.time() < deadline and not jndi_probe.hits_for(111):
        time.sleep(0.05)

    assert jndi_probe.hits_for(111) >= 1
    # 别的 spec 不能被算上
    assert jndi_probe.hits_for(222) == 0

    payload = "${jndi:ldap://127.0.0.1:%d/a}" % port
    ok, tech, ev = judge_attempts("jndi_injection",
                                  [{"attempt_no": 1, "payload": payload, "resp_body_head": "x"}],
                                  spec_id=111)
    assert ok and tech == "jndi_lookup" and ev.get("connections", 0) >= 1

    ok2, _, _ = judge_attempts("jndi_injection",
                               [{"attempt_no": 1, "payload": payload, "resp_body_head": "x"}],
                               spec_id=222)
    assert not ok2


# ── 4. MyBatis `${}` 参数路径反推（若依 5 条 sql_injection 的根因）───────────
@pytest.mark.parametrize("expr,expected", [
    ("params.dataScope", "params[dataScope]"),
    ("filter.user.id", "filter[user][id]"),
    ("ancestors", "ancestors"),
    ("", ""),
])
def test_mybatis_param_path(expr, expected):
    from src.iast.framework_sinks import _mybatis_param_path
    assert _mybatis_param_path(expr) == expected


def test_nested_param_name_is_valid():
    """`params[dataScope]` 必须被登记层接受，否则参数路径再准也会被 invalid_param_name 跳过。"""
    from src.core.param_resolver import is_valid_param_name as v
    assert v("params[dataScope]") is True
    assert v("filter[user][id]") is True
    # 脏值仍要拒
    assert v("a.b") is False
    assert v("a b") is False
    assert v('a"b') is False
    assert v("x" * 41) is False


def test_mapper_rule_emits_param_path():
    """框架规则必须把 `${params.dataScope}` 转成参数路径带出来。"""
    from src.iast.framework_sinks import _rule_mybatis_dollar
    xml = ('<mapper namespace="x.SysDeptMapper">'
           '<select id="selectDeptList">select * from sys_dept where ${params.dataScope}</select>'
           '</mapper>')
    hits = _rule_mybatis_dollar(xml, "SysDeptMapper.xml")
    assert hits, "mapper 里的 ${} 必须命中"
    assert hits[0].param == "params[dataScope]"


# ── 5. 框架 sink 豁免（XSS.java 的 5 条真值此前连登记都没进）───────────────
def test_spurious_no_sink_exempts_framework_hit():
    from src.iast.property_evidence import spurious_no_sink
    # Spring @ResponseBody 返回字符串：没有 getWriter()/.print(
    code = "public String reflect(String xss) { return \"<div>\" + xss + \"</div>\"; }"
    assert spurious_no_sink(code, "xss") is True          # 无框架证据 ⇒ 仍判捏造
    assert spurious_no_sink(code, "xss", framework_sink=True) is False  # 框架命中 ⇒ 放行


def test_spurious_no_sink_reflective_rce():
    """反射型 RCE 没有 Runtime.exec，但 Class.forName + invoke 是同一后果。"""
    from src.iast.property_evidence import spurious_no_sink
    code = ("Object bean = Class.forName(beanName).newInstance();"
            "Method m = bean.getClass().getDeclaredMethod(methodName);"
            "m.invoke(bean);")
    assert spurious_no_sink(code, "command_execution") is False
    # 只有 forName、没有 invoke ⇒ 不算命令执行
    assert spurious_no_sink("Class.forName(x);", "command_execution") is True


# ── 6. CORS 判据（此前 5 条 spec 全停在 no-arrival）────────────────────────
def test_cors_judged_by_response_header():
    from src.iast.technique_oracle import detect_technique, judge_attempts

    p = "http://sastai-oracle.example.com"
    assert detect_technique("cors", p) == "cors_reflect"
    # ssrf 的载荷也是 URL，但技术不同 —— 族必须能区分
    assert detect_technique("ssrf", p) == "ssrf_echo"

    def judge(hdr):
        return judge_attempts("cors", [{"attempt_no": 100, "payload": p,
                                        "resp_headers_digest": hdr}])[0]

    assert judge("access-control-allow-origin=" + p + ",content-type=application/json") is True
    assert judge("access-control-allow-origin=*,content-type=text/html") is True
    assert judge("access-control-allow-origin=http://127.0.0.1:8080,content-type=text/html") is False
    assert judge("content-type=text/html") is False
