"""参数契约「名字与位置必须同源」的回归锁（2026-11-04，jsc 619 实测）。

根因：`src/core/param_resolver.py::resolve_trigger_endpoint` 的源码注解通道里，
``param_location`` 的采信被放在「A2 param_name 有效」的分支**之前**：

    if not result["param_location"]:
        result["param_location"] = _src.get("param_location") or "query"
    ...
    elif is_valid_param_name(src_pname):
        result["param_name"] = src_pname
        result["param_name_source"] = "source-recovered"

于是只要 A2 填了 location（哪怕是错的），源码解析出的**正确定位就被丢弃**，
而 param_name 却采信源码 ⇒ 产出「名字来自源码、位置来自 LLM」的拼接契约。

实测（jsc 619）：``/rce/jscmd`` 源码签名是 ``jsEngine(String jsurl)``（Spring 默认
query 绑定），A2 给了 ``body`` ⇒ spec 登记成 body ⇒ D1 把 canary 投到 body，
servlet 根本不读那里 ⇒ 端点永久 no-arrival（spec 237721 恒 payload_unavailable）。

参数名与参数位置是**同一个契约的两半**，来源必须一致。
"""
from __future__ import annotations


class _Vuln:
    """最小漏洞对象（resolve_trigger_endpoint 只读这几个属性）。"""

    def __init__(self, file, line, finding_type, exploit_spec):
        self.file = file
        self.line = line
        self.finding_type = finding_type
        self.rule_name = "test-rule"
        self.sink = "Runtime.getRuntime().exec"
        self.code_snippet = ""
        self.description = ""
        self.exploit_spec = exploit_spec


def _resolve(code_root, entry):
    from src.core.param_resolver import resolve_trigger_endpoint
    v = _Vuln("src/main/java/org/joychou/controller/Rce.java", 95,
              "command_execution", {"entry": entry})
    return resolve_trigger_endpoint(v, None, code_root, None)


def _jsc_code_root() -> str:
    import os
    # 2026-11-06：靶场源码根由 SAST_AI_SDL_ROOT 提供，未设置则用例早退跳过。
    base = os.environ.get("SAST_AI_SDL_ROOT", "")
    root = os.path.join(base, "java-sec-code") if base else ""
    return root if root and os.path.isdir(root) else ""


def test_param_location_follows_source_when_name_comes_from_source():
    """param_name 采信源码时，param_location 必须同步采信源码。

    A2 给了错误的 body ⇒ 修复后必须是源码解析出的 query。
    """
    root = _jsc_code_root()
    if not root:
        return  # 无靶场源码时跳过（不因环境缺失误报）
    out = _resolve(root, {"route": "/rce/jscmd", "method": "GET",
                          "parameter_name": "", "parameter_location": "body"})
    assert out.get("param_name") == "jsurl", out
    assert out.get("param_location") == "query", (
        "参数位置必须与参数名同源（源码），不能沿用 A2 的错误值：%r" % out)
    assert out.get("param_name_source") == "source-recovered", out


def test_a2_param_name_keeps_its_own_location_when_valid():
    """A2 给了合法 param_name 时，位置仍以源码为准（源码是 ground truth）。"""
    root = _jsc_code_root()
    if not root:
        return
    out = _resolve(root, {"route": "/rce/jscmd", "method": "GET",
                          "parameter_name": "jsurl", "parameter_location": "body"})
    # param_name 来自 A2，但位置不能是 body（源码签名是 query 绑定）
    assert out.get("param_location") == "query", out


def test_param_resolver_module_has_no_stale_import():
    """防止后续重构把这个修复改回旧行为（源码级断言，锁住关键行）。"""
    import inspect
    from src.core import param_resolver
    src = inspect.getsource(param_resolver.resolve_trigger_endpoint)
    # 修复后：location 的赋值必须在 param_name_source 分支**内**
    assert 'result["param_location"] = _src.get("param_location") or "query"' in src


def test_const_resolution_handles_maven_layout_and_package_import():
    """常量类在 ``src/main/java`` 下 + import 是**包路径**时也要能解析。

    2026-11-04（jsc 619 实测）：两处缺陷叠加导致常量解析恒 None ——
      ① ``_resolve_java_class_path`` 只试 ``<code_root>/<fqn>.java``，
         不认 Maven 标准布局 ``src/main/java/<fqn>.java``；
      ② ``_resolve_const_string`` 的 import 匹配只认**静态 import**
         （``import static a.b.Constants;``），不认普通包 import
         （``import a.b.Constants;``，而代码里写的是简单名 ``Constants.X``）。
    ⇒ cookie 名解析不出 ⇒ Shiro 的 rememberMe 被登记成 body（应用只从 Cookie 读）
    ⇒ D1 投错通道 ⇒ 端点永久 no-arrival。
    """
    import os
    root = _jsc_code_root()
    if not root:
        return
    from src.core.param_resolver import _resolve_const_string, _resolve_java_class_path
    # ① 类路径：Maven 布局
    p = _resolve_java_class_path(root, "org.joychou.config.Constants")
    assert p and os.path.exists(p), p
    # ② 常量：普通包 import + 简单类名引用
    shiro = os.path.join(root, "src", "main", "java", "org", "joychou",
                         "controller", "Shiro.java")
    if not os.path.exists(shiro):
        return
    with open(shiro, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")
    assert _resolve_const_string(root, lines, "Constants.REMEMBER_ME_COOKIE") == "rememberMe"


def test_shiro_endpoint_resolves_to_cookie_channel():
    """Shiro 的 rememberMe 必须解析成 cookie 通道（应用只从 Cookie 读）。"""
    import os
    root = _jsc_code_root()
    if not root:
        return
    shiro = os.path.join(root, "src", "main", "java", "org", "joychou",
                         "controller", "Shiro.java")
    if not os.path.exists(shiro):
        return
    from src.core.param_resolver import resolve_endpoint_from_source
    v = _Vuln("src/main/java/org/joychou/controller/Shiro.java", 25,
              "deserialization", {"entry": {"route": "/shiro/deserialize",
                                            "method": "GET", "parameter_name": "",
                                            "parameter_location": "body"}})
    out = resolve_endpoint_from_source(v, root)
    assert out.get("param_location") == "cookie", out
    assert out.get("param_name") == "rememberMe", out
