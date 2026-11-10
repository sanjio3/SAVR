"""端点解析：靶场控制器非 *Controller.java 命名时的引用反查修复（落地2 漏斗治理）。

java-sec-code 把 REST 控制器命名为 SSRF.java / XSS.java / CommandInject.java，完全没有
*Controller.java 后缀。原 ``_resolve_controller_route_by_reference`` 只 ``rglob("*Controller.java")``，
对这类靶场直接返回空 → util/service 类 sink（HttpUtils 被 SSRF.java 引用）永远 missing_route
（run 24 实测 90 条漏斗主因）。本测试用合成源码锁定修复：

1. 注解感知的控制器发现（*Controller.java 主通道零回归，兜底按 @RestController/@Controller 识别）。
2. 完整类名精确引用优先于去后缀别名（避免 Http→HttpURLConnection 误中 /codeinject）。
3. 多控制器共用工具类且无族名匹配时返回 None（歧义守卫，宁漏不误）。
4. 族名 ↔ 控制器名匹配时跨多引用择优（jsonp 族 → Jsonp.java 而非 CommandInject）。
"""

import os
import tempfile

from src.core.param_resolver import resolve_trigger_endpoint


def _mkroot(files: dict) -> str:
    d = tempfile.mkdtemp(prefix="pr_ctrlname_")
    for fname, code in files.items():
        with open(os.path.join(d, fname), "w", encoding="utf-8") as f:
            f.write(code)
    return d


_COMMON_IMPORTS = (
    "import org.springframework.web.bind.annotation.*;\n"
    "import org.springframework.stereotype.*;\n"
)

SSRF_JAVA = (
    "package org.joychou.controller;\n"
    + _COMMON_IMPORTS
    + "import org.joychou.util.HttpUtils;\n"
    "@RestController\n@RequestMapping(\"/ssrf\")\n"
    "public class SSRF {\n"
    "    @PostMapping(\"/urlConnection/vuln\")\n"
    "    public String vuln(String url) { return HttpUtils.URLConnection(url); }\n"
    "}\n"
)

HTTPUTILS_JAVA = (
    "package org.joychou.util;\n"
    "public class HttpUtils {\n"
    "    public static String URLConnection(String url) { return new java.net.URL(url).toString(); }\n"
    "}\n"
)

XSS_JAVA = (
    "package org.joychou.controller;\n"
    + _COMMON_IMPORTS
    + "@RestController\n@RequestMapping(\"/xss\")\n"
    "public class XSS {\n"
    "    @GetMapping(\"/reflect\")\n"
    "    public String reflect(String input) { return input; }\n"
    "}\n"
)

COMMANDINJECT_JAVA = (
    "package org.joychou.controller;\n"
    + _COMMON_IMPORTS
    + "import org.joychou.util.WebUtils;\n"
    "@RestController\n@RequestMapping(\"/codeinject\")\n"
    "public class CommandInject {\n"
    "    @GetMapping(\"/run\")\n"
    "    public String run() { return WebUtils.convertStreamToString(null); }\n"
    "}\n"
)

JSONP_JAVA = (
    "package org.joychou.controller;\n"
    + _COMMON_IMPORTS
    + "import org.joychou.util.WebUtils;\n"
    "@RestController\n@RequestMapping(\"/jsonp\")\n"
    "public class Jsonp {\n"
    "    @GetMapping(\"/cb\")\n"
    "    public String cb(String callback) { return WebUtils.json2Jsonp(callback, \"{}\"); }\n"
    "}\n"
)

WEBUTILS_JAVA = (
    "package org.joychou.util;\n"
    "public class WebUtils {\n"
    "    public static String convertStreamToString(java.io.InputStream is) { return \"\"; }\n"
    "    public static String json2Jsonp(String callback, String jsonStr) { return callback + jsonStr; }\n"
    "}\n"
)


def _mk_java_sec_code_root():
    return _mkroot({
        "SSRF.java": SSRF_JAVA,
        "HttpUtils.java": HTTPUTILS_JAVA,
        "XSS.java": XSS_JAVA,
        "CommandInject.java": COMMANDINJECT_JAVA,
        "Jsonp.java": JSONP_JAVA,
        "WebUtils.java": WEBUTILS_JAVA,
    })


def test_ssrf_util_resolves_to_ssrf_controller():
    """HttpUtils（util，无 @RequestMapping）被 SSRF.java 引用 → 解析到 /ssrf（精确类名优先）。"""
    root = _mk_java_sec_code_root()
    vuln = {
        "file": os.path.join(root, "HttpUtils.java"), "line": 2,
        "finding_family": "ssrf", "display_family": "ssrf",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""}},
        "a1_evidence": {},
    }
    res = resolve_trigger_endpoint(vuln, {}, code_root=root)
    assert res["resolvable"] is True, res
    assert res["route"].startswith("/ssrf"), res
    assert res["param_name_source"] == "caller-controller-reverse-lookup", res


def test_webutils_xss_ambiguous_stays_missing():
    """WebUtils 被多个不相关控制器共用、且无控制器名匹配 xss 族 → 歧义守卫返回 missing_route。"""
    root = _mk_java_sec_code_root()
    vuln = {
        "file": os.path.join(root, "WebUtils.java"), "line": 2,
        "finding_family": "xss", "display_family": "xss",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""}},
        "a1_evidence": {},
    }
    res = resolve_trigger_endpoint(vuln, {}, code_root=root)
    assert res["resolvable"] is False, res
    assert res["resolution_failure"] == "missing_route", res


def test_webutils_jsonp_family_resolves_to_jsonp():
    """jsonp 族 + WebUtils（json2Jsonp 是 JSONP XSS sink）→ 跨多引用择优到 /jsonp。"""
    root = _mk_java_sec_code_root()
    vuln = {
        "file": os.path.join(root, "WebUtils.java"), "line": 3,
        "finding_family": "jsonp", "display_family": "jsonp",
        "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""}},
        "a1_evidence": {},
    }
    res = resolve_trigger_endpoint(vuln, {}, code_root=root)
    assert res["resolvable"] is True, res
    assert res["route"].startswith("/jsonp"), res
