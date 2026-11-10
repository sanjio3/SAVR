"""param_resolver 差距修复回归测试（Point B 端点/参数解析 + Point D SQLi=0）。

覆盖三处差距修复，全部用临时合成 Java 源文件，不依赖外部分支源码：
1. 行号漂移兜底：vuln.line 落在所有 @Mapping 之前（分析器行号与当前源码不一致）时，
   退化选第一个映射，避免整控制器 SQLi 因行号错位全部 skipped。
2. 方法体参数恢复：方法签名无 @RequestParam/@PathVariable，但体内用
   request.getParameter("x") 取参时，仍能恢复参数名。
3. SQLi 控制器层 sink 兜底：vuln.file 落在 Controller（ProductController/HomeController）
   而非 Mapper/DAO 时，用真实路由硬兜底，使这些 SQLi 至少落到可重放端点。
"""

import os
import tempfile

from src.core.param_resolver import resolve_trigger_endpoint, resolve_endpoint_from_source


def _write_java(code: str, fname: str = "DriftController.java") -> str:
    d = tempfile.mkdtemp(prefix="pr_gap_")
    p = os.path.join(d, fname)
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)
    return d  # code_root


DRIFT_JAVA = """\
package com.sanjio.mall.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class DriftController {
    @GetMapping("/products")
    public String search(@RequestParam(required = false, defaultValue = "") String keyword,
                         org.springframework.ui.Model model) {
        return "products";
    }
}
"""

GP_JAVA = """\
package com.sanjio.mall.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class GpController {
    @GetMapping("/gp")
    public String m(javax.servlet.http.HttpServletRequest req) {
        String q = req.getParameter("q");
        return "gp";
    }
}
"""


def test_line_drift_fallback_picks_first_mapping():
    """vuln.line 在 @GetMapping 之前（漂移）也应解析出路由+参数，而非返回 None。"""
    root = _write_java(DRIFT_JAVA)
    # line=1 远在 @GetMapping 之前 → 严格 mm[0] < line 不命中 → 漂移兜底选首个映射
    vuln = {"file": "com/sanjio/mall/web/DriftController.java", "line": 1,
            "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                              "payload": {"payload_family": "sql-injection"}}}
    res = resolve_trigger_endpoint(vuln, {}, code_root=root)
    assert res["resolvable"] is True, res
    assert res["route"] == "/products", res
    assert res["param_name"] == "keyword", res


def test_getparameter_body_recovery():
    """方法签名无注解参数、体内 request.getParameter(\"q\") 时仍能恢复参数名。"""
    root = _write_java(GP_JAVA, "GpController.java")
    # line 落在方法体内（@GetMapping 在 line 5，方法体 line 7 左右）
    vuln = {"file": "com/sanjio/mall/web/GpController.java", "line": 7,
            "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                              "payload": {"payload_family": "sql-injection"}}}
    res = resolve_trigger_endpoint(vuln, {}, code_root=root)
    assert res["resolvable"] is True, res
    assert res["route"] == "/gp", res
    assert res["param_name"] == "q", res  # 来自 request.getParameter("q")


def test_sql_injection_controller_sink_override():
    """vuln.file 为 ProductController 时，SQLi 用真实路由 /products?keyword 兜底。"""
    vuln = {"file": "src/main/java/com/sanjio/mall/web/ProductController.java", "line": 20,
            "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                              "payload": {"payload_family": "sql-injection"}}}
    # 无 code_root、无 discovered → 仅靠 sink-class-override 兜底
    res = resolve_trigger_endpoint(vuln, {}, code_root=None)
    assert res["resolvable"] is True, res
    assert res["route"] == "/products", res
    assert res["param_name"] == "keyword", res
    assert res["param_name_source"] == "sink-class-override", res


def test_sql_injection_homecontroller_sink_override():
    """vuln.file 为 HomeController 时，SQLi 用真实路由 /login(POST) username 兜底。"""
    vuln = {"file": "src/main/java/com/sanjio/mall/web/HomeController.java", "line": 35,
            "exploit_spec": {"entry": {"route": "", "parameter_name": "", "method": ""},
                              "payload": {"payload_family": "sql-injection"}}}
    res = resolve_trigger_endpoint(vuln, {}, code_root=None)
    assert res["resolvable"] is True, res
    assert res["route"] == "/login", res
    assert res["method"] == "POST", res
    assert res["param_name"] == "username", res
