"""②-2 类级路由误判修复回归守卫（2026-09-22）。

背景（run 38 真实数据）：175 条 spec 里有 **41 条** 的 target_endpoint 恰好等于某个控制器的
类级 @RequestMapping 基路径（/ssrf 16 条、/cors 8 条、/jwt 5 条、/deserialize 2 条…），
且 param_name 全为空；其中 40 条的 param_name_source 是 caller-controller-reverse-lookup。

根因：`_METHOD_MAPPING_RE`（@(Get|Post|Put|Delete|Patch|Request)Mapping\\(）同样能匹配
**类级** @RequestMapping，而两处扫描方法级映射的循环都没有排除它 —— 类级注解位于文件最靠前，
于是成为 method_cands[0] / 行号漂移时的 chosen，解析出的 route 就是不可调用的类级基路径。

本文件锁定：类级基路径**绝不得**被当成可调用端点返回。
"""
import os
import tempfile

from src.core.param_resolver import (
    _resolve_controller_route_by_reference,
    resolve_endpoint_from_source,
)


SSRF_JAVA = """\
package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/ssrf")
public class SSRF {

    @GetMapping("/urlConnection/vuln")
    public String urlConnectionVuln(@RequestParam("url") String url) {
        return HttpFetcher.fetch(url);
    }

    @GetMapping("/openStream")
    public String openStream(@RequestParam("url") String url) {
        return HttpFetcher.fetch(url);
    }
}
"""

CORS_JAVA = """\
package org.joychou.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/cors")
public class Cors {

    @GetMapping("/vuln/origin")
    public String vulnOrigin() {
        return WebUtils.render();
    }

    @GetMapping("/sec/crossOrigin")
    public String secCrossOrigin() {
        return "ok";
    }
}
"""

CLASS_ONLY_JAVA = """\
package org.joychou.controller;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/onlybase")
public class OnlyBase {
    // 只有类级 @RequestMapping，没有任何方法级映射 —— 不可调用
}
"""


def _root(files):
    """构造临时 code_root，files 为 {文件名: 源码}。"""
    d = tempfile.mkdtemp(prefix="pr_class_level_")
    for name, code in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write(code)
    return d


class TestReverseLookupNeverReturnsClassBase:
    def test_reverse_lookup_returns_real_subroute(self):
        """漏洞类被 SSRF.java 引用 → 必须返回真实子路由，不是 /ssrf。"""
        root = _root({"SSRF.java": SSRF_JAVA, "HttpFetcher.java": "package x;\npublic class HttpFetcher {}\n"})
        vuln = {"file": "src/main/java/x/HttpFetcher.java", "line": 10, "type": "ssrf"}
        got = _resolve_controller_route_by_reference(vuln, root)
        assert got is not None
        assert got["route"] != "/ssrf", f"返回了类级基路径：{got}"
        assert got["route"].startswith("/ssrf/"), f"应返回真实子路由：{got}"
        # 顺带拿到真实参数名（此前 param_name 全空）
        assert got["param_name"] == "url", got

    def test_reverse_lookup_cors(self):
        root = _root({"Cors.java": CORS_JAVA, "WebUtils.java": "package x;\npublic class WebUtils {}\n"})
        vuln = {"file": "src/main/java/x/WebUtils.java", "line": 5, "type": "cors"}
        got = _resolve_controller_route_by_reference(vuln, root)
        assert got is not None
        assert got["route"] != "/cors", got
        assert got["route"].startswith("/cors/"), got

    def test_controller_with_only_class_level_mapping_is_skipped(self):
        """只有类级 @RequestMapping、无方法级映射 → 路由不可靠，留空（不猜、不锁基路径）。"""
        root = _root({"OnlyBase.java": CLASS_ONLY_JAVA, "Util.java": "package x;\npublic class Util {}\n"})
        vuln = {"file": "src/main/java/x/Util.java", "line": 3}
        assert _resolve_controller_route_by_reference(vuln, root) is None


class TestSourceResolutionNeverReturnsClassBase:
    def test_line_before_all_method_maps_falls_back_to_real_method(self):
        """vuln.line 落在所有方法级映射之前时，兜底选的必须是真实方法映射，不是类级 base。"""
        root = _root({"SSRF.java": SSRF_JAVA})
        got = resolve_endpoint_from_source(
            {"file": "src/main/java/org/joychou/controller/SSRF.java", "line": 8}, root
        )
        assert got is not None
        assert got["route"] != "/ssrf", f"返回了类级基路径：{got}"
        assert got["route"].startswith("/ssrf/"), got

    def test_normal_line_still_resolves_its_own_method(self):
        """正常行号（落在 urlConnectionVuln 之后）仍解析到该方法自己的路由 —— 无回归。"""
        root = _root({"SSRF.java": SSRF_JAVA})
        got = resolve_endpoint_from_source(
            {"file": "src/main/java/org/joychou/controller/SSRF.java", "line": 13}, root
        )
        assert got is not None
        assert got["route"] == "/ssrf/urlConnection/vuln", got
