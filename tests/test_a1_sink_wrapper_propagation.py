"""跨文件 sink 包装方法传播 回归测试（R25#11）。

背景：SSRF / 命令注入的 sink 常被封装进项目内工具类（HttpFetcher.fetch / CmdUtil.run），
调用方 Controller 文件内不含任何 sink 文本 → 逐文件 sink 匹配只在「工具类」出条，
而真正带 HTTP 入口、可验证的「调用点」被漏报（#11 SSRF /admin/fetch 即此类）。

覆盖：
- 从全量文件自动学出「含 sink 的方法」，不硬编码任何靶场类名。
- 调用点被回标同族，且行号落在调用行（可被路由解析绑定到真路由）。
- 只传播确定性族（XSS / open-redirect 等上下文相关族不传播）。
- 只认限定调用 ClassName.method(；裸方法名调用不传播，避免跨类同名误伤。
- 不传 sink_wrappers 时行为与历史完全一致（向后兼容）。
- 端到端：靶场 AdminController 第 56 行（HttpFetcher.fetch）→ /admin/fetch?url=。
"""
import os
import unittest
from pathlib import Path

from src.agents.a1_injection_heuristic import (
    analyze_content,
    analyze_files,
    build_sink_wrappers,
)

# 工具类：sink 本体（new URL / openConnection）
UTIL_SRC = """
package com.example.util;
import java.net.HttpURLConnection;
import java.net.URL;
public final class HttpFetcher {
    public static String fetch(String targetUrl) {
        URL url = new URL(targetUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        return "ok";
    }
}
"""

# 调用方：Controller，文件内无任何 sink 文本
CTRL_SRC = """
package com.example.web;
import com.example.util.HttpFetcher;
@Controller
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/fetch")
    @ResponseBody
    public String fetch(@RequestParam String url) {
        return HttpFetcher.fetch(url);
    }
}
"""

# 非传播族：XSS（innerHTML）不在 _PROPAGATABLE_FAMILIES 内
XSS_UTIL_SRC = """
package com.example.util;
public class HtmlRender {
    public static String render(String s) {
        return "<div>" + s + "</div>";
    }
}
"""
XSS_CALLER_SRC = """
package com.example.web;
public class PageController {
    public String page(String s) {
        return HtmlRender.render(s);
    }
}
"""

CODE_ROOT = r"<sdl-root>/target-mall"


class TestSinkWrapperLearning(unittest.TestCase):
    def test_learns_wrapper_from_sink_body(self):
        w = build_sink_wrappers([
            {"path": "HttpFetcher.java", "content": UTIL_SRC},
            {"path": "AdminController.java", "content": CTRL_SRC},
        ])
        self.assertIn(("HttpFetcher", "fetch"), w)
        self.assertIn("ssrf", w[("HttpFetcher", "fetch")])

    def test_caller_without_sink_text_is_not_learned(self):
        """调用方自身不含 sink，不应被当成包装方法。"""
        w = build_sink_wrappers([
            {"path": "HttpFetcher.java", "content": UTIL_SRC},
            {"path": "AdminController.java", "content": CTRL_SRC},
        ])
        self.assertNotIn(("AdminController", "fetch"), w)

    def test_non_propagatable_family_not_learned(self):
        w = build_sink_wrappers([
            {"path": "HtmlRender.java", "content": XSS_UTIL_SRC},
        ])
        # HtmlRender.render 体内无 sink，本就不该出现；即便出现也必须是非传播族
        for (_cls, _m), fams in w.items():
            self.assertNotIn("xss", fams)


class TestSinkWrapperPropagation(unittest.TestCase):
    def _wrappers(self):
        return build_sink_wrappers([
            {"path": "HttpFetcher.java", "content": UTIL_SRC},
            {"path": "AdminController.java", "content": CTRL_SRC},
        ])

    def test_callsite_gets_same_family(self):
        """调用点应拿到与工具类同族的条目（这是 #11 的核心断言）。"""
        w = self._wrappers()
        vs = analyze_content("AdminController.java", CTRL_SRC, "java", sink_wrappers=w)
        ssrf = [v for v in vs if v.type == "SSRF"]
        self.assertEqual(len(ssrf), 1, "调用点应恰好产出 1 条 SSRF")

    def test_callsite_line_is_the_call_line(self):
        """行号必须落在调用行——否则路由解析绑不到 /admin/fetch。"""
        w = self._wrappers()
        vs = analyze_content("AdminController.java", CTRL_SRC, "java", sink_wrappers=w)
        ssrf = [v for v in vs if v.type == "SSRF"][0]
        line_text = CTRL_SRC.splitlines()[ssrf.line - 1]
        self.assertIn("HttpFetcher.fetch(url)", line_text)
        self.assertEqual(ssrf.line, CTRL_SRC[: CTRL_SRC.index("HttpFetcher.fetch(url)")].count("\n") + 1)

    def test_no_propagation_without_wrappers(self):
        """向后兼容：不传表时与历史行为一致（调用方 0 条）。"""
        vs = analyze_content("AdminController.java", CTRL_SRC, "java")
        self.assertEqual([v for v in vs if v.type == "SSRF"], [])

    def test_analyze_files_builds_wrappers_across_files(self):
        vs = analyze_files([
            {"path": "HttpFetcher.java", "content": UTIL_SRC},
            {"path": "AdminController.java", "content": CTRL_SRC},
        ])
        by_file = {}
        for v in vs:
            by_file.setdefault(Path(v.file).name, []).append(v.type)
        self.assertIn("SSRF", by_file.get("AdminController.java", []))
        # 工具类本体仍出条（不因传播而丢失）
        self.assertIn("SSRF", by_file.get("HttpFetcher.java", []))

    def test_unqualified_call_not_propagated(self):
        """裸方法名 fetch( 不传播——跨类同名语义不同，直接匹配会大面积误伤。"""
        src = CTRL_SRC.replace("HttpFetcher.fetch(url)", "fetch(url)")
        w = self._wrappers()
        vs = analyze_content("AdminController.java", src, "java", sink_wrappers=w)
        self.assertEqual([v for v in vs if v.type == "SSRF"], [])

    def test_non_propagatable_family_call_not_emitted(self):
        w = build_sink_wrappers([{"path": "HtmlRender.java", "content": XSS_UTIL_SRC}])
        vs = analyze_content("PageController.java", XSS_CALLER_SRC, "java", sink_wrappers=w)
        self.assertEqual([v for v in vs if v.type == "XSS"], [])


@unittest.skipUnless(os.path.isdir(CODE_ROOT), "需要靶场源码")
class TestTargetMallAdminFetch(unittest.TestCase):
    """端到端：靶场 AdminController 的 SSRF 调用点必须出现，且绑定到 /admin/fetch。"""

    @classmethod
    def setUpClass(cls):
        files = []
        for p in Path(CODE_ROOT).rglob("*"):
            if p.is_file() and p.suffix.lower() in (".java",):
                try:
                    files.append({"path": str(p), "content": p.read_text(encoding="utf-8", errors="ignore")})
                except Exception:
                    pass
        cls.files = files

    def test_admin_controller_ssrf_callsite_present(self):
        vs = analyze_files(self.files)
        hits = [
            v for v in vs
            if Path(v.file).name == "AdminController.java" and v.type == "SSRF"
        ]
        self.assertTrue(hits, "AdminController 应产出 SSRF 调用点条目")
        self.assertIn(56, [v.line for v in hits], "应落在第 56 行 HttpFetcher.fetch(url)")

    def test_callsite_binds_to_admin_fetch_route(self):
        from src.core.param_resolver import resolve_endpoint_from_source

        ep = resolve_endpoint_from_source(
            {
                "file": r"src\main\java\com\sanjio\mall\web\AdminController.java",
                "line": 56,
                "type": "SSRF",
            },
            CODE_ROOT,
        )
        self.assertEqual(ep.get("route"), "/admin/fetch")
        self.assertEqual(ep.get("param_name"), "url")


if __name__ == "__main__":
    unittest.main()
