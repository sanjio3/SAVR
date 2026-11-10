"""R24-G：#11 SSRF 归 finding-only 的登记链路修复回归守卫。

根因（2026-09-11 复查，run 11/ run 13 双轮实证）：
A2 对 AdminController 的 SSRF finding **语义正确但行号落错** —— description 明写
「fetch 方法直接使用用户提供的 url 参数发起 HTTP 请求」，但 `line` 落在相邻 ping 方法的
javadoc 收尾行（40）。`resolve_endpoint_from_source` 取「最近的前置映射」，于是解析回落到
dashboard 的 `/admin`，导致 ssrf 族永远没有 `/admin/fetch` 的 spec（归 finding-only）。

这不是「类级兜底吃掉方法级路由」（line 53/55/56 能正确解析出 `/admin/fetch`），
而是行号归因错误。修复：按「漏洞文本点名的方法名」在同文件内纠偏真实路由 ——
仅在**同文件确有该方法的 Spring 映射**时生效，属代码级事实而非猜测。
"""
import textwrap

from src.core.param_resolver import (
    resolve_endpoint_by_method_hint,
    resolve_endpoint_from_source,
)

JAVA = textwrap.dedent('''
    package demo;

    import org.springframework.web.bind.annotation.*;

    @Controller
    @RequestMapping("/admin")
    public class AdminController {

        @GetMapping({"", "/"})
        public String dashboard() { return "admin"; }

        /**
         * 网络连通性检测。
         * payload: host=127.0.0.1 & whoami
         */
        @GetMapping("/ping")
        @ResponseBody
        public String ping(@RequestParam String host) { return "pong"; }

        /**
         * 远程资源抓取——SSRF。
         * payload: url=http://169.254.169.254/
         */
        @GetMapping("/fetch")
        @ResponseBody
        public String fetch(@RequestParam String url) { return "ok"; }
    }
''').lstrip("\n")

REL = "src/main/java/demo/AdminController.java"


def _write_fixture(tmp_path):
    p = tmp_path / REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(JAVA, encoding="utf-8")
    return str(tmp_path)


def _line_of(tmp_path, needle):
    lines = (tmp_path / REL).read_text(encoding="utf-8").splitlines()
    for i, ln in enumerate(lines, 1):
        if needle in ln:
            return i
    raise AssertionError("fixture 里找不到：" + needle)


def test_line_based_resolution_falls_back_to_dashboard(tmp_path):
    """基线：行号落在 ping javadoc 时，按 line 解析会回落 dashboard 的 /admin。"""
    root = _write_fixture(tmp_path)
    javadoc_end = _line_of(tmp_path, "payload: host=127.0.0.1") + 1   # */ 收尾行
    r = resolve_endpoint_from_source({"file": REL, "line": javadoc_end}, root)
    assert r and r["route"] == "/admin"


def test_fetch_line_resolves_correctly(tmp_path):
    """对照：line 落在 fetch 方法体时能正确解析出 /admin/fetch（说明解析器本身没问题）。"""
    root = _write_fixture(tmp_path)
    ln = _line_of(tmp_path, '@GetMapping("/fetch")') + 2
    r = resolve_endpoint_from_source({"file": REL, "line": ln}, root)
    assert r and r["route"] == "/admin/fetch" and r["param_name"] == "url"


def test_method_hint_corrects_fetch_route(tmp_path):
    """核心：文本点名 fetch → 纠偏回 /admin/fetch（且带 url 参数）。"""
    root = _write_fixture(tmp_path)
    javadoc_end = _line_of(tmp_path, "payload: host=127.0.0.1") + 1
    vuln = {"file": REL, "line": javadoc_end}
    vd = {"description": "fetch 方法直接使用用户提供的 url 参数发起 HTTP 请求，可能导致 SSRF 攻击"}
    r = resolve_endpoint_by_method_hint(vuln, root, vd)
    assert r and r["route"] == "/admin/fetch"
    assert r["param_name"] == "url"
    assert r["function"] == "fetch"


def test_method_hint_ping_stays_consistent(tmp_path):
    """点名 ping → 结果与按 line 解析一致（不引入错误重绑）。"""
    root = _write_fixture(tmp_path)
    ln = _line_of(tmp_path, '@GetMapping("/ping")') + 1
    r = resolve_endpoint_by_method_hint({"file": REL, "line": ln}, root,
                                        {"description": "ping 方法把 host 拼进命令，命令注入"})
    assert r and r["route"] == "/admin/ping" and r["param_name"] == "host"


def test_method_hint_none_when_no_method_named(tmp_path):
    """文本没点名方法 → 不纠偏（返回 None，交回按 line 的解析）。"""
    root = _write_fixture(tmp_path)
    ln = _line_of(tmp_path, '@GetMapping("/fetch")') + 2
    assert resolve_endpoint_by_method_hint({"file": REL, "line": ln}, root,
                                           {"description": "管理页面存在 SSRF 风险"}) is None


def test_method_hint_none_for_unknown_name(tmp_path):
    """点名了文件里不存在的方法名 → 不纠偏。"""
    root = _write_fixture(tmp_path)
    assert resolve_endpoint_by_method_hint({"file": REL, "line": 1}, root,
                                           {"description": "deleteAll 方法未鉴权"}) is None


def test_method_hint_english_and_hash_forms(tmp_path):
    """英文 "fetch method" 与 "#fetch" 两种写法都能识别。"""
    root = _write_fixture(tmp_path)
    assert resolve_endpoint_by_method_hint({"file": REL, "line": 1}, root,
                                           {"description": "the fetch method performs SSRF"})["route"] == "/admin/fetch"
    assert resolve_endpoint_by_method_hint({"file": REL, "line": 1}, root,
                                           {"sink": "AdminController#fetch"})["route"] == "/admin/fetch"
