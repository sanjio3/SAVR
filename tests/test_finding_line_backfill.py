"""findings 定位行回填（待请示 6 项 #6，2026-09-16）。

回归背景：R28 run 10 抽查 83 条已确认发现，47% 的 line 落在空行/右花括号/字段声明/构造赋值上，
定位不准；更糟的是靶场自带「自我描述漏洞目录」被当定位依据。路由归属又依赖 finding.line 落在
注解行，故回填必须只在「当前 line 明显不可信」时用端点注解行覆盖，命中真实 sink 的可信行不动。

本测试钉死：
1. _line_content_looks_implausible 正确识别空行/}/构造赋值/字段声明，不误伤含方法调用的真实行；
2. _backfill_finding_line 仅在当前 line 不可信时回填到端点注解行，并打 line_backfilled 标；
3. _pre_resolve_a2_endpoints 从 discovered_routes 捕获注解行到 entry.source_line 并触发回填。
"""

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.cli import benchmark_cli as bc


def test_implausible_detects_bad_lines():
    assert bc._line_content_looks_implausible("") is True
    assert bc._line_content_looks_implausible("   ") is True
    assert bc._line_content_looks_implausible("}") is True
    assert bc._line_content_looks_implausible("this.foo = bar;") is True
    assert bc._line_content_looks_implausible("private String name;") is True
    # 含方法调用的真实 sink 行不能判为不可信
    assert bc._line_content_looks_implausible('String a = req.getParameter("a");') is False
    assert bc._line_content_looks_implausible("String sql = \"select * from t\";") is False


def _make_src(tmp: Path):
    code = (
        "package x;\n"
        "import y;\n"
        "@RestController\n"
        "class C {\n"
        '@GetMapping("/x")\n'
        "    public void x() {\n"
        "        this.foo = bar;\n"
        '        String a = req.getParameter("a");\n'
        "    }\n"
        "}\n"
    )
    f = tmp / "C.java"
    f.write_text(code, encoding="utf-8")
    return f


def test_backfill_overrides_implausible_line():
    with tempfile.TemporaryDirectory() as _td:
        tmp = Path(_td)
        src = _make_src(tmp)
        vuln = SimpleNamespace(
            type="sql_injection", file=str(src), line=7,  # 行 7 = this.foo = bar; 不可信
            exploit_spec={"entry": {"source_line": 5, "route": "/x", "method": "GET"}},
            line_backfilled=False, contract_completeness={},
        )
        bc._backfill_finding_line(vuln, str(tmp))
        assert vuln.line == 5, f"应回填到注解行 5，实际 {vuln.line}"
        assert vuln.line_backfilled is True


def test_backfill_keeps_plausible_line():
    with tempfile.TemporaryDirectory() as _td:
        tmp = Path(_td)
        src = _make_src(tmp)
        vuln = SimpleNamespace(
            type="sql_injection", file=str(src), line=8,  # 行 8 = 真实 sink 行，可信
            exploit_spec={"entry": {"source_line": 5, "route": "/x", "method": "GET"}},
            line_backfilled=False, contract_completeness={},
        )
        bc._backfill_finding_line(vuln, str(tmp))
        assert vuln.line == 8, "命中真实 sink 的可信行不得被覆盖"
        assert vuln.line_backfilled is False


def test_pre_resolve_captures_annotation_line_and_backfills(monkeypatch):
    with tempfile.TemporaryDirectory() as _td:
        tmp = Path(_td)
        src = _make_src(tmp)
        # fixture 必须是 entry_discovery_service._discover_file 的**真实**条目形状：
        # entry_type / file / line / signature / confidence / source / entry_hash，
        # **没有 route 也没有 method**。2026-09-16 教训：上一版 fixture 自造了
        # {"route": ..., "method": ...} 两个生产里不存在的键，测试绿灯但线上回填 0 次
        # （run 11 实测 71 条 spec 的 source_line 全空）。fixture 必须对齐生产者。
        discovered = [{
            "entry_type": "web_route", "file": "C.java", "line": 5,
            "signature": '@GetMapping("/x")', "confidence": "high",
            "source": "regex-entry-discovery", "entry_hash": "deadbeef",
        }]

        def _fake_resolve(vuln, a1_ev, code_root=None, discovered_routes=None):
            return {"resolvable": True, "route": "/x", "method": "GET",
                    "param_name": "a", "param_location": "query", "category": ""}

        monkeypatch.setattr(bc, "resolve_endpoint_full", _fake_resolve)

        vuln = SimpleNamespace(
            type="sql_injection", file=str(src), line=7,  # 不可信行
            exploit_spec={"entry": {}}, entry_resolution={}, entry_resolved=False,
            contract_completeness={}, a1_evidence={},
        )
        scan_result = SimpleNamespace(vulnerabilities=[vuln])
        bc._pre_resolve_a2_endpoints([scan_result], str(tmp), discovered_routes=discovered)

        assert vuln.exploit_spec["entry"].get("source_line") == 5
        assert vuln.line == 5, f"应回填到注解行 5，实际 {vuln.line}"
        assert vuln.line_backfilled is True


def test_route_and_method_from_signature_real_shapes():
    # 生产者 signature 的真实形态：注解 + 引号路径（类级前缀已提前拼进 signature）
    assert bc._route_and_method_from_signature('@GetMapping("/x")') == ("/x", "GET")
    assert bc._route_and_method_from_signature('    @PostMapping("/api/admin/users")') == (
        "/api/admin/users", "POST")
    assert bc._route_and_method_from_signature('@RequestMapping("/api")') == ("/api", "")
    assert bc._route_and_method_from_signature(
        '@RequestMapping(value = "/o", method = RequestMethod.PUT)') == ("/o", "PUT")
    assert bc._route_and_method_from_signature('@DeleteMapping') == ("", "DELETE")
    # Python 路由：拿不到 Spring 注解名 → method 为空（通配），但路径仍可用于定位行
    assert bc._route_and_method_from_signature('@app.route("/p")') == ("/p", "")
    # 完全没有引号路径（如无参注解）→ 路由为空，只能靠兜底
    assert bc._route_and_method_from_signature("@GetMapping") == ("", "GET")


def test_annotation_line_matches_real_entry_without_route_key():
    entries = [
        {"entry_type": "web_route", "file": "OrderController.java", "line": 12,
         "signature": '@RequestMapping("/api")'},
        {"entry_type": "web_route", "file": "OrderController.java", "line": 40,
         "signature": '@GetMapping("/api/orders/{id}")'},
        {"entry_type": "web_route", "file": "UserController.java", "line": 8,
         "signature": '@PostMapping("/api/profile")'},
    ]
    # 大小写/尾斜杠差异不应造成 miss（只用于定位行，不参与路由回写）
    assert bc._annotation_line_for_route("/api/orders/{id}", "GET", entries) == 40
    assert bc._annotation_line_for_route("/api/orders/{id}/", "GET", entries) == 40
    assert bc._annotation_line_for_route("/API/Orders/{id}", "GET", entries) == 40
    # 方法不符则不取该条，退化到同文件同方法的兜底
    assert bc._annotation_line_for_route("/api/orders/{id}", "POST", entries) == 0
    # 路由对不上（如解析器补了上下文前缀）→ 按同文件 + 同方法兜底
    assert bc._annotation_line_for_route("/ctx/api/profile", "POST", entries,
                                         vuln_file="src/x/UserController.java") == 8
    # 没有任何可用条目 → 0（调用方据此跳过回填）
    assert bc._annotation_line_for_route("/nope", "GET", []) == 0
    assert bc._annotation_line_for_route("/api/orders/{id}", "GET",
                                        [{"signature": '@GetMapping("/api/orders/{id}")', "line": 0}]) == 0
