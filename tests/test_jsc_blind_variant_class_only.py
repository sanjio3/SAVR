# -*- coding: utf-8 -*-
"""L1 盲化粒度回归锁：--scope class-only 只改类级注解，方法级全路径原样。

背景（2026-11-07）：L1 本轮用的 --scope class 对**每个**带路径注解的首段
都做 hash，方法级全路径注解（@RequestMapping("/jdbc/vuln")）也中招，因此
-12.5pp 是「语义先验 + 路径层结构变化」的合计上界。class-only 把两种因素
分开，但尚未用于实测；本文件锁死它的行为，也锁死既有 class 行为不回退。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "jsc_make_blind_variant.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("jsc_blind_variant", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def tool():
    return _load_tool()


def _seed_tree(src: Path) -> None:
    def put(rel: str, text: str) -> None:
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    put("pom.xml", "<project><artifactId>x</artifactId></project>\n")
    # 类级有路径 + 方法级写全路径；注释/字符串里放假的类型声明干扰边界判定。
    put("src/main/java/org/joychou/controller/SQLI.java", """
package org.joychou.controller;
@RequestMapping("/sqli")
public class SQLI {
    // String fake = "class NotARealClass";
    @RequestMapping("/jdbc/vuln")
    public String vuln(String id) { return "class AlsoFake"; }
}
""")
    put("src/main/java/org/joychou/security/WebSecurityConfig.java", """
package org.joychou.security;
public class WebSecurityConfig {
    void conf() {
        http.formLogin().loginPage("/login").permitAll();
        http.logout().logoutUrl("/logout").permitAll();
    }
}
""")
    put("src/main/resources/application.properties",
        "joychou.no.need.login.url= /login, /sqli/**\n"
        "joychou.security.csrf.exclude.url= /sqli/**\n")


def _run(tool, src: Path, out: Path, scope: str, monkeypatch):
    _seed_tree(src)
    monkeypatch.setattr(sys, "argv", ["jsc_make_blind_variant.py",
                                     "--src", str(src), "--out", str(out),
                                     "--scope", scope])
    assert tool.main() == 0
    return json.loads((out / "blind_map.json").read_text(encoding="utf-8"))


def test_mask_noncode_preserves_offsets_and_hides_fake_declarations(tool):
    code = '// class FakeOne\nString s = "class FakeTwo";\npublic class Real { }\n'
    masked = tool._mask_noncode(code)
    assert len(masked) == len(code)
    assert "FakeOne" not in masked and "FakeTwo" not in masked
    assert tool._class_decl_pos(code) == code.index("class Real")
    assert code[tool._class_decl_pos(code):].startswith("class Real")


def test_rewrite_java_class_only_touches_only_class_annotation(tool):
    seg_map = {"/sqli": "/b111111"}
    code = ('@RequestMapping("/sqli")\npublic class SQLI {\n'
            '    @RequestMapping("/jdbc/vuln")\n    public String v() { return "x"; }\n}\n')
    changed, hits = tool._rewrite_java(code, "class-only", seg_map)
    assert hits == 1
    assert '@RequestMapping("/b111111")' in changed
    assert '@RequestMapping("/jdbc/vuln")' in changed


def test_rewrite_java_class_scope_still_hashes_method_first_segment(tool):
    """既有 class 行为不回退：L1 本轮的读数必须可复现。"""
    seg_map = {"/sqli": "/b111111", "/jdbc": "/b222222"}
    code = ('@RequestMapping("/sqli")\npublic class SQLI {\n'
            '    @RequestMapping("/jdbc/vuln")\n    public String v() { return "x"; }\n}\n')
    changed, hits = tool._rewrite_java(code, "class", seg_map)
    assert hits == 2
    assert '@RequestMapping("/b111111")' in changed
    assert '@RequestMapping("/b222222/vuln")' in changed


def test_generator_class_only_keeps_method_paths_and_auth(tool, tmp_path, monkeypatch):
    mapping = _run(tool, tmp_path / "src", tmp_path / "blind_semantic",
                   "class-only", monkeypatch)
    assert mapping["scope"] == "class-only"
    assert "尚未用于实测" in mapping["scope_note"]
    assert set(mapping["segments"]) == {"/sqli"}     # /jdbc 不进映射
    assert mapping["coverage"]["percent"] == 100.0

    sqli = (tmp_path / "blind_semantic/src/main/java/org/joychou/controller/SQLI.java").read_text(
        encoding="utf-8")
    new_seg = mapping["segments"]["/sqli"]
    assert '@RequestMapping("%s")' % new_seg in sqli
    assert '@RequestMapping("/jdbc/vuln")' in sqli   # 方法级原样

    wsc = (tmp_path / "blind_semantic/src/main/java/org/joychou/security/WebSecurityConfig.java").read_text(
        encoding="utf-8")
    assert 'loginPage("/login")' in wsc and 'logoutUrl("/logout")' in wsc

    props = (tmp_path / "blind_semantic/src/main/resources/application.properties").read_text(
        encoding="utf-8")
    assert "/login" in props and new_seg + "/**" in props


def test_generator_class_scope_unchanged(tool, tmp_path, monkeypatch):
    mapping = _run(tool, tmp_path / "src2", tmp_path / "blind_class",
                   "class", monkeypatch)
    assert mapping["scope"] == "class"
    assert set(mapping["segments"]) == {"/sqli", "/jdbc"}
    sqli = (tmp_path / "blind_class/src/main/java/org/joychou/controller/SQLI.java").read_text(
        encoding="utf-8")
    assert '@RequestMapping("%s")' % mapping["segments"]["/sqli"] in sqli
    assert '@RequestMapping("%s/vuln")' % mapping["segments"]["/jdbc"] in sqli


def test_shipped_l1_variant_still_uses_class_scope():
    """守住 本轮的可复现性：现成变体树不能被新 scope 覆盖。"""
    p = ROOT / "data" / "blind_variants" / "jsc-blind" / "blind_map.json"
    if not p.is_file():
        pytest.skip("本机 L1 变体树不存在（干净 clone 无 data/blind_variants）")
    assert json.loads(p.read_text(encoding="utf-8"))["scope"] == "class"
