# -*- coding: utf-8 -*-
"""L1 盲化变体回归锁：认证链路路径不得参与路由盲化。

背景（2026-11-07）：首版变体把 /login、/logout 也 hash 成 /bc42c80、
/bc94d04，而 workspace 4 的 login.url / csrf.fetch_url 与 D1 的
_is_login_wall_response() / _logout_paths() 都硬依赖原路径。若直接部署，
L1 的掉点会全部落在登录墙 302 上，无法与「路由先验依赖」区分。
"""
from __future__ import annotations

import importlib.util
import json
import os
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


def test_protected_segments_excluded_from_map(tool):
    seg_map = tool.build_segment_map({"/sqli": 3, "/spel": 2, "/login": 1, "/logout": 1})
    assert "/login" not in seg_map and "/logout" not in seg_map
    assert set(seg_map) == {"/sqli", "/spel"}
    assert all(v.startswith("/b") for v in seg_map.values())


def test_protected_constants_are_explicit(tool):
    assert tool.PROTECTED_SEGMENTS == frozenset({"/login", "/logout"})


def _seed_tree(src: Path) -> None:
    def put(rel: str, text: str) -> None:
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    put("pom.xml", "<project><artifactId>x</artifactId></project>\n")
    put("src/main/java/org/joychou/controller/SQLI.java", """
package org.joychou.controller;
@RequestMapping("/sqli/jdbc/vuln")
public class SQLI { }
""")
    put("src/main/java/org/joychou/controller/Login.java", """
package org.joychou.controller;
@RequestMapping("/login")
public class Login {
    @GetMapping("/logout") public String out() { return "ok"; }
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


def test_end_to_end_generator_keeps_auth_literals(tool, tmp_path, monkeypatch):
    src, out = tmp_path / "src_repo", tmp_path / "blind"
    _seed_tree(src)
    monkeypatch.setattr(sys, "argv", ["jsc_make_blind_variant.py",
                                     "--src", str(src), "--out", str(out)])
    assert tool.main() == 0

    mapping = json.loads((out / "blind_map.json").read_text(encoding="utf-8"))
    assert "/login" not in mapping["segments"]
    assert "/logout" not in mapping["segments"]
    assert "/sqli" in mapping["segments"]
    assert set(mapping["protected_segments"]) == {"/login", "/logout"}
    assert mapping["coverage"]["percent"] == 100.0

    wsc = (out / "src/main/java/org/joychou/security/WebSecurityConfig.java").read_text(
        encoding="utf-8")
    assert 'loginPage("/login")' in wsc
    assert 'logoutUrl("/logout")' in wsc

    sqli = (out / "src/main/java/org/joychou/controller/SQLI.java").read_text(
        encoding="utf-8")
    assert '"/sqli/jdbc/vuln"' not in sqli
    assert mapping["segments"]["/sqli"] + "/jdbc/vuln" in sqli

    login = (out / "src/main/java/org/joychou/controller/Login.java").read_text(
        encoding="utf-8")
    assert '"/login"' in login and '"/logout"' in login

    props = (out / "src/main/resources/application.properties").read_text(encoding="utf-8")
    assert "/login" in props
    assert "/sqli/**" not in props
    assert mapping["segments"]["/sqli"] + "/**" in props

    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "target_path 必须同步切到本目录" in readme
