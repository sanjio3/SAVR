"""发难清单 Q6~Q9 修复的单测（2026-10-02 落地）。

Q6 通配符 import / 同包隐式引用；Q7 泛型/限定父类 + lombok 访问器合成；
Q8 常量求解器（拼接/变量间接/配置注入）；Q9 缓存键 realpath+normcase + LRU。
"""
import os
import platform

import pytest

import src.core.sanitizer_miner as sm
from src.core.sanitizer_miner import SourceNavigator, get_navigator


def _mkdir(p):
    os.makedirs(p, exist_ok=True)
    return p


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ---------------- Q9 缓存键 ----------------

def test_get_navigator_key_normalization(tmp_path):
    root = _mkdir(str(tmp_path / "proj"))
    nav1 = get_navigator(root)
    # 相对/绝对混合写法（sub/.. 归一后同根）
    assert get_navigator(os.path.join(root, "sub", "..")) is nav1
    # Windows 大小写归一
    if platform.system() == "Windows":
        assert get_navigator(root.upper()) is nav1
    # realpath：软链/短路径（8.3 等）归一后同键（无软链环境则退化为同根同实例）
    assert get_navigator(os.path.abspath(root)) is nav1


def test_nav_cache_lru_eviction(tmp_path):
    old_max = sm._NAV_CACHE_MAX
    try:
        sm._NAV_CACHE_MAX = 2
        sm._NAV_CACHE.clear()
        r1 = _mkdir(str(tmp_path / "r1"))
        r2 = _mkdir(str(tmp_path / "r2"))
        r3 = _mkdir(str(tmp_path / "r3"))
        get_navigator(r1)
        get_navigator(r2)
        get_navigator(r1)  # r1 升为最近使用
        get_navigator(r3)  # 淘汰最久未用的 r2，不全清
        keys = set(sm._NAV_CACHE.keys())
        assert len(keys) == 2
        assert os.path.normcase(os.path.realpath(r1)) in keys
        assert os.path.normcase(os.path.realpath(r3)) in keys
        assert os.path.normcase(os.path.realpath(r2)) not in keys
    finally:
        sm._NAV_CACHE_MAX = old_max
        sm._NAV_CACHE.clear()


# ---------------- Q6 通配符 / 同包隐式 ----------------

def test_wildcard_import_resolution(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(os.path.join(root, "a", "b"))
    _write(os.path.join(root, "a", "b", "SecFilter.java"),
           "package a.b;\npublic class SecFilter {\n"
           "  public boolean check(String v) {\n"
           "    if (v.contains(\";\")) { return true; }\n"
           "    return false;\n  }\n}\n")
    caller = _write(os.path.join(root, "x", "Caller.java"),
                    "package x;\nimport a.b.*;\npublic class Caller {\n"
                    "  public void handle(String v) { new SecFilter().check(v); }\n}\n")
    nav = SourceNavigator(root)
    ctx = nav.import_context(caller)
    assert ctx["wildcards"] == ["a.b"]
    body, path = nav.resolve_call("SecFilter", "check", caller)
    assert body and "contains" in body
    assert path.endswith("SecFilter.java")


def test_same_package_implicit_resolution(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(os.path.join(root, "a", "b"))
    _write(os.path.join(root, "a", "b", "Helper.java"),
           "package a.b;\npublic class Helper {\n"
           "  public String clean(String v) {\n"
           "    return v.replace(\"..\", \"\");\n  }\n}\n")
    caller = _write(os.path.join(root, "a", "b", "Caller2.java"),
                    "package a.b;\npublic class Caller2 { void go(String v){ new Helper().clean(v); } }\n")
    nav = SourceNavigator(root)
    assert "Helper" in nav.same_package_classes(caller)
    body, path = nav.resolve_call("Helper", "clean", caller)
    assert body and "replace" in body
    assert path.endswith("Helper.java")


def test_explicit_import_beats_same_package(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(os.path.join(root, "p1"))
    _mkdir(os.path.join(root, "p2"))
    _write(os.path.join(root, "p1", "Util.java"),
           "package p1;\npublic class Util { public String a(String v){ return v.trim(); } }\n")
    _write(os.path.join(root, "p2", "Util.java"),
           "package p2;\npublic class Util { public String a(String v){ return v.strip(); } }\n")
    caller = _write(os.path.join(root, "p2", "Main.java"),
                    "package p2;\nimport p1.Util;\npublic class Main { void go(String v){ new Util().a(v); } }\n")
    nav = SourceNavigator(root)
    body, path = nav.resolve_call("Util", "a", caller)
    # 显式 import p1.Util 优先于同包 p2.Util
    assert path.endswith(os.path.join("p1", "Util.java"))


# ---------------- Q7 泛型/限定父类 + lombok ----------------

def test_generic_superclass_climb(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(os.path.join(root, "com"))
    _write(os.path.join(root, "com", "Base.java"),
           "package com;\npublic class Base<T> {\n"
           "  protected String guard(String v) {\n"
           "    if (v.matches(\"^[a-z]+$\")) { return v; }\n"
           "    return \"\";\n  }\n}\n")
    child = _write(os.path.join(root, "com", "Child.java"),
                   "package com;\npublic class Child extends Base<String> {\n}\n")
    nav = SourceNavigator(root)
    assert nav.superclass_of(child) == "Base"
    body, path = nav.body_for({"file": child, "method": "guard"})
    assert body and "matches" in body
    assert path.endswith("Base.java")


def test_qualified_superclass_climb(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(os.path.join(root, "p"))
    _write(os.path.join(root, "p", "InnerBase.java"),
           "package p;\npublic class InnerBase {\n"
           "  protected String filter(String v){ if(v.contains(\"|\")) return \"\"; return v; }\n}\n")
    child = _write(os.path.join(root, "p", "Sub.java"),
                   "package p;\npublic class Sub extends p.InnerBase { }\n")
    nav = SourceNavigator(root)
    # 旧正则会把 p.InnerBase 截成 p（断链），现在应拿到完整限定名
    assert nav.superclass_of(child) == "p.InnerBase"
    body, path = nav.body_for({"file": child, "method": "filter"})
    assert body and "contains" in body


def test_lombok_accessor_synthesis(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(root)
    f = _write(os.path.join(root, "Dto.java"),
               "import lombok.Data;\n@Data\npublic class Dto {\n"
               "  private String secret;\n  private boolean admin;\n}\n")
    nav = SourceNavigator(root)
    assert nav.lombok_fields(f) == [("secret", "String"), ("admin", "boolean")]
    body = nav.lombok_accessor_body(f, "getSecret")
    assert body and "this.secret" in body
    body2 = nav.lombok_accessor_body(f, "isAdmin")
    assert body2 and "boolean" in body2
    # body_for 集成：getter 在源码里不存在，但经合成后可参与守卫判定
    got, _ = nav.body_for({"file": f, "method": "getSecret"})
    assert got and "secret" in got


# ---------------- Q8 常量求解器 ----------------

def test_resolve_const_concat_mixed(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(root)
    f = _write(os.path.join(root, "Rules.java"),
               "public class Rules {\n"
               "  private static final String ALLOWED = \"[a-zA-Z0-9_/.-]\";\n"
               "  private static final java.util.regex.Pattern FILTER_PATTERN = Pattern.compile(\"^\" + ALLOWED + \"$\");\n"
               "}\n")
    nav = SourceNavigator(root)
    assert nav.resolve_const(f, "ALLOWED") == "[a-zA-Z0-9_/.-]"
    assert nav.resolve_const(f, "FILTER_PATTERN") == "^[a-zA-Z0-9_/.-]$"


def test_resolve_const_literal_with_plus_inside_regex(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(root)
    f = _write(os.path.join(root, "R2.java"),
               "public class R2 {\n"
               "  private static final java.util.regex.Pattern P = Pattern.compile(\"^[a-z]+$\");\n}\n")
    nav = SourceNavigator(root)
    # 正则字面量内部的 '+' 不得被当拼接切掉
    assert nav.resolve_const(f, "P") == "^[a-z]+$"


def test_resolve_const_variable_indirection(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(root)
    f = _write(os.path.join(root, "R3.java"),
               "public class R3 {\n"
               "  private static final String BASE = \"^/safe/\";\n"
               "  private static final String RULE = BASE;\n}\n")
    nav = SourceNavigator(root)
    assert nav.resolve_const(f, "RULE") == "^/safe/"


def test_resolve_const_config_injection(tmp_path):
    proj = str(tmp_path / "proj")
    _write(os.path.join(proj, "src", "main", "resources", "application.properties"),
           "filter.pattern=^safe+$\n")
    f = _write(os.path.join(proj, "src", "main", "java", "Cfg.java"),
               "public class Cfg {\n"
               "  private String rule = env.getProperty(\"filter.pattern\");\n}\n")
    nav = SourceNavigator(proj)
    assert nav.resolve_const(f, "rule") == "^safe+$"


def test_resolve_const_depth_guard(tmp_path):
    root = str(tmp_path / "proj")
    _mkdir(root)
    f = _write(os.path.join(root, "Loop.java"),
               "public class Loop {\n"
               "  private static final String A = B;\n"
               "  private static final String B = A;\n}\n")
    nav = SourceNavigator(root)
    # 循环引用：深度限 3 内终止，不无限递归
    assert nav.resolve_const(f, "A") is None
