"""语料适配层 / 通用「值不可控」判据的回归锁定。

锁的是 r60 之后那次「把语料特定规则换成通用机制」的整改。每一条都是实测踩出来的：

1. 常量返回 helper 必须靠**解析方法体**识别，不能按方法名（名字硬编码换个项目零命中）；
2. 透传 request 的同名方法必须**不**判常量（原来靠 deny 名单保语义，现在机制自带）；
3. 「值不可控 ⇒ 安全」**只对输入驱动族成立** —— 不区分族语义直接放开，
   r60 实测误杀 44 个 TP（TPR 降 3.11pp，超 3pp 门限）；
4. 列表求值只要有一次 get 取到 UNKNOWN 就整段判不安全（fail-safe）；
5. 画像层：未知族一律不启用通用判据（fail-open，宁可少抑制）。
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.core import untaint  # noqa: E402
from src.core.corpus_profile import StackProfile, active_profile  # noqa: E402

CONST_HELPER = """
public class Widget {
    public String label(String p) {
        return "bar";
    }
    public int size() {
        return 42;
    }
}
"""

PASSTHROUGH_HELPER = """
public class Widget {
    private HttpServletRequest request;
    public String label(String p) {
        return request.getParameter(p);
    }
}
"""

MIXED_HELPER = """
public class Widget {
    private HttpServletRequest request;
    public String label(String p) {
        if (p == null) {
            return "bar";
        }
        return request.getParameter(p);
    }
}
"""

USE_HELPER = """
public class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        Widget w = new Widget();
        String param = w.label("T");
        stmt.executeQuery("SELECT * FROM t WHERE a = '" + param + "'");
    }
}
"""

LIST_LITERAL = """
List<String> v = new ArrayList<String>();
v.add("safe");
v.add(request.getParameter("p"));
v.add("moresafe");
v.remove(0);
bar = v.get(1);
"""

LIST_UNKNOWN_GET = """
List<String> v = new ArrayList<String>();
v.add("safe");
v.add(request.getParameter("p"));
v.remove(0);
bar = v.get(0);
"""

LIST_NO_ASSIGN = """
List<String> v = new ArrayList<String>();
v.add("safe");
v.remove(0);
v.get(0);
"""


def test_const_helper_detected_by_body_not_by_name():
    names = untaint.constant_returning_methods(CONST_HELPER)
    assert "label" in names, names
    assert "size" in names, names


def test_passthrough_helper_is_not_constant():
    """return request.getParameter(p) ⇒ 不是字面量 ⇒ 不许判常量（误杀真漏洞）。"""
    assert "label" not in untaint.constant_returning_methods(PASSTHROUGH_HELPER)


def test_mixed_helper_is_not_constant():
    """只要有一个 return 不是字面量，整个方法就不算常量返回。"""
    assert "label" not in untaint.constant_returning_methods(MIXED_HELPER)


def test_constant_call_source(tmp_path):
    with open(os.path.join(str(tmp_path), "Widget.java"), "w", encoding="utf-8") as f:
        f.write(CONST_HELPER)
    assert untaint.constant_call_source(USE_HELPER, code_root=str(tmp_path)) is True


def test_constant_call_source_rejected_when_helper_passthrough(tmp_path):
    with open(os.path.join(str(tmp_path), "Widget.java"), "w", encoding="utf-8") as f:
        f.write(PASSTHROUGH_HELPER)
    assert untaint.constant_call_source(USE_HELPER, code_root=str(tmp_path)) is False


def test_constant_call_source_rejected_when_class_has_external_input():
    src = USE_HELPER.replace('w.label("T")', 'w.label("T") + request.getParameter("q")')
    assert untaint.constant_call_source(src, code_root="") is False


def test_literal_list_index_ok():
    assert untaint.literal_list_index(LIST_LITERAL) is True


def test_literal_list_index_rejects_unknown_get():
    """get 取到变量 ⇒ 整段判不安全（宁可漏抑制不误杀）。"""
    assert untaint.literal_list_index(LIST_UNKNOWN_GET) is False


def test_literal_list_index_requires_assignment():
    """算出来是常量、但代码没把它赋给任何变量 ⇒ 与 sink 之间无联系 ⇒ 不抑制。"""
    assert untaint.literal_list_index(LIST_NO_ASSIGN) is False


def test_untainted_value_is_family_scoped():
    """weak_hash 不是输入驱动族 —— 用 MD5 哈希一个常量仍然是漏洞。"""
    ok, rule = untaint.untainted_value(USE_HELPER, family="weak_hash")
    assert ok is False and rule == ""
    # 注入类才是输入驱动族（这里没有 helper 源码所以判不出常量，但族闸门必须先过）
    assert untaint.untainted_value("", family="sql_injection")[0] is False


def test_profile_unknown_family_is_not_input_driven():
    p = active_profile()
    assert p.is_input_driven("sql_injection") is True
    assert p.is_input_driven("weak_hash") is False
    assert p.is_input_driven("weak_random") is False
    assert p.is_input_driven("这个族没登记过") is False


def test_profile_detects_external_input():
    p = StackProfile("t")
    assert p.has_external_input('String x = request.getParameter("a");')
    assert p.has_external_input("String x = System.getenv(\"PATH\");")
    assert not p.has_external_input("String x = \"literal\";")
