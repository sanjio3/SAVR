"""族名归一 _norm_family 的回归锁（2026-10-04 落地）。

背景（不看这条会重蹈覆辙）：`vuln_hash._norm_family` 的 mapping 里
**没有 xpath 针**，而 path-traversal 的中文针是裸「路径」（纯子串、无词边界）。
XPath 全称 XML Path Language，A2 产出的描述里天然出现「XML 路径」 ⇒ xpath 用例被
path-traversal 抢走。OWASP sample-205 实证：真值 xpathi 用例
BenchmarkTest01014 上 rule_name=XPath注入 是对的，但 type / finding_family /
display_family 全被写成 路径穿越 / path_traversal；全量 path_traversal 107 条成为
第一大族，跨 cmdi / xpathi / ldapi / crypto 无差别搭售，是 gate 判 FAIL 的直接原因。

修复：xpath 针插到 path-traversal **之前**，中文针收紧为路径穿越语义的整词。

四条锁：
    1. 含「XML 路径」描述的 XPath 用例必须归一到 xpath-injection（不能被抢）；
    2. 各种 xpath 写法（英文 type / 中文 type / family=xpathi）都能收敛；
    3. 真·路径穿越（英文 type、路径穿越、路径遍历、目录遍历）仍然判 path-traversal；
    4. 其它族（sql / command / ldap）不受影响，尤其 LDAP 描述含「目录」不能被抢。
"""
from __future__ import annotations

import pytest

from src.core.vuln_hash import _norm_family


def test_xpath_description_with_xml_path_must_not_become_path_traversal():
    """这条是原缺陷的最小复现：修复前返回 path-traversal。"""
    item = {
        "type": "XPath Injection",
        "description": "XPath 表达式由外部输入拼接，XML 路径可被篡改",
        "sink": "javax.xml.xpath 引用",
    }
    assert _norm_family(item) == "xpath-injection"


@pytest.mark.parametrize("item", [
    {"type": "XPath Injection", "sink": "javax.xml.xpath 引用"},
    {"type": "XPath注入", "sink": "javax.xml.xpath 引用"},
    {"type": "XPath Injection", "display_family": "xpathi",
     "sink": "javax.xml.xpath.XPathExpression.evaluate"},
    {"type": "xpath-injection", "sink": "XPath.evaluate"},
    {"original_type": "XPath Injection", "sink": "javax.xml.xpath.XPath.compile"},
])
def test_xpath_variants_converge(item):
    assert _norm_family(item) == "xpath-injection"


@pytest.mark.parametrize("item", [
    {"type": "Path Traversal", "sink": "文件路径拼接"},
    {"type": "路径穿越", "sink": "文件读写 sink"},
    {"type": "路径遍历", "sink": "file read"},
    {"type": "目录遍历", "sink": "file read"},
    {"type": "Path Traversal", "display_family": "path-traversal",
     "sink": "new FileOutputStream(...)"},
])
def test_real_path_traversal_still_works(item):
    assert _norm_family(item) == "path-traversal"


def test_other_families_unchanged():
    assert _norm_family({"type": "SQL Injection", "sink": "JDBC createStatement"}) == "sql-injection"
    assert _norm_family({"type": "Command Injection", "sink": "ProcessBuilder"}) == "command-execution"
    # LDAP 描述常含「目录」，不能被 path-traversal 的目录遍历针抢走（针位序保护）
    assert _norm_family({"type": "LDAP Injection", "description": "LDAP 目录查询",
                         "sink": "DirContext.search"}) == "ldap_injection"
