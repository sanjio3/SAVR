"""M2 第二项补：XML 解析器配置环境事实（2026-10-03）。

覆盖三件事：
1. setFeature / setXIncludeAware / setExpandEntityReferences / setAttribute 的
   源码静态解析（括号、字符串逗号都不该切错）；
2. 三态收敛（enabled/disabled/on/off/unknown），冲突取不安全值且留痕；
3. 与 env_premise 对接后仍然遵守「事实未知 fail-open」。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core import runtime_facts as rf      # noqa: E402
from src.core import env_premise as ep        # noqa: E402


# ---------------------------------------------------------------------------
# 词法层
# ---------------------------------------------------------------------------

def test_split_args_ignores_commas_in_string_and_nested_paren():
    body = '"a,b", true'
    assert rf._split_call_args(body) == ["\"a,b\"", "true"]
    body2 = 'getFeature("x"), (a, b), false'
    assert rf._split_call_args(body2) == ['getFeature("x")', "(a, b)", "false"]


def test_bool_value_accepts_literals_and_constant_and_negation():
    assert rf._bool_value("true") is True
    assert rf._bool_value("FALSE") is False
    assert rf._bool_value(" !true ") is False
    assert rf._bool_value("XMLConstants.FEATURE_SECURE_PROCESSING") is True
    assert rf._bool_value("FEATURE_SECURE_PROCESSING") is True
    # 走变量/方法调用的形态一律不猜
    assert rf._bool_value("flag") is None
    assert rf._bool_value("Boolean.parseBoolean(p)") is None
    assert rf._bool_value("") is None


def test_find_calls_yields_inner_body_only():
    text = 'f.setFeature("disallow-doctype-decl", true);\n// setFeature("x", false)\nf.setFeature(\n  "secure-processing",\n  true\n);'
    got = [s.strip() for s in rf._find_calls(text, "setFeature")]
    assert len(got) == 3
    assert got[0] == '"disallow-doctype-decl", true'
    assert got[-1] == '"secure-processing",\n  true'
    # 注释行里那个 setFeature("x", false) 也算本体外的命中，括号体要截对
    assert '"x", false' in got[1]


def test_xml_feature_key_from_full_url_and_constant():
    assert rf._xml_feature_key('"http://apache.org/xml/features/disallow-doctype-decl"') == "xml_dtd"
    assert rf._xml_feature_key('"http://xml.org/sax/features/external-general-entities"') == "xml_external_entities"
    assert rf._xml_feature_key("XMLConstants.FEATURE_SECURE_PROCESSING") == "xml_secure_processing"
    assert rf._xml_feature_key("UNKNOWN_FEATURE") == ""
    assert rf._xml_feature_key("") == ""


# ---------------------------------------------------------------------------
# 收敛层
# ---------------------------------------------------------------------------

def _item(fact, value_bool, site="A.java", literal=True):
    """造一条已归一化的扫描命中（带站点）。"""
    pair = rf._XML_FACT_VALUE_PAIR.get(fact) or (rf._XML_FACT_SAFE_VALUE.get(fact, "on"), "off")
    return {"fact": fact, "value": pair[0] if value_bool else pair[1],
            "value_bool": value_bool, "literal": literal, "file": site}


def test_all_sites_hardened_yields_safe_fact():
    facts, conflicts = rf._aggregate_xml_facts(
        [_item("xml_external_entities", False, "A.java"), _item("xml_dtd", True, "A.java"),
         _item("xml_external_entities", False, "B.java"), _item("xml_dtd", True, "B.java")],
        sites=["A.java", "B.java"],
    )
    assert facts["xml_external_entities"] == "disabled"
    assert facts["xml_dtd"] == "disallowed"
    # 冲突明细里只该出现「根本没写」的那几条（它们同样按默认开放判不安全），
    # 我们确实写了的那两条不能有
    assert [c for c in conflicts if c.startswith(("xml_external_entities=", "xml_dtd="))] == []


def test_one_unhardened_site_makes_the_whole_workspace_unsafe():
    """站点级的意义：java-sec-code 那种一半端点加固、一半只开 XInclude 的库，
    不能被「所有显式配置都关着」洗成全局安全。"""
    facts, conflicts = rf._aggregate_xml_facts(
        [_item("xml_external_entities", False, "A.java"),
         _item("xml_external_entities", True, "B.java"),
         _item("xml_dtd", True, "A.java"),
         _item("xml_dtd", True, "B.java")],
        sites=["A.java", "B.java"],
    )
    assert facts["xml_external_entities"] == "enabled"
    assert facts["xml_dtd"] == "disallowed"          # 这条两边都关了，可以敢下结论
    assert any(c.startswith("xml_external_entities=enabled") for c in conflicts)


def test_site_with_no_config_counts_as_unsafe_for_default_open_features():
    facts, _ = rf._aggregate_xml_facts([_item("xml_dtd", True, "A.java")], sites=["A.java", "B.java"])
    # A 关了 DOCTYPE，但 B 一个字没写 ⇒ DOCTYPE 这条照样判不安全（B 能打）
    assert facts["xml_dtd"] == "allowed"
    assert facts["xml_external_entities"] == "enabled"   # 两边都没关外部实体
    assert facts["xml_load_external_dtd"] == "enabled"


def test_default_safe_feature_stays_unknown_when_never_explicitly_set():
    """secure-processing / xinclude 默认就是安全的，没人显式设就不得编出结论。"""
    facts, conflicts = rf._aggregate_xml_facts([_item("xml_dtd", True, "A.java")], sites=["A.java"])
    assert "xml_secure_processing" not in facts   # 不猜 on
    assert "xml_xinclude" not in facts
    # 冲突明细允许出现「没写的默认开放项」，但这两条默认安全的绝不能被点名
    assert [c for c in conflicts
            if c.startswith(("xml_secure_processing=", "xml_xinclude="))] == []


def test_default_safe_feature_reports_when_explicitly_turned_off():
    facts, _ = rf._aggregate_xml_facts([_item("xml_secure_processing", False, "A.java")], sites=["A.java"])
    assert facts["xml_secure_processing"] == "off"
    facts, _ = rf._aggregate_xml_facts([_item("xml_xinclude", True, "A.java")], sites=["A.java"])
    assert facts["xml_xinclude"] == "enabled"


def test_aggregate_no_sites_produces_nothing():
    facts, conflicts = rf._aggregate_xml_facts([_item("xml_dtd", True, "A.java")], sites=[])
    assert facts == {}
    assert conflicts == []


def test_aggregate_explicit_unsafe_value_on_default_safe_feature():
    facts, _ = rf._aggregate_xml_facts([_item("xml_xinclude", True, "A.java")], sites=["A.java"])
    assert facts["xml_xinclude"] == "enabled"


def test_aggregate_needs_literal_value_otherwise_unsafe_site():
    """值走变量（看不懂）按「没设」处理：默认开放的 ⇒ 不安全，默认安全的 ⇒ 不算。"""
    facts, conflicts = rf._aggregate_xml_facts(
        [{"fact": "xml_external_entities", "value": "", "literal": False, "file": "A.java"}],
        sites=["A.java"],
    )
    assert facts["xml_external_entities"] == "enabled"
    assert any(c.startswith("xml_external_entities=enabled") for c in conflicts)


def test_aggregate_secure_processing_maps_to_on_off():
    facts, _ = rf._aggregate_xml_facts([_item("xml_secure_processing", True, "A.java")], sites=["A.java"])
    assert facts["xml_secure_processing"] == "on"
    facts, _ = rf._aggregate_xml_facts([_item("xml_secure_processing", False, "A.java")], sites=["A.java"])
    assert facts["xml_secure_processing"] == "off"


def test_access_attribute_facts():
    facts, _ = rf._aggregate_xml_facts(
        [{"fact": "xml_external_dtd_access", "value": "restricted", "literal": True, "file": "A.java"}],
        sites=["A.java"],
    )
    assert facts["xml_external_dtd_access"] == "restricted"
    facts, _ = rf._aggregate_xml_facts(
        [{"fact": "xml_external_dtd_access", "value": "open", "literal": True, "file": "A.java"}],
        sites=["A.java"],
    )
    assert facts["xml_external_dtd_access"] == "open"
    # ACCESS_EXTERNAL_* 本身被设了 ⇒ 它就是结论；不许顺手替别的外部实体事实下结论
    assert facts["xml_external_schema_access"] == "open"  # 同类缺席 → 默认开放判不安全
    assert facts["xml_external_dtd_access"] != "restricted"


# ---------------------------------------------------------------------------
# 扫描层（临时源码目录）
# ---------------------------------------------------------------------------

def _write(tmp, name, text):
    p = Path(tmp) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_detect_scan_xxe_safe_parser(tmp_path):
    _write(tmp_path, "src/XmlUtil.java", """
package x;
import javax.xml.parsers.*;
public class XmlUtil {
    public Document parse(byte[] in) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setXIncludeAware(false);
        return f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(in));
    }
}
""")
    cfg = rf.detect_xml_parser_config(str(tmp_path))
    facts = cfg["facts"]
    assert facts["xml_dtd"] == "disallowed"
    assert facts["xml_external_entities"] == "disabled"
    assert cfg["files_scanned"] >= 1
    # 这道站点对这两条是收口的 ⇒ 冲突明细里不许出现它的指认
    # （其它没写过的默认开放项沿用「缺席即不安全」，那是另一回事）
    assert [c for c in cfg["conflicts"]
            if c.startswith(("xml_dtd=", "xml_external_entities="))] == []


def test_detect_marks_only_the_unhardened_site(tmp_path):
    """两个文件：一个关死、一个只 new 解析器 —— 只有后者被点名。"""
    _write(tmp_path, "src/Good.java", """
public class Good {
    void t() throws Exception {
        var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();  // 关死
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }
}
""")
    _write(tmp_path, "src/Loosely.java", """
public class Loosely {
    void t() throws Exception {
        var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();  // 什么都没设
        f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(new byte[]{1}));
    }
}
""")
    cfg = rf.detect_xml_parser_config(str(tmp_path))
    assert len(cfg["sites"]) == 2
    assert cfg["facts"]["xml_external_entities"] == "enabled"
    assert any("Loosely.java" in c for c in cfg["conflicts"] if c.startswith("xml_external_entities="))
    assert not any("Good.java" in c for c in cfg["conflicts"] if c.startswith("xml_external_entities="))
    # 加固到位的那一条从不出现在「外部实体没关」的指认里
    good_conflicts = [c for c in cfg["conflicts"] if c.startswith("xml_external_entities=")]
    assert good_conflicts and all("Good.java" not in c for c in good_conflicts)


def test_detect_scan_xxe_open_parser(tmp_path):
    _write(tmp_path, "src/BadXml.java", """
import javax.xml.parsers.DocumentBuilderFactory;
public class BadXml {
    void t() throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://xml.org/sax/features/external-general-entities", true);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "all");
    }
}
""")
    facts = rf.detect_xml_parser_config(str(tmp_path))["facts"]
    assert facts["xml_external_entities"] == "enabled"
    assert facts["xml_secure_processing"] == "off"
    assert facts["xml_external_dtd_access"] == "open"


def test_detect_no_config_yields_no_conclusion(tmp_path):
    _write(tmp_path, "src/Plain.java", "public class Plain { int x = 1; }")
    facts = rf.detect_xml_parser_config(str(tmp_path))["facts"]
    assert facts == {}  # 没看到配置 ≠ 开了 XXE，只能算未知（键缺席）


def test_detect_ignores_unrecognised_value_shapes(tmp_path):
    """两个「看不懂」的形态都不得变成结论：
    setFeature 的值走变量，setAttribute 的值拼了字符串 —— 都不进 facts。"""
    _write(tmp_path, "src/Dyn.java", """
public class Dyn {
    void t() throws Exception {
        var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        f.setFeature(FEATURES[0], flagValue);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "file," + proto);
    }
}
""")
    cfg = rf.detect_xml_parser_config(str(tmp_path))
    assert len(cfg["sites"]) == 1
    assert [f for f in cfg["features"] if f["literal"]] == []      # 一条字面量都没认出来
    # 认不出的取值不会产出事实；缺席项按默认开放判不安全（allowed/enabled/open）
    assert cfg["facts"]["xml_dtd"] == "allowed"
    assert cfg["facts"]["xml_external_dtd_access"] == "open"
    assert "xml_secure_processing" not in cfg["facts"]            # 默认安全 + 没人显式设 = 未知


def test_detect_missing_dir_is_factless(tmp_path):
    cfg = rf.detect_xml_parser_config(str(tmp_path / "nope"))
    assert cfg["facts"] == {}


# ---------------------------------------------------------------------------
# 接线层
# ---------------------------------------------------------------------------

def test_collect_facts_carries_xml_facts(tmp_path):
    _write(tmp_path, "src/XmlUtil.java", """
public class XmlUtil {
    void t() throws Exception {
        var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }
}
""")
    facts = rf.collect_facts(str(tmp_path))
    assert facts["xml_dtd"] == "disallowed"
    assert facts["xml_external_entities"] == "disabled"
    assert "xml_external_entities=" not in str(facts.get("xml_parser_conflicts") or "")


def test_collect_facts_records_conflicts_when_sites_disagree(tmp_path):
    _write(tmp_path, "src/A.java", """
public class A {
    void t() throws Exception {
        var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        f.setFeature("http://xml.org/sax/features/external-general-entities", true);
    }
}
""")
    _write(tmp_path, "src/B.java", """
public class B {
    void t() throws Exception {
        var f = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    }
}
""")
    facts = rf.collect_facts(str(tmp_path))
    assert facts["xml_external_entities"] == "enabled"
    assert "xml_external_entities=enabled" in facts["xml_parser_conflicts"]


def test_collect_facts_without_target_path_leaves_xml_unknown():
    facts = rf.collect_facts(None)
    assert "xml_dtd" not in facts


def test_env_override_for_xml_fact(monkeypatch):
    monkeypatch.setenv("SAST_AI_XML_EXTERNAL_ENTITIES", "enabled")
    facts = rf.collect_facts(None)
    assert facts["xml_external_entities"] == "enabled"


def test_env_premise_xml_keys_are_known_and_fail_open():
    assert {"xml_dtd", "xml_external_entities", "xml_secure_processing"} <= set(ep.KNOWN_FACT_KEYS)

    facts = {"xml_external_entities": "disabled"}
    assert ep.check_premise({"xml_external_entities": ["disabled"]}, facts)[0] == ep.SATISFIED

    facts["xml_external_entities"] = "enabled"
    state, _ = ep.check_premise({"xml_external_entities": ["disabled"]}, facts)
    assert state == ep.UNSATISFIED

    # 事实缺席（没采到）→ unknown，绝不误杀
    state, reason = ep.check_premise({"xml_external_entities": ["disabled"]}, {})
    assert state == ep.UNKNOWN
    assert "fact_missing" in reason


def test_env_premise_xml_key_name_is_not_accidentally_admitted():
    # 拼错的键名必须报错式处理（记 unknown_fact_key），不能静默放行
    state, reason = ep.check_premise({"xml_externall_enteties": ["disabled"]}, {"xml_externall_enteties": "disabled"})
    assert state == ep.UNKNOWN
    assert "unknown_fact_key" in reason


def test_full_pipeline_xxe_premise_on_real_repo_root_has_no_invention():
    """对真实仓库根扫一次：不得凭空产出事实（扫不到就是键缺席）。

    SAVR 自己不是 XML 靶场，正常预期是扫不到任何 setFeature ⇒ facts 为空。
    这里钉的是**不变量**（产出值的键必须是白名单键、值必须在取值域内），
    而不是「必须扫到东西」。
    """
    root = Path(__file__).resolve().parents[1]
    cfg = rf.detect_xml_parser_config(str(root), max_files=200)
    assert isinstance(cfg["features"], list)
    allowed_pairs = set(rf._XML_FACT_VALUE_PAIR) | set(rf._XML_ACCESS_ATTR_TO_FACT.values())
    allowed_values = {
        fk: {rf._XML_FACT_VALUE_PAIR[fk][0], rf._XML_FACT_VALUE_PAIR[fk][1]} for fk in rf._XML_FACT_VALUE_PAIR
    }
    allowed_values.update({fk: {"restricted", "open"} for fk in rf._XML_ACCESS_ATTR_TO_FACT.values()})
    for it in cfg["features"]:
        assert it["fact"] in allowed_pairs, it["fact"]
        if it.get("literal"):
            assert it["value"] in allowed_values[it["fact"]], it
    for k in cfg["facts"]:
        assert k in ep.KNOWN_FACT_KEYS


@pytest.mark.parametrize("name", ["setFeature", "setXIncludeAware", "setExpandEntityReferences"])
def test_call_scanners_are_independent(name):
    assert list(rf._find_calls('a.%s(true);' % name, name)) == ["true"]
