#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""族名唯一真相源（P1）、并集去重（P2）、聚合吸收留痕（P3）的单测。

这三个改动是「误报漏报」治理的地基，锁住它们是为了防止回退：
- P1：CodeQL 原生名必须映射成平台族，未映射不许靠 Title Case 猜
- P2：两个引擎的族名不同也要能去重（否则同一漏洞报 2~3 条）
- P3：聚合吸收掉的成员要留 vhash，否则它的 spec 会被当孤儿删
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core import family_map as fm  # noqa: E402


# ─────────────────────────────────────────── P1：族名映射
def test_mapped_rules():
    assert fm.canonical_from_rule("java/xss")[0] == "xss"
    assert fm.canonical_from_rule("java/path-injection")[0] == "path_traversal"
    assert fm.canonical_from_rule("java/xxe")[0] == "xxe"
    assert fm.canonical_from_rule("java/http-response-splitting")[0] == "crlf_injection"
    assert fm.canonical_from_rule("java/ssrf")[0] == "ssrf"


def test_relative_path_command_is_command_not_pathtraversal():
    """本轮实证：java/relative-path-command 曾落成 `路径穿越`，实际是命令执行。"""
    fam, reason = fm.canonical_from_rule("java/relative-path-command")
    assert fam == "command_execution" and reason == "mapped"


def test_native_display_name_never_leaks():
    """回归：以前兜底是 Title Case，`java/log-injection` 会变成 'Log Injection' 带空格。"""
    fam, reason = fm.canonical_from_rule("java/log-injection")
    assert " " not in fam and "/" not in fam
    assert fam == "log_injection"


def test_unsupported_is_explicit():
    fam, reason = fm.canonical_from_rule("java/format-string")
    assert fam == fm.UNMAPPED and reason == "unsupported"


def test_unknown_rule_is_unmapped_not_guessed():
    fam, reason = fm.canonical_from_rule("java/some-brand-new-query")
    assert fam == fm.UNMAPPED and reason == "unmapped"


def test_empty_rule_id():
    assert fm.canonical_from_rule("") == (fm.UNMAPPED, "empty_rule_id")


def test_d2_supported_flag():
    assert fm.is_d2_supported("xss") is True
    assert fm.is_d2_supported("sql_injection") is True
    assert fm.is_d2_supported(fm.UNMAPPED) is False
    assert fm.is_d2_supported("") is False


def test_type_and_family_no_longer_diverge():
    """`_map_rule_to_type` 与 `_map_rule_to_family` 必须同源，否则 type 又会漏显示名。"""
    from src.agents.a1_codeql_semantic_agent import _map_rule_to_family, _map_rule_to_type
    for rid in ("java/xss", "java/log-injection", "java/path-injection", "java/unknown-x"):
        assert _map_rule_to_type(rid, "") == _map_rule_to_family(rid, "")


# ─────────────────────────────────────────── P2：并集去重
def _vuln(type_, line, sink=""):
    from src.core.models import Vulnerability
    return Vulnerability(type=type_, severity="MEDIUM", line=line,
                         description="", file="A.java", sink=sink)


def test_dedup_across_engines_with_different_type_names():
    """CodeQL 出 `cross-site scripting`、启发式出 `xss`，同一行必须只留一条。"""
    from src.pipeline.a1.service import A1PipelineService
    codeql = _vuln("xss", 10, "java/xss")
    heur = _vuln("xss", 12, "getWriter")
    from src.core.models import ScanResult
    res = [ScanResult(file="A.java", vulnerabilities=[codeql], agent="a1")]
    out, added = A1PipelineService._merge_heuristic_into_codeql(res, [heur])
    assert added == 0, "同一族同一行附近的两条应被去重"


def test_no_dedup_when_different_family():
    from src.pipeline.a1.service import A1PipelineService
    from src.core.models import ScanResult
    a = _vuln("path_traversal", 10, "java/path-injection")
    b = _vuln("command_execution", 10, "Runtime.exec")
    res = [ScanResult(file="A.java", vulnerabilities=[a], agent="a1")]
    out, added = A1PipelineService._merge_heuristic_into_codeql(res, [b])
    assert added == 1


def test_no_dedup_when_two_real_sinks_same_family():
    """同族同一行但两个**真实 sink**（都不带 `/`）不能被合并。"""
    from src.pipeline.a1.service import A1PipelineService
    from src.core.models import ScanResult
    a = _vuln("path_traversal", 10, "Files.write")
    b = _vuln("path_traversal", 10, "FileOutputStream")
    res = [ScanResult(file="A.java", vulnerabilities=[a], agent="a1")]
    out, added = A1PipelineService._merge_heuristic_into_codeql(res, [b])
    assert added == 1


# ─────────────────────────────────────────── P3：聚合吸收留痕
def test_aggregate_records_absorbed_vhashes():
    """同族同行的多条聚合后，canonical 行要带上被吸收成员的 vhash。

    没有这个字段，被吸收成员的 spec 会在 reconcile_orphan_specs 里被当孤儿删掉
    （本轮删了 16 条，含 Fastjson L23 / Deserialize L50 / Rce L113）。
    """
    from src.benchmark.report_manager import ReportManager
    mgr = ReportManager.__new__(ReportManager)  # 不跑 __init__，只用纯函数
    items = [
        {"file": "A.java", "line": 10, "type": "xss", "family": "xss",
         "severity": "HIGH", "description": "d1", "code_snippet": "s"},
        {"file": "A.java", "line": 10, "type": "xss", "family": "xss",
         "severity": "MEDIUM", "description": "d2", "code_snippet": "s"},
    ]
    out = mgr._aggregate_canonical_findings(items)
    assert len(out) == 1, "同族同行应收敛成一条"
    assert out[0].get("absorbed_vhashes"), "被吸收成员的 vhash 必须留痕"


# ── 2026-11-01 第二轮：本轮暴露的两个族名污染源 ──────────────────────

def test_empty_rule_id_is_not_unmapped():
    """空 rule_id 是「没有规则」，不是「未登记的规则」。

    混成 unmapped 会让族空间里出现 8 条假映射缺口（本轮实测），
    而它们其实是 LLM 研判残项（只有 file/line，无 type/rule_id）。
    """
    from src.agents.a1_codeql_semantic_agent import _map_rule_to_family

    assert _map_rule_to_family("", "") == ""
    assert _map_rule_to_family("   ", "") == ""
    # 真的未登记规则仍必须落 unmapped（这是审计口径，不能一起放宽）
    assert _map_rule_to_family("java/definitely-not-a-real-query", "") == "unmapped"


def test_code_injection_maps_to_command_execution():
    """`code injection` 是启发式引擎对 Rce.java 的输出，此前无归一 ⇒ D2 无模板。"""
    from src.core.normalize import is_known_family, normalize_family
    from src.agents.a1_codeql_semantic_agent import _map_rule_to_family

    for raw in ("code injection", "code-injection", "code_injection"):
        fam = normalize_family(raw)
        assert fam == "command_execution", raw
        assert is_known_family(fam)
    assert _map_rule_to_family("java/code-injection", "") == "command_execution"


def test_log4j_rce_still_jndi():
    """补 code injection 别名不能把 `log4j rce` 抢走（族分组按整串匹配）。"""
    from src.core.normalize import normalize_family

    assert normalize_family("log4j rce") == "jndi_injection"


# ── LLM 研判漏 rule_id 的按位回填（本轮 8 条 unmapped，其中 1 条是唯一确认的 SQLi）──

class _FakeGateway:
    """只回一条「缺 rule_id」的研判项，模拟真实 LLM 的漏字段行为。"""

    def __init__(self, payload):
        self._payload = payload
        self.calls = 0

    def complete(self, purpose=None, prompt=None, context=None):
        self.calls += 1

        class _R:
            text = self._payload

        return _R()


def test_llm_triage_recovers_rule_id_by_position():
    """LLM 只回 file/line 时，必须按 (file,line) 回填原告警 rule_id，而不是落 unmapped。"""
    import json as _json
    from src.agents.a1_codeql_semantic_agent import A1CodeQLSemanticAgent

    alerts = [{"rule_id": "java/sql-injection", "file": "A.java", "line": 64,
               "message": "tainted value to query", "severity": "error"}]
    payload = _json.dumps([{"file": "A.java", "line": 64, "verdict": "true_positive",
                            "severity": "HIGH", "reason": "real"}])
    agent = A1CodeQLSemanticAgent({"a1_use_codeql": True})
    agent.gateway = _FakeGateway(payload)

    out = agent._llm_triage(alerts, {})

    assert len(out) == 1
    assert out[0].type == "sql_injection", out[0].type
    assert out[0].type != "unmapped"


def test_llm_triage_drops_item_with_no_identity():
    """既无 rule_id 又无法按位置回填的残项必须丢弃，不能落 unmapped 污染族空间。"""
    import json as _json
    from src.agents.a1_codeql_semantic_agent import A1CodeQLSemanticAgent

    payload = _json.dumps([{"file": "Ghost.java", "line": 7, "verdict": "true_positive"}])
    agent = A1CodeQLSemanticAgent({"a1_use_codeql": True})
    agent.gateway = _FakeGateway(payload)

    assert agent._llm_triage([], {}) == []


# ── 2026-11-01 第二轮回归：映射表必须产出**平台已知族** ──────────────────
# 背景：yaml 曾把 weak-crypto/randomness/hash 映射成 crypto/weakrand/hash（OWASP 真值 CSV 的类目名），
# 这三个 `is_known_family` 全为 False ⇒ D2 拿不到模板 ⇒ OWASP 上 no-arrival 2→117、confirmed 212→140。
# 这条用例锁的是「yaml 的右值必须是平台族」，不是某个具体字符串。

def test_all_mapped_families_are_platform_known():
    from src.core.family_map import table_snapshot
    from src.core.normalize import is_known_family

    rules = table_snapshot().get("rules") or {}
    assert rules, "映射表不应为空"
    unknown = sorted({v for v in rules.values() if not is_known_family(v)})
    # 允许保留的「属性类但平台无族」白名单：它们不进动态分母（is_d2_supported=False），
    # 但必须显式列在这里，新增未知族就会让本用例变红。
    allowed = {"information_exposure", "log_injection", "format_string", "code_injection", "rmi"}
    bad = [f for f in unknown if f not in allowed]
    assert not bad, f"映射表产出了平台不认识的族：{bad}"


def test_weak_family_tokens_are_the_platform_ones():
    from src.agents.a1_codeql_semantic_agent import _map_rule_to_family
    from src.core.normalize import is_known_family

    assert _map_rule_to_family("java/weak-cryptographic-algorithm", "") == "weak_crypto"
    assert _map_rule_to_family("java/insecure-randomness", "") == "weak_random"
    assert _map_rule_to_family("sastai/java/weak-hash-algorithm", "") == "weak_hash"
    for fam in ("weak_crypto", "weak_random", "weak_hash"):
        assert is_known_family(fam), fam


def test_owasp_audited_rule_ids_are_registered():
    """585 审计出的 4 条未登记规则必须已补，否则它们落 unmapped（27 条告警）。"""
    from src.agents.a1_codeql_semantic_agent import _map_rule_to_family

    for rid in ("java/stack-trace-exposure", "java/tainted-format-string",
                "java/potentially-weak-cryptographic-algorithm", "java/xml/xpath-injection",
                "java/concatenated-command-line", "java/exec-tainted-environment"):
        assert _map_rule_to_family(rid, "") != "unmapped", rid


# ── 族优先顺序守卫（2026-11-01）─────────────────────────────────────────────
#
# 事故：`_a1_findings_by_file` 先用 `_map_rule_to_family(v.sink, ...)` 把 **sink 名**
# 当 CodeQL rule_id 查表，framework_sinks 产出且**自带正确族**的 finding 被覆盖成
# unmapped（本轮实时日志：Cookie.setSecure / QLExpress.execute / Velocity.evaluate /
# Access-Control-Allow-Origin 全落 unmapped ⇒ 这些 spec 拿不到 D2 证明模板）。
# 正解是 finding 自带的族优先，映射只做兜底。


def test_finding_own_family_wins_over_sink_name_mapping():
    from src.cli.benchmark_cli import _a1_findings_by_file
    from src.core.models import Vulnerability

    cases = [
        ("Access-Control-Allow-Origin", "cors"),
        ("Cookie.setSecure", "secure_cookie"),
        ("QLExpress.execute", "expression_injection"),
        ("Velocity.evaluate", "ssti"),
        ("PostMapping", "csrf"),
    ]

    class _R:
        def __init__(self, f):
            self.file = f
            self.vulnerabilities = []
            self.evidence = {}

    r = _R("D:/tmp/App.java")
    for sink, fam in cases:
        r.vulnerabilities.append(Vulnerability(
            type=fam, severity="HIGH", line=10, description="x",
            file="D:/tmp/App.java", sink=sink))

    out = _a1_findings_by_file([r])
    fams = [x["family"] for x in out[list(out)[0]]]
    assert fams == [c[1] for c in cases], (
        "finding 自带的族被 sink 名映射覆盖了：%s" % fams)
