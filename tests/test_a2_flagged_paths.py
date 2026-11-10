"""flag 开关路径的集成自测（20.4.1 意图注入 / 20.5.1 决策缓存 / 20.3.3 契约档）。

为什么必须写这个：这两条新链路是**第一次**在统一重跑里被打开，
跑批一轮 2 小时，路径上任何一个小 bug 都要赔上一整轮。
所以在跑批前用假 LLM 把两条路径各走一遍（不调 Ollama）。

覆盖：
- 默认（开关关）行为零变化：intent_hints 空 ⇒ prompt 不追加任何提示；
- 20.4.1：intent_hints 会进 A2 的 user prompt；
- 20.5.1：同文件 + 同族组合，第二次调用命中决策缓存 ⇒ 不再调 LLM，但结果一致。
"""
import json
import os

import pytest

from src.agents import a2_integrated_analyst as A2


SPEC = {
    "line": 1,
    "verdict": "real",
    "reason": "注入可达",
    "spec": {
        "route": "/x", "method": "GET", "param_name": "p", "param_location": "query",
        "payload": "1' OR '1'='1", "bypass_payloads": ["a", "b"],
        "sanitizer": {"present": False, "type": "none", "strength": "strong",
                      "location": "", "snippet": "", "why_bypassable": ""},
    },
}


class _FakeAnalyst:
    """记录调用次数与收到的 intent_hints，返回固定 spec。"""

    calls = 0
    seen_hints = []

    def __init__(self, *a, **kw):
        pass

    def analyze(self, code, filename, findings, extra_context="", intent_hints=""):
        type(self).calls += 1
        type(self).seen_hints.append(intent_hints)
        return [dict(SPEC)]


@pytest.fixture(autouse=True)
def _reset_fake():
    _FakeAnalyst.calls = 0
    _FakeAnalyst.seen_hints = []
    yield
    _FakeAnalyst.calls = 0
    _FakeAnalyst.seen_hints = []


def _files():
    return [{"rel_path": "src/main/java/A.java",
             "content": "class A { void f(){} }"}]


def test_default_path_has_no_intent_block():
    """默认路径：intent_hints 为空 ⇒ prompt 里不得出现任何意图块（零影响）。"""
    p = A2._user_prompt("code", "A.java", [{"line": 1, "family": "xss"}])
    assert "历史探索摘要" not in p
    p2 = A2._user_prompt("code", "A.java", [{"line": 1, "family": "xss"}],
                         intent_hints="")
    assert "历史探索摘要" not in p2


def test_intent_hints_are_injected_into_prompt():
    p = A2._user_prompt("code", "A.java", [{"line": 1, "family": "xss"}],
                        intent_hints="  - /x p(query): action=change_payload")
    assert "历史探索摘要" in p
    assert "change_payload" in p


def test_analyze_forwards_intent_hints_to_llm():
    """analyze() 把 intent_hints 透传到 user prompt（假 LLM 捕获 messages）。"""
    captured = {}

    def fake_llm(msgs):
        captured["msgs"] = msgs
        return json.dumps([SPEC])

    an = A2.IntegratedAnalyst(llm_call=fake_llm)
    an.analyze("code", "A.java", [{"line": 1, "family": "xss"}],
               intent_hints="ACTION_MARKER change_encoding")
    user = captured["msgs"][-1]["content"]
    assert "ACTION_MARKER change_encoding" in user


def test_decision_cache_hit_skips_llm(tmp_path, monkeypatch):
    """20.5.1：同文件 + 同族组合，第二次应命中缓存不再调 LLM，结果一致。"""
    from src.cli import benchmark_cli as B

    db_path = tmp_path / "app.db"
    monkeypatch.setenv("SAST_AI_DB_PATH", str(db_path))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "1")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    findings = [{"line": 1, "family": "sql_injection", "note": "sink"}]
    a1 = {"src/main/java/A.java": findings}

    r1, _ = B.run_a2_integrated_scan(_files(), a1)
    assert _FakeAnalyst.calls == 1
    r2, _ = B.run_a2_integrated_scan(_files(), a1)
    assert _FakeAnalyst.calls == 1, "第二次应命中决策缓存，不再调 LLM"
    # 结果一致性：两次都产出了同一条漏洞（run_a2_integrated_scan 返回 (results, client) 元组）
    n1 = sum(len(getattr(r, "vulnerabilities", []) or []) for r in r1)
    n2 = sum(len(getattr(r, "vulnerabilities", []) or []) for r in r2)
    assert n1 == n2 and n1 >= 1


def test_decision_cache_off_calls_llm_each_time(tmp_path, monkeypatch):
    """默认关闭：两次都调 LLM（行为零变化）。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    findings = [{"line": 1, "family": "sql_injection", "note": "sink"}]
    a1 = {"src/main/java/A.java": findings}
    B.run_a2_integrated_scan(_files(), a1)
    B.run_a2_integrated_scan(_files(), a1)
    assert _FakeAnalyst.calls == 2


def test_intent_hints_forwarded_through_scan(tmp_path, monkeypatch):
    """20.4.1：run_a2_integrated_scan 把 intent_hints 透到 analyze()。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    findings = [{"line": 1, "family": "sql_injection", "note": "sink"}]
    a1 = {"src/main/java/A.java": findings}
    B.run_a2_integrated_scan(_files(), a1, intent_hints="INTENT_MARKER change_payload")
    assert _FakeAnalyst.seen_hints == ["INTENT_MARKER change_payload"]


class _A1V:
    def __init__(self, vtype, line, desc=""):
        self.type = vtype
        self.line = line
        self.description = desc or vtype
        self.sink = ""


class _A1R:
    def __init__(self, file, vulns):
        self.file = file
        self.vulnerabilities = vulns
        self.evidence = {}


class _A1V:
    def __init__(self, vtype, line, desc=""):
        self.type = vtype
        self.line = line
        self.description = desc or vtype
        self.sink = ""


class _A1R:
    def __init__(self, file, vulns):
        self.file = file
        self.vulnerabilities = vulns
        self.evidence = {}


# ─────────────────────────────────────────────────────────────
# 20.4.x / P4：全门禁文件跳过 A2（471 实测 13.8% 文件可跳过）
# ─────────────────────────────────────────────────────────────

BENCH = __import__("pathlib").Path(
    r"<sdl-root>/owasp-code/BenchmarkJava-master")
_GATED = BENCH / "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java"
_VULN = BENCH / "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java"


@pytest.mark.skipif(not _GATED.exists(), reason="Benchmark 源码不在本机")
def test_skip_gated_file_avoids_llm(tmp_path, monkeypatch):
    """全部 finding 被门禁剔除的文件，A2 不该调 LLM（结果本来就会被丢弃）。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.setenv("SAST_AI_A2_SKIP_GATED_FILES", "1")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    code = _GATED.read_text(encoding="utf-8", errors="replace")
    files = [{"rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
              "content": code}]
    a1 = [_A1R("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
               [_A1V("cross-site scripting", 79)])]
    B.run_a2_integrated_scan(files, a1)
    assert _FakeAnalyst.calls == 0, "全门禁文件不应调用 LLM"


@pytest.mark.skipif(not _VULN.exists(), reason="Benchmark 源码不在本机")
def test_skip_gated_does_not_skip_vulnerable_file(tmp_path, monkeypatch):
    """反向保护：真漏洞文件必须照常分析。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.setenv("SAST_AI_A2_SKIP_GATED_FILES", "1")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    code = _VULN.read_text(encoding="utf-8", errors="replace")
    files = [{"rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java",
              "content": code}]
    a1 = [_A1R("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java",
               [_A1V("xss", 56)])]
    B.run_a2_integrated_scan(files, a1)
    assert _FakeAnalyst.calls == 1, "真漏洞文件必须照常分析"


def test_skip_gated_flag_off_by_default(tmp_path, monkeypatch):
    """默认关闭：不设开关时全门禁文件也要分析（零行为变化）。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.delenv("SAST_AI_A2_SKIP_GATED_FILES", raising=False)
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    if not _GATED.exists():
        pytest.skip("Benchmark 源码不在本机")
    code = _GATED.read_text(encoding="utf-8", errors="replace")
    files = [{"rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
              "content": code}]
    a1 = [_A1R("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
               [_A1V("cross-site scripting", 79)])]
    B.run_a2_integrated_scan(files, a1)
    assert _FakeAnalyst.calls == 1, "开关默认关，应照常分析"


class _A1V:
    def __init__(self, vtype, line, desc=""):
        self.type = vtype
        self.line = line
        self.description = desc or vtype
        self.sink = ""


class _A1R:
    def __init__(self, file, vulns):
        self.file = file
        self.vulnerabilities = vulns
        self.evidence = {}


class _A1V:
    def __init__(self, vtype, line, desc=""):
        self.type = vtype
        self.line = line
        self.description = desc or vtype
        self.sink = ""


class _A1R:
    def __init__(self, file, vulns):
        self.file = file
        self.vulnerabilities = vulns
        self.evidence = {}


# ─────────────────────────────────────────────────────────────
# 20.4.x / P4：全门禁文件跳过 A2（471 实测 13.8% 文件可跳过）
# ─────────────────────────────────────────────────────────────

BENCH = __import__("pathlib").Path(
    r"<sdl-root>/owasp-code\BenchmarkJava-master")
_GATED = BENCH / "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java"
_VULN = BENCH / "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java"


@pytest.mark.skipif(not _GATED.exists(), reason="Benchmark 源码不在本机")
def test_skip_gated_file_avoids_llm(tmp_path, monkeypatch):
    """全部 finding 被门禁剔除的文件，A2 不该调 LLM（结果本来就会被丢弃）。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.setenv("SAST_AI_A2_SKIP_GATED_FILES", "1")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    code = _GATED.read_text(encoding="utf-8", errors="replace")
    files = [{"rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
              "content": code}]
    a1 = [_A1R("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
               [_A1V("cross-site scripting", 79)])]
    B.run_a2_integrated_scan(files, a1)
    assert _FakeAnalyst.calls == 0, "全门禁文件不应调用 LLM"


@pytest.mark.skipif(not _VULN.exists(), reason="Benchmark 源码不在本机")
def test_skip_gated_does_not_skip_vulnerable_file(tmp_path, monkeypatch):
    """反向保护：真漏洞文件必须照常分析。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.setenv("SAST_AI_A2_SKIP_GATED_FILES", "1")
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    code = _VULN.read_text(encoding="utf-8", errors="replace")
    files = [{"rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java",
              "content": code}]
    a1 = [_A1R("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java",
               [_A1V("xss", 56)])]
    B.run_a2_integrated_scan(files, a1)
    assert _FakeAnalyst.calls == 1, "真漏洞文件必须照常分析"


def test_skip_gated_flag_off_by_default(tmp_path, monkeypatch):
    """默认关闭：不设开关时全门禁文件也要分析（零行为变化）。"""
    from src.cli import benchmark_cli as B

    monkeypatch.setenv("SAST_AI_DB_PATH", str(tmp_path / "app.db"))
    monkeypatch.setenv("SAST_AI_DECISION_CACHE", "0")
    monkeypatch.delenv("SAST_AI_A2_SKIP_GATED_FILES", raising=False)
    monkeypatch.setattr("src.agents.a2_integrated_analyst.IntegratedAnalyst", _FakeAnalyst)

    if not _GATED.exists():
        pytest.skip("Benchmark 源码不在本机")
    code = _GATED.read_text(encoding="utf-8", errors="replace")
    files = [{"rel_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
              "content": code}]
    a1 = [_A1R("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00022.java",
               [_A1V("cross-site scripting", 79)])]
    B.run_a2_integrated_scan(files, a1)
    assert _FakeAnalyst.calls == 1, "开关默认关，应照常分析"
