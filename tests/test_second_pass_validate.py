"""问题 5：run_validate_pass 的 fail-open 精度过滤逻辑单测。

不依赖真实 LLM：用 FakeGateway 注入响应，验证
- 默认关闭（validate_enabled=False）时不调用、不改动；
- 判真(TP) 不动 verdict/confidence；
- 判假(FP) 仅打「假漏洞」标记 + 降置信度 low，不删 finding；
- 异常 / 离线 一律 fail-open 保持原状；
- 资格筛选：chain_proven 跳过、无 code_snippet 跳过、已确认可利用(exploitable) 不降判。
"""
import pytest

from src.core.models import Vulnerability, ScanResult
from src.core.second_pass_proof import run_validate_pass


class FakeGateway:
    def __init__(self, text=None, raises=None, offline=False, model="test-model"):
        self._text = text
        self._raises = raises
        self.is_offline = offline
        self.model = model

    def complete(self, *, purpose="", prompt="", prompt_version="", context=None, **kwargs):
        if self._raises is not None:
            raise self._raises
        class _R:
            pass
        r = _R()
        r.text = self._text
        return r


def _vuln(**kw):
    base = dict(
        type="SQL注入", severity="HIGH", line=42, description="拼接 SQL",
        file="Jdbc.java", code_snippet="String sql = \"select \" + input;",
        proof_tier="broad_static", verdict="", confidence="", exploitable=None,
    )
    base.update(kw)
    return Vulnerability(**base)


def _run(vulns, gateway, **overrides):
    sr = ScanResult(file="Jdbc.java", vulnerabilities=vulns)
    return run_validate_pass([sr], gateway=gateway, overrides={"validate_enabled": True, **overrides})


def test_disabled_by_default():
    gw = FakeGateway(text='{"is_true_positive": true}')
    sr = ScanResult(file="Jdbc.java", vulnerabilities=[_vuln()])
    # 不传 overrides（用 config 默认值 validate_enabled=False）
    stats = run_validate_pass([sr], gateway=gw)
    assert stats["enabled"] is False
    assert stats["judged_tp"] == 0 and stats["judged_fp"] == 0


def test_true_positive_does_not_change_verdict():
    v = _vuln()
    gw = FakeGateway(text='{"is_true_positive": true, "reason": "可控入参"}')
    stats = _run([v], gw)
    assert stats["judged_tp"] == 1
    assert v.verdict == "" and v.confidence == ""  # 判真不动


def test_false_positive_marks_fp_lowers_confidence():
    v = _vuln()
    gw = FakeGateway(text='{"is_true_positive": false, "reason": "预编译"}')
    stats = _run([v], gw)
    assert stats["judged_fp"] == 1
    assert v.verdict == "假漏洞"
    assert v.confidence == "low"


def test_fail_open_on_exception():
    v = _vuln()
    gw = FakeGateway(raises=RuntimeError("Ollama 500"))
    stats = _run([v], gw)
    assert stats["judged_tp"] == 0 and stats["judged_fp"] == 0
    assert stats["failed"] == 1
    assert v.verdict == ""  # 原状保持


def test_offline_skipped():
    v = _vuln()
    gw = FakeGateway(text='{"is_true_positive": false}', offline=True)
    stats = _run([v], gw)
    assert stats["offline_skipped"] == 1
    assert stats["judged_fp"] == 0
    assert v.verdict == ""


def test_skips_chain_proven():
    v_ok = _vuln()                         # broad_static，应被验
    v_done = _vuln(proof_tier="chain_proven")  # 已证成，跳过
    gw = FakeGateway(text='{"is_true_positive": true}')
    stats = _run([v_ok, v_done], gw)
    assert stats["candidates"] == 1
    assert stats["judged_tp"] == 1


def test_skips_missing_snippet():
    v = _vuln(code_snippet="")             # 无片段，跳过
    gw = FakeGateway(text='{"is_true_positive": false}')
    stats = _run([v], gw)
    assert stats["candidates"] == 0
    assert stats["judged_fp"] == 0


def test_exploitable_not_downgraded():
    v = _vuln(exploitable=True)            # 已确认可利用，不降判
    gw = FakeGateway(text='{"is_true_positive": false}')
    stats = _run([v], gw)
    assert stats["candidates"] == 0
    assert stats["judged_fp"] == 0
    assert v.verdict == ""
