"""阶段2a 确认态 sink 身份校验 post-pass 的单测。

锁住四条行为约定：
  1. xpathi/trustbound 的 canary 只到旁路 sink（不在族真 sink 实参）⇒ 抑制；
  2. canary 进入族真 sink 实参 ⇒ 不抑制（不误杀真报）；
  3. 硬边界：path_traversal 等族即使只到旁路也不抑制（旁路 TP 多）；
  4. 零事件 / 总开关关闭 ⇒ 不动。
"""
from __future__ import annotations

import importlib

import pytest

IDENT_A = "s4st41" + "a" * 16


def _marker(ident: str, payload: str = "x") -> str:
    return f"{ident}PAYLOAD{payload}"


class FakeSDB:
    def __init__(self, specs, events):
        self.specs = specs
        self.events = events
        self.updates = []

    def execute(self, sql, params=None, fetchall=False):
        s = " ".join(str(sql).split())
        if s.startswith("SELECT id, target_endpoint"):
            return [dict(x) for x in self.specs if not x.get("suppressed_by_safe_verdict")]
        if s.startswith("SELECT sink_file, source_value FROM iast_events"):
            return list(self.events.get(params[1], []))
        if s.startswith("UPDATE trigger_specs SET suppressed_by_safe_verdict=1"):
            self.updates.append(params[-1])
            return None
        return [] if fetchall else None


def _spec(sid, endpoint, marker, family="xpath_injection"):
    return {
        "id": sid,
        "target_endpoint": endpoint,
        "expected_sink_file": "X.java",
        "taint_marker": marker,
        "family": family,
        "capability_family": family,
        "suppressed_by_safe_verdict": 0,
    }


@pytest.fixture()
def cli():
    return importlib.import_module("src.cli.benchmark_cli")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE", "1")


def test_xpathi_bypass_only_suppressed(cli):
    """canary 只到 PrintWriter（旁路），不在 XPath.evaluate 实参 ⇒ 抑制。"""
    specs = [_spec(1, "/xp/BenchmarkTest00001", _marker(IDENT_A))]
    events = {IDENT_A: [{"sink_file": "java.io.PrintWriter.write",
                         "source_value": "some static output"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 1
    assert sdb.updates == [1]


def test_xpathi_true_sink_not_suppressed(cli):
    """canary 在 XPath.evaluate 实参 ⇒ 不抑制。"""
    specs = [_spec(1, "/xp/BenchmarkTest00002", _marker(IDENT_A))]
    events = {IDENT_A: [{
        "sink_file": "com.sun.org.apache.xpath.internal.jaxp.XPathImpl.evaluate",
        "source_value": f"expr={_marker(IDENT_A)}",
    }]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_trustbound_bypass_suppressed(cli):
    """trustbound canary 只到 Cookie（旁路）⇒ 抑制。"""
    specs = [_spec(1, "/tb/BenchmarkTest00003", _marker(IDENT_A),
                   family="trust_boundary_violation")]
    events = {IDENT_A: [{"sink_file": "javax.servlet.http.Cookie.<init>",
                         "source_value": "[color, red]"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 1


def test_trustbound_true_sink_not_suppressed(cli):
    """trustbound canary 在 StandardSession.setAttribute 实参 ⇒ 不抑制。"""
    specs = [_spec(1, "/tb/BenchmarkTest00004", _marker(IDENT_A),
                   family="trust_boundary_violation")]
    events = {IDENT_A: [{
        "sink_file": "org.apache.catalina.session.StandardSession.setAttribute",
        "source_value": f"[{_marker(IDENT_A)}, 10340]",
    }]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 0


def test_path_traversal_not_in_whitelist(cli):
    """硬边界：path_traversal 即使只到旁路也不抑制（旁路 TP=66）。"""
    specs = [_spec(1, "/pt/BenchmarkTest00005", _marker(IDENT_A), family="path_traversal")]
    events = {IDENT_A: [{"sink_file": "java.io.PrintWriter.write", "source_value": "x"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_zero_event_not_suppressed(cli):
    """零事件（没到任何 sink）不在本规则范围 ⇒ 不抑制。"""
    specs = [_spec(1, "/xp/BenchmarkTest00006", _marker(IDENT_A))]
    sdb = FakeSDB(specs, {})
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 0


def test_value_gate_disabled_noop(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE", "0")
    specs = [_spec(1, "/xp/BenchmarkTest00007", _marker(IDENT_A))]
    events = {IDENT_A: [{"sink_file": "java.io.PrintWriter.write", "source_value": "x"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 0


def test_multi_spec_group_all_suppressed(cli):
    """同组多个 spec：整组被抑制。"""
    specs = [_spec(1, "/xp/BenchmarkTest00008", _marker(IDENT_A)),
             _spec(2, "/xp/BenchmarkTest00008", _marker(IDENT_A))]
    events = {IDENT_A: [{"sink_file": "java.io.PrintWriter.write", "source_value": "x"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_confirm_sink_identity_postpass(1, sdb) == 2
    assert sorted(sdb.updates) == [1, 2]


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
