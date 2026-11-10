"""Phase 1.5 孤儿 spec 补入（_enqueue_orphan_trigger_specs）单测。

背景：r102 cmdi 实测 55 条 spec `failure_attribution=pipeline_gap`（18 真报 + 37 误报），
payload/replayable/endpoint 齐全却从未进入 D2 重放。本函数把它们补成 D2 候选。

锁住四条约定：
  1. 只补「无结论」（空 / no_evidence）的 spec，已有判定的不补；
  2. replayable=0 或无 target_endpoint 不补；
  3. 合成 vuln 的 vhash 必须仍能反查到 spec（不得改动参与 hash 的字段）；
  4. 总开关 SAST_AI_D2_ORPHAN_REPLAY=0 时完全不补。
"""
from __future__ import annotations

import importlib
import json

import pytest

from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2 as vh2

RAW = {
    "type": "命令注入",
    "severity": "HIGH",
    "line": 77,
    "description": "命令拼接",
    "file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00091.java",
    "code_snippet": "r.exec(args, argsEnv);",
}
SPEC_VH = vh2(canonicalize_vuln_for_hash(RAW))


@pytest.fixture()
def cli():
    return importlib.import_module("src.cli.benchmark_cli")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SAST_AI_D2_ORPHAN_REPLAY", "1")
    monkeypatch.delenv("SAST_AI_D2_ORPHAN_MAX", raising=False)


def _spec(**kw):
    s = {
        "id": 1,
        "target_endpoint": "/cmdi-00/BenchmarkTest00091",
        "expected_sink_file": "BenchmarkTest00091.java",
        "expected_sink_line": 77,
        "raw_json": json.dumps(RAW, ensure_ascii=False),
        "vulnerability_hash_v2": SPEC_VH,
        "verification_status": "",
        "replayable": 1,
        "family": "command_execution",
        "category": "",
    }
    s.update(kw)
    return s


def _idx(*specs):
    idx = {}
    for s in specs:
        idx.setdefault(s["vulnerability_hash_v2"], []).append(s)
    return idx


def test_adds_orphan_spec(cli):
    allv = []
    n = cli._enqueue_orphan_trigger_specs(allv, _idx(_spec()))
    assert n == 1
    assert len(allv) == 1
    v = allv[0]
    # 关键：合成 vuln 的 vhash 必须仍能反查回原 spec
    assert vh2(canonicalize_vuln_for_hash(v)) == SPEC_VH
    assert v["exploit_spec"]["entry"]["route"] == "/cmdi-00/BenchmarkTest00091"
    assert v["orphan_spec_id"] == 1


def test_skips_spec_with_verdict(cli):
    allv = []
    for st in ("confirmed_exploitable", "unconfirmed", "sink_reached", "invalidated"):
        assert cli._enqueue_orphan_trigger_specs(allv, _idx(_spec(verification_status=st))) == 0
    assert allv == []


def test_no_evidence_is_replayable(cli):
    allv = []
    assert cli._enqueue_orphan_trigger_specs(allv, _idx(_spec(verification_status="no_evidence"))) == 1


def test_skips_non_replayable_or_no_endpoint(cli):
    allv = []
    assert cli._enqueue_orphan_trigger_specs(allv, _idx(_spec(replayable=0))) == 0
    assert cli._enqueue_orphan_trigger_specs(allv, _idx(_spec(target_endpoint=""))) == 0
    assert allv == []


def test_skips_already_covered(cli):
    allv = [dict(RAW)]  # 已有同 vhash 的 finding 驱动
    assert cli._enqueue_orphan_trigger_specs(allv, _idx(_spec())) == 0


def test_dedupes_across_index_keys(cli):
    s = _spec()
    idx = {SPEC_VH: [s], "stable-key-xxx": [s]}
    allv = []
    assert cli._enqueue_orphan_trigger_specs(allv, idx) == 1


def test_master_switch_off(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_D2_ORPHAN_REPLAY", "0")
    allv = []
    assert cli._enqueue_orphan_trigger_specs(allv, _idx(_spec())) == 0
    assert allv == []


def test_max_cap(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_D2_ORPHAN_MAX", "2")
    specs = [_spec(id=i) for i in range(1, 6)]
    allv = []
    assert cli._enqueue_orphan_trigger_specs(allv, _idx(*specs)) == 2
