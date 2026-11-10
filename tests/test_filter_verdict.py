"""2026-10-02：净化器可绕过性三分类（可绕过 / 不可绕过 / 未定）回归测试。

钉死的核心：同一过滤器对不同族结论不同 —— java-sec-code 允许集 `[a-zA-Z0-9_/.-]`
对命令注入（需 ; | & $）是**不可绕过**，对路径穿越（需 . 和 /）仍是**可绕过**。
不可绕过即终态：不再造弹、不再升变体、不再进重试环（判完就停，不死磕）。
"""
import json

import pytest

from src.core.filter_verdict import (
    VERDICT_BYPASSABLE, VERDICT_NON_BYPASSABLE, VERDICT_UNDETERMINED,
    classify, is_terminal, parse_allowed_chars,
)
from src.core.sanitizer_miner import FilterSpec

# java-sec-code SecurityUtil 的真实允许集（cmdFilter 用 FILTER_PATTERN 全量匹配）
JSC_ALLOW = "^[a-zA-Z0-9_/\\\\.-]+$"


def _allow_spec():
    return FilterSpec(FilterSpec.KIND_ALLOW, patterns=[JSC_ALLOW], source="deterministic")


def test_same_filter_different_family_verdict():
    """同一允许集：命令注入不可绕过，路径穿越可绕过。"""
    spec = _allow_spec()
    cmd = classify(spec, "command_execution")
    trav = classify(spec, "path_traversal", candidates=["../../etc/passwd"])
    assert cmd["verdict"] == VERDICT_NON_BYPASSABLE
    assert trav["verdict"] == VERDICT_BYPASSABLE


def test_non_bypassable_is_terminal():
    v = classify(_allow_spec(), "command_execution")
    assert is_terminal(v) is True
    assert is_terminal(classify(_allow_spec(), "path_traversal", candidates=["../"])) is False
    assert is_terminal(None) is False


def test_deny_with_surviving_candidate_is_bypassable():
    spec = FilterSpec(FilterSpec.KIND_DENY, tokens=[";", "|"], source="deterministic")
    v = classify(spec, "command_execution", candidates=["${IFS}id"])
    assert v["verdict"] == VERDICT_BYPASSABLE
    assert "${IFS}id" in v["payloads"]


def test_deny_covering_all_required_is_non_bypassable():
    # 该族全部必需语法（; | & $ ` 换行）都被拦 → 判不可利用
    spec = FilterSpec(FilterSpec.KIND_DENY, tokens=[";", "|", "&", "$", "`", "\n"],
                      source="deterministic")
    v = classify(spec, "command_execution", candidates=[])
    assert v["verdict"] == VERDICT_NON_BYPASSABLE


def test_fake_sanitizer_signals_are_bypassable():
    """先解码后检查 = 假净化器信号 → 可绕过。"""
    spec = FilterSpec(FilterSpec.KIND_DENY, tokens=[";"], decode_first=True,
                      source="deterministic")
    v = classify(spec, "command_execution", candidates=["%3bid"])
    assert v["verdict"] == VERDICT_BYPASSABLE
    assert any("解码" in s for s in v["signals"])


def test_unknown_constraint_is_undetermined():
    assert classify(None, "command_execution")["verdict"] == VERDICT_UNDETERMINED
    unknown = FilterSpec(note="抽不出")
    assert classify(unknown, "command_execution")["verdict"] == VERDICT_UNDETERMINED


def test_semantic_family_is_undetermined_not_clean():
    """反序列化这类语义/解析器级绕过，静态字符级判定不了 → 未定，绝不谎报不可绕过。"""
    v = classify(_allow_spec(), "deserialization")
    assert v["verdict"] == VERDICT_UNDETERMINED


def test_parse_allowed_chars():
    chars = parse_allowed_chars("^[a-zA-Z0-9_.-]+$")
    assert chars is not None
    for c in "azAZ09_.-":
        assert c in chars
    assert ";" not in chars and "|" not in chars


# ---------------------------------------------------------------- 防误判（安全三重保险）
def test_unanchored_allow_is_not_terminal():
    """允许集未锚定 → 存在局部匹配绕过空间，判未定而不是终态（不敢掐掉真漏洞）。"""
    spec = FilterSpec(FilterSpec.KIND_ALLOW, patterns=["[a-zA-Z0-9]+"], source="deterministic")
    v = classify(spec, "command_execution")
    assert v["verdict"] == VERDICT_UNDETERMINED
    assert is_terminal(v) is False


def test_terminal_requires_high_confidence():
    v = classify(_allow_spec(), "command_execution")
    assert v["confidence"] == "high" and is_terminal(v) is True


def test_env_override_disables_terminal(monkeypatch):
    """SAST_AI_VERDICT_TERMINAL=0 → 退回可重试（总开关，防误判兜底）。"""
    monkeypatch.setenv("SAST_AI_VERDICT_TERMINAL", "0")
    v = classify(_allow_spec(), "command_execution")
    assert v["verdict"] == VERDICT_NON_BYPASSABLE
    assert is_terminal(v) is False


# ---------------------------------------------------------------- 口径闭环
def test_mark_filtered_not_exploitable_status():
    from src.agents.i2_feedback import (
        FILTERED_NOT_EXPLOITABLE, mark_filtered_not_exploitable,
    )

    class _StubDB:
        def __init__(self, rows):
            self.rows = rows
            self.updated = []

        def execute(self, sql, params=None, fetchone=False, fetchall=False):
            if "SELECT" in sql.upper():
                return self.rows
            if "UPDATE" in sql.upper():
                self.updated.append(params)
            return []

    verdict = classify(_allow_spec(), "command_execution")
    terminal = json.dumps({"filter_verdict": verdict})
    rows = [
        {"id": 1, "verification_status": "unconfirmed", "raw_json": terminal},
        {"id": 2, "verification_status": "confirmed_exploitable", "raw_json": terminal},
        {"id": 3, "verification_status": "no_evidence", "raw_json": json.dumps({})},
    ]
    db = _StubDB(rows)
    n = mark_filtered_not_exploitable(db, 7)
    assert n == 1
    # Q5/Q7：终态落「一等列」——UPDATE 写 verification_status + bypass_state +
    # bypass_reason + filter_spec_json + WHERE id。已确认(2)不动、无判定(3)不动，
    # 只有「unconfirmed 且静态终态」(1) 被标记。
    assert len(db.updated) == 1
    _upd = db.updated[0]
    assert _upd[0] == FILTERED_NOT_EXPLOITABLE
    assert _upd[1] == verdict["verdict"]   # bypass_state 取静态 filter_verdict.verdict
    assert _upd[2]                         # bypass_reason 非空
    assert _upd[3] == "{}"                 # filter_spec_json（无 filter_spec 时空对象）
    assert _upd[4] == 1                    # WHERE id = 1


# ---------------------------------------------------------------- 最后一公里：指令送 A2
def test_directive_reaches_a2_feedback():
    from src.agents.i2_feedback import attach_directives, a2_actionable
    from src.iast.replay_intel import ReplayMemory, build_directive

    spec = FilterSpec(FilterSpec.KIND_DENY, tokens=[";", "|"], source="deterministic")
    d = build_directive("blocked", {"status_code": 200}, spec=spec, memory=ReplayMemory(),
                        family="command_execution", endpoint="/codeinject/sec", sink="Runtime.exec")
    routed = {"hypothesis_defect": [{"hypothesis_id": "h1", "reason": "原原因"}]}
    adjustments = [{"hypothesis_id": "h1", "directive": d, "actions": ["escalate_variant"]}]
    merged = attach_directives(routed, adjustments)
    fb = a2_actionable(merged)[0]
    assert fb.get("directive") is d                    # 结构化指令到位
    assert "改进指令" in fb["reason"]                   # 文本也带上（只透传 reason 也不丢）
    assert "已试过" in fb["reason"] or ";" in fb["reason"]


# ---------------------------------------------------------------- 导航器缓存（性能）
def test_navigator_cache_reused_per_code_root(tmp_path):
    from src.core.sanitizer_miner import get_navigator
    a = get_navigator(str(tmp_path))
    b = get_navigator(str(tmp_path))
    assert a is b  # 同一源码根复用，避免每条 spec 重复建索引
    other = tmp_path / "other"
    other.mkdir()
    assert get_navigator(str(other)) is not a


# ---------------------------------------------------------------- 重试环：判完就停
def test_retryable_loop_skips_terminal_specs():
    """不可绕过的 spec 不再进 retryable（被归入 exhausted）。"""
    from src.agents.i2_feedback import plan_retryable_replay

    class _StubDB:
        def execute(self, sql, params=None, fetchone=False, fetchall=False):
            if "trigger_specs" in sql:
                return [
                    {"id": 1, "vulnerability_hash_v2": "h1", "family": "command_execution",
                     "target_endpoint": "/codeinject/sec",
                     "verification_status": "unconfirmed",
                     "raw_json": json.dumps({"filter_verdict": classify(_allow_spec(), "command_execution")})},
                    {"id": 2, "vulnerability_hash_v2": "h2", "family": "sqli",
                     "target_endpoint": "/search", "verification_status": "unconfirmed",
                     "raw_json": json.dumps({})},
                ]
            return []

    out = plan_retryable_replay(_StubDB(), 1)
    ids = [i["spec_id"] for i in out["retryable"]]
    assert 1 not in ids          # 终态：被拦在重试环外
    assert 2 in ids              # 普通未确认：照常可重试
    assert any(i.get("terminal_reason") for i in out["exhausted"])
