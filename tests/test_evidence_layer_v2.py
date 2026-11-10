# -*- coding: utf-8 -*-
"""证据分层 v2（2026-10-10）F 批回归锁：8 项核心不变量 + E 批路由锁。

每条锁对应一个真实事故或一条设计铁律，改动对应实现前先跑本文件：

1.  state_rank_single_source   —— D1：编排器/关联层的状态序位表只许引用 canary.STATE_RANK_STR，
                                  禁止另立副本（此前两处各抄一份且 arrived/sanitized 序位反转，
                                  是 confirmed_runtime 口径漂移的根因）。
2.  value_hit_four_states      —— A3：值级四态 hit_live/hit_sanitized/hit_opaque/miss 的语义与
                                  definitive 标注（hit_sanitized 是合法的 definitive 阴性，
                                  miss/hit_opaque 是证据缺失）。
3.  confirm_gate_requires_semantic —— 确认闸需要语义判据：本族消毒 definitive 阴性压过「仅到达」
                                  断言；sink 异常通道须过族签名与真 sink 闸。
4.  late_reconcile_respects_gate   —— B3：迟到补捞「仅到达」只升 unconfirmed，绝不臆断有害
                                  （r250 召回崩塌教训：低覆盖判据只许做正向）。
5.  no_evidence_attribution    —— D5：no-iast-evidence 归因二分三分支（probe_coverage_gap /
                                  attack_plan_defect / unknown），unknown 绝不臆断。
6.  business_diff_three_states —— C 批：差分矩阵三态（confirmed/no_difference/ambiguous），
                                  差分没跑成 = ambiguous 而非真阴性。
7.  family_sink_tokens_order   —— F7：族 token 包含匹配的次序不变量（xpathi 不被 pathtraver
                                  抢判、别名写法 path_traversal 仍命中、跨族异常不串族）。
8.  channel_priority_stability —— F8：通道注册表完整性 + (strength, priority) 唯一性 + 仲裁确定性
                                  + 同档良性优先（fail-open）。

E 批补充锁：
9.  i2_refutation_and_threw_routing —— E1：hit_sanitized → runtime_refutation（不进 A2）、
                                  threw → hypothesis_defect（回灌 A2）。
10. a2_regen_conditional_entry —— E2：仅 hit_live + threw 放行 A2 payload 重生成。
"""
from __future__ import annotations

import base64

import pytest

from src.agents import d2_facade  # noqa: F401  # 注册全部通道评估器（真实链路前提）
from src.core import evidence_channels as ec
from src.agents import i2_feedback as i2fb
from src.iast import canary, correlation, orchestrator
from src.iast.orchestrator import (
    TriggerTransactionOrchestrator,
    compute_value_hit,
)

CANARY = "s4st414bf83225e75d3b9f"
SQL_SINK = "org.hsqldb.jdbc.JDBCStatement.execute"


# ── 1. D1 状态序位单一真相源 ────────────────────────────────────────────────

def test_state_rank_single_source():
    # 引用同一对象（is），不是值相等的副本 —— 防止再有人抄一份然后漂移
    assert orchestrator._STATE_RANK is canary.STATE_RANK_STR
    assert correlation._STATE_RANK is canary.STATE_RANK_STR
    r = canary.STATE_RANK_STR
    # 序位不变量：探针显式断言态最强，sanitized 高于裸 no-arrival
    assert r["no-arrival"] < r["arrival-sanitized"] < r["arrived"] \
        < r["sink-reached"] < r["sink-reached-probe"]


# ── 2. A3 值级四态 ─────────────────────────────────────────────────────────

def test_value_hit_four_states():
    # hit_live：canary 原文到达 sink 实参且无消毒器 → definitive 阳性
    h = compute_value_hit(CANARY, {
        "source_value": "SELECT * FROM u WHERE n='%s'" % CANARY,
        "sink_file": SQL_SINK,
    })
    assert h["hit"] is True and h["form"] == "hit_live"
    assert h["definitive"] is True and h["harmful"] is True

    # hit_sanitized：到达但实参录得消毒器 → definitive 阴性（有判据，非证据缺失）
    h2 = compute_value_hit(CANARY, {
        "source_value": CANARY,
        "sink_file": SQL_SINK,
        "evidence": {"sink_sanitizer": "html_encode|sqli,xss"},
    })
    assert h2["hit"] is True and h2["form"] == "hit_sanitized"
    assert h2["definitive"] is True and h2["harmful"] is False
    assert h2["sanitizer"]

    # hit_opaque：canary 以 base64 抽象化出现，原文无法比对 → 证据缺失
    b64 = base64.b64encode(CANARY.encode("utf-8")).decode("ascii")
    h3 = compute_value_hit(CANARY, {"source_value": "wrapped:" + b64})
    assert h3["hit"] is False and h3["form"] == "hit_opaque"
    assert h3["definitive"] is False

    # miss：canary 不在可读实参里 → 证据缺失（fail-open）
    h4 = compute_value_hit(CANARY, {"source_value": "constant value here"})
    assert h4["hit"] is False and h4["form"] == "miss" and h4["definitive"] is False

    # 失败形态一律 miss，绝不抛异常
    assert compute_value_hit("", {"source_value": CANARY})["form"] == "miss"
    assert compute_value_hit(CANARY, "not-a-dict")["form"] == "miss"
    assert compute_value_hit(CANARY, {})["form"] == "miss"


# ── 3. 确认闸需要语义判据 ──────────────────────────────────────────────────

def _channels(iast: dict, dast: dict | None = None) -> dict:
    return ec.verify_with_channels("sqli", iast, dast or {"reached": True, "status_code": 200, "body": ""})


def test_confirm_gate_requires_semantic():
    # (a) 本族消毒 definitive 阴性（strength 4）压过「仅到达」探针断言（strength 2）
    vh = compute_value_hit(CANARY, {
        "source_value": CANARY, "sink_file": SQL_SINK,
        "evidence": {"sink_sanitizer": "html_encode|sqli"},
    })
    v = _channels({
        "state": "sink-reached-probe", "matched_sink_file": SQL_SINK,
        "value_hits": [vh],
    })
    assert v["primary_channel"] == "value_level_sink_arg"
    assert v["harmful"] is False and v["evidence_strength"] == 4

    # (b) 消毒器与本族正交（只针对 ldapi）→ 数据按未消毒到达，回退阳性
    vh2 = compute_value_hit(CANARY, {
        "source_value": CANARY, "sink_file": SQL_SINK,
        "evidence": {"sink_sanitizer": "ldap_encode|ldapi"},
    })
    v2 = _channels({"state": "sink-reached-probe", "matched_sink_file": SQL_SINK,
                    "value_hits": [vh2]})
    assert v2["primary_channel"] == "value_level_sink_arg" and v2["harmful"] is True

    # (c) sink 异常通道：异常不属本族签名 → 不产 definitive（证据缺失，不臆断）
    v3 = _channels({
        "state": "sink-reached", "matched_sink_file": SQL_SINK,
        "sink_exception_class": "java.io.FileNotFoundException",  # pathtraver 签名，非 sqli
    })
    assert v3["primary_channel"] != "sink_exception"

    # (d) 本族真 sink 现场抛出本族签名异常 → 独立 definitive 阳性，且压过探针断言
    v4 = _channels({
        "state": "sink-reached", "matched_sink_file": SQL_SINK,
        "sink_exception_class": "java.sql.SQLException",
    })
    assert v4["primary_channel"] == "sink_exception"
    assert v4["harmful"] is True and v4["evidence_strength"] == 3


# ── 4. B3 迟到补捞确认闸 ───────────────────────────────────────────────────

class _StubIast:
    """最小 iast_service 桩：无 db 属性 ⇒ 摄取静止等待直接跳过。"""

    def __init__(self, rows, blind):
        self._rows, self._blind = rows, blind

    def poll_events_by_canary(self, canary, since, limit, app_name=None, agent_id=None):
        return list(self._rows)

    def poll_authz_blindspots(self, canary, app_name=None, agent_id=None):
        return list(self._blind)


class _Res:
    def __init__(self):
        self.iast_evidence = {"state": "no-iast-evidence"}
        self.verification_decision = {}
        self.exploitable = False
        self.business_confirmed = False
        self.final_state = "no_evidence"


def _reconcile(rows, blind):
    res = _Res()
    ts = {"id": 1, "taint_marker": CANARY, "business_logic_category": "sqli"}
    n = d2_facade.reconcile_late_iast_evidence(
        [(res, ts, "vhash-x")], _StubIast(rows, blind),
        quiet_seconds=0.05, max_wait=0.2,
    )
    return n, res


def test_late_reconcile_respects_gate():
    # (a) authz 盲点 → 机制级确认
    n, res = _reconcile([{"event_type": "AUTHZ"}], [{"event_type": "AUTHZ_BLIND"}])
    assert n == 1
    assert res.exploitable is True
    assert res.verification_decision["verification_status"] == "confirmed_exploitable"

    # (b) 仅普通到达（无值级命中、无 sink 异常）→ 只升 unconfirmed，绝不臆断有害
    n2, res2 = _reconcile([{"event_type": "TAINT_FLOW", "source_value": "unrelated"}], [])
    assert n2 == 1
    assert res2.exploitable is False
    assert res2.verification_decision["verification_status"] == "unconfirmed"
    assert res2.final_state == "unconfirmed"

    # (c) 值级 hit_live 语义命中 → 准予确认
    rows3 = [{"event_type": "TAINT_FLOW", "source_value": "x" + CANARY,
              "sink_file": SQL_SINK}]
    n3, res3 = _reconcile(rows3, [])
    assert n3 == 1 and res3.exploitable is True

    # (d) sink 异常签名 → 准予确认
    rows4 = [{"event_type": "TAINT_FLOW", "sink_exception_class": "java.sql.SQLException"}]
    n4, res4 = _reconcile(rows4, [])
    assert n4 == 1 and res4.exploitable is True


# ── 5. D5 no-iast-evidence 归因二分 ────────────────────────────────────────

def test_no_evidence_attribution():
    attr = TriggerTransactionOrchestrator.attribute_no_iast_evidence
    # hook 就位（inventory 含本族关键 hook）但无事件 → A2/D1 攻击计划缺陷
    assert attr("sqli", {"jdbc": 3}) == "attack_plan_defect"
    # 无本族关键 hook → 探针组件缺陷（关键 hook 未织入）
    assert attr("sqli", {"cookie": 1}) == "probe_coverage_gap"
    # 无 inventory / 未登记族 → unknown（证据缺失，绝不臆断）
    assert attr("sqli", {}) == "unknown"
    assert attr("sqli", None) == "unknown"
    assert attr("weakrand", {"random": 5}) == "unknown"

    inv = TriggerTransactionOrchestrator.extract_hook_inventory
    assert inv([{"hook_inventory": {"jdbc": 1}}]) == {"jdbc": 1}
    assert inv([{"evidence": {"hook_inventory": {"jdbc": 1}}}]) == {"jdbc": 1}
    assert inv([{"evidence": {"context": {"hook_inventory": {"jdbc": 1}}}}]) == {"jdbc": 1}
    assert inv([{"nope": 1}, None, "str"]) == {}
    assert inv(None) == {}


# ── 6. C 批差分三态 ────────────────────────────────────────────────────────

def test_business_diff_three_states():
    f = d2_facade.differential_three_state
    # 差分/副作用确认 → 真阳性
    assert f(True, True, "ok") == "confirmed"
    assert f(True, False, "") == "confirmed"
    # 差分真跑且 verdict 非歧义 → 真阴性（correct_reject）
    assert f(False, True, "clean") == "no_difference"
    # 差分没跑成（缺账户 / 闸门 skip / 回滚失败）→ ambiguous（证据缺失 ≠ 真阴性）
    assert f(False, False, "clean") == "ambiguous"
    for bad in ("no_restore_baseline", "restore_failed",
                "skipped_destructive_guard", "non_dict_result"):
        assert f(False, True, bad) == "ambiguous", bad


# ── 7. F7 族 token 次序不变量 ──────────────────────────────────────────────

def test_family_sink_tokens_order():
    m = d2_facade._exception_matches_family
    # 本族命中
    assert m("java.sql.SQLException", "sqli") is True
    assert m("java.io.IOException", "cmdi") is True
    assert m("java.io.FileNotFoundException", "pathtraver") is True
    assert m("javax.xml.transform.TransformerException", "xpathi") is True
    # 跨族不串：xpathi 不被 pathtraver 签名抢判，反之亦然
    assert m("java.io.FileNotFoundException", "xpathi") is False
    assert m("javax.xml.transform.TransformerException", "pathtraver") is False
    assert m("java.sql.SQLException", "cmdi") is False
    assert m("javax.naming.NamingException", "sqli") is False
    # 别名写法（_/-）归一后仍命中（F7 修复点）
    assert m("java.io.FileNotFoundException", "path_traversal") is True
    assert m("java.io.FileNotFoundException", "path-traversal") is True
    assert m("java.sql.SQLException", "sql_injection") is True
    # 归一后 xpathi/pathtraver 仍互不包含
    assert m("java.io.FileNotFoundException", "xpath_injection") is False
    # 空 input 一律 False
    assert m("", "sqli") is False
    assert m("java.sql.SQLException", "") is False


# ── 8. F8 通道优先级稳定性 ─────────────────────────────────────────────────

def test_channel_priority_stability():
    # 注册表完整性：四张表键集一致（漏登记会导致定序/预算回退默认值，静默漂移）
    chans = set(ec.CHANNEL_STRENGTH)
    assert chans == set(ec.CHANNEL_LABEL)
    assert chans == set(ec._CHANNEL_PRIORITY)
    assert chans == set(ec.CHANNEL_REPLAY_COST)

    # (strength, priority) 组合唯一 ⇒ 排序全序、无并列歧义
    pairs = [(ec.CHANNEL_STRENGTH[c], ec._CHANNEL_PRIORITY[c]) for c in chans]
    assert len(pairs) == len(set(pairs))

    # 仲裁确定性：乱序输入产出同一主判据
    strong = ec.make_outcome("value_level_sink_arg", harmful=True, sink_reached=True,
                             confidence="high", reason="hit", definitive=True)
    weak = ec.make_outcome("sink_exception", harmful=True, sink_reached=True,
                           confidence="high", reason="exc", definitive=True)
    v1 = ec.arbitrate([weak, strong])
    v2 = ec.arbitrate([strong, weak])
    assert v1["primary_channel"] == v2["primary_channel"] == "value_level_sink_arg"

    # 同档良性优先（fail-open）：strength-3 内良性 result_point_diff 压过 sink_exception
    benign = ec.make_outcome("result_point_diff", harmful=False, sink_reached=True,
                             confidence="high", reason="clean", definitive=True)
    v3 = ec.arbitrate([weak, benign])
    assert v3["primary_channel"] == "result_point_diff" and v3["harmful"] is False

    # 无 definitive → 兜底 none，绝不臆断有害
    v4 = ec.arbitrate([ec.make_outcome("time_blind", harmful=False, sink_reached=False,
                                       confidence="low", reason="miss", definitive=False)])
    assert v4["primary_channel"] == "none" and v4["harmful"] is False


# ── 9. E1：I2 证否样本与生成异常路由 ───────────────────────────────────────

def test_i2_refutation_and_threw_routing():
    # hit_sanitized 值级证否 → runtime_refutation
    assert i2fb.classify_feedback(
        {"reason": "值级命中但被消毒", "value_hit_form": "hit_sanitized"}
    ) == i2fb.RUNTIME_REFUTATION
    assert i2fb.classify_feedback(
        {"reason": "x", "value_level_sanitized": True}
    ) == i2fb.RUNTIME_REFUTATION
    # threw / 生成异常 → hypothesis_defect（回灌 A2）
    assert i2fb.classify_feedback({"reason": "payload SyntaxError: unexpected token"}) \
        == i2fb.HYPOTHESIS_DEFECT
    assert i2fb.classify_feedback({"threw": True, "reason": "x"}) == i2fb.HYPOTHESIS_DEFECT
    # 普通 miss 不许被误判成证否（证据缺失 ≠ 阴性）
    assert i2fb.classify_feedback(
        {"reason": "canary 未到达", "value_hit_form": "miss"}
    ) != i2fb.RUNTIME_REFUTATION

    # 分流：refutation 单独成桶且不进 a2_actionable
    routed = i2fb.route_feedbacks([
        {"hypothesis_id": "h1", "value_hit_form": "hit_sanitized", "reason": "sanitized"},
        {"hypothesis_id": "h2", "threw": True, "reason": "SyntaxError"},
    ])
    assert len(routed[i2fb.RUNTIME_REFUTATION]) == 1
    assert len(routed[i2fb.HYPOTHESIS_DEFECT]) == 1
    a2 = i2fb.a2_actionable(routed)
    assert [x["hypothesis_id"] for x in a2] == ["h2"]


# ── 10. E2：A2 payload 重生成条件化入口 ────────────────────────────────────

def test_a2_regen_conditional_entry():
    ok, why = i2fb.a2_rerun_actionable([
        {"hypothesis_id": "h1", "value_hit_form": "hit_live", "threw": True},
    ])
    assert ok is True and "重生成" in why
    # miss + threw：路径未证真实，不放行
    ok2, _ = i2fb.a2_rerun_actionable([
        {"hypothesis_id": "h2", "value_hit_form": "miss", "threw": True},
    ])
    assert ok2 is False
    # hit_live 但没抛异常：payload 没坏，不放行
    ok3, _ = i2fb.a2_rerun_actionable([
        {"hypothesis_id": "h3", "value_hit_form": "hit_live"},
    ])
    assert ok3 is False
    # hit_sanitized + threw：消毒阴性不是 payload 质量问题，不放行
    ok4, _ = i2fb.a2_rerun_actionable([
        {"hypothesis_id": "h4", "value_hit_form": "hit_sanitized", "threw": True},
    ])
    assert ok4 is False


# ── 11. E3：闭环 A2 重跑文件收窄（绝不回退全量）────────────────────────────

def test_failed_files_narrowed_not_exploded(tmp_path, monkeypatch):
    """E3（2026-10-10）三不变量：
    1. feedback 只带 hypothesis_id（无 vulnerability_hash_v2）也能定位失败文件
       （旧实现 hashes 恒空 → 直接回退全量 files）；
    2. DB 查不到映射 → 返回 []（跳过文件级重跑），绝不爆炸成全量；
    3. 正常映射 → 收窄到失败文件本身。
    """
    import os as _os

    from src.cli.benchmark_cli import _failed_files_from_feedback
    from src.infrastructure.db import Database

    task = 424242
    db_path = str(tmp_path / "gate.db")
    monkeypatch.setenv("SAST_AI_DB_PATH", db_path)
    db = Database(db_path)
    _ts = "2026-10-10T00:00:00"
    # 父表先行（trigger_specs 对 workspaces / scan_tasks 有 FK）
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, settings_json, created_at, updated_at) "
        "VALUES (1, 'ws', '/tmp/proj', '{}', ?, ?)", (_ts, _ts),
    )
    db.execute(
        "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, "
        "options_json, summary_json, created_at) VALUES (?, 1, 't', 'completed', 'done', "
        "'/tmp/out', '{}', '{}', ?)", (task, _ts),
    )
    db.execute(
        "INSERT INTO trigger_specs (id, task_id, workspace_id, family, target_endpoint, "
        "verification_status, expected_sink_file, vulnerability_hash_v2, created_at) "
        "VALUES (1, ?, 1, 'sqli', '/benchmark/x', 'unconfirmed', ?, ?, ?)",
        (task, "/src/main/java/BenchmarkTest00001.java", "h1", _ts),
    )

    files = ["/prep/src/main/java/BenchmarkTest00001.java",
             "/prep/src/main/java/BenchmarkTest00002.java"]

    # 不变量 1：只有 hypothesis_id 也能收窄（此前此形状恒回退全量）
    out = _failed_files_from_feedback(task, [{"hypothesis_id": "h1"}], files)
    assert out == ["/prep/src/main/java/BenchmarkTest00001.java"]

    # 不变量 2：映射不到 → 收窄为空，绝不回退全量
    out2 = _failed_files_from_feedback(task, [{"hypothesis_id": "h-not-exist"}], files)
    assert out2 == []

    # 无 hash 无 id → 同样为空
    out3 = _failed_files_from_feedback(task, [{"reason": "no identity"}], files)
    assert out3 == []
