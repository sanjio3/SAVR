# -*- coding: utf-8 -*-
"""重放调整存活与重试 gate 回归锁（2026-10-08）。

背景（run 245/240/226 vs 244/242/239 跨任务实证）：
- 闭环 iter 内 apply_replay_adjustments 写入的 replay_adjust，会被同轮 a2_rerun 的
  second_pass「先清本 task 全部 spec 再重登记」整体清掉 —— 凡最后一轮带 a2_rerun 的
  任务，actions 落地恒 0，重试环原样重放（17 条救回全是 late-event 运气）。
- 修复 = 重登记后补写（benchmark_cli，bump_round=False）+ 真实落地数进闭环 history
  + 零到达 spec 重试轮次上限。

本文件锁三个语义：
1. apply_replay_adjustments 的 bump_round True/False 语义（False 不推 round，防止
   补写把 round 推到封顶导致重试环整体失效）。
2. apply 返回值 = 真实落地条数（hid 失配的条目不计入、不静默）。
3. plan_retryable_replay 的零到达轮次上限（no-arrival/no-iast-evidence/空状态封顶
   SAST_AI_RETRY_ZERO_ARRIVAL_ROUNDS 轮；sink-reached-* 不受限；downtime 豁免）。
"""
import json
import os
import unittest

from unittest.mock import patch

from src.agents import i2_feedback
from src.agents.i2_feedback import apply_replay_adjustments, plan_retryable_replay


class _ApplyDB:
    """支撑 apply_replay_adjustments 三类 SQL 的假库。vhash->spec_row；未登记的 hid=miss。"""

    def __init__(self, specs):
        # specs: {vhash: {"id": int, "param_location": str, "raw_json": dict}}
        self.specs = dict(specs)
        self.updates = []

    def execute(self, sql, params=None, fetchone=False, fetchall=False):
        u = (sql or "").strip().upper()
        if u.startswith("SELECT ID, PARAM_LOCATION"):
            vh = params[1]
            spec = self.specs.get(vh)
            if not spec:
                return None
            return {
                "id": spec["id"],
                "param_location": spec.get("param_location") or "query",
                "representative_request_params_json": "",
                "param_name": "",
                "raw_json": json.dumps(spec.get("raw_json") or {}, ensure_ascii=False),
            }
        if u.startswith("UPDATE TRIGGER_SPECS SET PARAM_LOCATION"):
            self.updates.append(("param_location", params[1], params[0]))
            return None
        if u.startswith("UPDATE TRIGGER_SPECS SET RAW_JSON"):
            self.updates.append(("raw_json", params[1], json.loads(params[0])))
            return None
        return None


def _adj(hid, actions):
    return {"hypothesis_id": hid, "failure_class": "param_not_arrived",
            "actions": list(actions), "reason": "unit"}


class ApplyBumpRoundTests(unittest.TestCase):
    def test_bump_round_true_increments_and_merges_actions(self):
        db = _ApplyDB({"aaaa": {"id": 1, "param_location": "query", "raw_json": {}}})
        n = apply_replay_adjustments(db, 7, [_adj("aaaa", ["inject_all_params"])])
        self.assertEqual(n, 1)
        raw_writes = [w for w in db.updates if w[0] == "raw_json"]
        self.assertEqual(len(raw_writes), 1)
        adj = raw_writes[0][2]["replay_adjust"]
        self.assertEqual(adj["actions"], ["inject_all_params"])
        self.assertEqual(adj["round"], 1)

    def test_bump_round_false_preserves_round(self):
        # 补写场景：清库重建后 round 从 0 起步，补写不得推 round。
        db = _ApplyDB({"bbbb": {"id": 2, "param_location": "query", "raw_json": {}}})
        n = apply_replay_adjustments(db, 7, [_adj("bbbb", ["switch_param_location"])],
                                     bump_round=False)
        self.assertEqual(n, 1)
        raw_writes = [w for w in db.updates if w[0] == "raw_json"]
        adj = raw_writes[0][2]["replay_adjust"]
        self.assertEqual(adj["actions"], ["switch_param_location"])
        self.assertEqual(int(adj.get("round") or 0), 0)  # 不写 round 键，下游按 0 处理

    def test_switch_param_location_rewrites_location(self):
        db = _ApplyDB({"cccc": {"id": 3, "param_location": "query", "raw_json": {}}})
        apply_replay_adjustments(db, 7, [_adj("cccc", ["switch_param_location"])])
        loc_writes = [w for w in db.updates if w[0] == "param_location"]
        self.assertEqual(len(loc_writes), 1)
        self.assertEqual(loc_writes[0][2], "json")  # (kind, id, new_loc) — query 下一档

    def test_return_counts_only_landed_rows(self):
        # hid 失配的调整不计入返回值（run 245 曾计划 68、落地 0 且无观测）。
        db = _ApplyDB({"dddd": {"id": 4, "param_location": "query", "raw_json": {}}})
        n = apply_replay_adjustments(db, 7, [_adj("dddd", ["inject_all_params"]),
                                             _adj("no_such_hash", ["inject_all_params"])])
        self.assertEqual(n, 1)


class _PlanDB:
    """支撑 plan_retryable_replay 两类 SELECT 的假库。"""

    def __init__(self, rows, downtime=False):
        self._rows = rows
        self._downtime = downtime

    def execute(self, sql, params=None, fetchone=False, fetchall=False):
        u = (sql or "").strip().upper()
        if u.startswith("SELECT ID, VULNERABILITY_HASH_V2"):
            return list(self._rows)
        if u.startswith("SELECT ID FROM SCAN_TASK_EVENTS"):
            return ([{"id": 1}] if self._downtime else [])
        return None


def _row(sid, status, iast_state, round_n=0):
    return {"id": sid, "vulnerability_hash_v2": "vh%d" % sid, "family": "sqli",
            "target_endpoint": "/e%d" % sid, "verification_status": status,
            "iast_state": iast_state,
            "raw_json": json.dumps({"replay_adjust": {"round": round_n}}) if round_n else "{}"}


class ZeroArrivalGateTests(unittest.TestCase):
    def test_zero_arrival_exhausted_after_cap(self):
        # round 已 1 轮、仍 no-arrival → 默认 cap=1 → exhausted。
        rows = [_row(1, "no_evidence", "no-arrival", round_n=1)]
        with patch.dict(os.environ, {}, clear=False):
            out = plan_retryable_replay(_PlanDB(rows), 11)
        self.assertEqual(len(out["retryable"]), 0)
        self.assertEqual(len(out["exhausted"]), 1)
        self.assertEqual(out["exhausted"][0].get("exhaust_reason"), "zero_arrival_rounds")

    def test_zero_arrival_first_round_still_retryable(self):
        rows = [_row(2, "no_evidence", "no-iast-evidence", round_n=0)]
        out = plan_retryable_replay(_PlanDB(rows), 11)
        self.assertEqual(len(out["retryable"]), 1)

    def test_sink_reached_not_capped(self):
        rows = [_row(3, "unconfirmed", "sink-reached-probe", round_n=1)]
        out = plan_retryable_replay(_PlanDB(rows), 11)
        self.assertEqual(len(out["retryable"]), 1)

    def test_downtime_lifts_cap(self):
        rows = [_row(4, "no_evidence", "no-arrival", round_n=1)]
        out = plan_retryable_replay(_PlanDB(rows, downtime=True), 11)
        self.assertEqual(len(out["retryable"]), 1)

    def test_env_override_restores_old_behavior(self):
        rows = [_row(5, "no_evidence", "no-arrival", round_n=1)]
        with patch.dict(os.environ, {"SAST_AI_RETRY_ZERO_ARRIVAL_ROUNDS": "2"}):
            out = plan_retryable_replay(_PlanDB(rows), 11)
        self.assertEqual(len(out["retryable"]), 1)
        self.assertEqual(len(out["exhausted"]), 0)


if __name__ == "__main__":
    unittest.main()
