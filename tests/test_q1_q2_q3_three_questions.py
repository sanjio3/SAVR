"""Q1/Q2/Q3 三问落地单测。

Q1：sink 身份校验下沉为终态准入唯一入口——运行时层（噪声 sink 判未确证有害）与
    spec 层（confirmed_exploitable）不再打架。
Q2：指令送达可观测 + hid 口径统一 + 指令真正落进执行端（replay_adjust.directive）。
Q3：结构化报告聚合口径（overview / 分布 / 族矩阵 / 证据强度）。
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NOISE_SINK = "org.apache.catalina.connector.Response.setHeader"


def _ev(sink_file=NOISE_SINK, state="sink-reached-probe"):
    return {"state": state, "reached_sink_files": [sink_file], "chain_conformance": {}}


# ============================================================ Q1
class TestQ1SinkIdentityAtFinalState:
    def test_noise_sink_not_confirmed(self):
        """非 XSS/SSTI 族 + canary 只落框架噪声 sink ⇒ 不得 confirmed。"""
        from src.iast.adjudicator import I2Adjudicator
        from src.iast.adjudicator import FINAL_AMBIGUOUS
        r = I2Adjudicator.adjudicate_final_state(
            iast_evidence=_ev(), dast_impact_evidence={"reached": True, "impact_observed": True},
            d2_verdict={"harmful": False, "sink_reached": False}, family="sql_injection",
        )
        assert r["confirmed"] is False
        assert r["final_state"] == FINAL_AMBIGUOUS
        assert "噪声 sink" in r["judge_reason"]

    def test_xss_family_noise_sink_still_confirmed(self):
        """XSS 族真页面上下文 sink（writer）即 sink，黑名单不适用 ⇒ 维持确认（零误杀）。

        2026-11-03（jsc-leakfix-r17 收紧）：HTTP 基础设施写入（setHeader /
        StringHttpMessageConverter.writeInternal）对写入族也判非真——jsc 607 实测
        websocket 异常串经 writeInternal、log4j 回显经 setHeader 被误确认 xss。
        故本用例的 sink 从 NOISE_SINK 改为 CoyoteWriter（response.getWriter() 实际类）。"""
        from src.iast.adjudicator import I2Adjudicator
        r = I2Adjudicator.adjudicate_final_state(
            iast_evidence=_ev(sink_file="org.apache.catalina.connector.CoyoteWriter.print"),
            dast_impact_evidence={"reached": True, "impact_observed": True},
            d2_verdict={"harmful": True, "sink_reached": True}, family="xss",
        )
        assert r["confirmed"] is True
        # 基础设施写入即便对写入族也不得确认（FP 根因，jsc 607 实测 3 条）
        r2 = I2Adjudicator.adjudicate_final_state(
            iast_evidence=_ev(),  # 默认 NOISE_SINK = Response.setHeader
            dast_impact_evidence={"reached": True, "impact_observed": True},
            d2_verdict={"harmful": True, "sink_reached": True}, family="xss",
        )
        assert r2["confirmed"] is False

    def test_genuine_sink_still_confirmed(self):
        """真 sink 抵达 + 结果点有害 ⇒ 维持 confirmed（不误杀真漏洞）。"""
        from src.iast.adjudicator import I2Adjudicator
        r = I2Adjudicator.adjudicate_final_state(
            iast_evidence=_ev(sink_file="java.lang.Runtime.exec"),
            dast_impact_evidence={"reached": True, "impact_observed": True},
            d2_verdict={"harmful": True, "sink_reached": True}, family="command_execution",
        )
        assert r["confirmed"] is True

    def test_no_sink_file_failopen(self):
        """无 sink_file 信息（迟到升级）⇒ fail-open 视为真实，不误杀。"""
        from src.iast.adjudicator import I2Adjudicator
        r = I2Adjudicator.adjudicate_final_state(
            iast_evidence={"state": "sink-reached-probe", "chain_conformance": {}},
            dast_impact_evidence={"reached": True, "impact_observed": True},
            d2_verdict={"harmful": True, "sink_reached": True}, family="sql_injection",
        )
        assert r["confirmed"] is True

    def test_three_layers_agree_no_conflict(self):
        """Q1 本质：两层对同一证据必须同结论（不再打架）。"""
        from src.agents.d2_facade import _verify_sink_result
        from src.iast.adjudicator import I2Adjudicator
        ev = _ev()
        dast = {"reached": True, "impact_observed": True}
        d2v = _verify_sink_result(ev, dast, "sql_injection")
        i2 = I2Adjudicator.adjudicate_final_state(
            iast_evidence=ev, dast_impact_evidence=dast, d2_verdict=d2v, family="sql_injection")
        assert d2v["harmful"] is False
        assert i2["confirmed"] is False


class TestQ1ConsistencyGate:
    def _decision(self, confirmed=True):
        from src.iast.adjudicator import I2Decision
        return I2Decision(hypothesis_id="h1", final_state="confirmed_attributable",
                          action="pass", confirmed=confirmed, confidence="high", reason="r")

    def test_false_sink_reached_blocks_confirmed(self):
        """d2_verdict 显式 harmful=False + sink_reached=False ⇒ 否决 confirmed。"""
        from src.agents.d2_facade import _build_verification_result
        vr = _build_verification_result([self._decision()], _ev(), {"reached": True},
                                       {"harmful": False, "sink_reached": False})
        assert vr.exploitable is False
        assert vr.verification_decision["verification_status"] == "unconfirmed"
        assert vr.verification_decision["q1_sink_identity_downgraded"] is True
        assert vr.next_action["action"] == "re_send"

    def test_degraded_attack_not_blocked(self):
        """降级攻击 harmful=False，但有**真实影响证据**（impact_observed）⇒ 不被误否决。

        2026-10-19 修正：原用例只给 {"reached": True}，没有影响通道。按 arrival-only 规则
        （2026-10-07：探针断言到 sink 实参只证明到达、不证明利用），那种形态**应当**降级，
        故补上生产形态里的 impact_observed —— 本用例要锁的是「harmful=False 不得推翻真实影响」。
        """
        from src.agents.d2_facade import _build_verification_result
        vr = _build_verification_result(
            [self._decision()], _ev(),
            {"reached": True, "impact_observed": True},
            {"harmful": False, "sink_reached": True, "attack_degraded": True})
        assert vr.exploitable is True

    def test_business_logic_channel_not_blocked(self):
        """业务族差分通道 harmful=False 但有 business_logic.confirmed ⇒ 交 I2 全权决定。

        2026-10-19 修正：业务证据的生产形态是 dast_impact_evidence["business_logic"]["confirmed"]
        （见 d2_facade._verify_business_logic 的 vr.dast_impact_evidence 构造）；
        原用例把它塞进 d2_verdict，与生产形态不一致，导致判定读不到证据。
        """
        from src.agents.d2_facade import _build_verification_result
        vr = _build_verification_result(
            [self._decision()], _ev(),
            {"reached": True, "business_logic": {"confirmed": True}},
            {"harmful": False, "business_logic_confirmed": True})
        assert vr.exploitable is True


# ============================================================ Q2
class TestQ2DirectiveDelivery:
    def test_directive_stats_reported(self):
        from src.agents.i2_feedback import attach_directives
        routed = {"hypothesis_defect": [{"hypothesis_id": "h1", "reason": "端点幻觉"}]}
        adj = [{"hypothesis_id": "h1", "directive": {"instruction": "改用真实端点"}}]
        out = attach_directives(routed, adj)
        st = out["_directive_stats"]
        assert st["matched"] == 1 and st["unmatched"] == 0
        assert "改用真实端点" in out["hypothesis_defect"][0]["reason"]

    def test_unmatched_counted_not_silent(self):
        """hid 失配必须被计数——此前完全静默，是「指令没进去」不可查的成因。"""
        from src.agents.i2_feedback import attach_directives
        routed = {"hypothesis_defect": [{"hypothesis_id": "hX", "reason": "r"}]}
        adj = [{"hypothesis_id": "h1", "directive": {"instruction": "i"}}]
        st = attach_directives(routed, adj)["_directive_stats"]
        assert st["matched"] == 0 and st["unmatched"] == 1
        assert st["unmatched_ids"] == ["hX"]

    def test_hid_fallback_to_vuln_hash(self):
        """反馈只带 vulnerability_hash_v2 时也须匹配上（口径统一）。"""
        from src.agents.i2_feedback import attach_directives
        routed = {"hypothesis_defect": [{"vulnerability_hash_v2": "vh1", "reason": "r"}]}
        adj = [{"hypothesis_id": "vh1", "directive": {"instruction": "改弹"}}]
        out = attach_directives(routed, adj)
        assert out["_directive_stats"]["matched"] == 1
        assert "改弹" in out["hypothesis_defect"][0]["reason"]

    def test_replay_directive_attached_for_five_class(self):
        """五类不进 a2_actionable，但必须挂 replay_directive 供重放侧改弹。"""
        from src.agents.i2_feedback import attach_directives
        routed = {"runtime_observation": [{"hypothesis_id": "h1", "reason": "到达未确认"}]}
        adj = [{"hypothesis_id": "h1", "directive": {"instruction": "升级变体"}}]
        out = attach_directives(routed, adj)
        assert out["runtime_observation"][0]["replay_directive"]["instruction"] == "升级变体"
        assert out["_directive_stats"]["replay_directive_attached"] == 1

    def test_directive_stats_not_leaked_into_a2_feedback(self):
        """_directive_stats 是统计 dict，不得被 a2_actionable 当反馈项吐给 A2。"""
        from src.agents.i2_feedback import attach_directives, a2_actionable
        routed = {"hypothesis_defect": [{"hypothesis_id": "h1", "reason": "r"}]}
        adj = [{"hypothesis_id": "h1", "directive": {"instruction": "i"}}]
        out = a2_actionable(attach_directives(routed, adj))
        assert len(out) == 1
        assert all(isinstance(x, dict) and "hypothesis_id" in x for x in out)

    def test_directive_persisted_into_replay_adjust(self):
        """指令必须真正落进执行端 spec.raw_json（此前只搬 actions，指令正文丢失）。"""
        from src.agents.i2_feedback import apply_replay_adjustments
        from src.infrastructure.db import Database
        import tempfile, os as _os
        fd, p = tempfile.mkstemp(suffix=".db"); _os.close(fd)
        db = Database(p)  # 自带完整 schema（含 trigger_specs），无需手工建表
        try:
            db.execute("INSERT INTO workspaces (name,target_path,description,settings_json,created_at,updated_at) "
                       "VALUES ('w','t','','{}','2026-10-02','2026-10-02')")
            db.execute("INSERT INTO trigger_specs (workspace_id,created_at,task_id,vulnerability_hash_v2,param_location,raw_json) "
                       "VALUES (1,'2026-10-02',1,'h1','query','{}')")
            n = apply_replay_adjustments(db, 1, [{
                "hypothesis_id": "h1", "actions": ["switch_param_location"],
                "failure_class": "arrived_unconfirmed",
                "directive": {"instruction": "升级编码变体", "avoid": [";id"]}}])
            assert n == 1
            row = db.execute("SELECT raw_json FROM trigger_specs WHERE id=1", fetchone=True)
            meta = json.loads(row["raw_json"])
            adj = meta["replay_adjust"]
            assert adj["directive"]["instruction"] == "升级编码变体"
            assert adj["failure_class"] == "arrived_unconfirmed"
            assert "switch_param_location" in adj["actions"]
        finally:
            db.close()
            _os.unlink(p)


# ============================================================ Q3
class TestQ3StructuredReport:
    def test_aggregates_from_db(self, tmp_path, monkeypatch):
        import src.api.routers.reports as R
        from src.infrastructure.db import Database
        p = str(tmp_path / "t.db")
        db = Database(p)  # 自带完整 schema
        db.execute("INSERT INTO workspaces (name,target_path,description,settings_json,created_at,updated_at) "
                   "VALUES ('w','t','','{}','2026-10-02','2026-10-02')")
        # FK 上游：findings.task_id → scan_tasks；iast_events.session_id → iast_sessions
        db.execute("INSERT INTO scan_tasks (workspace_id,name,status,phase,output_dir,created_at) "
                   "VALUES (1,'t','running','d2','o','2026-10-02')")
        db.execute("INSERT INTO iast_sessions (app_name,agent_id,target_url,workspace_id,registered_at,updated_at,probe_token) "
                   "VALUES ('app','a1','http://127.0.0.1:8080',1,'2026-10-02','2026-10-02','tok')")
        db.execute(
            "INSERT INTO findings (task_id,workspace_id,finding_type,severity,file_path,line,title,"
            "source,raw_json,created_at) VALUES (1,1,'sql_injection','HIGH','A.java',10,'t','A2','{}','2026-10-02')")
        db.execute(
            "INSERT INTO findings (task_id,workspace_id,finding_type,severity,file_path,line,title,"
            "source,raw_json,created_at) VALUES (1,1,'xss','LOW','B.java',20,'t','A2','{}','2026-10-02')")
        db.execute(
            "INSERT INTO trigger_specs (workspace_id,created_at,task_id,vulnerability_hash_v2,family,"
            "verification_status,iast_state,taint_marker) "
            "VALUES (1,'2026-10-02',1,'h1','sql_injection','confirmed_exploitable',"
            "'sink-reached-probe','s4st41aaaaaaaaaaaaaaaa')")
        db.execute("INSERT INTO iast_events (session_id,workspace_id,app_name,agent_id,event_type,ingested_at,task_id,canary,sink_file) "
                   "VALUES (1,1,'app','a1','sink_call','2026-10-02',1,?,?)",
                   ("s4st41aaaaaaaaaaaaaaaa", NOISE_SINK))
        db.execute(
            "INSERT INTO vuln_blackboard (workspace_id,vulnerability_hash_v2,run_id,task_id,created_at,updated_at,"
            "family,verification_status,iast_state,sink_reached,target_endpoint,http_method) "
            "VALUES (1,'h1',1,1,'2026-10-02','2026-10-02','sql_injection','confirmed_exploitable',"
            "'sink-reached-probe',1,'/a','GET')")

        class C:
            pass
        c = C(); c.db = db
        monkeypatch.setattr(R, "container", c)
        d = R._build_structured(1)
        assert d["overview"]["app_findings"] == 2
        assert d["overview"]["confirmed_specs"] == 1
        assert d["overview"]["total_specs"] == 1
        assert d["distributions"]["severity"] == {"HIGH": 1, "LOW": 1}
        assert "sql_injection" in d["family_matrix"]
        # 关键：落噪声 sink 的 confirmed 判为 weak（Q1 口径在展示层同样可见）
        assert d["findings"][0]["evidence_strength"] == "weak"
