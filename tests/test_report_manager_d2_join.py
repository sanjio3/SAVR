"""回归测试：D2 裁决（五态 + 运行时证据）必须回填进每条 finding。

背景（2026-08-31 报告层缺口）：run_d2_verify 产出的逐漏洞验证 dict 已携带 final_state /
iast_evidence / dast_impact_evidence / trigger_spec_detail / d2_verdict 等富证据，但
generate_final_report 的合并块只拷了 exploitable / verification_decision 等窄字段，导致前端即便探针
已确证 gadget 抵达，finding 仍显 final_state=None / Unknown。

此外，A1 canonical finding（如 "Java 反序列化链" / chain_id "deserialization:project_chain"）与 A2
假说（如 "反序列化" / chain_id "反序列化:...debugcontroller.java:26"）对同一漏洞给出不同身份标签，
精确匹配全 miss，A1 那条永远 Unknown。_verification_fallback_match 按「同文件(basename) + 同 family」
兜底衔接。

两个测试分别锁死：(1) 富字段透传；(2) A1/A2 孪生兜底 join。

P2 回归（2026-09-02）：业务/越权类漏洞因 resolve_trigger_endpoint 是 sink 驱动、无 sink→
exploit_spec.entry.route 恒空（通道 B 填充率仅 ~16.7%），导致 a21_selected 真漏洞被
is_contract_ready_item 错杀、进不了 D2 主线。修复：①门禁兜底读通道 A（trigger_spec_detail.endpoint
= trigger_specs.target_endpoint）；②报告装配时把通道 A 回写通道 B（保底不清空）。
另两条测试分别锁死门禁兜底与报告级回写。
"""

import tempfile
import unittest

from src.benchmark.report_manager import ReportManager
from src.core.models import ScanResult, Vulnerability


def _deser_vuln(type_label, file_path, line, chain_id):
    return Vulnerability(
        type=type_label,
        severity="HIGH",
        file=file_path,
        line=line,
        description="deserialization entry",
        code_snippet="readObject()",
        source="a2",
        canonical_group_key=chain_id,
        is_canonical=True,
    )


class ReportManagerD2VerdictJoinTests(unittest.TestCase):
    def test_rich_d2_fields_copied_into_finding(self):
        vuln = _deser_vuln(
            "Java 反序列化链",
            "src/main/java/com/quote/controller/DebugController.java",
            24,
            "deserialization:project_chain",
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "deserialization:project_chain",
                            "match_keys": ["canonical:deserialization:project_chain"],
                            "file": vuln.file,
                            "type": "Java 反序列化链",
                            "line": 24,
                            "exploitable": "Yes",
                            "confidence": "high",
                            "test_status": "DONE",
                            "reason": "IAST SINK_HIT",
                            "final_state": "confirmed_attributable",
                            "iast_evidence": {"state": "sink-reached", "sink_method": "readObject"},
                            "dast_impact_evidence": {"reached": True, "status_code": 200},
                            "trigger_spec_provided": True,
                            "trigger_spec_hash": "f49f56e3e7f3bccc4be55f68",
                            "trigger_spec_detail": {
                                "endpoint": "/api/debug/import",
                                "http_method": "POST",
                                "param_name": "data",
                                "family": "deserialization",
                                "canary_identity": "s4st41ba079e737032b2c8",
                                "vulnerability_hash_v2": "f49f56e3e7f3bccc4be55f68",
                            },
                            "d2_verdict": {"harmful": True, "confidence": "high", "reason": "gadget reached sink"},
                            "next_action": {},
                            "docker_attempted": False,
                            "docker_used": False,
                            "container_id": "",
                            "service_url": "",
                            "container_kept_running": False,
                            "service_ready": False,
                            "poc_generated": False,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "",
                            "poc_details": {},
                            "exploit_spec": {},
                            "contract_completeness": {},
                            "failure_classification": {},
                            "execution_evidence": {},
                            "verification_decision": {"verification_status": "confirmed_exploitable"},
                            "verified_bundle": {},
                        }
                    ],
                    "pocs": [],
                    "exploitable_count": 1,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        # §报告层缺口修复：富 D2 证据必须透传到 finding
        self.assertEqual(finding["exploitable"], "Yes")
        self.assertEqual(finding["final_state"], "confirmed_attributable")
        self.assertEqual(finding["iast_evidence"]["state"], "sink-reached")
        self.assertTrue(finding["trigger_spec_provided"])
        self.assertEqual(finding["trigger_spec_detail"]["canary_identity"], "s4st41ba079e737032b2c8")
        self.assertEqual(finding["d2_verdict"]["harmful"], True)
        self.assertTrue(finding["dast_impact_evidence"]["reached"])

    def test_a1_canonical_twin_joined_via_fallback(self):
        # A1 canonical finding：chain_id 是 generic 的 "deserialization:project_chain"，
        # 与本 task 的 A2 验证（chain_id 带文件路径/行号、type 标签不同）精确匹配 miss。
        # 必须靠「同文件 + 同 family」兜底 join，否则该 finding 永远 Unknown。
        vuln = _deser_vuln(
            "Java 反序列化链",
            "src/main/java/com/quote/controller/DebugController.java",
            24,
            "deserialization:project_chain",
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            # 精确匹配全部故意留空，强制走 fallback
                            "canonical_group_key": "",
                            "match_keys": [],
                            "file": None,
                            "type": "反序列化",
                            "line": None,
                            # 带文件路径的 chain_id 触发 fallback
                            "chain_id": "反序列化:src/main/java/com/quote/controller/debugcontroller.java:26",
                            "exploitable": "Yes",
                            "confidence": "high",
                            "test_status": "DONE",
                            "reason": "IAST SINK_HIT",
                            "final_state": "confirmed_attributable",
                            "iast_evidence": {"state": "sink-reached"},
                            "dast_impact_evidence": {},
                            "trigger_spec_provided": True,
                            "trigger_spec_hash": "f49f56e3e7f3bccc4be55f68",
                            "trigger_spec_detail": {
                                "endpoint": "/api/debug/import",
                                "http_method": "POST",
                                "param_name": "data",
                                "family": "deserialization",
                                "canary_identity": "s4st41ba079e737032b2c8",
                            },
                            "d2_verdict": {"harmful": True},
                            "next_action": {},
                            "docker_attempted": False,
                            "docker_used": False,
                            "container_id": "",
                            "service_url": "",
                            "container_kept_running": False,
                            "service_ready": False,
                            "poc_generated": False,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "",
                            "poc_details": {},
                            "exploit_spec": {},
                            "contract_completeness": {},
                            "failure_classification": {},
                            "execution_evidence": {},
                            "verification_decision": {"verification_status": "confirmed_exploitable"},
                            "verified_bundle": {},
                        }
                    ],
                    "pocs": [],
                    "exploitable_count": 1,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        self.assertEqual(finding["exploitable"], "Yes")
        self.assertEqual(finding["final_state"], "confirmed_attributable")
        self.assertEqual(finding["iast_evidence"]["state"], "sink-reached")
        self.assertTrue(finding["trigger_spec_provided"])

    def test_fallback_does_not_cross_file_or_family(self):
        # 反例：不同文件（CacheProcessor vs DebugController）或不同族（path-traversal vs deserialization）
        # 兜底不得误归因。
        vuln = _deser_vuln(
            "Java 反序列化链",
            "src/main/java/com/quote/processor/CacheProcessor.java",
            38,
            "deserialization:cache_chain",
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "",
                            "match_keys": [],
                            "file": None,
                            "type": "反序列化",
                            "line": None,
                            "chain_id": "反序列化:src/main/java/com/quote/controller/debugcontroller.java:26",
                            "exploitable": "Yes",
                            "confidence": "high",
                            "test_status": "DONE",
                            "reason": "IAST SINK_HIT",
                            "final_state": "confirmed_attributable",
                            "iast_evidence": {"state": "sink-reached"},
                            "dast_impact_evidence": {},
                            "trigger_spec_provided": True,
                            "trigger_spec_hash": "f49f56e3e7f3bccc4be55f68",
                            "trigger_spec_detail": {"family": "deserialization", "canary_identity": "s4st41x"},
                            "d2_verdict": {"harmful": True},
                            "next_action": {},
                            "docker_attempted": False,
                            "docker_used": False,
                            "container_id": "",
                            "service_url": "",
                            "container_kept_running": False,
                            "service_ready": False,
                            "poc_generated": False,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "",
                            "poc_details": {},
                            "exploit_spec": {},
                            "contract_completeness": {},
                            "failure_classification": {},
                            "execution_evidence": {},
                            "verification_decision": {"verification_status": "confirmed_exploitable"},
                            "verified_bundle": {},
                        }
                    ],
                    "pocs": [],
                    "exploitable_count": 1,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        # 跨文件（CacheProcessor vs DebugController）→ 兜底不命中 → 保持 Unknown
        self.assertEqual(finding["exploitable"], "Unknown")
        self.assertIsNone(finding.get("final_state"))

    def test_p2_gate_passes_business_item_after_channel_b_backfill(self):
        # §P2：报告装配的回写（Edit 2）把通道 A 的 target_endpoint 写入通道 B 的
        # exploit_spec.entry.route。门禁 is_contract_ready_item 的 `entry.get('route')` 分支
        # 因此能识别业务类 a21_selected 真漏洞为可进 D2 主线，而非因无 sink→route 恒空而错杀。
        from src.benchmark.report_manager import is_contract_ready_item

        # 模拟回写后的 finding：entry.route 已被通道 A 端点填充
        backfilled = {
            "a21_selected": True,
            "family": "bola",
            "exploit_spec": {
                "business_logic_category": "bola",
                "entry": {"route": "/api/user/{id}", "method": "GET"},
            },
            "trigger_spec_detail": {"endpoint": "/api/user/{id}", "http_method": "GET"},
        }
        self.assertTrue(
            is_contract_ready_item(backfilled),
            "回写后 entry.route 非空，业务类 a21_selected 真漏洞应放行进 D2 主线",
        )

        # 反例：既无通道 A 端点（无回写源）也无 entry.route、且非 a21_selected → 门禁不应放行
        not_ready = {
            "a21_selected": False,
            "family": "bola",
            "exploit_spec": {"business_logic_category": "bola", "entry": {}},
            "trigger_spec_detail": {},
        }
        self.assertFalse(
            is_contract_ready_item(not_ready),
            "无端点且非 a21_selected，门禁不应放行",
        )

    def test_p2_report_backfills_entry_route_from_trigger_spec_detail(self):
        # §P2：generate_final_report 必须把通道 A 的 target_endpoint 回写通道 B 的
        # exploit_spec.entry.route（保底不清空），使下游面板/闸门看到真实可达入口。
        from src.benchmark.report_manager import is_contract_ready_item

        vuln = Vulnerability(
            type="越权访问",
            severity="HIGH",
            file="src/main/java/com/mall/controller/UserController.java",
            line=45,
            description="IDOR on user resource",
            code_snippet="@GetMapping(\"/user/{id}\")",
            source="a2",
            canonical_group_key="bola:user_chain",
            is_canonical=True,
            a21_selected=True,
            entry_point="/api/user/{id}",
        )
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                {
                    "verifications": [
                        {
                            "canonical_group_key": "bola:user_chain",
                            "match_keys": ["canonical:bola:user_chain"],
                            "file": vuln.file,
                            "type": "越权访问",
                            "line": 45,
                            "exploitable": "No",
                            "confidence": "low",
                            "test_status": "NOT_TESTED",
                            "reason": "D2 未产出动态实证",
                            "final_state": "",
                            "iast_evidence": {},
                            "dast_impact_evidence": {},
                            "trigger_spec_provided": True,
                            "trigger_spec_hash": "b0a12345cdef6789a0b1c2d3",
                            "trigger_spec_detail": {
                                "endpoint": "/api/user/{id}",
                                "http_method": "GET",
                                "param_name": "id",
                                "family": "bola",
                                "canary_identity": "s4st41b0a12345cdef6789",
                                "vulnerability_hash_v2": "b0a12345cdef6789a0b1c2d3",
                            },
                            "d2_verdict": {},
                            "next_action": {},
                            "docker_attempted": False,
                            "docker_used": False,
                            "container_id": "",
                            "service_url": "",
                            "container_kept_running": False,
                            "service_ready": False,
                            "poc_generated": False,
                            "poc_verified": False,
                            "verification_note": "",
                            "no_poc_reason": "",
                            "llm_poc_code": "",
                            "poc_details": {},
                            # 通道 B：entry.route 故意留空（无 sink），模拟真实召回漏斗根因
                            "exploit_spec": {
                                "business_logic_category": "bola",
                                "entry": {},
                            },
                            "contract_completeness": {},
                            "failure_classification": {},
                            "execution_evidence": {},
                            "verification_decision": {},
                            "verified_bundle": {},
                        }
                    ],
                    "pocs": [],
                    "exploitable_count": 0,
                    "verified_poc_count": 0,
                },
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )

        finding = report["report"]["vulnerabilities"][0]
        # ① 通道 B 必须被回写为通道 A 的端点
        self.assertEqual(
            finding["exploit_spec"]["entry"].get("route"),
            "/api/user/{id}",
            "报告装配应把通道 A 的 target_endpoint 回写通道 B 的 entry.route",
        )
        self.assertEqual(
            finding["exploit_spec"]["entry"].get("method"),
            "GET",
            "回写应同时带 http_method",
        )
        # ② 门禁现在应放行该业务类 a21_selected 真漏洞进 D2 主线
        self.assertTrue(
            is_contract_ready_item(finding),
            "回写后门禁应判定业务类 a21_selected 真漏洞可进 D2 主线",
        )


def _plain_vuln(type_label, file_path, line, proof_tier="broad_static", a21_selected=None):
    return Vulnerability(
        type=type_label,
        severity="HIGH",
        file=file_path,
        line=line,
        description="x",
        code_snippet="y",
        source="a2",
        proof_tier=proof_tier,
        a21_selected=a21_selected,
    )


class ReportManagerD2NotScheduledTests(unittest.TestCase):
    """§③ 显式未验证原因（2026-09-22，闭环 D2_NOT_SCHEDULED）。

    需求约定：未测必须显式记 runtime 原因，不得留 unknown。此前无匹配 verification 时一律写
    verification_decision={}，报告里成为既无证据、也无原因的沉默空壳。修复后必须落：
      - not_scheduled        未进 D2 队列（原因取自 run_d2_verify 的调度留痕）
      - no_verification_record  chain_proven 已强制入队却仍无验证记录（属缺陷）
    """

    def _render(self, vuln, d2_verifications):
        report_manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            report_manager.output_dir = tempdir
            report = report_manager.generate_final_report(
                [],
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a2")],
                d2_verifications,
                files=[],
                discovered_endpoints={},
                target_path="demo",
            )
        return report["report"]["vulnerabilities"][0]

    def test_skipped_entry_yields_not_scheduled_with_reason(self):
        vuln = _plain_vuln("SpEL注入", "src/main/java/Env.java", 33)
        finding = self._render(
            vuln,
            {
                "verifications": [],
                "pocs": [],
                "scheduling": {
                    "skipped": [
                        {
                            "file": vuln.file,
                            "type": vuln.type,
                            "line": vuln.line,
                            "reason": "no_trigger_spec: 无重放目标",
                        }
                    ]
                },
                "exploitable_count": 0,
                "verified_poc_count": 0,
            },
        )
        decision = finding["verification_decision"]
        self.assertEqual(decision.get("verification_status"), "not_scheduled")
        self.assertEqual(decision.get("final_state"), "not_scheduled")
        self.assertIn("no_trigger_spec", decision.get("scheduling_reason", ""))
        self.assertNotEqual(decision, {})

    def test_chain_proven_without_record_yields_no_verification_record(self):
        """已按强制入队规则进候选，却没有任何验证记录 → 必须显式标成上游结果丢失。"""
        vuln = _plain_vuln("命令注入", "src/main/java/Cmd.java", 7, proof_tier="chain_proven")
        finding = self._render(
            vuln,
            {"verifications": [], "pocs": [], "exploitable_count": 0, "verified_poc_count": 0},
        )
        decision = finding["verification_decision"]
        self.assertEqual(decision.get("verification_status"), "no_verification_record")
        self.assertEqual(decision.get("scheduling_reason"), "enqueued_but_no_verification_record")
        self.assertNotEqual(decision, {})

    def test_non_chain_proven_without_record_stays_silent(self):
        """反例：非 chain_proven 且无调度原因 → 保持空 decision（不臆造原因）。"""
        vuln = _plain_vuln("命令注入", "src/main/java/Cmd.java", 7)
        finding = self._render(
            vuln,
            {"verifications": [], "pocs": [], "exploitable_count": 0, "verified_poc_count": 0},
        )
        self.assertEqual(finding["verification_decision"], {})

    def test_not_scheduled_is_not_counted_as_executed(self):
        """口径守卫：显式未验证原因（not_scheduled / no_verification_record）绝不能被
        「verification_decision 非空」的真值判据抬进「已执行/已确认」计数。

        is_executed_d2_item 一旦把这两个状态算作已执行，count_dynamic_stats.confirmed_count
        与 d2_stats 的已执行档就会把「没跑的」也数进去，等于反向抬高口径。
        这里直接构造 mainline 形态（chain_proven + contract ready）以便断言真正走到守卫，
        而不是被 is_mainline_d2_item 提前挡掉导致「假通过」。
        """
        from src.benchmark.report_manager import (
            D2_NOT_EXECUTED_STATUSES,
            count_dynamic_stats,
            is_confirmed_exploitable,
            is_executed_d2_item,
            is_mainline_d2_item,
        )

        base = {
            "proof_tier": "chain_proven",
            "a21_selected": True,
            "contract_completeness": {"status": "ready"},
            "file": "src/main/java/Cmd.java",
            "type": "命令注入",
            "line": 7,
            "exploitable": "Unknown",
            "execution_evidence": {},
        }
        for status in sorted(D2_NOT_EXECUTED_STATUSES):
            vuln = dict(base, verification_decision={
                "verification_status": status,
                "scheduling_reason": "no_trigger_spec: 无重放目标",
            })
            self.assertTrue(is_mainline_d2_item(vuln), "前置：必须落在 D2 主线上，断言才有意义")
            self.assertFalse(
                is_executed_d2_item(vuln),
                "标了 %s 的 finding 不得被判为「已执行 D2」" % status,
            )
            self.assertFalse(is_confirmed_exploitable(vuln))
            stats = count_dynamic_stats([vuln])
            self.assertEqual(stats["confirmed_count"], 0)
            self.assertEqual(stats["exploitable_count"], 0)

        # 正向对照：真正跑过并确证的 finding 必须仍被算作已执行，守卫不得误伤。
        executed = dict(
            base,
            verification_decision={"verification_status": "confirmed_exploitable"},
            execution_evidence={"requests_made": ["GET /cmd"]},
            steps_executed=3,
            exploitable="Yes",
        )
        self.assertTrue(is_executed_d2_item(executed))
        self.assertTrue(is_confirmed_exploitable(executed))
        self.assertEqual(count_dynamic_stats([executed])["confirmed_count"], 1)

    def test_unverified_reason_surfaces_in_verdict_note(self):
        """需求约定「未测必须显式记 runtime 原因」——原因不能只留在结构化字段里，
        必须能在用户可见的裁决摘要 note 上读到。

        同时锁死一条耦合：「已检出未验证」的判据是「无真正 D2 实证」，
        不能退回成「verification_decision 是否为空」——否则写了显式原因状态后，
        这批 finding 会丢掉 ⚠️ 已检出未验证 的渲染、退回成 A2 的 ✅ 真漏洞结论。
        """
        vuln = Vulnerability(
            type="路径穿越",
            severity="HIGH",
            file="src/main/java/SecurityUtil.java",
            line=184,
            description="x",
            code_snippet="y",
            source="a2",
            proof_tier="chain_proven",
            a21_selected=True,
            verdict="✅ A2:真漏洞-HTTP入口可触发",
        )
        finding = self._render(
            vuln,
            {
                "verifications": [],
                "pocs": [],
                "scheduling": {
                    "skipped": [
                        {
                            "file": vuln.file,
                            "type": vuln.type,
                            "line": vuln.line,
                            "reason": "no_trigger_spec: 既无自身 entry.route，也未登记任何 spec",
                        }
                    ]
                },
                "exploitable_count": 0,
                "verified_poc_count": 0,
            },
        )
        self.assertIn("no_trigger_spec", str(finding.get("verdict_note", "")),
                      "显式未验证原因应出现在裁决摘要 note 上")
        self.assertEqual(finding.get("d2_status"), "unverified",
                         "无真正 D2 实证时必须仍置 d2_status=unverified")
        self.assertNotIn("已验证", str(finding.get("final_verdict", "")),
                         "无 D2 实证时 final_verdict 不得声称已验证")
        self.assertNotEqual(
            finding.get("verification_state"), "confirmed",
            "无 D2 实证时四态不得落到 confirmed",
        )


if __name__ == "__main__":
    unittest.main()
