"""回归锁：bug④ 收尾回填 trigger_specs → findings.verification_decision。

## 断链现场

r88 run 333（pathtraver-1）：trigger_specs / vuln_blackboard 上已有 8 条
`confirmed_exploitable`（case 级 6 个真漏洞），但报告 vulnerabilities 里同 case 的 vuln
的 `verification_decision.verification_status` 仍是 `unconfirmed` ⇒ 前端与对账都读不到确认态，
6 个真漏洞被算进漏报。

## 修复约束（本测试锁定的两条）

1. **只升级不降级**：已处于确认态的 vuln 一律不动，避免把真阳性改坏。
2. **异常即 noop**：db 为 None / 查库抛错 / 无确认记录 ⇒ 返回 0，绝不阻断收尾。
"""
import pytest

from src.iast.trigger_spec_registry import (
    backfill_verification_status_from_triggers)


class _FakeDB:
    """最小 Database 替身：只实现 execute(sql, params, fetchall=True)。"""

    def __init__(self, rows=None, raise_exc=False):
        self.rows = rows if rows is not None else []
        self.raise_exc = raise_exc
        self.calls = []

    def execute(self, sql, params=(), fetchone=False, fetchall=False,
                return_rowcount=False):
        self.calls.append((sql, tuple(params)))
        if self.raise_exc:
            raise RuntimeError("db down")
        return self.rows


def _vuln(case, status="unconfirmed", state="detected_unverified"):
    return {
        "file": f"/pathtraver-00/{case}",
        "chain_id": case,
        "verification_state": state,
        "exploitable": "No",
        "verification_decision": {"verification_status": status},
    }


class TestTriggerSpecWriteback:
    def test_confirmed_exploitable_upgrades_finding(self):
        """trigger 层已确认 ⇒ findings 收尾应升级为 confirmed_exploitable。"""
        db = _FakeDB(rows=[{"target_endpoint": "/p/BenchmarkTest00045",
                            "vulnerability_hash_v2": None,
                            "verification_status": "confirmed_exploitable"}])
        findings = [_vuln("BenchmarkTest00045")]
        assert backfill_verification_status_from_triggers(db, 333, findings, None) == 1
        vd = findings[0]["verification_decision"]
        assert vd["verification_status"] == "confirmed_exploitable"
        assert vd["verification_status_source"] == "trigger_specs"
        assert findings[0]["verification_state"] == "confirmed"
        assert findings[0]["exploitable"] == "Yes"

    def test_no_confirmed_rows_is_noop(self):
        db = _FakeDB(rows=[{"target_endpoint": "/p/BenchmarkTest00045",
                            "vulnerability_hash_v2": None,
                            "verification_status": "sink_reached"}])
        findings = [_vuln("BenchmarkTest00045")]
        assert backfill_verification_status_from_triggers(db, 333, findings, None) == 0
        assert findings[0]["verification_state"] == "detected_unverified"

    def test_existing_confirmed_not_downgraded(self):
        """已确认的条目不得被回填逻辑改写（只升级不降级）。"""
        db = _FakeDB(rows=[])
        findings = [_vuln("BenchmarkTest00045",
                          status="confirmed_code_property", state="confirmed")]
        assert backfill_verification_status_from_triggers(db, 333, findings, None) == 0
        assert findings[0]["verification_decision"]["verification_status"] == (
            "confirmed_code_property")

    def test_db_none_is_noop(self):
        assert backfill_verification_status_from_triggers(None, 333, [_vuln("x")], None) == 0

    def test_empty_findings_is_noop(self):
        assert backfill_verification_status_from_triggers(_FakeDB(rows=[]), 333, [], None) == 0

    def test_db_exception_is_swallowed(self):
        """查库失败必须 noop，不能把收尾流程打断。"""
        db = _FakeDB(rows=[], raise_exc=True)
        assert backfill_verification_status_from_triggers(db, 333, [_vuln("x")], None) == 0
