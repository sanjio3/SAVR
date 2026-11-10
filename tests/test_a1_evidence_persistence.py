"""R23-1 回归守卫：a1_evidence 落库时序。

事故：task-7 实测 findings.a1_evidence 378/378 全空、route_status=0（task-1..6 均有 61~82 条）。
根因链：
  ① a1_evidence 的唯一写入点是注册期 ``UPDATE findings SET a1_evidence=? WHERE vulnerability_hash_v2=?``，
     而 findings 行直到任务收尾 ``replace_for_task`` 才写入 → 登记时本任务无行可更新（命中 0 行）；
  ② 该 UPDATE 未按 task_id 限定 → 证据只能落到「上一轮已完成任务」的同 vhash 行上，
     表现为每个 task 的 a1_evidence 实为下一轮 A1 产物、最新一轮恒空；
  ③ 收尾 ``replace_for_task`` 的 INSERT 不含 a1_evidence 列 → 本任务行永远写不进证据。

修复（三处）：
  ① report_manager.generate_final_report 的 findings payload 携带 a1_evidence；
  ② FindingRepository.replace_for_task 的 INSERT 显式写入 a1_evidence 列；
  ③ 注册期补偿写入抽为 persist_a1_evidence_to_findings，限定 task_id 且只补空值。

本文件守卫以上三处，任何一处回退都会失败。
"""

import tempfile
from pathlib import Path

import pytest

from src.benchmark.report_manager import ReportManager
from src.core.models import ScanResult, Vulnerability
from src.core.vuln_hash import enrich_finding_hash
from src.infrastructure.db import Database
from src.infrastructure.repositories import FindingRepository
from src.iast.trigger_spec_registry import persist_a1_evidence_to_findings

WORKSPACE_ID = 1

# 与生产一致的 A1 证据形状（业务逻辑族 + Q2 静态路由标记）
_A1_EV = {
    "business_logic": True,
    "category": "vertical_privesc",
    "family": "vertical-privesc",
    "target_endpoint": "/admin/users",
    "http_method": "GET",
    "route_status": "static",
    "static_route_params": ["id"],
    "route_handler": "AdminController#listUsers",
}


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    database.execute(
        "INSERT INTO workspaces (name, target_path, description, settings_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("ws", "/tmp/proj", "", "{}", now, now),
    )
    for task_id in (1, 2, 3):
        database.execute(
            "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, options_json, summary_json, error_message, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (WORKSPACE_ID, f"task{task_id}", "completed", "done", "/tmp/out", "{}", "{}", "", now),
        )
    return database


def _finding(*, line: int = 10, code: str = "return repo.findAll();") -> dict:
    return {
        "type": "broken access control",
        "display_family": "vertical-privesc",
        "file": "src/main/java/com/demo/AdminController.java",
        "line": line,
        "severity": "HIGH",
        "source": "a1",
        "code_snippet": code,
    }


# ---------------------------------------------------------------- ① 报告层携带


class TestReportPayloadCarriesA1Evidence:
    def test_report_payload_includes_a1_evidence(self):
        vuln = Vulnerability(
            type="Broken Access Control",
            severity="HIGH",
            file="src/main/java/com/demo/AdminController.java",
            line=42,
            description="admin route without guard",
            code_snippet="@GetMapping(\"/admin/users\")",
            source="a1",
        )
        # A1 侧是 setattr 挂载的（pipeline/a1/service.py）
        setattr(vuln, "a1_evidence", dict(_A1_EV))

        manager = ReportManager()
        with tempfile.TemporaryDirectory() as tempdir:
            manager.output_dir = tempdir
            report = manager.generate_final_report(
                [ScanResult(file=vuln.file, vulnerabilities=[vuln], agent="a1")],
                [],
                {"verifications": [], "pocs": []},
            )

        vulns = report["report"]["vulnerabilities"]
        assert len(vulns) == 1
        assert vulns[0].get("a1_evidence") == _A1_EV, "报告 payload 必须携带 A1 证据，否则收尾 INSERT 无从取值"

    def test_aggregation_keeps_nonempty_a1_evidence(self):
        """同族多副本合并时 canonical 取自 ranked[0]，可能恰好无证据；须从组内兜底取证。"""
        manager = ReportManager()
        no_ev = enrich_finding_hash(_finding(line=10, code="return repo.findAll();"))
        with_ev = enrich_finding_hash(_finding(line=11, code="return repo.findByOwner();"))
        with_ev["a1_evidence"] = dict(_A1_EV)
        # 同一 canonical 组（同 file/type）
        no_ev["canonical_group_key"] = "grp"
        with_ev["canonical_group_key"] = "grp"

        merged = manager._aggregate_canonical_findings([no_ev, with_ev])
        assert len(merged) == 1
        assert merged[0].get("a1_evidence") == _A1_EV

    def test_aggregation_single_item_keeps_a1_evidence(self):
        manager = ReportManager()
        only = enrich_finding_hash(_finding())
        only["a1_evidence"] = dict(_A1_EV)
        merged = manager._aggregate_canonical_findings([only])
        assert merged[0].get("a1_evidence") == _A1_EV


# ---------------------------------------------------------------- ② 落库层写入


class TestReplaceForTaskPersistsA1Evidence:
    def test_insert_writes_a1_evidence_column(self, db: Database):
        payload = enrich_finding_hash(_finding())
        payload["a1_evidence"] = dict(_A1_EV)

        FindingRepository(db).replace_for_task(1, WORKSPACE_ID, [payload])

        row = db.execute(
            "SELECT a1_evidence FROM findings WHERE task_id = ?", (1,), fetchone=True
        )
        assert row is not None
        stored = Database.loads(row["a1_evidence"])
        assert stored == _A1_EV, "A1 证据必须随本任务收尾 INSERT 一次落定"
        assert stored.get("route_status") == "static"

    def test_accepts_json_string_without_double_encoding(self, db: Database):
        payload = enrich_finding_hash(_finding())
        payload["a1_evidence"] = Database.dumps(_A1_EV)  # 已是 JSON 字符串

        FindingRepository(db).replace_for_task(1, WORKSPACE_ID, [payload])

        row = db.execute("SELECT a1_evidence FROM findings WHERE task_id = ?", (1,), fetchone=True)
        assert Database.loads(row["a1_evidence"]) == _A1_EV

    def test_missing_a1_evidence_stores_empty_object(self, db: Database):
        payload = enrich_finding_hash(_finding())  # 无 a1_evidence 键
        FindingRepository(db).replace_for_task(1, WORKSPACE_ID, [payload])
        row = db.execute("SELECT a1_evidence FROM findings WHERE task_id = ?", (1,), fetchone=True)
        assert Database.loads(row["a1_evidence"]) == {}


# ---------------------------------------------------------------- ③ 注册期补偿写入


class TestRegistryEvidenceWriteScoping:
    def _seed_two_tasks_same_vhash(self, db: Database) -> str:
        """同一漏洞在两轮任务各留一行（内容相同 → 同 vhash），返回该 vhash。"""
        repo = FindingRepository(db)
        repo.replace_for_task(1, WORKSPACE_ID, [enrich_finding_hash(_finding())])
        repo.replace_for_task(2, WORKSPACE_ID, [enrich_finding_hash(_finding())])
        rows = db.execute(
            "SELECT task_id, vulnerability_hash_v2 FROM findings ORDER BY task_id", fetchall=True
        )
        vhashes = {int(r["task_id"]): str(r["vulnerability_hash_v2"]) for r in rows}
        assert vhashes[1] == vhashes[2], "同内容漏洞跨任务应得同一 vhash（前置条件）"
        return vhashes[1]

    def _read(self, db: Database, task_id: int) -> dict:
        row = db.execute(
            "SELECT a1_evidence FROM findings WHERE task_id = ?", (task_id,), fetchone=True
        )
        return Database.loads(row["a1_evidence"])

    def test_write_is_task_scoped_and_never_touches_other_tasks(self, db: Database):
        vhash = self._seed_two_tasks_same_vhash(db)

        affected = persist_a1_evidence_to_findings(db, _A1_EV, vhash, 2)

        assert affected == 1
        assert self._read(db, 2) == _A1_EV, "本任务应补到证据"
        assert self._read(db, 1) == {}, "跨任务不得被污染（旧实现按全局 vhash 更新会写到这里）"

    def test_write_complements_but_never_overwrites_authoritative_value(self, db: Database):
        vhash = self._seed_two_tasks_same_vhash(db)
        authoritative = {"route_status": "static", "target_endpoint": "/admin/users", "authoritative": True}
        FindingRepository(db).replace_for_task(
            1, WORKSPACE_ID, [{**enrich_finding_hash(_finding()), "a1_evidence": authoritative}]
        )

        affected = persist_a1_evidence_to_findings(db, _A1_EV, vhash, 1)

        assert affected == 0
        assert self._read(db, 1) == authoritative, "收尾写入的权威证据不得被注册期覆盖"

    def test_noop_when_no_matching_row(self, db: Database):
        assert persist_a1_evidence_to_findings(db, _A1_EV, "deadbeef", 1) == 0
        assert persist_a1_evidence_to_findings(db, {}, "deadbeef", 1) == 0
        assert persist_a1_evidence_to_findings(db, _A1_EV, "", 1) == 0
