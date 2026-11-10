"""R23-3 回归守卫：业务族生产者门控 + 受害者标识派生（§6.13）。

实测瓶颈（task-7，114 条业务族 spec）：
- victim_resource_id 为空 99/114（87%）→ D1 差分重放没有受害者目标，无从构造请求；
- victim_identifiers 为空 114/114 → 即便重放跑通也无法判定「取回了受害者数据」；
- accounts_json 为空 114/114 → bootstrap 从未落盘（R23-2 修）。

修复：
(a) 生产者门控按「规范业务族 ∈ 差分证明族」判定，不再只看 payload_family 恰为 bola/idor：
    - A1 ``_hypo_to_vulnerability``（Q1 之后 A1 已是业务族一级生产者）写 payload_family + 哨兵；
    - A2 ``_build_exploit_spec`` 门控放开到全部 DIFFERENTIAL_PROOF_FAMILIES。
(b) 注册期 ``_derive_victim_identifiers`` 增第 ③ 来源：账户发现产物（dast_accounts，跨轮持久）。
"""

from pathlib import Path

import pytest

from src.agents.a2_intelligent_agent import A2SemanticAgent
from src.core.exploit_spec import DIFFERENTIAL_PROOF_FAMILIES
from src.core.models import Vulnerability
from src.infrastructure.db import Database
from src.iast.trigger_spec_registry import (
    _derive_victim_identifiers,
    _load_discovered_accounts,
    _victim_identifiers_from_accounts,
)
from src.pipeline.a1.service import _hypo_to_vulnerability


# ---------------------------------------------------------------- (a) A1 生产者


class TestA1ProducerExploitSpec:
    def _hypo(self, **over):
        h = {
            "file": "src/main/java/com/demo/AdminController.java",
            "line": 42,
            "category": "vertical_privesc",
            "vuln_type": "垂直越权",
            "family": "vertical-privesc",
            "target_endpoint": "/admin/users",
            "http_method": "GET",
            "vulnerable_param": "id",
        }
        h.update(over)
        return h

    def test_business_hypo_gets_canonical_family_and_victim_sentinel(self):
        v = _hypo_to_vulnerability(self._hypo())
        spec = getattr(v, "exploit_spec", {}) or {}
        assert spec["payload"]["payload_family"] == "vertical_privesc"
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL"

    def test_race_hypo_gets_victim_sentinel(self):
        v = _hypo_to_vulnerability(self._hypo(
            category="race", vuln_type="竞态条件", family="race-condition",
            target_endpoint="/api/order/submit", http_method="POST"))
        spec = getattr(v, "exploit_spec", {}) or {}
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL"

    def test_entry_route_written_when_empty(self):
        """Vulnerability 默认已带空 exploit_spec，entry.route 必须按字段判空补位（曾漏写）。"""
        v = _hypo_to_vulnerability(self._hypo())
        spec = getattr(v, "exploit_spec", {}) or {}
        assert spec["entry"]["route"] == "/admin/users"
        assert spec["entry"]["method"] == "GET"

    def test_source_path_never_written_as_route(self):
        """离线 BOLA 分析器的 entry_point 是源码定位（X.java:118），不得当 HTTP 路由。"""
        v = _hypo_to_vulnerability({
            "entry_point": "src/main/java/com/demo/OrderService.java:118",
            "category": "bola", "family": "idor", "vuln_type": "BOLA"})
        spec = getattr(v, "exploit_spec", {}) or {}
        assert spec["entry"]["route"] == ""
        assert spec["payload"]["payload_family"] == "idor"
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL"

    def test_injection_hypo_has_no_victim_sentinel(self):
        v = _hypo_to_vulnerability({
            "file": "src/main/java/com/demo/SearchController.java", "line": 9,
            "category": "sql-injection", "vuln_type": "SQL注入", "family": "sql-injection"})
        spec = getattr(v, "exploit_spec", {}) or {}
        assert spec["prerequisites"]["victim_resource_id"] == ""

    def test_all_differential_families_get_sentinel(self):
        for fam in ("bola", "idor", "vertical_privesc", "cross_module_privesc",
                    "state_machine", "race", "calculation_logic", "auth_session", "abuse_dos"):
            v = _hypo_to_vulnerability(self._hypo(category=fam, family=fam, vuln_type=fam))
            spec = getattr(v, "exploit_spec", {}) or {}
            assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL", fam
            assert spec["payload"]["payload_family"] == fam, fam


# ---------------------------------------------------------------- (a) A2 门控


class TestA2GateCoversAllDifferentialFamilies:
    def _agent(self):
        return A2SemanticAgent({}, "qwen")

    # bola/idor 受 守门：须落在带 HTTP 方法注解的方法上，否则降级（辅助方法/注释块误报收敛）
    _HTTP_SNIPPET = '@GetMapping("/api/order/{id}")\npublic Order get(@PathVariable String id)'

    def _spec_for(self, category: str, code_snippet: str = ""):
        v = Vulnerability(
            type="业务逻辑缺陷", severity="HIGH",
            file="src/main/java/com/demo/C.java", line=10,
            description="business logic flaw", source="a1",
            code_snippet=code_snippet,
        )
        v.business_logic_category = category
        return self._agent()._build_exploit_spec(v)

    @pytest.mark.parametrize("category", [
        "vertical_privesc", "cross_module_privesc", "state_machine", "race",
        "calculation_logic", "auth_session", "abuse_dos", "signature_bypass",
    ])
    def test_sentinel_emitted_for_every_differential_family(self, category):
        spec = self._spec_for(category)
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL", category

    @pytest.mark.parametrize("category", ["bola", "idor"])
    def test_sentinel_emitted_for_bola_with_http_annotation(self, category):
        spec = self._spec_for(category, code_snippet=self._HTTP_SNIPPET)
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL"

    @pytest.mark.parametrize("category", ["bola", "idor"])
    def test_bola_without_annotation_degrades(self, category):
        """守门：无 HTTP 注解的 bola/idor 视为辅助方法误报，不产出 victim 目标。"""
        spec = self._spec_for(category)
        assert spec["prerequisites"]["victim_resource_id"] == ""

    def test_race_condition_alias_is_recognized(self):
        spec = self._spec_for("race_condition")
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL"

    @pytest.mark.parametrize("text,expected", [
        ("/order/{id}", ""),
        ("/admin/users", ""),
        ("src/main/java/com/demo/OrderService.java:118", ""),
        ("/api/order/42", "42"),
    ])
    def test_resource_id_extraction_is_conservative(self, text, expected):
        """放宽门控后，具体 victim id 只允许取文本里的真实数字路径段，否则回落哨兵。"""
        assert A2SemanticAgent._extract_resource_id_from_text(text) == expected

    def test_concrete_id_preferred_over_sentinel(self):
        v = Vulnerability(
            type="BOLA", severity="HIGH",
            file="src/main/java/com/demo/C.java", line=10,
            description="attacker reads /api/order/42 owned by another user",
            source="a1", code_snippet='@GetMapping("/api/order/{id}")',
        )
        v.business_logic_category = "bola"
        spec = self._agent()._build_exploit_spec(v)
        assert spec["prerequisites"]["victim_resource_id"] == "42"

    def test_sentinel_when_no_concrete_id(self):
        v = Vulnerability(
            type="BOLA", severity="HIGH",
            file="src/main/java/com/demo/C.java", line=10,
            description="attacker reads another user's order",
            source="a1", code_snippet='@GetMapping("/api/order/{id}")',
        )
        v.business_logic_category = "bola"
        spec = self._agent()._build_exploit_spec(v)
        assert spec["prerequisites"]["victim_resource_id"] == "VICTIM_FROM_POOL"

    def test_no_sentinel_for_injection(self):
        v = Vulnerability(
            type="SQL注入", severity="HIGH", sink="Statement.execute",
            file="src/main/java/com/demo/S.java", line=3,
            description="sql injection", source="a1",
        )
        spec = self._agent()._build_exploit_spec(v)
        assert spec["prerequisites"]["victim_resource_id"] == ""


# ---------------------------------------------------------------- (b) 标识派生


# 与 data/app.db 中 target-mall（workspace-3）真实账户发现产物同形
_DISCOVERED = [
    {"role": "admin", "subject": "admin",
     "metadata": {"username": "admin", "role": "admin", "real_role": "admin"}},
    {"role": "user", "subject": "alice",
     "metadata": {"username": "alice", "role": "user", "real_role": "user"}},
    {"role": "user", "subject": "bob",
     "metadata": {"username": "bob", "role": "user", "real_role": "user"}},
]


class TestVictimIdentifiersFromAccounts:
    def test_excludes_attacker_and_role_tokens(self):
        # 攻击者=最低特权(alice)；受害者候选=bob/admin，其中 admin 是角色名故剔除
        assert _victim_identifiers_from_accounts(_DISCOVERED) == ["bob"]

    def test_single_account_yields_nothing(self):
        assert _victim_identifiers_from_accounts([_DISCOVERED[0]]) == []
        assert _victim_identifiers_from_accounts([]) == []
        assert _victim_identifiers_from_accounts(None) == []

    def test_explicit_victim_role_contributes(self):
        accounts = [
            {"role": "attacker", "username": "mallory"},
            {"role": "victim", "username": "carol", "email": "carol@corp.tld"},
        ]
        assert _victim_identifiers_from_accounts(accounts) == ["carol", "carol@corp.tld"]

    def test_role_names_never_used_as_markers(self):
        accounts = [
            {"role": "user", "subject": "u1"},
            {"role": "admin", "subject": "admin"},
        ]
        # 'admin' 既是最低特权攻击者的……不，攻击者是 u1；admin 是角色名 → 剔除
        assert _victim_identifiers_from_accounts(accounts) == []


class TestDeriveVictimIdentifiers:
    def _vuln(self, prereq=None):
        return {"exploit_spec": {"prerequisites": prereq or {}}}

    def test_priority_one_prerequisites_win(self):
        out = _derive_victim_identifiers(
            self._vuln({"victim_identifiers": ["explicit@corp.tld"]}), {},
            discovered_accounts=_DISCOVERED)
        assert out[0] == "explicit@corp.tld"
        assert "bob" in out  # 发现产物作为补充

    def test_third_source_used_when_nothing_else(self):
        assert _derive_victim_identifiers(self._vuln(), {}) == []
        assert _derive_victim_identifiers(self._vuln(), {}, discovered_accounts=_DISCOVERED) == ["bob"]

    def test_ctx_role_marked_accounts_still_supported(self):
        ctx = {"accounts": [{"role": "victim", "username": "dave"}]}
        assert _derive_victim_identifiers(self._vuln(), ctx) == ["dave"]

    def test_backward_compatible_signature(self):
        # 不传 discovered_accounts 时行为与修复前一致
        assert _derive_victim_identifiers(self._vuln(), {}) == []


class TestLoadDiscoveredAccounts:
    @pytest.fixture()
    def db(self, tmp_path: Path) -> Database:
        database = Database(str(tmp_path / "app.db"))
        now = "2026-01-01T00:00:00"
        for role, subj in (("admin", "admin"), ("user", "alice"), ("user", "bob")):
            database.execute(
                "INSERT INTO dast_accounts (app_id, account_id, role, tenant, subject, "
                "auth_headers_json, auth_cookies_json, token_ref, metadata_json, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("workspace-7", subj, role, "default", subj, "{}", "{}", "",
                 Database.dumps({"username": subj, "role": role}), now),
            )
        return database

    def test_reads_workspace_scoped_accounts(self, db: Database):
        accounts = _load_discovered_accounts(db, 7)
        assert len(accounts) == 3
        assert {a["subject"] for a in accounts} == {"admin", "alice", "bob"}
        # metadata 已展开
        assert all(a.get("username") for a in accounts)
        # 端到端：派生结果与直接喂入同形数据一致
        assert _victim_identifiers_from_accounts(accounts) == ["bob"]

    def test_other_workspace_returns_empty(self, db: Database):
        assert _load_discovered_accounts(db, 999) == []

    def test_missing_db_is_safe(self):
        assert _load_discovered_accounts(None, 7) == []
        assert _load_discovered_accounts(object(), None) == []


def test_differential_family_set_is_the_gate_source_of_truth():
    """门控依据必须是规范族集合本身（避免再次出现 bola/idor 硬编码漏掉 7 族）。"""
    assert "race" in DIFFERENTIAL_PROOF_FAMILIES
    assert "state_machine" in DIFFERENTIAL_PROOF_FAMILIES
    assert "calculation_logic" in DIFFERENTIAL_PROOF_FAMILIES
    assert "sql-injection" not in DIFFERENTIAL_PROOF_FAMILIES
