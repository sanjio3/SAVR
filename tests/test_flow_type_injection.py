"""回归：flow_type 字段注入（单一真相源 derive_flow_type）。

锁定「业务型 vs 注入型」判别在 7 个后端投影点统一经 derive_flow_type 派生，
不再各处硬编码 family 列表（对应  收敛后的唯一判据）。

覆盖：
A. derive_flow_type 单一来源（英文规范族 + 中文别名）。
B. AttackPlanService._project 投影补 flow_type。
C. benchmark_cli._aggregate_d1_replay / _d2_verification_detail 明细补 flow_type。
D. load_trigger_specs_by_workspace 投影补 flow_type（业务族→business_logic，注入族→injection）。
"""

import os
import tempfile

from src.application.attack_plan_service import AttackPlanService
from src.cli import benchmark_cli
from src.core.exploit_spec import derive_flow_type
from src.iast.trigger_spec_registry import auto_register_from_a2, load_trigger_specs_by_workspace
from src.infrastructure.db import Database


def _Vuln(d):
    class _V:
        def __init__(self, d):
            self._d = d

        def to_dict(self):
            return self._d
    return _V(d)


def _ScanResult(vulns):
    class _R:
        def __init__(self, v):
            self.vulnerabilities = v
    return _R(vulns)


def _sql_vuln(route="/api/user", param_name="name"):
    return _Vuln({
        "type": "SQL Injection",
        "file": "com/example/Ctrl.java",
        "line": 42,
        "exploit_spec": {
            "payload": {"payload_family": "sql"},
            "entry": {
                "parameter_name": param_name,
                "route": route,
                "method": "GET",
                "parameter_location": "query",
            },
            "prerequisites": {"role_or_permission": ""},
        },
    })


def test_derive_flow_type_single_source():
    biz = ["bola", "idor", "vertical_privesc", "cross_module_privesc",
           "state_machine", "race", "calculation_logic", "auth_session", "abuse_dos"]
    for f in biz:
        assert derive_flow_type(f) == "business_logic", f
    inj = ["sql", "sql_injection", "xss", "command", "deserialization",
           "ssrf", "ssti", "xxe", "path_traversal"]
    for f in inj:
        assert derive_flow_type(f) == "injection", f
    # 中文别名也应归一（依赖别名表，证明单一真相源而非局部硬编码）
    assert derive_flow_type("状态机跳步") == "business_logic"
    assert derive_flow_type("金额篡改") == "business_logic"
    # 2026-09-02 别名表缺口补全（#3）：纯中文/带括号/连字符落库形态须归业务型
    for f in ["业务逻辑", "退款滥用", "垂直越权 (privilege escalation)",
              "business-logic-manipulation", "unauthorized-access",
              "concurrent-race-condition", "signature-bypass", "signature-forgery"]:
        assert derive_flow_type(f) == "business_logic", f
    # 空族 → 注入（宽松兜底，不卡注入型信号）
    assert derive_flow_type("") == "injection"


def test_attack_plan_project_injects_flow_type():
    svc = AttackPlanService(db=None)
    biz = svc._project({"id": 1, "family": "state_machine", "target_endpoint": "/x",
                        "http_method": "POST", "param_name": "p", "param_location": "query",
                        "taint_marker": "", "raw_json": "{}",
                        "business_logic_category": "state_machine"}, 1)
    assert biz["flow_type"] == "business_logic"
    inj = svc._project({"id": 2, "family": "sql", "target_endpoint": "/x",
                        "http_method": "GET", "param_name": "p", "param_location": "query",
                        "taint_marker": "", "raw_json": "{}"}, 2)
    assert inj["flow_type"] == "injection"
    # idor 在 D1 层归 bola（业务型）
    idor = svc._project({"id": 3, "family": "idor", "target_endpoint": "/x",
                         "http_method": "GET", "param_name": "p", "param_location": "query",
                         "taint_marker": "", "raw_json": "{}"}, 3)
    assert idor["flow_type"] == "business_logic"


def test_benchmark_cli_replay_detail_injects_flow_type():
    # _aggregate_d1_replay
    v = {"trigger_spec_provided": True,
         "trigger_spec_detail": {"endpoint": "/x", "http_method": "GET", "param_name": "p",
                                "param_location": "query", "family": "race",
                                "canary_identity": "s4st41" + "0" * 16, "source": "a2",
                                "vulnerability_hash_v2": "h1"},
         "iast_evidence": {"state": "no-arrival"}, "dast_impact_evidence": {}}
    agg = benchmark_cli._aggregate_d1_replay([v])
    assert agg["replayed_specs_detail"][0]["flow_type"] == "business_logic"

    # _d2_verification_detail
    v2 = {"chain_id": "h1", "type": "Race Condition",
          "trigger_spec_detail": {"family": "race"},
          "iast_evidence": {}, "dast_impact_evidence": {}, "d2_verdict": {}}
    det = benchmark_cli._d2_verification_detail(v2)
    assert det["flow_type"] == "business_logic"


def test_load_trigger_specs_injects_flow_type():
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "app.db")
    os.environ["SAST_AI_DB_PATH"] = db_path
    db = Database(db_path)
    db.execute("INSERT INTO workspaces (name, target_path, created_at, updated_at) VALUES (?,?,?,?)",
               ("ws", tmp, "2026-01-01", "2026-01-01"))
    workspace_id = db.execute("SELECT id FROM workspaces ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    db.execute("INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) VALUES (?,?,?,?,?,?)",
               (workspace_id, "task", "pending", "queued", "/tmp/out", "2026-01-01"))
    task_id = db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    # 触发建表（auto_register 会 ensure trigger_specs 表并登记一条 sql spec）
    auto_register_from_a2(task_id, [_ScanResult([_sql_vuln()])])
    # 直接插入一条业务族 spec，验证 load 投影补 flow_type（单一来源 derive_flow_type）
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, family, created_at) "
        "VALUES (?,?,?,?,?)",
        (workspace_id, task_id, "vh_biz", "state_machine", "2026-01-01"),
    )
    by_hash = load_trigger_specs_by_workspace(workspace_id)
    biz = by_hash.get("vh_biz", [{}])[0]
    assert biz.get("flow_type") == "business_logic", biz
    assert biz.get("family") == "state_machine"
    # 所有加载的 spec 都应有非空的 flow_type（含 auto_register 登记的 sql 族）
    for specs in by_hash.values():
        for s in specs:
            ft = s.get("flow_type")
            assert ft in ("business_logic", "injection"), s
