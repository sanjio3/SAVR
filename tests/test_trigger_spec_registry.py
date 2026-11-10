"""实证回归：A2→TriggerSpec 登记链路。

直接回答「ws=4（java-quote 实时会话）当初 trigger_specs 0 条」的根因归属：

结论（由下方测试实证）：
- 不是 enable_a3 / enable_verification 守卫所致——统一链路已把登记与验证开关解耦，
  auto_register_from_a2 只要拿到 a2_results 就登记，不读任何 enable_* 开关。
- 真实机制是 code_root 为空（workspace.target_path 为空 且 无在线 IAST 会话 code_path），
  导致无法从源码解析 (param_name, route)，A2 既有字段又非法/缺失的漏洞被逐个 skip，
  最终 registered=0。

本测试覆盖：
A. workspace.target_path 优先于会话 code_path：无 IAST 会话也能登记（修复后行为）。
B. 空 code_root + A2 缺字段 → 全部 skip（复现 ws=4 当初 0 条的真实机制）。
C. load_trigger_specs_by_workspace 按漏洞 hash 分组返回。
D. task_id=None（离线 CLI 入口）被明确拒绝，返回 (0, 0)（失败报错）。
"""

import os

from src.iast.trigger_spec_registry import auto_register_from_a2, load_trigger_specs_by_workspace
from src.infrastructure.db import Database


class _Vuln:
    def __init__(self, vuln_dict):
        self._d = vuln_dict

    def to_dict(self):
        return self._d


class _ScanResult:
    def __init__(self, vulns):
        self.vulnerabilities = vulns


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


def _seed(tmp_path, target_path):
    db_path = os.path.join(str(tmp_path), "app.db")
    os.environ["SAST_AI_DB_PATH"] = db_path
    db = Database(db_path)
    db.execute(
        "INSERT INTO workspaces (name, target_path, created_at, updated_at) VALUES (?,?,?,?)",
        ("ws", target_path, "2026-01-01", "2026-01-01"),
    )
    workspace_id = db.execute("SELECT id FROM workspaces ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) VALUES (?,?,?,?,?,?)",
        (workspace_id, "task", "pending", "queued", "/tmp/out", "2026-01-01"),
    )
    task_id = db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    return db, workspace_id, task_id


def test_workspace_target_path_priority_registers_without_session():
    """A. 修复后：workspace.target_path 优先，即使无 IAST 会话也应成功登记。

    这直接证伪『ws=4 0 条是 enable_a3 守卫所致』——函数根本不读 enable_* 开关，
    且只要有 code_root（此处来自 workspace.target_path）就能从 A2 既有字段登记。
    """
    import tempfile

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path=tmp)  # 非空 target_path，无 IAST 会话
    funnel = auto_register_from_a2(task_id, [_ScanResult([_sql_vuln()])])
    registered = funnel.get("registered", 0)
    skipped = funnel.get("skipped", 0)
    assert registered == 1, f"期望登记 1 条，实际 registered={registered}, skipped={skipped}"
    assert skipped == 0
    # 验证已落入 DB
    rows = db.execute("SELECT * FROM trigger_specs WHERE workspace_id=?", (workspace_id,), fetchall=True)
    assert len(rows) == 1
    assert rows[0]["target_endpoint"] == "/api/user"
    assert rows[0]["param_name"] == "name"


def test_empty_code_root_skips_all_reproducing_ws4_zero_records():
    """B. 复现 ws=4 当初 0 条的真实机制：code_root 为空 + A2 缺字段 → 全部 skip。

    当 workspace.target_path 为空且无在线 IAST 会话时，code_root 为空，无法从源码解析
    (param_name, route)，A2 既有字段又非法/缺失的漏洞被逐个 skip，最终 registered=0。
    这正是 ws=4 实时会话 trigger_specs 为 0 的根因（与 enable_a3 守卫无关）。
    """
    import tempfile

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path="")  # 空 target_path，无 IAST 会话 → code_root 为空
    # A2 给的路由/参数名都是空（非法），且 code_root 空无法从源码兜底
    funnel = auto_register_from_a2(
        task_id, [_ScanResult([_sql_vuln(route="", param_name="")])]
    )
    registered = funnel.get("registered", 0)
    skipped = funnel.get("skipped", 0)
    assert registered == 0, f"空 code_root 时应 0 登记，实际 registered={registered}"
    assert skipped >= 1
    rows = db.execute("SELECT * FROM trigger_specs WHERE workspace_id=?", (workspace_id,), fetchall=True)
    assert len(rows) == 0


def test_load_trigger_specs_grouped_by_hash():
    """C. 加载按漏洞 hash 分组，供 D2 verify 关联重放。"""
    import tempfile

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path=tmp)
    auto_register_from_a2(task_id, [_ScanResult([_sql_vuln()])])
    by_hash = load_trigger_specs_by_workspace(workspace_id)
    assert len(by_hash) == 1
    spec_list = next(iter(by_hash.values()))
    assert spec_list[0]["target_endpoint"] == "/api/user"


def test_offline_cli_entry_rejected_without_task_id():
    """D. 离线 CLI 入口（task_id=None）被明确拒绝并返回 (0, 0)，而非静默解包崩溃。"""
    import tempfile

    tmp = tempfile.mkdtemp()
    _seed(tmp, target_path=tmp)
    result = auto_register_from_a2(None, [_ScanResult([_sql_vuln()])])
    assert result == (0, 0)


def test_a2_entry_resolves_without_code_root():
    """#D 计划 7.3 正向护栏：空 code_root 且无 entry_discovery 真实路由时，A2 结构化 entry
    （经 A1/CodeQL 证据注入 A2 prompt 后产出）仍能解析出可登记的 (route, param_name)，
    不退化到静默 skip。

    这是 test_empty_code_root_skips_all_reproducing_ws4_zero_records 的正向镜像：
    那个用例用「非法空 A2 entry」复现 0 条登记；本用例用「合法 A2 entry」证明即使
    workspace.target_path（code_root）为空，resolver Tier-2 仍能借 A2 既有结构化入口
    产出 spec，registered=1。

    设计说明（与 7.3 原文一致）：A1/CodeQL 的 entry_candidates 不再作为 resolver 的独立
    回退层，而是改为在 A2 生成阶段注入 prompt，使 A2 产出的 entry 已携带 A1 喂入的路由/
    参数名；resolver Tier-2 在无 code_root 时消费该 A2 entry。故本测试守护的是
    「A2 entry 兜底」这条真实生效的路径，而非已移除的「a1_ev.entry_candidates 直读」旧路径。
    """
    import tempfile

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path="")  # 空 target_path → code_root 为空
    funnel = auto_register_from_a2(task_id, [_ScanResult([_sql_vuln()])])
    registered = funnel.get("registered", 0)
    skipped = funnel.get("skipped", 0)
    assert registered == 1, (
        f"空 code_root 时合法 A2 entry 仍应登记 1 条，实际 registered={registered}, skipped={skipped}"
    )
    assert skipped == 0
    rows = db.execute("SELECT * FROM trigger_specs WHERE workspace_id=?", (workspace_id,), fetchall=True)
    assert len(rows) == 1
    assert rows[0]["target_endpoint"] == "/api/user"
    assert rows[0]["param_name"] == "name"
    assert rows[0]["param_name_source"] == "a2"


def test_a1_evidence_persisted_to_findings_on_register():
    """#D 计划 7.3：带 a1_evidence 的 A2 finding 经 auto_register_from_a2 后，
    findings.a1_evidence 被真实写入（Step2 落库），而非此前 INSERT 不含该列导致的循环空写。

    此前 trigger_spec_registry 的 UPDATE findings SET a1_evidence 因 a1_ev 恒为空而从不触发；
    自 A1 发射 evidence 后（④ Step1），合并进 A2 vuln 的 a1_evidence 非空，此 UPDATE 生效。
    """
    import tempfile

    from src.core.vuln_hash import vulnerability_hash_v2

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path="")  # 空 code_root；靠 A2 entry 兜底登记
    vuln = _sql_vuln()  # 合法 A2 entry
    a1_ev = {
        "rule_id": "java/sql-injection",
        "message": "Tainted value flows to SQL query",
        "severity": "high",
        "file": "com/example/Ctrl.java",
        "line": 42,
        "entry_candidates": [{"route": "/api/user", "method": "GET", "parameter_name": "name", "location": "query"}],
        "source_candidates": [{"name": "name", "location": "query"}],
    }
    # 把 a1_evidence 注入 finding dict，使其与 A2 vuln 同源（auto_register 据此算 vhash）
    vuln._d["a1_evidence"] = a1_ev
    vhash = vulnerability_hash_v2(vuln.to_dict())
    # 预置一条 matching findings 行，供 trigger_spec_registry 的 UPDATE 命中
    db.execute(
        "INSERT INTO findings (task_id, workspace_id, finding_type, severity, file_path, line, title, "
        "raw_json, vulnerability_hash_v2, hash_components_json, source, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (task_id, workspace_id, "SQL Injection", "HIGH", "com/example/Ctrl.java", 42, "t",
         "{}", vhash, "{}", "a2", "2026-01-01"),
    )

    funnel = auto_register_from_a2(task_id, [_ScanResult([vuln])])
    registered = funnel.get("registered", 0)
    skipped = funnel.get("skipped", 0)
    assert registered == 1, f"应登记 1 条，实际 registered={registered}, skipped={skipped}"
    assert skipped == 0

    row = db.execute(
        "SELECT a1_evidence FROM findings WHERE vulnerability_hash_v2=?", (vhash,), fetchone=True
    )
    assert row is not None, "应存在 matching findings 行"
    saved = db.loads(row["a1_evidence"])
    assert saved.get("rule_id") == "java/sql-injection", "findings.a1_evidence 应真实写入 A1 rule_id"
    assert saved.get("entry_candidates"), "findings.a1_evidence 应含 entry_candidates（Step2 落库生效）"
    assert saved.get("source_candidates"), "findings.a1_evidence 应含 source_candidates（Step2 落库生效）"


def test_reconcile_orphan_specs_removes_specs_without_finding():
    """#B / Q3(c)：reconcile_orphan_specs 只删除「全局都查无对应 finding」的孤儿 spec。

    §Q3(c) 修正：findings 按 vulnerability_hash_v2 全局去重（同一漏洞在 task-1 写了 finding 后，
    task-4 重扫同代码不再写 finding 行，仅 task-1 持有该 hash 的 finding）。因此判定孤儿必须按
    **全局** vulnerability_hash_v2 匹配——spec 的 vhash 在任一 task 存在 finding 即非孤儿（漏洞真实、
    重放目标有效，不得剪掉，尤其不得剪掉 D1 待重放的 spec）；仅当全局都查无此 hash 的 finding 时才清理。
    """
    import tempfile

    from src.iast.trigger_spec_registry import auto_register_from_a2, reconcile_orphan_specs

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path=tmp)
    # 另一 task（task-1）先写一条 finding（vhash 与 task-4 的某条 spec 相同）
    db.execute(
        "INSERT INTO scan_tasks (workspace_id, name, status, phase, output_dir, created_at) VALUES (?,?,?,?,?,?)",
        (workspace_id, "task1", "done", "done", "/tmp/out1", "2026-01-01"),
    )
    task1 = db.execute("SELECT id FROM scan_tasks ORDER BY id DESC LIMIT 1", fetchone=True)["id"]
    vhash_kept = "abc123def456"          # 该 vhash 在 task-1 有 finding → task-4 的 spec 应保留
    vhash_orphan = "fff000orphan999"     # 全局都无 finding → 真孤儿，应清理
    db.execute(
        "INSERT INTO findings (task_id, workspace_id, finding_type, severity, file_path, line, title, "
        "raw_json, vulnerability_hash_v2, hash_components_json, source, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (task1, workspace_id, "SQL Injection", "HIGH", "com/example/Ctrl.java", 42, "t",
         "{}", vhash_kept, "{}", "a2", "2026-01-01"),
    )
    # task-4 两条 spec：一条 vhash 命中 task-1 finding（应保留），一条全局无 finding（应清理）
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, target_endpoint, "
        "http_method, param_name, taint_marker, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (workspace_id, task_id, vhash_kept, "/api/x", "GET", "q", "s4st41abc123def4567890", "2026-01-01"),
    )
    db.execute(
        "INSERT INTO trigger_specs (workspace_id, task_id, vulnerability_hash_v2, target_endpoint, "
        "http_method, param_name, taint_marker, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (workspace_id, task_id, vhash_orphan, "/api/y", "GET", "q", "s4st41fff000orphan9999", "2026-01-01"),
    )
    # task-4 自身无这两条 vhash 的 finding
    dry = reconcile_orphan_specs(task_id, dry_run=True)
    assert dry == 1, f"dry-run 应识别 1 条真孤儿（全局无 finding），实际 {dry}"
    n = reconcile_orphan_specs(task_id, dry_run=False)
    assert n == 1, f"应清理 1 条真孤儿，实际 {n}"
    remain = db.execute(
        "SELECT count(*) c FROM trigger_specs WHERE task_id=?", (task_id,), fetchone=True
    )["c"]
    # 仅真孤儿被删，命中 task-1 finding 的 spec 必须保留（D1 重放目标不能丢）
    assert remain == 1, f"task-4 应仅保留 1 条 spec，实际剩余 {remain}"
    kept = db.execute(
        "SELECT vulnerability_hash_v2 FROM trigger_specs WHERE task_id=?", (task_id,), fetchone=True
    )
    assert kept["vulnerability_hash_v2"] == vhash_kept, f"应保留命中 task-1 finding 的 spec，实际 {kept}"
    # task-1 的 spec（若有）不受影响——此处 task-1 无 spec，校验跨 task 不误删
    t1_specs = db.execute(
        "SELECT count(*) c FROM trigger_specs WHERE task_id=?", (task1,), fetchone=True
    )["c"]
    assert t1_specs == 0


def test_a2_blanked_param_backfilled_into_raw_json_entry():
    """集成回归锁：A2 抹空 entry 参数字段后，登记期必须用 resolve_endpoint_full
    的权威解析结果回写 raw_json.exploit_spec.entry，使其与 trigger_specs 的
    param_name / param_location 列恒一致（jsc 622 spec 238032/238042/238072 实证）。

    通道 A（DB 列）由 resolve_endpoint_full 解析，D1 重放真正消费它；通道 B（raw_json.entry）
    此前只回写 route，A2 的 ssrf/idor 分支（benchmark_cli 2549-2557 / 2621-2629）把
    parameter_name/location 抹成空串后便一直悬空，导致报告/对账层读到空参数、与 D1 实际
    投放位置漂移。修复点在 trigger_spec_registry 1401-1425：回写 route 时同步补齐两个参数字段。

    夹具关键：a1_evidence.rule='mybatis_dollar_substitution' 走 resolve_endpoint_full 884-897
    的权威覆盖路径，把参数名无条件覆盖为 'userId'；entry 里保留一个非空的脏值 'oldName'
    （A2 entry 参数名一旦被抹空，core resolver 会把整条 entry 判无效、连 route 一并丢弃，
    直接被登记门 skip，反而走不到回写），这样既能解析出非空 route 跨过注册门，又制造了
    「DB 列=userId / entry 初始=oldName」的严格对照，专测回写是否把 entry 覆盖为权威值。
    """
    import json
    import tempfile

    tmp = tempfile.mkdtemp()
    db, workspace_id, task_id = _seed(tmp, target_path="")  # 空 code_root，跳过源码门禁，靠 A2 entry 兜底
    vuln = _sql_vuln(route="/api/user", param_name="oldName")  # 非空脏值：保证 route 可解析
    entry = vuln.to_dict()["exploit_spec"]["entry"]
    entry["parameter_location"] = ""      # 模拟 A2 ssrf/idor 分支抹空 location（回写应补 'query'）
    vuln.to_dict()["a1_evidence"] = {      # 强制 resolver 把参数名覆盖为权威值 'userId'
        "rule": "mybatis_dollar_substitution",
        "param": "userId",
    }

    funnel = auto_register_from_a2(task_id, [_ScanResult([vuln])])
    registered = funnel.get("registered", 0)
    skipped = funnel.get("skipped", 0)
    assert registered == 1, f"应登记 1 条，实际 registered={registered}, skipped={skipped}"

    row = db.execute(
        "SELECT param_name, param_location, raw_json FROM trigger_specs WHERE workspace_id=?",
        (workspace_id,), fetchone=True,
    )
    assert row is not None
    assert row["param_name"] == "userId", "通道 A：DB 列应为 resolver 解析出的权威参数名"
    rj = json.loads(row["raw_json"] or "{}")
    rj_entry = (rj.get("exploit_spec") or {}).get("entry") or {}
    # 修复前 rj_entry['parameter_name'] 停留在 A2 的脏值 'oldName'、location 停留在 ''，
    # 与 DB 列 'userId'/'query' 漂移；修复后必须被回写为权威值。
    assert rj_entry.get("parameter_name") == row["param_name"] == "userId", (
        "通道 B：raw_json.entry.parameter_name 必须回写覆盖脏值、与 DB 列一致"
    )
    assert rj_entry.get("parameter_location") == row["param_location"] == "query", (
        "通道 B：raw_json.entry.parameter_location 必须回写、与 DB 列一致"
    )
    assert rj_entry.get("route") == "/api/user"
