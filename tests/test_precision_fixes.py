"""F4 后精确率五点整改回归测试（2026-09-26）。

覆盖：①族名归一（benchmark 靶场实测分裂写法收敛）；②安全实现负向模式；
③D2 注入族离线裁决收紧（降级攻击不再直升 confirmed_attributable）；
④攻击计划过滤闸门辅助函数；⑤黑板分级输出（suspicious/provisional 档）。
"""
from datetime import datetime
from types import SimpleNamespace

from src.core.normalize import normalize_family, is_known_family
from src.core.safe_patterns import safe_implementation_hit, filter_vulnerabilities
from src.core.blackboard import sync_blackboard, derive_counts
from src.iast.adjudicator import I2Adjudicator, FINAL_AMBIGUOUS, FINAL_CONFIRMED_ATTRIBUTABLE
from src.infrastructure.db import Database


# ---------------------------------------------------------------------------
# ① 族名归一
# ---------------------------------------------------------------------------
def test_family_norm_benchmark_split_names():
    # run 10 实测同族多写法 → 必须收敛到单一规范键
    assert normalize_family("弱哈希算法") == "weak_hash"
    assert normalize_family("weak-hash") == "weak_hash"
    assert normalize_family("不安全加密算法") == "weak_crypto"
    assert normalize_family("加密算法使用不当") == "weak_crypto"
    assert normalize_family("弱随机数") == "weak_random"
    assert normalize_family("weak-random-number-generation") == "weak_random"
    assert normalize_family("弱随机数生成") == "weak_random"
    assert normalize_family("信任边界违背") == "trust_boundary_violation"
    assert normalize_family("cookie 安全属性缺失") == "secure_cookie"
    assert normalize_family("cookie-security-configuration") == "secure_cookie"
    assert normalize_family("LDAP注入") == "ldap_injection"
    assert normalize_family("敏感数据存储") == "sensitive_data_exposure"
    assert normalize_family("未授权接口泄露") == "sensitive_data_exposure"


def test_is_known_family_gate():
    assert is_known_family("sql_injection")
    assert is_known_family("弱随机数")
    assert not is_known_family("完全不认识的族名XYZ")
    assert not is_known_family("")


# ---------------------------------------------------------------------------
# ② 安全实现负向模式
# ---------------------------------------------------------------------------
def _v(type_, snippet, file="", line=None):
    return SimpleNamespace(type=type_, file=file, line=line, code_snippet=snippet)


def test_safe_pattern_sqli_prepared_statement():
    safe = (
        "String query = \"SELECT * FROM users WHERE id = ?\";\n"
        "PreparedStatement ps = con.prepareStatement(query);\n"
        "ps.setString(1, request.getParameter(\"id\"));\n"
        "ResultSet rs = ps.executeQuery();\n"
    )
    assert safe_implementation_hit("sql_injection", snippet=safe) == "prepared_statement_bound"
    # 不安全：拼接 SQL
    unsafe = (
        "String query = \"SELECT * FROM users WHERE id = '\" + request.getParameter(\"id\") + \"'\";\n"
        "Statement st = con.createStatement();\n"
        "ResultSet rs = st.executeQuery(query);\n"
    )
    assert safe_implementation_hit("sql_injection", snippet=unsafe) is None


def test_safe_pattern_xss_encoder():
    assert safe_implementation_hit("xss", snippet="out.println(Encode.forHtml(param));") == "encoder_present"
    assert safe_implementation_hit("xss", snippet="out.println(param);") is None


def test_safe_pattern_weak_random():
    assert safe_implementation_hit("weak_random", snippet="SecureRandom sr = new SecureRandom(); int v = sr.nextInt();") == "secure_random_only"
    # SecureRandom 与不安全 Random 共存 → 负向规则拦下，不抑制
    mixed = "SecureRandom sr = new SecureRandom(); Random r = new Random();"
    assert safe_implementation_hit("weak_random", snippet=mixed) is None


def test_safe_pattern_weak_hash_strong_only():
    assert safe_implementation_hit("weak_hash", snippet="MessageDigest md = MessageDigest.getInstance(\"SHA-256\");") is not None
    assert safe_implementation_hit("weak_hash", snippet="MessageDigest md = MessageDigest.getInstance(\"MD5\");") is None


def test_safe_pattern_secure_cookie_needs_both():
    both = "cookie.setHttpOnly(true); cookie.setSecure(true);"
    only_one = "cookie.setHttpOnly(true);"
    assert safe_implementation_hit("secure_cookie", snippet=both) is not None
    assert safe_implementation_hit("secure_cookie", snippet=only_one) is None


def test_safe_pattern_fail_open_without_evidence():
    # 无 snippet 且文件读不到 → 不抑制（保召回）
    assert safe_implementation_hit("xss", file_path="/nonexistent/NoFile.java", line=10) is None


def test_filter_vulnerabilities_reports_suppressed():
    vulns = [
        _v("xss", "out.println(Encode.forHtml(p));"),
        _v("xss", "out.println(p);"),
    ]
    kept, suppressed = filter_vulnerabilities(vulns)
    assert len(kept) == 1
    assert len(suppressed) == 1
    assert suppressed[0]["rule"] == "encoder_present"


# ---------------------------------------------------------------------------
# ③ D2 收紧：注入族降级攻击不再直升确认
# ---------------------------------------------------------------------------
def test_injection_degraded_no_sink_not_confirmed():
    res = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": "no-arrival", "confidence": "low"},
        dast_impact_evidence={"impact_observed": True, "attack_degraded": True},
        d2_verdict={},
        family="sql_injection",
    )
    assert res["final_state"] == FINAL_AMBIGUOUS, res
    assert res["confirmed"] is False


def test_injection_real_payload_impact_still_confirmed():
    res = I2Adjudicator.adjudicate_final_state(
        iast_evidence={"state": "no-arrival", "confidence": "low"},
        dast_impact_evidence={"impact_observed": True, "attack_degraded": False},
        d2_verdict={},
        family="sql_injection",
    )
    assert res["final_state"] == FINAL_CONFIRMED_ATTRIBUTABLE, res
    assert res["confirmed"] is True


# ---------------------------------------------------------------------------
# ⑤ 黑板分级输出
# ---------------------------------------------------------------------------
def _now():
    return datetime.utcnow().isoformat()


def test_derive_counts_tiers(tmp_path):
    db = Database(str(tmp_path / "app.db"))
    ws, task, run = 3, 911, 911
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, created_at, updated_at) VALUES (?, 'ws', '/p', ?, ?)",
        (ws, _now(), _now()),
    )
    db.execute(
        "INSERT INTO scan_tasks (id, workspace_id, name, status, phase, output_dir, created_at) "
        "VALUES (?, ?, 't', 'completed', 'done', '/o', ?)",
        (task, ws, _now()),
    )
    db.execute(
        "INSERT INTO scan_runs (id, workspace_id, task_id, round_no, code_fingerprint, git_revision, "
        "key_files_json, options_json, metrics_json, status, started_at, finished_at, created_at) "
        "VALUES (?, ?, ?, 1, 'fp', '', '[]', '{}', '{}', 'completed', ?, ?, ?)",
        (run, ws, task, _now(), _now(), _now()),
    )
    db.execute("UPDATE scan_tasks SET run_id=? WHERE id=?", (run, task))
    for v in ("F1", "F2", "F3"):
        db.execute(
            "INSERT INTO findings (task_id, workspace_id, finding_type, severity, file_path, title, raw_json, created_at, vulnerability_hash_v2) "
            "VALUES (?, ?, 'sast', 'high', '/x', 'f', '{}', ?, ?)",
            (task, ws, _now(), v),
        )
    for vh, verif in (("V1", "confirmed_exploitable"), ("V2", "no_evidence"), ("V3", "provisional")):
        db.execute(
            "INSERT INTO trigger_specs (task_id, workspace_id, vulnerability_hash_v2, family, target_endpoint, "
            "http_method, verification_status, iast_state, taint_marker, created_at) "
            "VALUES (?, ?, ?, 'sqli', '/e', 'GET', ?, '', '', ?)",
            (task, ws, vh, verif, _now()),
        )
    sync_blackboard(db, task, run)
    d = derive_counts(db, task, run)
    # detected = F1..F3 + V1..V3 = 6；confirmed 仅 V1；suspicious = 5；provisional = 1
    assert d["detected"] == 6, d
    assert d["confirmed"] == 1, d
    assert d["suspicious"] == 5, d
    assert d["provisional"] == 1, d
