from src.core.vuln_hash import (
    canonicalize_vuln_for_hash,
    enrich_finding_hash,
    vulnerability_hash_v2,
    _looks_like_code_location,
    _norm_family,
)


# ---------------------------------------------------------------------------
# 族名归一的「子串误命中」回归守卫（2026-09-10）
# 背景：模板层 XSS 的 sink 含 src/main/resources/templates/*.html，其中 "resources"
# 含子串 "rce"，而 command-execution 规则排在 xss 之前 → 每轮 3 条模板 XSS 被错归
# command-execution（spec 仍登记、仍 confirmed，但按命令注入判据验证且族计数错位）。
# 修法：短 ASCII token（rce/sql/path/exec/sca/...）改为词边界匹配。
# ---------------------------------------------------------------------------

def test_template_xss_with_resources_path_is_not_command_execution():
    """resources 里的 rce 子串不得把模板层 XSS 打成 command-execution。"""
    item = {
        "type": "Reflected XSS",
        "sink": r"template:D:\proj\src\main\resources\templates\products.html:15 th:utext",
        "description": "请求参数 keyword 经 Controller 直传到 th:utext 非转义输出",
        "file": r"D:\proj\src\main\java\com\x\web\ProductController.java",
    }
    assert _norm_family(item) == "xss"


def test_real_command_injection_still_classified():
    """真命令注入不受词边界收紧影响。"""
    for item in (
        {"type": "Command Injection", "sink": "Runtime.getRuntime().exec(cmd)"},
        {"type": "远程命令执行", "description": "服务端拼接系统命令后执行"},
        {"type": "RCE", "sink": "ProcessBuilder"},
    ):
        assert _norm_family(item) == "command-execution"


def test_mysql_does_not_fall_into_sql_injection():
    """mysql 里的 sql 子串不得把非注入类打成 sql-injection。"""
    item = {"type": "安全配置错误", "sink": "jdbc:mysql://127.0.0.1:3306/mall"}
    assert _norm_family(item) != "sql-injection"


def test_classpath_does_not_fall_into_path_traversal():
    """classpath 里的 path 子串不得误判路径穿越。"""
    item = {"type": "信息泄露", "sink": "classpath:application.properties"}
    assert _norm_family(item) != "path-traversal"


def test_escalation_does_not_fall_into_sca():
    """escalation 里的 sca 子串不得误判 SCA。"""
    item = {"type": "privilege-escalation", "sink": "/admin/users"}
    assert _norm_family(item) != "sca"


def test_mybatis_executor_does_not_fall_into_command_execution():
    """MyBatis Executor 里的 exec 子串不得把 SQL 注入打成 command-execution。"""
    item = {"type": "SQL Injection", "sink": "org.apache.ibatis.executor.Executor.query"}
    assert _norm_family(item) == "sql-injection"


def test_vulnerability_hash_stable_against_line_and_description_changes():
    base = {
        "type": "Command Injection",
        "file": "app/controllers/debug.py",
        "line": 10,
        "entry_point": "request.args['cmd']",
        "sink": "subprocess.run",
        "code_snippet": "subprocess.run(cmd, shell=True)",
        "description": "model one wording",
    }
    changed = dict(base, line=99, description="another model wording")
    assert vulnerability_hash_v2(base) == vulnerability_hash_v2(changed)


def test_sca_hash_uses_component_and_advisory():
    item = enrich_finding_hash({
        "type": "SCA",
        "sca": {
            "component_name": "demo-lib",
            "component_version": "1.0.0",
            "ecosystem": "PyPI",
            "vulnerability_id": "GHSA-1234",
        },
    })
    assert item["hash_components"]["family"] == "sca"
    assert item["vulnerability_hash_v2"]


# ---------------------------------------------------------------------------
# source 组件的「代码定位」形态守卫（2026-09-21）
# 背景：hash 的 source 组件语义是「代码定位（文件:行）」，取值链 entry_point -> source
# -> trigger_route。而 A1 静态通道把检测器身份写进了 source（'a1-injection-heuristic'、
# 另有 'a1'/'a2'）。同一条漏洞于是分叉：
#   spec 侧（raw A2 dict，带 source）      source 组件 = 'a1-injection-heuristic'
#   finding 侧（report_manager dict，无 source 字段） source 组件 = ''
# 两侧 vhash 不等，spec 与 finding 永远关联不上（假孤儿）。实测 run 26 CVE-2022-22978
# 的 finding 与它自己的 spec 逐组件比对，唯一差异就是这个字段。
# 修法：source 只在「确为定位形态」时采信，检测器身份串不计入。
# ---------------------------------------------------------------------------

def test_detector_identity_source_does_not_change_hash():
    """spec 侧带检测器身份 source，finding 侧无 source —— 两侧必须同 hash（假孤儿回归守卫）。"""
    finding_side = {
        "type": "CVE-2022-22978",
        "file": "src/main/java/org/joychou/security/WebSecurityConfig.java",
        "line": 79,
        "entry_point": "",
        "sink": "Spring regexMatchers 授权绕过(CVE-2022-22978)",
    }
    spec_side = dict(finding_side, source="a1-injection-heuristic")
    assert vulnerability_hash_v2(canonicalize_vuln_for_hash(finding_side)) == \
        vulnerability_hash_v2(canonicalize_vuln_for_hash(spec_side))


def test_a2_detector_source_does_not_change_hash():
    """'a2' 同为检测器身份，不得进入 hash。"""
    base = {"type": "SQL Injection", "file": "a/b/UserMapper.java", "line": 22,
            "entry_point": "", "sink": "jdbcTemplate.query"}
    assert vulnerability_hash_v2(canonicalize_vuln_for_hash(base)) == \
        vulnerability_hash_v2(canonicalize_vuln_for_hash(dict(base, source="a2")))


def test_real_code_location_source_still_participates_in_hash():
    """真正的定位串仍须参与 hash（守卫不得把语义一起丢掉）。"""
    base = {"type": "SQL Injection", "file": "a/b/UserMapper.java", "line": 22,
            "entry_point": "", "sink": "jdbcTemplate.query"}
    assert vulnerability_hash_v2(canonicalize_vuln_for_hash(dict(base, source="UserMapper.java:22"))) != \
        vulnerability_hash_v2(canonicalize_vuln_for_hash(base))


def test_looks_like_code_location_directions():
    """形态判据方向：检测器身份/中文标签为 False，路径与 file:line 为 True。"""
    for value in ("a1-injection-heuristic", "a1", "a2", "codeql", "semgrep", "注入类离线兜底分析器", ""):
        assert not _looks_like_code_location(value), value
    for value in ("OrderService.java:118", "src/main/java/X.java", "WebSecurityConfig.java",
                  r"src\main\java\X.java", "app/controllers/debug.py"):
        assert _looks_like_code_location(value), value


# ---------------------------------------------------------------------------
# HTTP 路径（route）永不进入身份 hash（2026-09-21，任务③）
# 背景：_pick("target_endpoint","endpoint","route","http_path", _es_route) 曾把 _es_route 当位置
# 参数误传，使 exploit_spec.entry.route 永不生效（latent 陷阱）。用户指令要求 route 永不进入 hash：
# 历史 route 进 hash 因「通道 A/B 漂移」「plan_pocs 改写 entry.route」反复制造假孤儿误删 81 条真 POC。
# 修复：route_v 显式归零。回归守卫：route 字段（含 exploit_spec.entry.route）不得改变 vhash，
# 且 hash_components.route 恒为 ''。
# ---------------------------------------------------------------------------

def test_exploit_spec_entry_route_never_enters_hash():
    """exploit_spec.entry.route 存在与否不得改变 vhash，且 hash_components.route 恒空。"""
    base = {"type": "SQL Injection", "file": "a/b/UserMapper.java", "line": 22, "sink": "jdbcTemplate.query"}
    with_route = dict(base, exploit_spec={"entry": {"route": "/sqli/jdbc/vuln", "method": "GET"}})
    assert vulnerability_hash_v2(canonicalize_vuln_for_hash(base)) == \
        vulnerability_hash_v2(canonicalize_vuln_for_hash(with_route))
    comp = canonicalize_vuln_for_hash(with_route)
    assert comp["route"] == ""
    for alias in ("entry_route", "trigger_route", "target_endpoint", "endpoint", "route", "http_path"):
        assert comp[alias] == ""


def test_top_level_route_fields_never_enter_hash():
    """target_endpoint/endpoint/route/http_path 顶层字段也不得进入 hash（与 spec/finding 两侧对齐）。"""
    base = {"type": "SQL Injection", "file": "a/b/UserMapper.java", "line": 22, "sink": "jdbcTemplate.query"}
    decorated = dict(base, target_endpoint="/sqli", endpoint="/sqli", route="/sqli", http_path="/sqli")
    assert vulnerability_hash_v2(canonicalize_vuln_for_hash(base)) == \
        vulnerability_hash_v2(canonicalize_vuln_for_hash(decorated))


def test_spec_and_finding_route_drift_do_not_mismatch():
    """spec 侧 entry.route=/black_path 与 finding 侧 target_endpoint=/cors 须同 hash（route 不进 hash）。"""
    spec_side = {
        "type": "CVE-2022-22978",
        "file": "src/main/java/org/joychou/security/WebSecurityConfig.java",
        "line": 79,
        "sink": "Spring regexMatchers 授权绕过(CVE-2022-22978)",
        "exploit_spec": {"entry": {"route": "/black_path"}},
    }
    finding_side = {
        "type": "CVE-2022-22978",
        "file": "src/main/java/org/joychou/security/WebSecurityConfig.java",
        "line": 79,
        "sink": "Spring regexMatchers 授权绕过(CVE-2022-22978)",
        "target_endpoint": "/cors",
    }
    assert vulnerability_hash_v2(canonicalize_vuln_for_hash(spec_side)) == \
        vulnerability_hash_v2(canonicalize_vuln_for_hash(finding_side))
