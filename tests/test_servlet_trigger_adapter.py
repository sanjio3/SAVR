"""benchmark Servlet 触发器适配器（Layer 2）单测。

覆盖：路由解析（signature→route）、类别映射（finding type→benchmark 前缀）、
污点源参数抽取（query/header/cookie）、servlet 索引构建、端到端登记 +
stable_vuln_key 反查命中、多轮重试去重守卫、非 benchmark 靶场 noop。

不碰真实网络与真实靶场路径：servlet 源码用临时文件合成，DB 用临时文件库。
"""
import os
import tempfile
from pathlib import Path

from src.benchmark.servlet_trigger_adapter import (
    _route_from_signature,
    benchmark_category_for_route,
    build_benchmark_trigger_specs,
    build_servlet_index,
    category_for_finding_type,
    extract_servlet_taint_param,
)
from src.core.vuln_hash import stable_vuln_keys
from src.iast.service import IastService
from src.infrastructure.db import Database

_DB_COUNTER = [0]


def _db():
    # Database.execute 每次开新连接，:memory: 无法跨连接持久化，故用临时文件库。
    # 返回 (db, path)：path 供 monkeypatch SAST_AI_DB_PATH —— load_trigger_specs_by_workspace
    # 按该环境变量自建连接，不跟随传入的 db 实例。
    _DB_COUNTER[0] += 1
    path = os.path.join(tempfile.gettempdir(), f"savr_bench_adapter_{os.getpid()}_{_DB_COUNTER[0]}.db")
    if os.path.exists(path):
        os.remove(path)
    return Database(path), path


def _setup_ws_and_session(db, workspace_id=5, session_id=1):
    db.execute(
        "INSERT INTO workspaces (id, name, target_path, description, settings_json, created_at, updated_at) "
        "VALUES (?, 'owasp-benchmark-sample', 'x', '', '{}', datetime('now'), datetime('now'))",
        (workspace_id,),
    )
    db.execute(
        "INSERT INTO iast_sessions (id, workspace_id, target_url, app_name, agent_id, probe_token, status, "
        "registered_at, updated_at) VALUES (?, ?, 'http://127.0.0.1:8443/benchmark', 'benchmark', "
        "'owasp-benchmark-sample', 'tok', 'ready', datetime('now'), datetime('now'))",
        (session_id, workspace_id),
    )


# ---------- 路由解析 ----------

def test_route_from_signature_webservlet():
    assert _route_from_signature('@WebServlet(value = "/sqli-00/BenchmarkTest00008")') == "/sqli-00/BenchmarkTest00008"


def test_route_from_signature_bare_and_urlpatterns():
    assert _route_from_signature('@WebServlet("/xss-00/BenchmarkTest00153")') == "/xss-00/BenchmarkTest00153"
    assert _route_from_signature('@WebServlet(urlPatterns = "/cmdi-00/BenchmarkTest00090")') == "/cmdi-00/BenchmarkTest00090"


def test_route_from_signature_name_first_still_finds_route():
    # name 在前时首个引号串不是路由，须跳过取以 / 开头的那个
    sig = '@WebServlet(name = "foo", value = "/sqli-00/BenchmarkTest00039")'
    assert _route_from_signature(sig) == "/sqli-00/BenchmarkTest00039"


# ---------- 类别映射 ----------

def test_category_for_route():
    assert benchmark_category_for_route("/sqli-00/BenchmarkTest00008") == "sqli"
    assert benchmark_category_for_route("/xss-02/BenchmarkTest00153") == "xss"
    assert benchmark_category_for_route("/weakrand-06/BenchmarkTest02740") == "weakrand"


def test_category_for_route_non_benchmark_returns_none():
    assert benchmark_category_for_route("/api/users") is None
    assert benchmark_category_for_route("") is None


def test_category_for_finding_type_all_main_families():
    cases = {
        "SQL 注入": "sqli", "xss": "xss", "command_execution": "cmdi",
        "path_traversal": "pathtraver", "不安全加密算法": "crypto", "弱哈希算法": "hash",
        "弱随机数": "weakrand", "cookie 安全属性缺失": "securecookie", "信任边界违背": "trustbound",
    }
    for t, cat in cases.items():
        assert category_for_finding_type(t) == cat, t


# ---------- 污点源参数抽取 ----------

def _write_servlet(tmpdir, class_name, body):
    p = Path(tmpdir) / f"{class_name}.java"
    p.write_text(body, encoding="utf-8")
    return p


def test_extract_param_query_same_as_class_name(tmp_path):
    cls = "BenchmarkTest00042"
    p = _write_servlet(tmp_path, cls, f"public void doPost(...) {{ String param = request.getParameter(\"{cls}\"); }}")
    name, loc = extract_servlet_taint_param(p, cls)
    assert (name, loc) == (cls, "query")


def test_extract_param_header(tmp_path):
    cls = "BenchmarkTest00008"
    p = _write_servlet(tmp_path, cls, f'String param = request.getHeader("{cls}");')
    name, loc = extract_servlet_taint_param(p, cls)
    assert (name, loc) == (cls, "header")


def test_extract_param_cookie(tmp_path):
    cls = "BenchmarkTest00090"
    p = _write_servlet(tmp_path, cls, f'Cookie c = getCookieValue("{cls}", "none");')
    name, loc = extract_servlet_taint_param(p, cls)
    assert (name, loc) == (cls, "cookie")


def test_extract_param_fallback_first_read(tmp_path):
    # 没有与类名同名的参数时退化取首个（如 Referer 头）
    cls = "BenchmarkTest00153"
    p = _write_servlet(tmp_path, cls, 'String param = request.getHeader("Referer");')
    name, loc = extract_servlet_taint_param(p, cls)
    assert (name, loc) == ("Referer", "header")


# ---------- servlet 索引 ----------

def test_build_servlet_index_from_signatures():
    routes = [
        {"entry_type": "web_route", "file": "org/owasp/benchmark/testcode/BenchmarkTest00008.java",
         "signature": '@WebServlet(value = "/sqli-00/BenchmarkTest00008")'},
        {"entry_type": "web_route", "file": "org/owasp/benchmark/testcode/BenchmarkTest00153.java",
         "signature": '@WebServlet(value = "/xss-00/BenchmarkTest00153")'},
        {"entry_type": "web_route", "file": "org/owasp/benchmark/service/X.java",
         "signature": '@GetMapping("/api/x")'},
    ]
    idx = build_servlet_index(routes)
    assert set(idx.keys()) == {"sqli", "xss"}
    assert idx["sqli"][0]["route"] == "/sqli-00/BenchmarkTest00008"


# ---------- 端到端登记 + 反查 ----------

_SERVLETS = [
    {"entry_type": "web_route", "file": "org/owasp/benchmark/testcode/BenchmarkTest00008.java",
     "signature": '@WebServlet(value = "/sqli-00/BenchmarkTest00008")'},
    {"entry_type": "web_route", "file": "org/owasp/benchmark/testcode/BenchmarkTest00028.java",
     "signature": '@WebServlet(value = "/pathtraver-00/BenchmarkTest00028")'},
    {"entry_type": "web_route", "file": "org/owasp/benchmark/testcode/BenchmarkTest00153.java",
     "signature": '@WebServlet(value = "/xss-00/BenchmarkTest00153")'},
]


def _mk_vuln(vtype, fname, line):
    return {"type": vtype, "file": fname, "line": line, "title": "t", "code": "x", "callers": "", "source": "A1"}


def test_end_to_end_register_and_stable_key_match(tmp_path, monkeypatch):
    # 合成 servlet 源文件供参数抽取
    (tmp_path / "org" / "owasp" / "benchmark" / "testcode").mkdir(parents=True)
    code_root = str(tmp_path)
    for f in _SERVLETS:
        Path(code_root, f["file"]).write_text(
            f'String param = request.getParameter("{Path(f["file"]).stem}");', encoding="utf-8")

    db, db_path = _db()
    _setup_ws_and_session(db)
    svc = IastService(db)
    vulns = [
        _mk_vuln("SQL 注入", "src/helpers/DatabaseHelper.java", 125),
        _mk_vuln("path_traversal", "src/helpers/Utils.java", 77),
        _mk_vuln("xss", "src/helpers/Utils.java", 210),
        # 无对应 servlet 类别 → 跳过
        _mk_vuln("xxe", "src/helpers/XXEHelper.java", 33),
    ]
    out = build_benchmark_trigger_specs(
        a1_vulns=vulns, discovered_routes=_SERVLETS, code_root=code_root,
        task_id=99, workspace_id=5, session_id=1, iast_service=svc)
    assert out["applied"] is True
    assert out["registered"] == 3
    assert out["skipped_no_servlet"] == 1
    assert out["by_category"] == {"sqli": 1, "pathtraver": 1, "xss": 1}

    # spec 内容：路由（非注解原文）、参数名、位置
    rows = db.execute("SELECT target_endpoint, http_method, param_name, param_location FROM trigger_specs", fetchall=True)
    eps = {r["target_endpoint"] for r in rows}
    assert eps == {"/sqli-00/BenchmarkTest00008", "/pathtraver-00/BenchmarkTest00028", "/xss-00/BenchmarkTest00153"}
    assert all(r["http_method"] == "GET" for r in rows)
    assert all(r["param_name"].startswith("BenchmarkTest") for r in rows)

    # stable_vuln_key 反查命中（与 D2 verify 同一口径）
    from src.iast.trigger_spec_registry import load_trigger_specs_by_workspace
    from src.cli.benchmark_cli import build_trigger_spec_assoc_index
    monkeypatch.setenv("SAST_AI_DB_PATH", db_path)
    assoc = build_trigger_spec_assoc_index(load_trigger_specs_by_workspace(5, task_id=99))
    for v in vulns[:3]:
        assert any(assoc.get(k) for k in stable_vuln_keys(v)), v
    # xxe 无 servlet → 不命中
    assert not any(assoc.get(k) for k in stable_vuln_keys(vulns[3]))


def test_dedup_guard_on_rerun(tmp_path):
    db, db_path = _db()
    _setup_ws_and_session(db)
    svc = IastService(db)
    vulns = [_mk_vuln("xss", "src/helpers/Utils.java", 210)]
    first = build_benchmark_trigger_specs(
        a1_vulns=vulns, discovered_routes=_SERVLETS, code_root=str(tmp_path),
        task_id=7, workspace_id=5, session_id=1, iast_service=svc)
    assert first["registered"] == 1
    second = build_benchmark_trigger_specs(
        a1_vulns=vulns, discovered_routes=_SERVLETS, code_root=str(tmp_path),
        task_id=7, workspace_id=5, session_id=1, iast_service=svc)
    assert second["registered"] == 0
    assert second.get("already_registered", 0) == 1
    cnt = db.execute("SELECT COUNT(*) c FROM trigger_specs WHERE task_id=7", fetchone=True)["c"]
    assert cnt == 1


def test_rep_params_always_carries_case_name_candidate():
    """2026-10-14 更新（r89 实测根因 A）：用例名一律在 query / cookie / header 三个候选位置各注入一次。

    原实现只在 ``class_name != param_name`` 时追加用例名 query 候选；当位置推断错、且抽到的名字
    恰是类名时（如 BenchmarkTest00023 被误判 cookie），去重会**跳过 query 候选** ⇒ canary 只投
    cookie、servlet 却从 query 读 ⇒ 零命中。改为多位置注入，消除对单点位置推断的依赖。
    同时保留抽到的参数（Referer 类用例 00013/00144 靠它，不能替换）。
    """
    from src.benchmark.servlet_trigger_adapter import _rep_params_with_case_name

    # 抽对了（== 类名）→ 用例名仍在 query / cookie / header 三处（消除位置依赖）
    p = _rep_params_with_case_name("BenchmarkTest00013", "query", "CAN", "BenchmarkTest00013")
    assert sorted(e["location"] for e in p if e["name"] == "BenchmarkTest00013") == \
        ["cookie", "header", "query"]

    # 抽错了（'param'）→ 原参数保留，且用例名三处候选
    p = _rep_params_with_case_name("param", "query", "CAN", "BenchmarkTest00047")
    assert {"name": "param", "location": "query", "value": "CAN"} in p
    assert {"name": "BenchmarkTest00047", "location": "query", "value": "CAN"} in p
    assert {"name": "BenchmarkTest00047", "location": "cookie", "value": "CAN"} in p
    assert {"name": "BenchmarkTest00047", "location": "header", "value": "CAN"} in p

    # Referer header 用例 → header 原样保留，同时用例名三处候选
    p2 = _rep_params_with_case_name("Referer", "header", "CAN", "BenchmarkTest00144")
    assert {"name": "Referer", "location": "header", "value": "CAN"} in p2
    assert {"name": "BenchmarkTest00144", "location": "query", "value": "CAN"} in p2


def test_registered_spec_carries_case_name_param(tmp_path):
    """端到端：登记进库的 spec，其注入参数候选里必须有用例名。"""
    import json as _json
    import re as _re
    db, _ = _db()
    _setup_ws_and_session(db)
    out = build_benchmark_trigger_specs(
        a1_vulns=[_mk_vuln("xss", "src/helpers/Utils.java", 210)],
        discovered_routes=_SERVLETS, code_root=str(tmp_path),
        task_id=11, workspace_id=5, session_id=1, iast_service=IastService(db))
    assert out["registered"] == 1
    row = db.execute(
        "SELECT target_endpoint, param_name, representative_request_params_json "
        "FROM trigger_specs WHERE task_id=11", fetchone=True)
    ep = str(row["target_endpoint"])
    m = _re.search(r"BenchmarkTest\d+", ep)
    assert m, f"路由里取不到用例名：{ep}"
    case = m.group(0)
    params = _json.loads(row["representative_request_params_json"] or "[]")
    names = {p.get("name") for p in params}
    assert params, "注入参数候选不能为空"
    assert case in names, f"用例名 {case} 未出现在候选参数里：{names}"
    assert row["param_name"] in names, f"原参数 {row['param_name']} 被弄丢了：{names}"


def test_noop_for_non_benchmark_routes(tmp_path):
    db, _ = _db()
    _setup_ws_and_session(db)
    out = build_benchmark_trigger_specs(
        a1_vulns=[_mk_vuln("xss", "a.java", 1)],
        discovered_routes=[{"entry_type": "web_route", "signature": '@GetMapping("/api/x")'}],
        code_root=str(tmp_path), task_id=8, workspace_id=5, session_id=1,
        iast_service=IastService(db))
    assert out["applied"] is False
    assert out["registered"] == 0
