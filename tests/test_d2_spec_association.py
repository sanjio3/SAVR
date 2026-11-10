"""D2 关联键加固回归守卫：钉死关联键 stable_vuln_key（route 漂移免疫）。

根因（历史轮次 终态复盘）：D2 把 trigger_spec 与运行时 vuln 关联的键是易变的
vulnerability_hash_v2，而该 hash 把 exploit_spec.entry.route 纳入了组件；_pre_resolve_a2_endpoints
改写 entry.route、plan_pocs 也可能以 LLM 产出覆盖之，导致「注册端」与「验证端」消费同一份
a2_results 时 entry.route 漂移 —— runtime_vhash != stored_vhash，trigger_spec 在表里却按 runtime_vhash
反查不到，Phase2 写回落空，表现为 10 条 trigger_spec 的 verification_status 永远为空（既不 confirmed
也不 unconfirmed，是「没跑」而非「未确认」）。

修复：关联键改用 route-漂移免疫的 stable_vuln_key（归一时强制置空全部 route 视图），vhash 仅兜底。
本文件把「10 条空状态 spec」变成可复现的通过用例：
  - 单测（无 DB）：构造 route 漂移后，断言 stable 主键命中、旧 vhash 主键落空；
  - 单测（内存库夹具）：用内存 SQLite 构造同样的空状态样本，断言全部 spec 仍能被其 vuln 命中。
原第二例读 data/app.db 的历史扫描产物，清库后夹具永久失效、只会 skip；改为内存夹具后，
断言的是当前行为，干净 clone 无数据库也能跑。
"""
import os
import sys
import json
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.vuln_hash import (
    stable_vuln_key,
    vulnerability_hash_v2,
    canonicalize_vuln_for_hash,
)
from src.cli.benchmark_cli import (
    build_trigger_spec_assoc_index,
    match_trigger_specs_for_vuln,
    _d2_gate_predicate,
)


def _make_spec(spec_id, vhash, target_endpoint, raw_json):
    return {
        "id": spec_id,
        "vulnerability_hash_v2": vhash,
        "target_endpoint": target_endpoint,
        "replayable": 1,
        "raw_json": raw_json,
    }


def test_stable_key_immune_to_nonidentity_field_drift_unit():
    """无 DB 单测：stable 主键只认源坐标(file/line/type/code)，免疫 sink/category/entry_point 漂移。

    注：canonicalize_vuln_for_hash（vhash 算法）事实上有个潜在缺陷——_es_route 被当作 _pick 的 default
    传入，route 从未真正进入 vhash；真正让 10 条空 spec 在 vhash 下失配的是 sink/entry_point/category/
    family 等字段在「注册端」与「验证端」之间漂移。stable_vuln_key 只依赖两端必相等的源坐标，故对所有
    此类漂移免疫。本测试用 sink/category 漂移来演示「vhash 失配、stable 仍命中」。
    """
    file_ = "src/main/java/com/sanjio/mall/web/CommentController.java"
    line = 37
    code = "c.setContent(content); // 未转义"
    reg_route = "/comment"

    base = {
        "type": "XSS", "file": file_, "line": line, "code_snippet": code,
        "exploit_spec": {"entry": {"route": reg_route, "method": "POST",
                                   "parameter_name": "content", "parameter_location": "query"}},
        "sink": "xss-sink-a", "entry_point": "com.sanjio.web.CommentController.setContent", "category": "xss",
    }
    spec = _make_spec(1, vulnerability_hash_v2(canonicalize_vuln_for_hash(base)), reg_route, json.dumps(base))

    # 验证端 vuln_payload：源坐标不变，但 route/sink/entry_point/category 全部漂移
    drifted = dict(base)
    drifted["exploit_spec"] = {"entry": {"route": "/drifted/x", "method": "GET",
                                         "parameter_name": "q", "parameter_location": "query"}}
    drifted["sink"] = "other-sink"
    drifted["entry_point"] = "com.sanjio.web.Other.m"
    drifted["category"] = "other"
    vuln = {
        "type": drifted["type"], "file": drifted["file"], "line": drifted["line"],
        "code_snippet": drifted["code_snippet"], "exploit_spec": drifted["exploit_spec"],
        "sink": drifted["sink"], "entry_point": drifted["entry_point"], "category": drifted["category"],
        "a1_evidence": {},
    }
    vuln["vuln_vhash"] = vulnerability_hash_v2(canonicalize_vuln_for_hash(vuln))

    specs_by_hash = {spec["vulnerability_hash_v2"]: [spec]}
    index = build_trigger_spec_assoc_index(specs_by_hash)

    # stable 主键：非源坐标字段漂移后理应仍命中 spec
    matched = match_trigger_specs_for_vuln(vuln, index)
    assert matched and matched[0]["id"] == 1, "stable_key 应免疫非源坐标字段漂移而命中 spec"

    # 反向证明旧的 vhash 主键受 sink/category 漂移影响而失配（这正是 10 条空 spec 的根因）
    assert vuln["vuln_vhash"] != spec["vulnerability_hash_v2"], \
        "vhash 受非源坐标字段漂移影响应失配（复现旧逻辑弱点）"
    assert not any(m["id"] == 1 for m in (specs_by_hash.get(vuln["vuln_vhash"]) or [])), \
        "旧逻辑仅用 vhash 反查时应落空（这正是 10 条空 spec 的根因）"

    # 门禁：vuln 自身 entry.route 为空（漂移后可能被清空），但已登记 spec 有 target_endpoint，
    # 应靠 stable 主键放行进 D2。
    vuln_empty_route = dict(vuln)
    vuln_empty_route["exploit_spec"] = {"entry": {}}
    vuln_empty_route["vuln_vhash"] = vulnerability_hash_v2(canonicalize_vuln_for_hash(vuln_empty_route))
    assert _d2_gate_predicate(vuln_empty_route, index) is True, \
        "门禁应靠 stable 主键命中已登记 spec（target_endpoint 非空）而放行"

    # stable_key 对源坐标变化敏感（非恒定）：改 code_snippet 应改变 key
    other = dict(base)
    other["code_snippet"] = "totally different code snippet"
    assert stable_vuln_key(other) != stable_vuln_key(base), "stable_key 应对源坐标变化敏感（非恒定键）"


def _seed_memory_specs():
    """内存库夹具：构造「空状态 spec」样本，替代已清库的历史扫描产物。"""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute(
        "CREATE TABLE trigger_specs ("
        "id INTEGER, raw_json TEXT, vulnerability_hash_v2 TEXT, "
        "target_endpoint TEXT, verification_status TEXT)"
    )
    samples = (
        ("XSS", "src/main/java/com/example/CommentController.java", 37,
         "c.setContent(content);"),
        ("SQLi", "src/main/java/com/example/UserMapper.java", 88,
         "SELECT * FROM t WHERE id = ${id}"),
        ("SSRF", "src/main/java/com/example/FetchController.java", 12,
         "new URL(url).openStream();"),
    )
    for spec_id, (type_, file_, line, code) in enumerate(samples, start=1):
        raw = {
            "type": type_, "file": file_, "line": line, "code_snippet": code,
            "exploit_spec": {"entry": {"route": "/entry-%d" % spec_id, "method": "POST"}},
            "sink": "sink-%d" % spec_id,
            "entry_point": "com.example.Handler.m%d" % spec_id,
            "category": type_.lower(),
        }
        vhash = vulnerability_hash_v2(canonicalize_vuln_for_hash(raw))
        # 前两条模拟历史「空状态 spec」，第三条是已确认的对照样本。
        status = "" if spec_id <= 2 else "confirmed_exploitable"
        db.execute(
            "INSERT INTO trigger_specs VALUES (?, ?, ?, ?, ?)",
            (spec_id, json.dumps(raw), vhash, "/entry-%d" % spec_id, status),
        )
    rows = db.execute(
        "SELECT id, raw_json, vulnerability_hash_v2, target_endpoint, verification_status "
        "FROM trigger_specs"
    ).fetchall()
    db.close()
    return [dict(row) for row in rows]


def test_empty_specs_all_match_via_stable_key():
    """回归守卫：空状态 spec 必须能被其 vuln 经 stable 主键命中（内存夹具）。

    原用例依赖 data/app.db 里某轮真实产物；清库后永久 skip，等于没有守卫。
    现在断言的是当前行为：route 与 sink/category 漂移后，stable 主键仍全命中，
    而旧的 vhash 主键对空状态样本全部落空。
    """
    spec_dicts = _seed_memory_specs()
    specs_by_hash = {}
    for s in spec_dicts:
        specs_by_hash.setdefault(s["vulnerability_hash_v2"], []).append(s)
    index = build_trigger_spec_assoc_index(specs_by_hash)

    empty_specs = [s for s in spec_dicts if not (s["verification_status"] or "").strip()]
    assert len(empty_specs) == 2, "夹具必须保留空状态样本，否则本守卫失去意义"

    def rebuild_vuln(raw_json):
        raw_d = json.loads(raw_json or "{}")
        es = raw_d.setdefault("exploit_spec", {})
        e = es.setdefault("entry", {})
        e["route"] = "/drifted/or/empty/route-xyz"
        vuln = {
            "type": raw_d.get("type", ""),
            "file": raw_d.get("file", ""),
            "line": raw_d.get("line", 0),
            "code_snippet": raw_d.get("code_snippet", ""),
            "exploit_spec": raw_d.get("exploit_spec", {}),
            "a1_evidence": {},
        }
        vuln["vuln_vhash"] = vulnerability_hash_v2(canonicalize_vuln_for_hash(vuln))
        return vuln

    unmatched = []
    for s in spec_dicts:
        vuln = rebuild_vuln(s["raw_json"])
        matched = match_trigger_specs_for_vuln(vuln, index)
        if not any(m["id"] == s["id"] for m in matched):
            unmatched.append(s["id"])
    assert not unmatched, "以下 spec 经 stable 主键仍无法被其 vuln 命中：%s" % unmatched

    vhash_only_unmatched = []
    for s in empty_specs:
        vuln = rebuild_vuln(s["raw_json"])
        if not any(m["id"] == s["id"] for m in (specs_by_hash.get(vuln["vuln_vhash"]) or [])):
            vhash_only_unmatched.append(s["id"])
    assert len(vhash_only_unmatched) == len(empty_specs), \
        "旧 vhash 主键应对空状态 spec 全部落空（复现根因）"
