"""A 组落地单测（2026-09-28）：RAG+LLM 攻击计划白名单校验 + 埋点 + 种子库。"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("SAST_AI_D2_PLAN_METRICS_PATH", "data/.tmp_test_d2_plan_metrics.json")
os.environ.setdefault("SAST_AI_POC_MEMORY_PATH", "data/.tmp_test_poc_memory.json")

from src.agents.d2_plan_rag import (  # noqa: E402
    attack_plan_completeness,
    get_plan_metrics,
    validate_llm_plan,
    bump_metric,
)
from src.agents.poc_memory_store import PocMemoryStore  # noqa: E402


def setup_function(_):
    for p in ("data/.tmp_test_d2_plan_metrics.json", "data/.tmp_test_poc_memory.json"):
        Path(p).unlink(missing_ok=True)


def teardown_function(_):
    for p in ("data/.tmp_test_d2_plan_metrics.json", "data/.tmp_test_poc_memory.json"):
        Path(p).unlink(missing_ok=True)


# ---------- 完备度评分 ----------
def test_completeness_full_contract_skips_llm():
    spec = {"entry": {"route": "/a", "parameter_name": "id"},
            "payload": {"payload_family": "sql-injection"}}
    comp = attack_plan_completeness(spec)
    assert comp["complete"] is True and comp["missing"] == []


def test_completeness_missing_route_and_param():
    spec = {"entry": {}, "payload": {"payload_family": "sql-injection"}}
    comp = attack_plan_completeness(spec)
    assert comp["complete"] is False
    assert set(comp["missing"]) == {"route", "parameter"}


# ---------- 白名单校验（A 第三步） ----------
def test_validate_accepts_whitelisted_route_and_param():
    plan = {"business_goal": "x", "suggested_route": "/benchmark/sqli-01/BenchmarkTest00001",
            "suggested_parameter": "username"}
    cleaned, rejected = validate_llm_plan(
        plan, allowed_endpoints=["/benchmark/sqli-01/BenchmarkTest00001"],
        allowed_params=["username", "password"])
    assert rejected == {}
    assert cleaned["suggested_route"].endswith("BenchmarkTest00001")
    assert cleaned["suggested_parameter"] == "username"


def test_validate_rejects_hallucinated_route_and_param():
    plan = {"business_goal": "x", "suggested_route": "/admin/secret",
            "suggested_parameter": "magic_param"}
    cleaned, rejected = validate_llm_plan(
        plan, allowed_endpoints=["/benchmark/sqli-01/BenchmarkTest00001"],
        allowed_params=["username"])
    assert set(rejected) == {"route", "param"}
    assert "suggested_route" not in cleaned and "suggested_parameter" not in cleaned
    m = get_plan_metrics()
    assert m["rejected_route"] >= 1 and m["rejected_param"] >= 1


def test_validate_query_string_and_trailing_slash_normalized():
    plan = {"business_goal": "x", "suggested_route": "/benchmark/sqli-01/BenchmarkTest00001?x=1"}
    cleaned, rejected = validate_llm_plan(plan, allowed_endpoints=["/benchmark/sqli-01/BenchmarkTest00001/"])
    assert rejected == {}


def test_validate_no_allowlist_never_adopts():
    """无集合可比对时按不采纳处理（不臆造放行）。"""
    plan = {"business_goal": "x", "suggested_route": "/anything"}
    cleaned, rejected = validate_llm_plan(plan, allowed_endpoints=None)
    assert rejected == {"route": "/anything"} and "suggested_route" not in cleaned


# ---------- 埋点（A 第四步） ----------
def test_metrics_roundtrip():
    before = get_plan_metrics()["llm_generated"]
    bump_metric("llm_generated", 3)
    assert get_plan_metrics()["llm_generated"] == before + 3
    bump_metric("nonexistent_key")  # 不应抛错也不应写入


# ---------- 种子库（A 第一步） ----------
def test_seed_store_record_and_retrieve():
    store = PocMemoryStore(path="data/.tmp_test_poc_memory.json")
    store.record({
        "family": "sql-injection", "framework": "any", "sink_signature": "sql-exec",
        "canary_form": "plain", "attack_shape": "seed:sql-injection",
        "attack_plan": {"business_goal": "t", "steps": ["s1"]},
        "observation": "template_seed", "verified": True,
    })
    assert store.size() == 1
    hits = store.retrieve("sql-injection", "any", "sql-exec", top_k=3)
    assert hits and hits[0]["attack_plan"]["business_goal"] == "t"


def test_seed_script_creates_nonempty_memory():
    """种子脚本幂等可执行且产出非空库（用临时路径隔离）。"""
    import subprocess
    env = dict(os.environ)
    env["SAST_AI_POC_MEMORY_PATH"] = "data/.tmp_test_poc_memory.json"
    r = subprocess.run([sys.executable, "scripts/seed_poc_memory.py"], capture_output=True,
                       text=True, env=env, cwd=str(Path(__file__).resolve().parents[1]))
    assert r.returncode == 0, r.stderr
    data = json.loads(Path("data/.tmp_test_poc_memory.json").read_text(encoding="utf-8"))
    assert sum(len(v) for v in data.values()) >= 50
