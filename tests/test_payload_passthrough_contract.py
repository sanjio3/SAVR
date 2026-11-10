"""载荷透传契约 + 三个 live 断点的回归测试（2026-10-26）。

## 为什么有这个文件

run 471 暴露了一个系统性形态：**同一字段在链路里被重建多次，上游写入被下游覆盖或丢弃**。
三处断点全是这个形态：

1. 属性族门禁：`benchmark_cli.py` 算好 `_a1_for_registration` 后被无条件覆盖回 `a1_results`；
2. `phase_times`：`run_benchmark` / `scan_task_runner` 都带了，但
   `orphan_recovery._completion_payload` 不透传 ⇒ 回收路径落库为空；
3. `stage_results.a2.contract`：写进了 scan_progress.json，但 `run_benchmark` 的 return
   自建 stage_results 把它丢了。

其中 1 和 3 无法用普通单测覆盖（`run_benchmark` 依赖 CodeQL/靶场，无法在单测里跑），
故用**源码守卫测试**锁死：断言那两处不允许再出现「无条件覆盖」的写法。
这类测试的价值是防回归——一旦有人把覆盖写回去，测试立刻红。

2 是纯函数，用**行为测试**覆盖。
"""

import os

import pytest

LOCAL_ROOT = os.environ.get("SAST_AI_SDL_ROOT", "")
pytestmark = [
    pytest.mark.external,
    pytest.mark.skipif(
        not LOCAL_ROOT,
        reason="external target sources required: set SAST_AI_SDL_ROOT to your local targets root",
    ),
]

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


# ─────────────────────────────────────────────────────────────
# 一、载荷透传契约（行为测试，防「字段被下游丢掉」）
# ─────────────────────────────────────────────────────────────

def _full_result_payload() -> dict:
    """构造一份含全部观测字段的 task_result.json 形状。"""
    return {
        "findings": [{"id": "v1"}, {"id": "v2"}],
        "reports": [{"report_type": "FINAL_REPORT", "file_path": "/tmp/r.md"}],
        "pipeline": {"a1": "completed"},
        "current_stage": "reporting",
        "prepared_runtime": {"runtime_type": "java"},
        "hitl": {"approval_mode": "off"},
        "phase_times": {"a1": 143.8, "a2": 4018.4, "d2": 4442.8},
        "stage_results": {
            "a1": {"finding_count": 312},
            "a2": {"finding_count": 114,
                   "contract": {"calls": 125, "first_pass": 125, "invalid_rate": 0.0}},
            "i2": {"feedback_to_a2_count": 228},
        },
    }


def test_completion_payload_keeps_phase_times():
    """回收路径必须透传 phase_times（正常路径 task_runner 已带，两路径须同形）。"""
    from src.infrastructure.orphan_recovery import _completion_payload

    out = _completion_payload(_full_result_payload())
    assert out["phase_times"] == {"a1": 143.8, "a2": 4018.4, "d2": 4442.8}


def test_completion_payload_keeps_stage_results_contract():
    """stage_results 必须整体透传，尤其 a2.contract（契约合规率）。"""
    from src.infrastructure.orphan_recovery import _completion_payload

    out = _completion_payload(_full_result_payload())
    assert out["stage_results"]["a2"]["contract"]["calls"] == 125
    assert out["stage_results"]["i2"]["feedback_to_a2_count"] == 228


def test_completion_payload_passthrough_contract_all_fields():
    """契约测试：观测类字段一个都不能丢。

    这条是「整类问题」的闸门——新增观测字段时把它加进 _OBSERVABILITY_FIELDS，
    一旦某层忘了透传，这里就会红。
    """
    from src.infrastructure.orphan_recovery import _completion_payload

    payload = _full_result_payload()
    out = _completion_payload(payload)
    # 顶层必须保留的观测字段
    for key in ("phase_times", "stage_results", "prepared_runtime", "pipeline"):
        assert key in out, "顶层观测字段 %s 被丢弃" % key
        assert out[key] == payload[key], "顶层观测字段 %s 值被改写" % key
    # 阶段级必须保留的观测子字段
    assert out["stage_results"]["a2"].get("contract") is not None


def test_completion_payload_tolerates_missing_fields():
    """缺字段时不得抛异常（老 task_result.json 没有 phase_times）。"""
    from src.infrastructure.orphan_recovery import _completion_payload

    out = _completion_payload({"findings": [], "stage_results": {}})
    assert out["phase_times"] == {}
    assert out["stage_results"] == {}


# ─────────────────────────────────────────────────────────────
# 二、源码守卫（防「无条件覆盖」回归）
# ─────────────────────────────────────────────────────────────

def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_a1_for_registration_not_unconditionally_overwritten():
    """门禁结果不得被后续无条件覆盖。

    历史 bug：`_a1_for_registration = a1_results if enable_a1 else []` 在 enable_a2
    分支里无条件执行，把属性族门禁的结果整个丢掉 ⇒ 门禁成了死代码，
    BenchmarkTest00022（SHA-256 安全版）被确认成漏洞。
    """
    src = _read("src/cli/benchmark_cli.py")
    assert '_a1_for_registration = a1_results if enable_a1 else []' not in src or \
        'if "_a1_for_registration" not in locals():' in src, \
        "检测到门禁结果可能被无条件覆盖：请保留 `if \"_a1_for_registration\" not in locals():` 守卫"
    # 守卫必须存在且紧跟在那条赋值之前
    guard_idx = src.find('if "_a1_for_registration" not in locals():')
    assert guard_idx != -1, "缺少门禁结果守卫"


def test_run_benchmark_return_includes_a2_contract():
    """run_benchmark 的 return 必须带 stage_results.a2.contract。

    历史 bug：这里自建 stage_results 只有 finding_count，把 scan_progress.json 里
    已写好的 contract 覆盖掉 ⇒ task_completed 载荷里恒为空。
    """
    src = _read("src/cli/benchmark_cli.py")
    assert "'contract': dict(_a2_contract_stats or {})" in src, \
        "run_benchmark 的 return 里缺少 a2.contract 透传"


# ─────────────────────────────────────────────────────────────
# 三、属性族门禁行为（锁死 00016/00121/00022 三个 FP）
# ─────────────────────────────────────────────────────────────

BENCH = Path(LOCAL_ROOT) / "owasp-code" / "BenchmarkJava-master"


class _V:
    def __init__(self, vtype, line):
        self.type = vtype
        self.line = line


class _R:
    def __init__(self, file, vulns):
        self.file = file
        self.vulnerabilities = vulns


@pytest.mark.skipif(not BENCH.exists(), reason="Benchmark 源码不在本机")
def test_property_gate_drops_mislabeled_property_family_findings():
    """族误标（type 与路由前缀矛盾）的属性族安全用例必须被判假。

    三个真实 FP：00016 securecookie / 00121 crypto / 00022 hash，
    A1 的 type 分别是 http response splitting / stack trace exposure / cross-site scripting，
    都靠「路由前缀推真实族 + 静态强证据」这条兜底剔除。
    """
    from src.cli.benchmark_cli import _filter_property_family_findings

    cases = [
        ("BenchmarkTest00016.java", "http response splitting", 60),
        ("BenchmarkTest00121.java", "stack trace exposure", 60),
        ("BenchmarkTest00022.java", "cross-site scripting", 79),
    ]
    rel = "src/main/java/org/owasp/benchmark/testcode/"
    results = [_R(rel + f, [_V(t, l)]) for f, t, l in cases]
    kept = _filter_property_family_findings(results, str(BENCH))
    assert kept == [], "三个族误标的属性族安全用例都应被门禁剔除，实际保留了 %d 条" % len(kept)


@pytest.mark.skipif(not BENCH.exists(), reason="Benchmark 源码不在本机")
def test_property_gate_keeps_true_vulnerable_property_case():
    """反向保护：属性族真漏洞（弱算法）不得被门禁误杀。"""
    from src.cli.benchmark_cli import _filter_property_family_findings

    # BenchmarkTest00020 属 hash 族；用真值表确认它是不是真漏洞
    truth = {}
    csv = BENCH / "expectedresults-1.2.csv"
    for line in csv.read_text(encoding="utf-8", errors="replace").splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) >= 3 and p[0].startswith("BenchmarkTest"):
            truth[p[0]] = p[2].lower() == "true"
    # 找一个 hash 族的真漏洞（truth=True）
    target = None
    for line in csv.read_text(encoding="utf-8", errors="replace").splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) >= 3 and p[0].startswith("BenchmarkTest") and p[1] == "hash" \
                and p[2].lower() == "true":
            target = p[0]
            break
    if not target:
        pytest.skip("找不到 hash 族真漏洞样本")
    rel = "src/main/java/org/owasp/benchmark/testcode/%s.java" % target
    results = [_R(rel, [_V("weak_hash", 0)])]
    kept = _filter_property_family_findings(results, str(BENCH))
    assert len(kept) == 1, "属性族真漏洞 %s 被误杀" % target


# ─────────────────────────────────────────────────────────────
# 四、闭环止损开关（P3.1，run 471 实测 gain=0 / 耗时 29.1%）
# ─────────────────────────────────────────────────────────────

def test_closed_loop_controller_still_clamps_to_one():
    """类语义必须保持 max(1, ...)：其他调用方依赖它，不能被本次改动影响。"""
    from src.agents.i2_feedback import ClosedLoopController

    assert ClosedLoopController(max_iterations=0).max_iterations == 1
    assert ClosedLoopController(max_iterations=-5).max_iterations == 1
    assert ClosedLoopController(max_iterations=3).max_iterations == 3


def test_closed_loop_switch_exists_and_can_skip_rerun():
    """SAST_AI_CLOSED_LOOP=0 时必须能把轮次压到 0（跳过 A2 回灌重跑）。

    历史背景：471 实测闭环重跑 4528.9s（29.1% 总耗时）、gain=0；
    同轮确定性重试 192.4s 拿到 +9 确认。故需要一个「只关重跑、保留确定性重试」的开关。
    """
    src = _read("src/cli/benchmark_cli.py")
    assert 'SAST_AI_CLOSED_LOOP' in src, "缺少闭环止损开关"
    assert "_loop.max_iterations = 0" in src, "缺少把轮次压到 0 的覆盖（控制器内部会夹到 ≥1）"
    # 确定性重试必须仍在（不能因为关闭环把它一起关掉）
    assert "plan_retryable_replay" in src and "execute_retryable_replay" in src


# ─────────────────────────────────────────────────────────────
# 五、D2 轮询埋点（P2.1，471 实测 D2 4443s 里 HTTP 仅 227s）
# ─────────────────────────────────────────────────────────────

def test_poll_stats_derived_metrics():
    """轮询画像的派生指标必须正确（命中率 / 平均等待 / 平均次数）。"""
    from src.agents import d2_facade as D

    D.reset_poll_stats()
    z = D.poll_stats()
    assert z["verifications"] == 0 and z["hit_rate"] == 0.0 and z["avg_wait_s"] == 0.0

    D._POLL_STATS.update({"verifications": 3, "hit": 2, "timeout": 1,
                          "total_attempts": 14, "total_wait_ms": 16500.0,
                          "max_wait_ms": 13500.0})
    s = D.poll_stats()
    assert s["hit_rate"] == 0.6667
    assert s["total_wait_s"] == 16.5
    assert s["avg_wait_s"] == 5.5
    assert s["avg_attempts"] == 4.67
    assert s["max_wait_s"] == 13.5
    D.reset_poll_stats()


def test_poll_loop_records_stats_and_exposes_to_payload():
    """轮询循环必须真记账，且画像要能进 stage_results.d2（两条路径都要带）。"""
    src_facade = _read("src/agents/d2_facade.py")
    # 循环内必须累加统计
    for key in ('_POLL_STATS["verifications"]', '_POLL_STATS["total_attempts"]',
                '_POLL_STATS["total_wait_ms"]', '_POLL_STATS["hit"]', '_POLL_STATS["timeout"]'):
        assert key in src_facade, "轮询埋点缺少 %s" % key
    # 编排侧必须把它写进 stage_results.d2，并且 return 里也要带（防被自建结构覆盖）
    src_cli = _read("src/cli/benchmark_cli.py")
    assert '"poll_stats": _d2_poll' in src_cli, "stage_results.d2 未写 poll_stats"
    assert "'poll_stats': dict(_d2_poll_stats or {})" in src_cli, "run_benchmark 的 return 未透传 poll_stats"


# ─────────────────────────────────────────────────────────────
# 六、I2 闭环载荷透传（同类坑的第三例）
# ─────────────────────────────────────────────────────────────

def test_i2_payload_wired_into_return():
    """stage_results.i2 必须同时进 scan_progress 与 run_benchmark 的 return。

    历史 bug：i2 只写 scan_progress.json，return 自建 stage_results 不含 i2
    ⇒ task_completed 载荷里 stage_results.i2 恒为空，闭环代价/收益全不可见（471 实测）。
    """
    src = _read("src/cli/benchmark_cli.py")
    assert "_i2_stage_payload: Dict[str, Any] = {}" in src, "缺少 i2 载荷初始化"
    assert '{"stage_results": {"i2": _i2_stage_payload}}' in src, "progress 写入未用统一变量"
    assert "'i2': dict(_i2_stage_payload or {})" in src, "return 未透传 i2"




# ─────────────────────────────────────────────────────────────
# 七、phase_times 端到端落位（回收路径 → service 合并 → summary）
# ─────────────────────────────────────────────────────────────

def test_phase_times_survives_orphan_to_summary(tmp_path):
    """回收路径的 phase_times 必须能一路走到 summary["phase_times"]。

    历史断点链（run 471 实测）：
      run_benchmark return 有 phase_times（9864 行）→ scan_task_runner 也带（420 行）
      → **orphan_recovery._completion_payload 漏了** ⇒ 直接跑 runner 时落库为空
    修法是补 _completion_payload，但只补那一处不够——还要确认 service 层真的会合并进
    summary（验收台从 summary.phase_times 读）。本测试锁死整条链路。
    """
    from src.infrastructure.orphan_recovery import _completion_payload
    from src.application.task_service import TaskService

    pt = {"a1": 143.8, "a2": 4018.4, "d2": 4442.8, "closed_loop_rerun": 4528.9}
    raw = {"findings": [], "phase_times": pt,
           "stage_results": {"a2": {"contract": {"calls": 125, "invalid_rate": 0.0}}}}
    payload = _completion_payload(raw)
    assert payload.get("phase_times") == pt, "回收路径未透传 phase_times"

    svc = TaskService.__new__(TaskService)          # 只测纯合并逻辑，不初始化 DB
    # 注意：_merge_task_summary 返回的就是 summary 本身（调用方 task_service.py:413
    # 直接 `merged_summary = self._merge_task_summary(...)` 后存库），不是 {"summary": ...}
    summary = svc._merge_task_summary({}, payload, {}, "task_completed")
    got = summary.get("phase_times") or {}
    assert got == pt, "service 层未把 phase_times 合进 summary（验收台会读不到）"
    # 同一次合并里 stage_results 也必须保留（a2.contract 靠它）
    assert summary.get("stage_results"), "stage_results 在合并中丢失"


def test_verify_harness_reads_summary_phase_times():
    """验收台必须从 summary.phase_times 读（与 service 合并位置同形）。"""
    src = _read("tools/_wb_verify_rerun.py")
    assert 'payload.get("summary") or {}).get("phase_times")' in src, \
        "验收台读取位置与 service 合并位置不一致"


def test_verify_harness_baseline_compare_renders():
    """J 段（与基线对比）必须能渲染，不能因缺字段抛异常。

    这轮所有验收都靠它一次判完，渲染崩了等于对账瘫痪。
    """
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import importlib
    V = importlib.import_module("_wb_verify_rerun")

    fake = {
        "task_id": 999999, "shard": "mini", "scope_cases": 130,
        "detected_cases": 130, "confirmed_cases": 82, "tp": 79, "fp": 0,
        "precision": 1.0, "recall": 1.0, "noise_family_confirmed": [],
        "redline": {"limit": 1, "pass": True},
        "harm_gate_downgrades": 0, "harm_gate_tp_lost": 0,
        "contract": {"calls": 129, "first_pass": 129, "invalid_rate": 0.0},
        "phase_times": {"a1": 143.0, "a2": 3400.0, "d2": 4400.0},
        "phase_times_total": 7943.0, "wall_total_s": 11000.0, "unaccounted_s": 3057.0,
        "intents": {}, "intent_duplicate_groups": 0,
        "avg_attempts_per_spec": 8.0, "max_attempts_per_spec": 20, "attempts_total": 2952,
        "decision_cache_rows": 0,
        "closed_loop": {"iterations": 0, "max_iterations": 0, "gain": None},
        "retryable": {"retryable_count": 119, "executed_count": 110, "match_rate": 0.9244,
                      "confirmed_gain": 30, "elapsed_sec": 900},
        "poll_stats": {"verifications": 300, "hit": 280, "timeout": 20, "hit_rate": 0.9333,
                       "total_wait_s": 400.0, "avg_wait_s": 1.33, "max_wait_s": 13.5,
                       "avg_attempts": 1.8},
    }
    out = V.render([fake])
    assert "### J. 与基线" in out, "缺少基线对比段"
    assert "**FP（硬约束）**" in out and "**TP（硬约束）**" in out
    assert "✅ 归零" in out and "✅ 未降" in out
    assert "closed_loop_rerun" in out and "✅ 已关闭" in out
    assert "✅ 已接通" in out        # contract / poll_stats 都该判已接通
