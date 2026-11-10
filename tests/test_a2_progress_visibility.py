"""A2 / a2_poc 阶段细粒度进度前端可见性（待请示 6 项 #5，2026-09-16）。

回归背景：R28 run 10 中 A2 跑 33.4 分钟、a2_poc 跑 33.9 分钟，期间 scan_progress.json 无任何
增量更新；a2_poc 甚至不在 pipeline 阶段列表里，前端只能显示「进行中」，与卡死无法区分。

本测试把前端契约钉死：
1. a2_progress 心跳（已分析 M/N 文件）必须并入 a2 阶段文案；
2. a2_poc 提升为 pipeline 可见阶段，且 a2_poc_progress 心跳（PoC 规划 M/N）并入其文案；
3. a2_poc 阶段在 running / completed 下都能正确展示状态。
"""

from src.infrastructure.task_runner import ScanTaskRunner


def test_a2_progress_shows_file_count():
    progress = {
        "a2_progress": {"total": 120, "done": 45, "status": "scanning"},
        "stage_results": {"a2": {"finding_count": 80}},
    }
    pipe = ScanTaskRunner._build_pipeline(progress, {"enable_a2": True})
    assert "已分析 45/120 文件" in pipe["a2"]["message"]


def test_a2_poc_is_visible_stage_with_progress():
    progress = {
        "a2_poc_progress": {"total": 191, "done": 120, "status": "planning"},
        "stage_results": {"a2_poc": {"status": "running", "message": "PoC 规划中（0/191）"}},
    }
    pipe = ScanTaskRunner._build_pipeline(progress, {"enable_a2": True})
    assert "a2_poc" in pipe, "a2_poc 必须成为 pipeline 可见阶段"
    assert pipe["a2_poc"]["status"] == "running"
    assert "PoC 规划 120/191" in pipe["a2_poc"]["message"]


def test_a2_poc_completed_stage():
    progress = {
        "a2_poc_progress": {"total": 191, "done": 191, "status": "planning_done"},
        "stage_results": {"a2_poc": {"status": "completed", "message": "PoC 规划完成（191/191）"}},
    }
    pipe = ScanTaskRunner._build_pipeline(progress, {"enable_a2": True})
    assert pipe["a2_poc"]["status"] == "completed"
    assert "PoC 规划 191/191" in pipe["a2_poc"]["message"]


def test_a2_poc_skipped_when_a2_disabled():
    progress = {"stage_results": {}}
    pipe = ScanTaskRunner._build_pipeline(progress, {"enable_a2": False})
    assert pipe["a2_poc"]["status"] == "skipped"


def test_plan_vulns_concurrent_fires_on_progress():
    """验证 a2_poc 的并发规划路径（as_completed 分支）每完成一条漏洞就回调 on_progress。

    用假 planner：llm_client 设为真值使代码走并发 executor 分支（生产同款），
    plan_vulnerability 直接返回不触网。on_progress 必须在每条完成后被调用一次。
    """
    from types import SimpleNamespace

    from src.agents.a2_contract_planner import A2ContractPlanner

    class _FakePlanner(A2ContractPlanner):
        def __init__(self):
            # 不调用真实 __init__（会建 LLM 客户端）。llm_client 设真值 → 走并发分支触发 on_progress。
            self.llm_client = object()

        def plan_vulnerability(self, vuln, a1_evidence=None, code_root=None, code_index=None):
            return vuln

    planner = _FakePlanner()
    vulns = [SimpleNamespace(type=f"v{i}") for i in range(7)]
    calls = []
    planner._plan_vulns_concurrent(vulns, None, on_progress=lambda d, t: calls.append((d, t)))
    assert len(calls) == 7, f"应回调 7 次，实际 {len(calls)}"
    assert calls[-1] == (7, 7)


def test_plan_scan_results_progress_is_global_cumulative():
    """a2_poc 进度必须跨文件全局累计，不得每个文件重置 done/total。

    实测缺陷：原按单文件批次回调，前端显示「PoC 规划 1/2」与 stage_results 的
    全局 「0/179」自相矛盾。修复后每完成一条全局 +1，total 恒为全项目漏洞数。
    """
    from types import SimpleNamespace

    from src.agents.a2_contract_planner import A2ContractPlanner
    from src.core.models import ScanResult

    class _FakePlanner(A2ContractPlanner):
        def __init__(self):
            self.llm_client = object()  # 真值 → 走并发 executor 分支（触发 on_progress）

        def plan_vulnerability(self, vuln, a1_evidence=None, code_root=None, code_index=None):
            return vuln

    results = [
        ScanResult(file="A.java", vulnerabilities=[SimpleNamespace(type="t1"), SimpleNamespace(type="t2")]),
        ScanResult(file="B.java", vulnerabilities=[SimpleNamespace(type="t3")]),
        ScanResult(file="C.java", vulnerabilities=[SimpleNamespace(type="t4"),
                                                    SimpleNamespace(type="t5"),
                                                    SimpleNamespace(type="t6")]),
    ]
    calls = []
    _FakePlanner().plan_scan_results(results, on_progress=lambda d, t: calls.append((d, t)))

    assert [d for d, _ in calls] == [1, 2, 3, 4, 5, 6], f"done 必须跨文件单调递增，实际 {calls}"
    assert all(t == 6 for _, t in calls), f"total 必须恒为全局 6，实际 {calls}"
