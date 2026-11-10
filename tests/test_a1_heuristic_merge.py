"""P1-2：CodeQL 与启发式五类规则并集融合的回归守卫。

背景（2026-09-25 task-6 复盘）：原逻辑「CodeQL 有结果就整段跳过 heuristic」会在
CodeQL 覆盖不满时丢掉五类保底召回。融合后：两通道并集，重叠按 (type, sink, 行±3)
去重保留 CodeQL 条目，engine 新增 codeql+heuristic 态。
"""
from src.core.models import ScanResult, Vulnerability
from src.pipeline.a1.service import A1PipelineService


def _v(file, line, type_="SQL Injection", sink="executeQuery", source="a1-injection-heuristic"):
    return Vulnerability(
        type=type_, severity="high", line=line, file=file, sink=sink,
        source=source, verdict="待分析",
    )


def _codeql_results():
    return [
        ScanResult(
            file="A.java",
            vulnerabilities=[_v("A.java", 42, source="a1-codeql")],
            agent="a1",
        ),
        ScanResult(file="B.java", vulnerabilities=[], agent="a1"),
    ]


def test_overlapping_hit_within_3_lines_deduped_keeps_codeql():
    """同文件同 type/sink、行差 ≤3：去重，保留 CodeQL 条目，不新增 heuristic 条。"""
    results, added = A1PipelineService._merge_heuristic_into_codeql(
        _codeql_results(), [_v("A.java", 44)]  # 行差 2，视为同一命中
    )
    a = next(r for r in results if r.file == "A.java")
    assert len(a.vulnerabilities) == 1
    assert a.vulnerabilities[0].source == "a1-codeql"
    assert added == 0


def test_far_line_or_different_sink_not_deduped():
    """行差 >3 或 sink 不同：视为不同命中，heuristic 独苗并入。"""
    results, added = A1PipelineService._merge_heuristic_into_codeql(
        _codeql_results(),
        [
            _v("A.java", 60),                                        # 同 type/sink 但行差 18
            _v("A.java", 42, sink="prepareStatement"),               # 行同但 sink 不同
            _v("A.java", 42, type_="Command Injection"),             # 行同但 type 不同
        ],
    )
    a = next(r for r in results if r.file == "A.java")
    assert len(a.vulnerabilities) == 4  # 1 codeql + 3 heuristic 独苗
    assert added == 3


def test_new_file_creates_scan_result():
    """heuristic 命中了 CodeQL 没覆盖的文件：新建 ScanResult（保持每文件一个契约）。"""
    results, added = A1PipelineService._merge_heuristic_into_codeql(
        _codeql_results(), [_v("C.java", 10, type_="Insecure Randomness")]
    )
    c = next(r for r in results if r.file == "C.java")
    assert c.agent == "a1" and len(c.vulnerabilities) == 1 and added == 1


def test_exact_same_line_deduped():
    """行号完全相同的同 type/sink 命中：去重。"""
    results, added = A1PipelineService._merge_heuristic_into_codeql(
        _codeql_results(), [_v("A.java", 42)]
    )
    a = next(r for r in results if r.file == "A.java")
    assert len(a.vulnerabilities) == 1 and added == 0
