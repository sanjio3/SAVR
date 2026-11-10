"""A2 族感知配额选择（max_files 规模坍缩本质修复）的单元测试。

覆盖：
  - 族感知选择把预算摊到多个族（不再 1.4 族通吃）；
  - 总量硬封顶 max_files；
  - 族内分层：sink+source 同现优先；
  - env SAST_AI_A2_FAMILY_QUOTA=0 回退遗留全局 top-N（单族坍缩）；
  - env SAST_AI_A2_MAX_FILES 显式/auto 缩放预算。
"""
import os

from src.core.capability_judge import capability_family_of
from src.pipeline.a2.service import (
    A2PipelineService,
    SCAN_MODE_FILTER_FIRST,
)


def _cmdi(i):
    return {
        "rel_path": f"src/cmdi/BenchmarkTest{i:05d}.java",
        "content": (
            "import javax.servlet.http.*;\n"
            "public void doGet(HttpServletRequest req, HttpServletResponse res){\n"
            f"  String cmd = req.getParameter(\"cmd{i}\");\n"
            "  Runtime.getRuntime().exec(cmd);\n"
            "}\n"
        ),
    }


def _sqli(i):
    return {
        "rel_path": f"src/sqli/BenchmarkTest{i:05d}.java",
        "content": (
            "import javax.servlet.http.*;\nimport java.sql.*;\n"
            "public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n"
            f"  String id = req.getParameter(\"id{i}\");\n"
            "  Statement st = con.createStatement();\n"
            "  st.executeQuery(id);\n"
            "}\n"
        ),
    }


def _xss(i):
    return {
        "rel_path": f"src/xss/BenchmarkTest{i:05d}.java",
        "content": (
            "import javax.servlet.http.*;\n"
            "public void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n"
            f"  String x = req.getParameter(\"x{i}\");\n"
            "  res.getWriter().print(x);\n"
            "}\n"
        ),
    }


def _generic(i):
    return {
        "rel_path": f"src/util/Helper{i:05d}.java",
        "content": f"package util;\npublic class Helper{i} {{ int v = {i}; }}\n",
    }


def _build(n_per=200):
    files = []
    for i in range(n_per):
        files.append(_cmdi(i))
        files.append(_sqli(i))
        files.append(_xss(i))
    return files


def _families(selected):
    out = {}
    for f in selected:
        fam, _ = capability_family_of(str(f.get("content", "") or ""))
        out.setdefault(fam or "", 0)
        out[fam or ""] += 1
    return out


def test_family_aware_spreads_budget_across_families():
    files = _build(200)
    selected = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
    assert len(selected) == 240, len(selected)
    fams = _families(selected)
    # 三个目标族都应分到预算，而不是全压在一个族
    assert fams.get("command_execution", 0) > 0
    assert fams.get("sql_injection", 0) > 0
    assert fams.get("xss", 0) > 0
    # 每个族都拿到接近均等的配额（240 // 3 = 80）
    for fam in ("command_execution", "sql_injection", "xss"):
        assert 60 <= fams[fam] <= 100, (fam, fams[fam])


def test_legacy_global_topn_collapses_to_one_family(monkeypatch):
    monkeypatch.setenv("SAST_AI_A2_FAMILY_QUOTA", "0")
    files = _build(200)
    # 文件顺序：先 200 cmdi，再 200 sqli，再 200 xss
    selected = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
    assert len(selected) == 240
    fams = _families(selected)
    # 关掉族感知后，全局 top-N 按文件序截断 → 几乎全落在第一个族（cmdi）
    assert fams.get("command_execution", 0) >= 200
    assert fams.get("sql_injection", 0) <= 40
    assert fams.get("xss", 0) <= 40


def test_family_aware_caps_at_max_files():
    files = _build(400)  # 远超预算
    selected = A2PipelineService._select_focus_files(files, max_files=120, scan_mode=SCAN_MODE_FILTER_FIRST)
    assert len(selected) == 120


def test_layering_prefers_sink_and_source_within_family():
    # 同一族（cmdi）内：50 个 sink+source，50 个只有 source（无 sink），配额 80
    files = []
    for i in range(50):
        files.append(_cmdi(i))  # 同时含 Runtime.exec（sink）与 getParameter（source）
    for i in range(50):
        # 同族（command_execution：含 ProcessBuilder 能力指纹），但只命中 source、
        # 不命中 sink 正则（分层层 1）；_cmdi 同时命中 sink+source（层 2）。
        files.append({
            "rel_path": f"src/cmdi/SourceOnly{i:05d}.java",
            "content": (
                "import javax.servlet.http.*;\n"
                "public void doGet(HttpServletRequest req, HttpServletResponse res){\n"
                f"  String a = req.getParameter(\"a{i}\");\n"
                "  new ProcessBuilder(a);\n"
                "}\n"
            ),
        })
    selected = A2PipelineService._select_focus_files(files, max_files=80, scan_mode=SCAN_MODE_FILTER_FIRST)
    assert len(selected) == 80
    # 所有「sink+source」文件都应优先入选（层 2）
    sel_paths = {f["rel_path"] for f in selected}
    for i in range(50):
        assert _cmdi(i)["rel_path"] in sel_paths


def test_env_max_files_explicit_and_auto():
    files = _build(300)
    # 显式整数
    os.environ["SAST_AI_A2_MAX_FILES"] = "90"
    try:
        sel = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
        assert len(sel) == 90
    finally:
        del os.environ["SAST_AI_A2_MAX_FILES"]
    # auto：随规模缩放
    os.environ["SAST_AI_A2_MAX_FILES"] = "auto"
    try:
        sel = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
        # 300 文件 → auto = min(300, max(240, 30)) = 240
        assert len(sel) == 240
    finally:
        del os.environ["SAST_AI_A2_MAX_FILES"]


def test_small_repo_returns_everything_family_aware():
    files = [_cmdi(i) for i in range(30)] + [_sqli(i) for i in range(30)]
    selected = A2PipelineService._select_focus_files(files, scan_mode=SCAN_MODE_FILTER_FIRST)
    assert len(selected) == 60
