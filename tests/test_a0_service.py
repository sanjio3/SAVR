"""A0 编排器（§8.1/§8.4）单测：路径校验 + R0 框架特化 + 入口发现 + 补盲回灌 + P0 计划。"""
from pathlib import Path

import pytest

from src.agents.p0_planning_agent import P0PlanningAgent
from src.agents.r0_recon_agent import R0ReconAgent
from src.application.a0_service import A0Service
from src.application.entry_discovery_service import EntryDiscoveryService
from src.pipeline.a0.service import A0PreprocessService


def _make_flask_proj(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("flask==2.3.0\n", encoding="utf-8")
    (proj / "app.py").write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/user/<int:uid>')\n"
        "def get_user(uid):\n"
        "    name = request.args.get('name')\n"
        "    return uid\n",
        encoding="utf-8",
    )
    return proj


def test_a0_run_path_validation_and_discovery(tmp_path):
    """§8.1 职责①路径校验 + 职责③入口发现整合：Flask 项目能发现入口并带 request_params。"""
    proj = _make_flask_proj(tmp_path)
    svc = A0Service(
        preprocess=A0PreprocessService(),
        entry_discovery=EntryDiscoveryService(),
        r0_agent_cls=R0ReconAgent,
        p0_agent_cls=P0PlanningAgent,
    )
    result = svc.run(str(proj))
    assert result["status"] == "completed"
    assert result["path_validation"]["status"] == "ok"
    assert result["entry_count"] >= 1
    # R0 识别 framework=flask，回带 framework 上下文（§8.4 第2点框架特化）
    assert result["framework"] == "flask"
    # 入口带 request_params（uid 路径参数 + name 查询参数）
    web_entries = [e for e in result["entries"] if e.get("entry_type") == "web_route"]
    assert web_entries
    names = {p["param_name"]: p["param_location"] for e in web_entries for p in e.get("request_params", [])}
    assert names.get("uid") == "path"
    assert names.get("name") == "query"
    # P0 计划产出（基于 R0 project_info）
    assert result["audit_plan"] is not None
    assert result["audit_plan"]["scan_depth"] == "deep"


def test_a0_run_invalid_path(tmp_path):
    """职责①：路径不存在 → status=error，不继续发现。"""
    svc = A0Service(preprocess=A0PreprocessService(), entry_discovery=EntryDiscoveryService())
    result = svc.run(str(tmp_path / "not-exist"))
    assert result["status"] == "error"
    assert "Path" in result.get("message", "")


def test_a0_backfill_blindspots(tmp_path):
    """§8.4 第3点：IAST observed_only 入口回灌成规则候选。"""
    svc = A0Service(entry_discovery=EntryDiscoveryService())
    candidates = svc.backfill_blindspots([
        {"sink_method": "Runtime.exec", "sink_file": "Ctrl.java", "sink_line": 42},
        {"sink_method": "Runtime.exec", "sink_file": "Ctrl.java", "sink_line": 42},  # 去重
        {"sink_method": "System.load", "sink_file": "Util.java", "sink_line": 10},
    ])
    assert len(candidates) == 2  # 去重后 2 条
    assert all(c["source"] == "iast-blindspot-backfill" for c in candidates)
    assert candidates[0]["pattern"] == "Runtime.exec"


def test_a0_run_with_backfill(tmp_path):
    """§8.4 第3点端到端：run 带 iast_observed_entries 时回灌进 rule_candidates。"""
    proj = _make_flask_proj(tmp_path)
    svc = A0Service(entry_discovery=EntryDiscoveryService())
    result = svc.run(str(proj), iast_observed_entries=[{"sink_method": "os.system", "sink_file": "x.py", "sink_line": 7}])
    assert result["status"] == "completed"
    assert result["blindspot_backfill"]
    assert any(c.get("source") == "iast-blindspot-backfill" for c in result["rule_candidates"])
