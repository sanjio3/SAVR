# -*- coding: utf-8 -*-
"""回归锁：四档口径不得因解释器漂移而静默降级。

2026-11-08 本轮实测：L3 run2' 的发车轮由系统 Python 3.13（无 PyYAML）
启动，``run_validation_round.py`` 的 ``PY = sys.executable`` 让四档子进程也用
同一解释器。``jsc_four_tier.py`` 三处 try/except 降级同时生效：

- ``src.core.normalize`` 导入失败 → 族名不归一，静态·文件+族 30/31 → 29/31；
- ``src.core.spec_state_normalize`` 导入失败 → 属性/配置族不剔除，动态分母 24 → 31；
- ``yaml`` 缺失 → ``config/known_unreachable.yaml`` 读不到，物理不可达 4 个豁免丢失。

结果落盘文件写成「重放 23/31 = 74.2%」，而权威口径是「23/24 = 95.8%」。
锁定四条不变量：
  A. 执行器优先用项目 .venv 解释器，找不到才回退当前解释器；
  B. 四档子进程 exit != 0 时执行器 fail-closed，不把降级读数当正式产物；
  C. 四档脚本缺依赖时默认拒绝输出（exit=2），只有显式 --allow-degraded 才放行；
  D. 降级输出必须自带「不得作为正式口径引用」标记。
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import jsc_four_tier as ft  # noqa: E402
from tools import run_validation_round as rr  # noqa: E402


class _Completed:
    def __init__(self, stdout="", stderr="", rc=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = rc


def _capture(monkeypatch, tmp_path, completed):
    seen = []
    monkeypatch.setattr(rr.subprocess, "run",
                        lambda cmd, **kw: (seen.append(cmd), completed)[1])
    monkeypatch.setattr(rr, "RUNS", str(tmp_path))
    return seen


# ── A. 解释器绑定 ───────────────────────────────────────────────────────────

def test_project_python_prefers_venv(monkeypatch):
    real_isfile = os.path.isfile

    def fake_isfile(path):
        if ".venv" in str(path).replace("\\", "/"):
            return True
        return real_isfile(path)

    monkeypatch.setattr(rr.os.path, "isfile", fake_isfile)
    chosen = rr.project_python()
    assert ".venv" in chosen.replace("\\", "/")
    assert chosen != sys.executable or ".venv" in sys.executable


def test_project_python_falls_back_to_current_interpreter(monkeypatch):
    monkeypatch.setattr(rr.os.path, "isfile", lambda path: False)
    assert rr.project_python() == sys.executable


def test_four_tier_invokes_project_python(monkeypatch, tmp_path):
    seen = _capture(monkeypatch, tmp_path, _Completed("重放确认 0/1"))
    rr.four_tier(641, "jsc-round")
    assert seen[0][0] == rr.PY


# ── B. 子进程失败 fail-closed ───────────────────────────────────────────────

def test_four_tier_raises_when_subprocess_fails(monkeypatch, tmp_path):
    _capture(monkeypatch, tmp_path,
             _Completed("", "[fatal] 四档口径依赖缺失", rc=2))
    with pytest.raises(RuntimeError, match="four-tier failed rc=2"):
        rr.four_tier(641, "jsc-round")
    body = open(os.path.join(str(tmp_path), "jsc-round.four_tier.txt"),
                encoding="utf-8").read()
    assert "[fatal]" in body


def test_four_tier_still_writes_report_on_success(monkeypatch, tmp_path):
    _capture(monkeypatch, tmp_path, _Completed("重放确认         0/62"))
    path = rr.four_tier(641, "jsc-round")
    assert "重放确认" in open(path, encoding="utf-8").read()


# ── C/D. 四档脚本依赖预检 ───────────────────────────────────────────────────

def test_dependency_report_is_empty_in_project_env():
    assert ft.dependency_report() == []


def test_main_refuses_degraded_readings_by_default(monkeypatch, capsys):
    monkeypatch.setattr(ft, "dependency_report",
                        lambda: ["PyYAML: No module named 'yaml'"])
    monkeypatch.setattr(sys, "argv", ["jsc_four_tier.py", "--task-id", "641"])
    assert ft.main() == 2
    out = capsys.readouterr().out
    assert "[fatal]" in out
    assert "PyYAML" in out
    assert "拒绝输出" in out


def test_main_allows_degraded_only_with_explicit_flag(monkeypatch, capsys):
    monkeypatch.setattr(ft, "dependency_report", lambda: ["fake dep missing"])
    monkeypatch.setattr(ft, "load_task", lambda db_path, task_id: ([], []))
    truth = os.path.join(ROOT, "data", "java_sec_code_truth_v2.csv")
    monkeypatch.setattr(sys, "argv", ["jsc_four_tier.py", "--task-id", "641",
                                      "--truth", truth, "--allow-degraded"])
    assert ft.main() == 0
    out = capsys.readouterr().out
    assert "[警告] 降级模式" in out
    assert "不得作为正式口径引用" in out


def test_missing_attribute_is_reported(monkeypatch):
    """模块能导入但缺关键属性同样是口径风险，不能算「依赖齐备」。"""
    real_import = ft.importlib.import_module

    def fake_import(name):
        if name == "src.core.normalize":
            return object()  # 无 normalize_family 属性
        return real_import(name)

    monkeypatch.setattr(ft.importlib, "import_module", fake_import)
    missing = ft.dependency_report()
    assert any("缺属性 normalize_family" in m for m in missing)
