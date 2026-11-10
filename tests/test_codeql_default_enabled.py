"""CodeQL 默认启用 + 链路修复验收（2026-10-20）。

修复三处：
  1. 内存固定 3-4GB（实测单查询 3GB/40.5s 成功；之前 6-16GB 导致 40 次 OOM）；
  2. 官方套件与自定义 .ql 隔离（analyze_extra，失败不影响官方结果）；
  3. finalize 显式校验（既有逻辑，本次验证）。
默认启用；SAST_AI_DISABLE_CODEQL=1 可禁用。
"""
import importlib

import pytest


@pytest.fixture()
def adapter_mod():
    return importlib.import_module("src.agents.a1_codeql_adapter")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SAST_AI_DISABLE_CODEQL", raising=False)
    monkeypatch.delenv("SAST_AI_ENABLE_CODEQL", raising=False)


def test_enabled_by_default_with_existing_bin(adapter_mod, tmp_path):
    f = tmp_path / "codeql"
    f.write_text("", encoding="utf-8")
    a = adapter_mod.CodeQLAdapter(codeql_bin=str(f))
    assert a.is_available() is True


def test_disabled_by_env(adapter_mod, monkeypatch, tmp_path):
    monkeypatch.setenv("SAST_AI_DISABLE_CODEQL", "1")
    f = tmp_path / "codeql"
    f.write_text("", encoding="utf-8")
    a = adapter_mod.CodeQLAdapter(codeql_bin=str(f))
    assert a.is_available() is False


def test_missing_bin_not_available(adapter_mod):
    a = adapter_mod.CodeQLAdapter(codeql_bin="C:/nonexistent/codeql")
    assert a.is_available() is False


def test_ram_budget_fixed_4gb(adapter_mod):
    """固定 4GB：3GB 时 TaintedPath 因 heap 仅 1344MB OOM，4GB 实测 11.2s 成功。"""
    assert adapter_mod.CodeQLAdapter._RAM_MIN_MB == 4096
    assert adapter_mod.CodeQLAdapter._RAM_MAX_MB == 4096


def test_analyze_extra_skipped_when_no_queries(adapter_mod, tmp_path):
    f = tmp_path / "codeql"
    f.write_text("", encoding="utf-8")
    a = adapter_mod.CodeQLAdapter(codeql_bin=str(f))
    r = a.analyze_extra(str(tmp_path), [])
    assert r["status"] == "skipped"


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
