"""配置注册表单测（2026-10-20）。

验收：yaml 加载、env 覆盖优先级、族白名单与代码默认一致、describe 可观测。
"""
import importlib

import pytest


@pytest.fixture()
def reg():
    return importlib.import_module("src.core.config_registry")


@pytest.fixture(autouse=True)
def _clear_cache(reg):
    # config_registry 现读不缓存；cache_clear 已不存在，安全 no-op 以兼容。
    def _clr():
        for fn in ("codeql_config", "families_config"):
            cc = getattr(getattr(reg, fn, None), "cache_clear", None)
            if callable(cc):
                cc()
    _clr()
    yield
    _clr()


def test_codeql_defaults(reg, monkeypatch):
    monkeypatch.delenv("SAST_AI_DISABLE_CODEQL", raising=False)
    monkeypatch.delenv("CODEQL_RAM_MB", raising=False)
    assert reg.codeql_enabled() is True
    assert reg.codeql_ram_mb() == 4096
    assert reg.codeql_threads() == 2
    assert reg.codeql_suite() == "java-security-extended"


def test_env_override_ram(reg, monkeypatch):
    monkeypatch.setenv("CODEQL_RAM_MB", "2048")
    assert reg.codeql_ram_mb() == 2048


def test_env_disable_codeql(reg, monkeypatch):
    monkeypatch.setenv("SAST_AI_DISABLE_CODEQL", "1")
    assert reg.codeql_enabled() is False


def test_env_override_bin(reg, monkeypatch):
    monkeypatch.setenv("CODEQL_BIN", "/tmp/codeql")
    assert reg.codeql_bin_path() == "/tmp/codeql"


def test_strict_c_families(reg):
    fams = reg.strict_c_families()
    assert "xpath_injection" in fams
    assert "xss" in fams
    # 硬边界：path_traversal 绝不纳入 strict-C
    assert "path_traversal" not in fams


def test_confirm_sink_families(reg):
    assert set(reg.confirm_sink_families()) == {"xpath_injection", "trust_boundary_violation"}


def test_value_gate_families(reg):
    fams = reg.value_gate_families()
    assert "path_traversal" in fams
    assert "sql_injection" in fams


def test_describe(reg):
    d = reg.describe()
    assert d["codeql.memory"]["ram_mb"] == 4096
    assert d["codeql.suite"] == "java-security-extended"
    assert d["families.confirm_sink"] == ["xpath_injection", "trust_boundary_violation"]


def test_default_fallback_when_yaml_missing(reg, monkeypatch):
    """yaml 缺失时回退代码默认，不抛异常。"""
    monkeypatch.setattr(reg, "CONFIG_DIR", "/nonexistent/config")
    assert reg.codeql_ram_mb(default=4096) == 4096
    assert reg.strict_c_families(default=["x"]) == ["x"]


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
