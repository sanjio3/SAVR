"""A1 外接 CodeQL 链路的两个真 bug 修复 + 自定义查询接入的回归守卫。

背景（2026-09-25 生产取证，benchmark-sample-200 / CodeQL CLI 2.23.9）：
1. ``codeql database create`` 不保证完成 finalize，未 finalize 的库执行 analyze 直接报
   "needs to be finalized before running queries" —— 实测三个项目（benchmark / target-mall /
   java-sec-code）的 .codeql-db 全部停在未 finalize 状态，且全盘找不到任何 .sarif，
   等于 CodeQL 通过平台从未产出过结果，A1 每次都静默回落到启发式兜底。
2. 适配器默认套件写的是裸名 ``security-extended``，CLI 2.23+ 只认 ``<language>-<suite>``，
   实测报 "Query pack security-extended cannot be found"。

本测试锁死这两处修复，以及自定义 .ql 查询接入与五族 rule-id → 族名映射。
"""
import os
from pathlib import Path

import pytest

from src.agents.a1_codeql_adapter import CodeQLAdapter
from src.agents.a1_codeql_semantic_agent import _map_rule_to_family


@pytest.fixture(autouse=True)
def _enable_codeql(monkeypatch):
    """2026-10-20：CodeQL 默认禁用（r113 实测 100% fallback），本文件测其自身行为，需显式开启。"""
    monkeypatch.setenv("SAST_AI_ENABLE_CODEQL", "1")


@pytest.fixture(autouse=True)
def _codeql_bin_present(monkeypatch):
    """构造适配器时会校验 codeql 可执行路径是否存在，否则视为不可用。

    本组测试测的是「命令拼装与内存护栏」，与开发机是否真装了 CodeQL 无关。此前用
    开发机上的绝对路径当样例，在没装 CodeQL 的机器（CI）上整组 4 例全挂在
    "cmd 未被捕获" 上 —— 依赖开发机环境的测试在干净环境里必然失真。
    故让该路径判定为存在，解除与被测逻辑无关的环境前置条件。
    """
    real_exists = Path.exists

    def _exists(self):
        if "codeql-home" in str(self).replace("\\", "/"):
            return True
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", _exists)


def _adapter() -> CodeQLAdapter:
    return CodeQLAdapter(codeql_bin="D:/codeql-home/codeql/codeql.exe")


# ---- bug 2：套件简写名必须规范化成 <language>-<suite> ----

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("security-extended", "java-security-extended"),
        (None, "java-security-extended"),
        ("experimental", "java-security-experimental"),
        ("security-and-quality", "java-security-and-quality"),
        ("java-security-extended", "java-security-extended"),
    ],
)
def test_suite_normalization(raw, expected):
    assert CodeQLAdapter._normalize_suite(raw, "java") == expected


def test_suite_normalization_keeps_explicit_path():
    p = "D:/x/java-security-extended.qls"
    assert CodeQLAdapter._normalize_suite(p, "java") == p


# ---- bug 1：未 finalize 的库必须能被识别出来 ----

def test_is_finalized_detects_inprogress(tmp_path):
    db = tmp_path / ".codeql-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text(
        "sourceLocationPrefix: x\ninProgress:\n  primaryLanguage: java\n", encoding="utf-8"
    )
    assert CodeQLAdapter._is_finalized(str(db)) is False


def test_is_finalized_detects_done(tmp_path):
    db = tmp_path / ".codeql-db"
    db.mkdir()
    (db / "codeql-database.yml").write_text(
        "sourceLocationPrefix: x\nprimaryLanguage: java\n", encoding="utf-8"
    )
    assert CodeQLAdapter._is_finalized(str(db)) is True


def test_is_finalized_missing_dir_is_false(tmp_path):
    assert CodeQLAdapter._is_finalized(str(tmp_path / "nope")) is False


# ---- 自定义查询接入 ----

def test_custom_queries_present():
    qs = CodeQLAdapter.custom_queries()
    names = {Path(q).name for q in qs}
    assert "WeakHashAlgorithm.ql" in names  # 官方 CWE-328 目录为空，由本查询补齐


def test_analyze_isolates_extra_queries(monkeypatch):
    """2026-10-20：自定义 .ql 与官方套件隔离——analyze 不含 extra，analyze_extra 单独带。

    r113 实证混跑会让整轮 analyze exit 1、官方结果一起丢。
    """
    a = _adapter()
    captured = []

    def fake_run(cmd, **kw):
        captured.append(cmd)
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    a.analyze("/tmp/db", extra_queries=["/q/A.ql", "/q/B.ql"])
    main_cmd = captured[-1]
    assert "/q/A.ql" not in main_cmd  # 官方套件命令不含自定义查询
    assert any(x.startswith("--threads=") for x in main_cmd)

    a.analyze_extra("/tmp/db", ["/q/A.ql", "/q/B.ql"])
    extra_cmd = captured[-1]
    assert "/q/A.ql" in extra_cmd and "/q/B.ql" in extra_cmd
    assert any(x.startswith("--threads=") for x in extra_cmd)


def _fake_commit_stats(monkeypatch, commit_free_mb, avail_mb):
    """注入假 _commit_stats_mb，控制 CommitFree 与物理可用读数（Windows 主路径）。"""
    a_cls = CodeQLAdapter
    monkeypatch.setattr(
        a_cls,
        "_commit_stats_mb",
        classmethod(lambda cls: (commit_free_mb + 8192, commit_free_mb, avail_mb)),
    )


# ---- ram 动态预算（task-6 复盘：固定 --ram=4096 拆出 1800M 堆，编译分层 OOM）----

def test_ram_dynamic_budget_within_clamp(monkeypatch):
    """默认路径：动态预算，clamp 到 [3072, 4096]（2026-10-20 固定 3-4GB）。"""
    _fake_commit_stats(monkeypatch, commit_free_mb=30000, avail_mb=25000)
    a = _adapter()  # 未显式配置 ram → 动态
    ram = a._resolve_ram_mb()
    assert 3072 <= ram <= 4096

    captured = {}
    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class R:
            returncode = 0
        return R()
    monkeypatch.setattr("subprocess.run", fake_run)
    a.analyze("/tmp/db")
    ram_flags = [x for x in captured["cmd"] if x.startswith("--ram=")]
    assert len(ram_flags) == 1
    assert ram_flags[0] == f"--ram={ram}"


def test_ram_fixed_4gb_even_when_tight(monkeypatch):
    """2026-10-20：固定 4GB，即使 CommitFree 紧张也传 --ram=4096（不再交自适应）。"""
    _fake_commit_stats(monkeypatch, commit_free_mb=5000, avail_mb=4000)
    a = _adapter()
    assert a._resolve_ram_mb() == 4096

    captured = {}
    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class R:
            returncode = 0
        return R()
    monkeypatch.setattr("subprocess.run", fake_run)
    a.analyze("/tmp/db")
    assert any(x == "--ram=4096" for x in captured["cmd"])


def test_ram_commit_stats_reads_real_commit(monkeypatch):
    """Windows 上 _commit_stats_mb 必须返回 (CommitLimit, CommitFree, PhysAvail)，
    且 CommitLimit 应接近 物理内存+页面文件（本机 32GB+8GB≈40.6GB），不得是纯页面文件量。"""
    stats = CodeQLAdapter._commit_stats_mb()
    if stats is None:
        pytest.skip("non-Windows or API unavailable")
    limit_mb, free_mb, avail_mb = stats
    assert limit_mb > 16384  # 纯页面文件读数是 8192，CommitLimit 必然大于此
    assert 0 < free_mb <= limit_mb
    assert avail_mb > 0


def test_ram_explicit_override(monkeypatch):
    """显式配置（入参/环境变量）优先于动态计算。"""
    a = CodeQLAdapter(codeql_bin="D:/codeql-home/codeql/codeql.exe", ram_mb=8192)
    assert a._resolve_ram_mb() == 8192
    a2 = CodeQLAdapter(codeql_bin="D:/codeql-home/codeql/codeql.exe", ram_mb="0")
    assert a2._resolve_ram_mb() == 0


def test_ram_zero_disables_flag(monkeypatch):
    """CODEQL_RAM_MB=0 / ram_mb=0：analyze 不传 --ram，交 CodeQL 按机器自适应。"""
    a = CodeQLAdapter(codeql_bin="D:/codeql-home/codeql/codeql.exe", ram_mb=0)
    captured = {}
    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class R:
            returncode = 0
        return R()
    monkeypatch.setattr("subprocess.run", fake_run)
    a.analyze("/tmp/db")
    assert not any(x.startswith("--ram=") for x in captured["cmd"])


def test_ram_fixed_4gb_regardless_of_stats(monkeypatch):
    """2026-10-20：固定 4GB，不再依赖 CommitFree/psutil 动态计算（动态会返回 0 不传 --ram）。"""
    monkeypatch.setattr(CodeQLAdapter, "_commit_stats_mb", classmethod(lambda cls: None))
    a = _adapter()
    assert a._resolve_ram_mb() == 4096


# ---- 族映射登记：Benchmark 五族 + 自定义查询 id ----

@pytest.mark.parametrize(
    "rule_id,expected_family",
    [
        # 2026-11-01 修正：这里原先断言的是 crypto / weakrand / hash —— 那是
        # **OWASP 真值 CSV 的类目名**，不是平台族名，`is_known_family` 全为 False，
        # D2 拿不到证明模板。本轮实测代价：no-arrival 2→117、confirmed 212→140。
        # 平台族是 weak_crypto / weak_random / weak_hash。
        # securecookie / trustbound 两个旧 token 可以保留（normalize_family 会归一）。
        ("java/weak-cryptographic-algorithm", "weak_crypto"),
        ("java/insecure-randomness", "weak_random"),
        ("java/insecure-cookie", "securecookie"),
        ("java/sensitive-cookie-not-httponly", "securecookie"),
        ("java/trust-boundary-violation", "trustbound"),
        ("sastai/java/weak-hash-algorithm", "weak_hash"),
    ],
)
def test_five_families_and_custom_ids_map(rule_id, expected_family):
    assert _map_rule_to_family(rule_id, "") == expected_family
