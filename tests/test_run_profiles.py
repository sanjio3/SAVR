# -*- coding: utf-8 -*-
"""回归锁：profile 纯展开，不得破坏 Gate 0 的 6 项 run_env 硬条件。

锁定不变量：
  A. 展开结果恰好 6 项、键集合与冻结基线完全一致、STAGE_CACHE=0；
  B. 多一项 / 少一项 / 换名 一律 fail-closed；
  C. B 区 tuning 绝不注入 run_env（否则变成第 7 项）；
  D. --profile 与 --env 互斥、workspace 冲突时 fail-closed；
  E. 占位符缺值 fail-closed，不猜默认值；{{name}} 替换进 dump 路径；
  F. 执行器落库 run_env 键集合不符时取消任务；
  G. 发车前 preflight 未通过时拒绝提交、豁免需显式留痕。
"""
import copy
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import run_profiles as rp  # noqa: E402
from tools import run_validation_round as rr  # noqa: E402

BASE_KEYS = set(rp.BASELINE_RUN_ENV_KEYS)


def _profile(**over):
    p = {
        "_name": "unit",
        "workspace_id": 4,
        "truth": "",
        "probe": {"app_name": "sec-code", "agent_id": "java-sec-code"},
        "run_env": {
            "SAST_AI_DESER_YSOSERIAL": "1",
            "SAST_AI_SHIRO_KEY": "kPH+test",
            "YSO_JAVA_HOME": "D:/jdk65",
            "SAST_AI_D1_DUMP_REQ": "1",
            "SAST_AI_D1_DUMP_PATH": "logs/d1_req_dump_{{name}}.jsonl",
            "SAST_AI_STAGE_CACHE": "0",
        },
        "tuning": {"SAST_AI_A2_LLM_NUM_PREDICT": 1024},
        "gpu": {"min_free_mib": 6200, "max_util_pct": 40},
    }
    p.update(over)
    return p


def test_baseline_is_exactly_six_keys():
    assert len(rp.BASELINE_RUN_ENV_KEYS) == 6
    assert "SAST_AI_STAGE_CACHE" in BASE_KEYS


def test_expand_yields_exactly_six_items_in_order():
    out = rp.expand_run_env(_profile(), "jsc-R1")
    assert len(out) == 6
    assert [kv.split("=", 1)[0] for kv in out] == list(rp.BASELINE_RUN_ENV_KEYS)
    assert dict(kv.split("=", 1) for kv in out)["SAST_AI_STAGE_CACHE"] == "0"
    assert "logs/d1_req_dump_jsc-R1.jsonl" in out[4]


def test_tuning_never_leaks_into_run_env():
    out = rp.expand_run_env(_profile(), "jsc-R1")
    assert all("NUM_PREDICT" not in kv and "PROMPT_TOKENS" not in kv for kv in out)
    assert len(out) == 6


def test_extra_key_fail_closed():
    p = _profile()
    p["run_env"]["SAST_AI_A2_LLM_NUM_PREDICT"] = "1024"
    with pytest.raises(rp.ProfileError) as ei:
        rp.expand_run_env(p, "jsc-R1")
    assert "多出" in str(ei.value)


def test_missing_key_fail_closed():
    p = _profile()
    del p["run_env"]["SAST_AI_STAGE_CACHE"]
    with pytest.raises(rp.ProfileError) as ei:
        rp.expand_run_env(p, "jsc-R1")
    assert "缺少" in str(ei.value)


def test_stage_cache_nonzero_fail_closed():
    p = _profile()
    p["run_env"]["SAST_AI_STAGE_CACHE"] = "1"
    with pytest.raises(rp.ProfileError) as ei:
        rp.expand_run_env(p, "jsc-R1")
    assert "STAGE_CACHE" in str(ei.value)


def test_no_run_env_profile_cannot_drive_executor():
    with pytest.raises(rp.ProfileError) as ei:
        rp.expand_run_env({"_name": "owasp"}, "x")
    assert "不能用于" in str(ei.value)


def test_placeholder_missing_fails_closed():
    p = _profile()
    p["run_env"]["SAST_AI_SHIRO_KEY"] = "${SAST_AI_UNSET_UNIT_KEY}"
    with pytest.raises(rp.ProfileError) as ei:
        rp.expand_run_env(p, "jsc-R1", environ={})
    assert "未提供" in str(ei.value)


def test_placeholder_resolves_from_environ():
    p = _profile()
    p["run_env"]["SAST_AI_SHIRO_KEY"] = "${MY_TEST_KEY}"
    out = rp.expand_run_env(p, "jsc-R1", environ={"MY_TEST_KEY": "value-xyz"})
    assert "SAST_AI_SHIRO_KEY=value-xyz" in out


def test_partial_placeholder_rejected():
    p = _profile()
    p["run_env"]["YSO_JAVA_HOME"] = "prefix-${MY_TEST_KEY}"
    with pytest.raises(rp.ProfileError) as ei:
        rp.expand_run_env(p, "jsc-R1", environ={"MY_TEST_KEY": "x"})
    assert "不支持的占位符" in str(ei.value)


def test_round_name_sanitized():
    with pytest.raises(rp.ProfileError):
        rp.expand_run_env(_profile(), "../../etc/passwd")


def test_tuning_drift_is_reported_not_applied():
    p = _profile()
    p["tuning"]["SAST_AI_A2_LLM_NUM_PREDICT"] = 4096
    drift = rp.check_tuning_drift(p)
    assert drift and "不注入" in drift[0]
    # drift 只报不改：展开仍是 6 项
    assert len(rp.expand_run_env(p, "jsc-R1")) == 6


def test_local_config_is_gitignored():
    gitignore = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
    assert "config/run_profiles.local.yaml" in gitignore


def test_shipped_template_has_no_plaintext_secret():
    text = open(os.path.join(ROOT, "config", "run_profiles.yaml"),
                encoding="utf-8").read()
    assert "kPH+bIxk5D2deZiIxcaaaA==" not in text
    assert "${SAST_AI_SHIRO_KEY}" in text
    assert "SAST_AI_PROBE_TOKEN" not in text.split("profiles:")[1]


# ---------------------------------------------------------------- 执行器接线
def test_preflight_helper_uses_workspace_enumeration(monkeypatch):
    seen = {}

    def fake(ws, **kw):
        seen.update({"ws": ws, **kw})
        return {"ready": True}

    monkeypatch.setattr(pp_target(), "preflight_workspace", fake)
    r = rr.run_probe_preflight(_profile(), 4, do_http=False)
    assert r["ready"] is True and seen["ws"] == 4


def pp_target():
    from tools import probe_preflight
    return probe_preflight


def test_profile_and_env_are_mutually_exclusive(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sys, "argv", [
        "run_validation_round.py", "--name", "x", "--profile", "jsc",
        "--env", "FOO=1", "--no-submit"])
    # 互斥在 GPU 闸门之前判定，无需 mock 闸门
    monkeypatch.setattr(rr, "wait_gate", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("不应走到 GPU 闸门")))
    assert rr.main() == 5


def test_workspace_conflict_fail_closed(monkeypatch):
    monkeypatch.setattr(sys, "argv", [
        "run_validation_round.py", "--name", "x", "--profile", "jsc",
        "--workspace-id", "8", "--no-submit"])
    monkeypatch.setattr(rr, "wait_gate", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("不应走到 GPU 闸门")))
    assert rr.main() == 5


def test_executor_expands_profile_without_submit(monkeypatch, capsys):
    """--no-submit 跳过 preflight 与提交；profile 展开仍须成功。"""
    # profile 的敏感值用 ${ENV} 占位符，加载器 fail-closed 不猜默认值。
    # 显式给出，避免依赖本机环境（干净 clone / CI 上没有本机的 local.yaml）。
    monkeypatch.setenv("SAST_AI_SHIRO_KEY", "unit-test-placeholder")
    monkeypatch.setenv("YSO_JAVA_HOME", os.path.join(ROOT, "probe-java"))
    monkeypatch.setattr(sys, "argv", [
        "run_validation_round.py", "--name", "jsc-smoke", "--profile", "jsc",
        "--no-submit", "--gate-wait-minutes", "0"])
    monkeypatch.setattr(rr, "wait_gate", lambda *a, **k: None)
    assert rr.main() == 3  # 闸门超时，但已证明 profile 阶段无异常


def test_owasp_profile_has_no_run_env():
    """OWASP 分片链不走 run_validation_round，禁止套用 Gate 0 的 6 项。"""
    prof = rp.load_profile("owasp-full")
    assert "run_env" not in prof or not prof["run_env"]
    assert prof["workspace_id"] == 7
    assert prof["probe"]["agent_id"] == "owasp-benchmark-full"
