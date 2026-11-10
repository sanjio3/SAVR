# -*- coding: utf-8 -*-
"""运行 profile 加载器：把「6 项 run_env 手敲」收敛成 ``--profile jsc``。

设计红线（对齐 Gate 0 有效轮判据，见 docs/gate0_release_criteria.md）：

- **纯展开，不推断、不合并**：``--profile`` 与 ``--env`` 互斥；profile 里的
  ``run_env`` 必须**恰好**是基线 6 项，多一项少一项都 fail-closed；
- **A 区（正确性硬依赖）**逐项展开成 ``--env KEY=VALUE`` 落库，作为有效轮审计证据；
- **B 区（性能调节）不注入 run_env**：``num_predict`` 等是组件代码默认值，
  写进 run_env 会变成第 7 项，直接破坏「6 项 run_env」硬条件。B 区只做
  「配置声明值 vs 代码默认值」的一致性校验，不一致就报 drift，不静默覆盖；
- **探针 token 无默认**：profile 里只有三元组，不存任何凭据；
- **豁免开关不进 profile**：``--no-replay-env`` / ``--allow-degraded`` 等
  只能显式在命令行给，避免默认放行被误读成有效轮。

配置文件分两层：``config/run_profiles.yaml`` 是可入库的脱敏模板
（敏感/本机相关值用 ``${ENV_VAR}`` 占位）；``config/run_profiles.local.yaml``
被 gitignore，本机可写明文，加载器优先读它。占位符从 ``os.environ`` 解析，
缺变量 fail-closed，不猜默认值。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(ROOT, "config")
TEMPLATE = os.path.join(CONFIG_DIR, "run_profiles.yaml")
LOCAL = os.path.join(CONFIG_DIR, "run_profiles.local.yaml")

# Gate 0 冻结的 6 项 run_env（docs/validation_run_state_20261106.md:242）。
# 顺序固定，保证落库 options_json.run_env 可复现、可对账。
BASELINE_RUN_ENV_KEYS: Tuple[str, ...] = (
    "SAST_AI_DESER_YSOSERIAL",
    "SAST_AI_SHIRO_KEY",
    "YSO_JAVA_HOME",
    "SAST_AI_D1_DUMP_REQ",
    "SAST_AI_D1_DUMP_PATH",
    "SAST_AI_STAGE_CACHE",
)

# B 区：代码里的默认值（src/agents/a2_integrated_analyst.py 等），只用于 drift 校验。
CODE_TUNING_DEFAULTS: Dict[str, Any] = {
    "SAST_AI_A2_LLM_NUM_PREDICT": 1024,
    "SAST_AI_A2_LLM_TIMEOUT": 300,
    "SAST_AI_A2_LLM_RETRIES": 2,
    "SAST_AI_A2_LLM_CIRCUIT_BREAK": 3,
    "SAST_AI_A2_PROMPT_TOKENS": 7000,
}

_ENV_PLACEHOLDER = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_NAME_PLACEHOLDER = "{{name}}"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class ProfileError(RuntimeError):
    """profile 不存在 / 结构非法 / 占位符未解析。调用方必须 fail-closed。"""


def _project_python() -> str:
    for parts in ((".venv", "Scripts", "python.exe"), (".venv", "bin", "python")):
        cand = os.path.join(ROOT, *parts)
        if os.path.isfile(cand):
            return cand
    return sys.executable


def _safe_load_yaml(path: str) -> Dict[str, Any]:
    """读 YAML；当前解释器缺 PyYAML 时改用项目 .venv 解析（解释器漂移防线）。

    绝不静默降级成「空配置」：解析失败一律抛 ProfileError。
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        code = ("import json,sys,yaml;"
                "print(json.dumps(yaml.safe_load(open(sys.argv[1],encoding='utf-8'))))")
        out = subprocess.run([_project_python(), "-c", code, path],
                             capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            raise ProfileError("用 .venv 解析 %s 失败：%s"
                               % (path, (out.stderr or out.stdout or "")[-300:]))
        try:
            return json.loads(out.stdout)
        except Exception as exc:  # noqa: BLE001
            raise ProfileError("profile YAML 解析结果非法：%s" % exc) from exc
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001
        raise ProfileError("读取 %s 失败：%s" % (path, exc)) from exc
    if not isinstance(data, dict):
        raise ProfileError("%s 顶层必须是 mapping" % path)
    return data


def config_source(path: Optional[str] = None) -> str:
    """返回实际生效的配置文件路径：显式 path > 本机 local > 模板。"""
    if path:
        if not os.path.isfile(path):
            raise ProfileError("指定的 profile 文件不存在：%s" % path)
        return path
    if os.path.isfile(LOCAL):
        return LOCAL
    if os.path.isfile(TEMPLATE):
        return TEMPLATE
    raise ProfileError("未找到 profile 配置：%s 与 %s 都不存在" % (LOCAL, TEMPLATE))


def load_all(path: Optional[str] = None) -> Dict[str, Any]:
    src = config_source(path)
    data = _safe_load_yaml(src)
    if int(data.get("version") or 0) != 1:
        raise ProfileError("%s 的 version 必须为 1" % src)
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ProfileError("%s 缺少非空 profiles 段" % src)
    return profiles


def load_profile(name: str, path: Optional[str] = None) -> Dict[str, Any]:
    profiles = load_all(path)
    if name not in profiles:
        raise ProfileError("未知 profile %r；可选：%s"
                           % (name, ", ".join(sorted(profiles))))
    prof = profiles[name]
    if not isinstance(prof, dict):
        raise ProfileError("profile %r 必须是 mapping" % name)
    prof = dict(prof)
    prof["_name"] = name
    prof["_source"] = config_source(path)
    return prof


def _resolve_placeholders(value: Any, environ: Dict[str, str]) -> str:
    text = str(value)
    m = _ENV_PLACEHOLDER.match(text.strip())
    if m:
        key = m.group(1)
        if key not in environ or not str(environ[key]).strip():
            raise ProfileError(
                "占位符 ${%s} 未提供：请在环境变量或 config/run_profiles.local.yaml "
                "里给出真实值；加载器不猜默认值" % key)
        return str(environ[key]).strip()
    if "${" in text:
        raise ProfileError("不支持的占位符写法：%r（只允许 ${VAR} 整段占位）" % text)
    return text


def expand_run_env(profile: Dict[str, Any], round_name: str, *,
                   environ: Optional[Dict[str, str]] = None) -> List[str]:
    """把 A 区展开成逐项 ``KEY=VALUE``；断言键集合 == 基线 6 项。"""
    env = dict(os.environ if environ is None else environ)
    raw = profile.get("run_env")
    if not isinstance(raw, dict):
        raise ProfileError(
            "profile %r 没有 run_env 段，不能用于 run_validation_round.py 发车；"
            "该 profile 只供 preflight / 分片脚本使用" % profile.get("_name"))
    keys = set(raw)
    expected = set(BASELINE_RUN_ENV_KEYS)
    if keys != expected:
        raise ProfileError(
            "profile %r 的 run_env 键集合与 Gate 0 基线 6 项不一致："
            "缺少=%s 多出=%s。禁止合并/新增/丢项"
            % (profile.get("_name"), sorted(expected - keys), sorted(keys - expected)))
    if not _SAFE_NAME.match(round_name or ""):
        raise ProfileError("--name 只允许 [A-Za-z0-9._-]，拒绝 %r（会进 dump 路径）"
                           % round_name)
    out: List[str] = []
    for key in BASELINE_RUN_ENV_KEYS:
        value = _resolve_placeholders(raw[key], env)
        value = value.replace(_NAME_PLACEHOLDER, round_name)
        if not value:
            raise ProfileError("run_env.%s 展开后为空" % key)
        out.append("%s=%s" % (key, value))
    if str(_resolve_placeholders(raw["SAST_AI_STAGE_CACHE"], env)) != "0":
        raise ProfileError("SAST_AI_STAGE_CACHE 必须显式为 0（代码默认是 1）")
    return out


def check_tuning_drift(profile: Dict[str, Any]) -> List[str]:
    """B 区只校验不注入：返回声明值与代码默认值的 drift 描述列表。"""
    tuning = profile.get("tuning") or {}
    if not isinstance(tuning, dict):
        return ["tuning 段必须是 mapping"]
    drift: List[str] = []
    for key, declared in tuning.items():
        if key in CODE_TUNING_DEFAULTS and str(CODE_TUNING_DEFAULTS[key]) != str(declared):
            drift.append("%s: 配置声明 %r，代码默认 %r（B 区不注入 run_env，"
                         "要改请改代码默认值）"
                         % (key, declared, CODE_TUNING_DEFAULTS[key]))
    return drift


def gpu_args(profile: Dict[str, Any]) -> Tuple[Optional[int], Optional[int]]:
    gpu = profile.get("gpu") or {}
    if not isinstance(gpu, dict):
        raise ProfileError("gpu 段必须是 mapping")
    return gpu.get("min_free_mib"), gpu.get("max_util_pct")


def describe(name: str, path: Optional[str] = None) -> Dict[str, Any]:
    """给 CLI / 文档用的脱敏摘要。"""
    prof = load_profile(name, path)
    return {
        "name": name,
        "source": prof["_source"],
        "workspace_id": prof.get("workspace_id"),
        "truth": prof.get("truth", ""),
        "probe": prof.get("probe") or {},
        "run_env_keys": list(BASELINE_RUN_ENV_KEYS) if prof.get("run_env") else [],
        "tuning_drift": check_tuning_drift(prof),
        "gpu": prof.get("gpu") or {},
        "note": prof.get("note", ""),
    }


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="查看/校验运行 profile")
    ap.add_argument("name", nargs="?", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--config", default="")
    args = ap.parse_args()
    try:
        if args.list or not args.name:
            profiles = load_all(args.config or None)
            print(json.dumps({"source": config_source(args.config or None),
                              "profiles": sorted(profiles)},
                             ensure_ascii=False, indent=2))
            return 0
        print(json.dumps(describe(args.name, args.config or None),
                         ensure_ascii=False, indent=2))
        return 0
    except ProfileError as exc:
        print("[profile][FATAL] %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
