"""POC 记忆库种子化（A 第一步，2026-09-28 批准落地）。

把确定性模板资产结构化导出为 poc_memory.json 正样本：
- d2_strategy._PROFILE_DEFAULTS（各族默认参数/payload/期望信号）
- d2_strategy._LANGUAGE_PROFILE_OVERRIDES（语言级覆写）
- d2_strategy._VERIFY_ROUTES（各 (语言, 族) 的验证链路名称）

种子样本 verified=True（记忆库只收正样本），observation="template_seed"，
framework 维度：_PROFILE_DEFAULTS 记 any（跨语言兜底），overrides 记对应语言，
_VERIFY_ROUTES 记对应语言。同 key 同 shape 幂等（重复执行只刷 hit_count）。

用法：python scripts/seed_poc_memory.py [--force]（--force 忽略已有样本重复刷写）
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.agents.d2_strategy import _PROFILE_DEFAULTS, _LANGUAGE_PROFILE_OVERRIDES, _VERIFY_ROUTES
from src.agents.poc_memory_store import default_store, normalize_sink_signature


def _plan_for(family: str, profile: dict, verify: str = "", lang: str = "") -> dict:
    """把 profile dict 组装成 attack_plan 结构（与 few-shot 消费字段对齐）。"""
    parameter = str(profile.get("parameter") or "")
    payload = str(profile.get("payload") or "")
    transport = str(profile.get("transport") or "param")
    expected = str(profile.get("expected") or "")
    baseline = str(profile.get("baseline") or "")
    steps = []
    if baseline:
        steps.append(f"先以合法基线值请求参数 {parameter}（baseline={baseline}），记录正常响应。")
    if payload:
        shape = "请求体" if transport == "body" or transport == "json" else "请求参数"
        steps.append(f"通过{shape} {parameter} 投放 payload：{payload[:120]}")
    if expected:
        steps.append(f"在响应中检索成功信号：{expected[:80]}")
    if verify:
        steps.append(f"按验证链路 {verify} 完成确定性复核。")
    return {
        "business_goal": f"验证目标是否存在 {family} 漏洞（模板种子）",
        "input_role": parameter or "attacker-controlled input",
        "delivery_shape": f"{'JSON 请求体' if transport in ('body', 'json') else 'GET/POST 请求参数'} {parameter}",
        "trigger_condition": "payload 到达对应 sink 且未被源头过滤",
        "verification_signal": expected or "响应中包含 payload 的可观测效果",
        "steps": steps or ["投放默认 payload 并观察响应差异。"],
        "constraints": [
            "payload 为模板默认值，实际执行时以 exploit_spec 的候选 payload 为准。",
            f"种子来源：{'language override' if lang else 'profile default'}",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="忽略幂等去重，强制刷写样本")
    args = ap.parse_args()

    store = default_store()
    before = store.size()

    # 1) _PROFILE_DEFAULTS：framework=any 兜底桶
    for family, profile in _PROFILE_DEFAULTS.items():
        verify = (_VERIFY_ROUTES.get(("java", family)) or ("", ""))[0]
        plan = _plan_for(family, profile, verify=verify)
        store.record({
            "family": family,
            "framework": "any",
            "sink_signature": normalize_sink_signature(family, family, ""),
            "canary_form": "plain",
            "attack_shape": f"seed:{family}",
            "attack_plan": plan,
            "exploit_spec_summary": {
                "family": family,
                "parameter": profile.get("parameter"),
                "payload": str(profile.get("payload") or "")[:120],
                "expected": profile.get("expected"),
                "transport": profile.get("transport", "param"),
            },
            "observation": "template_seed",
            "verified": True,
        })
        if args.force:
            # record 按 (canary_form, attack_shape) 幂等合并，force 语义即重复执行刷 hit_count/observation
            store.record({
                "family": family, "framework": "any",
                "sink_signature": normalize_sink_signature(family, family, ""),
                "canary_form": "plain", "attack_shape": f"seed:{family}",
                "attack_plan": plan, "observation": "template_seed(refresh)", "verified": True,
            })

    # 2) _LANGUAGE_PROFILE_OVERRIDES：framework=语言
    for (lang, family), profile in _LANGUAGE_PROFILE_OVERRIDES.items():
        verify = (_VERIFY_ROUTES.get((lang, family)) or ("", ""))[0]
        plan = _plan_for(family, profile, verify=verify, lang=lang)
        store.record({
            "family": family,
            "framework": lang,
            "sink_signature": normalize_sink_signature(family, family, ""),
            "canary_form": "plain",
            "attack_shape": f"seed:{lang}:{family}",
            "attack_plan": plan,
            "exploit_spec_summary": {
                "family": family,
                "parameter": profile.get("parameter"),
                "payload": str(profile.get("payload") or "")[:120],
                "expected": profile.get("expected"),
                "language": lang,
            },
            "observation": "template_seed",
            "verified": True,
        })

    # 3) _VERIFY_ROUTES：仅补验证链路信息（没有 payload 的语言/族组合）
    for (lang, family), (verify, label) in _VERIFY_ROUTES.items():
        plan = {
            "business_goal": f"验证目标是否存在 {family} 漏洞（{label}）",
            "input_role": "attacker-controlled input",
            "delivery_shape": "由 exploit_spec 决定",
            "trigger_condition": "payload 到达对应 sink 且未被源头过滤",
            "verification_signal": f"由 {verify} 链路判定",
            "steps": [f"执行验证链路 {verify}。"],
            "constraints": [f"种子来源：verify route（{lang}/{family}）"],
        }
        store.record({
            "family": family,
            "framework": lang,
            "sink_signature": normalize_sink_signature(family, family, ""),
            "canary_form": "verify-route",
            "attack_shape": f"seed:{lang}:{family}:verify",
            "attack_plan": plan,
            "exploit_spec_summary": {"family": family, "verify_route": verify, "language": lang},
            "observation": "template_seed",
            "verified": True,
        })

    print(f"poc_memory 种子化完成：{before} -> {store.size()} 条样本（data/poc_memory.json）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
