"""Skill（可插拔检测能力单元）运行时加载器。

打通规则生成闭环的「最后一公里」：此前 rule_feedback_service 产出候选规则写
generated_rules.yaml（staging），但**运行时没有加载方**。本模块把
``src/config/rules/`` 下激活的 ``*.yaml`` 载入为 RuleSkill，并提供两条消费路径：

  - A1 静态通道：``get_rule_expressions(family)`` 取 rule_expression（正则/关键词），
    注入静态匹配（a1_injection_heuristic._compile_registry_rules），不再靠硬编码登记
    （如 A3 CVE-2022-22978 这类）；
  - A2 提示词通道：``build_skill_hints(...)`` 取 prompt_fragment，注入 audit_file
    模板的 ``{skill_hints}`` 槽位，强化所有模型（强/弱）对特定形态的识别。

两条通道都**只消费 status=active 的 skill**：候选规则先以 staging 落盘，经 golden 回归 +
D2 差分门禁 + 人工确认后再置 active，避免未验证规则影响真实扫描。

RuleSkill 结构：
  {id, version, family, languages, trigger, payload, golden, gate}

模型无关：skill 只是一段文本要点 / 匹配表达式，不绑定任何具体模型，强弱模型同吃。
fail-open：目录为空或文件损坏都不影响主流程，返回空结果。
"""
from __future__ import annotations

import glob
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

def _default_rules_dir() -> Path:
    """规则目录默认值：优先用 tool_paths.get_rules_dir（唯一路径真相），取不到再退回相对路径。"""
    try:
        from src.core.tool_paths import get_rules_dir
        return Path(get_rules_dir())
    except Exception:
        return Path(__file__).resolve().parents[1] / "config" / "rules"


_RULES_DIR = _default_rules_dir()


@dataclass
class RuleSkill:
    id: str
    version: int = 1
    family: str = ""
    languages: List[str] = field(default_factory=list)
    trigger: Dict = field(default_factory=dict)
    payload: Dict = field(default_factory=dict)
    golden: Dict = field(default_factory=dict)
    gate: Dict = field(default_factory=dict)
    # 生命周期：staging（候选中，不参与运行时）→ active。
    # 只有 active 才被 A1 规则表达式 / A2 提示词消费；staging 仅落盘待验证。
    # 这是 「候选 → 门禁 → 人工确认 → 提升为 active」闭环的运行时开关。
    status: str = "active"
    # 定义该 skill 的 yaml 文件绝对路径。用于门禁提级时**定点回写 status 行**（保留文件注释）。
    source_path: str = ""

    @property
    def prompt_fragment(self) -> str:
        return str(self.payload.get("prompt_fragment") or "")

    @property
    def rule_expression(self) -> str:
        return str(self.payload.get("rule_expression") or "")

    @property
    def is_active(self) -> bool:
        return (self.status or "active").strip().lower() == "active"


_REGISTRY: Dict[str, RuleSkill] = {}
_LOCK = threading.Lock()


def _load_once() -> None:
    with _LOCK:
        if _REGISTRY:
            return
        for path in sorted(glob.glob(str(_RULES_DIR / "*.yaml"))):
            try:
                data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            for raw in (data.get("skills") or []):
                if not isinstance(raw, dict):
                    continue
                sid = str(raw.get("id") or "").strip()
                if not sid:
                    continue
                _REGISTRY[sid] = RuleSkill(
                    id=sid,
                    version=int(raw.get("version") or 1),
                    family=str(raw.get("family") or ""),
                    languages=list(raw.get("languages") or []),
                    trigger=raw.get("trigger") or {},
                    payload=raw.get("payload") or {},
                    golden=raw.get("golden") or {},
                    gate=raw.get("gate") or {},
                    status=str(raw.get("status") or "active"),
                    source_path=str(path),
                )


def load_rules() -> Dict[str, RuleSkill]:
    """返回全部 skill（id -> RuleSkill），含 staging（未激活，不参与运行时消费）。"""
    _load_once()
    with _LOCK:
        return dict(_REGISTRY)


def reload_rules() -> Dict[str, RuleSkill]:
    """清空进程内缓存并重新加载规则目录。

    `_load_once` 对 `_REGISTRY` 做进程内永久缓存，因此**改完 `status` 的 yaml 不会自动生效**。
    本函数供测试与「显式热加载」场景使用（后端常驻进程默认仍需重启才会重新读盘）。
    """
    with _LOCK:
        _REGISTRY.clear()
    _load_once()
    return load_rules()


def active_rules() -> Dict[str, RuleSkill]:
    """只返回 status=active 的 skill（运行时消费的唯一来源）。"""
    return {k: v for k, v in load_rules().items() if v.is_active}


def get_rule_expressions(family: str = "") -> List[Dict]:
    """A1 静态通道：取 active skill 的 rule_expression 列表（不含 prompt_fragment）。"""
    out: List[Dict] = []
    for sk in active_rules().values():
        if family and sk.family and sk.family != family:
            continue
        if sk.rule_expression:
            out.append({
                "id": sk.id, "family": sk.family,
                "expression": sk.rule_expression, "languages": sk.languages,
                "vuln_type": str(sk.payload.get("vuln_type") or ""),
                "severity": str(sk.payload.get("severity") or ""),
            })
    return out


def build_skill_hints(families: Optional[List[str]] = None, language: str = "") -> str:
    """A2 提示词通道：汇总 **active** skill 的 prompt_fragment 拼成一段补充检测要点。

    注入 audit_file 模板的 ``{skill_hints}`` 槽位。无 active 规则或语言不匹配时返回空串
    （render_prompt 收到空串即不增加任何内容）。
    """
    hints: List[str] = []
    for sk in active_rules().values():
        frag = sk.prompt_fragment
        if not frag:
            continue
        if language and sk.languages and language not in sk.languages:
            continue
        if families and sk.family and sk.family not in families:
            continue
        hints.append(f"- [{sk.family or '通用'}] {frag}")
    if not hints:
        return ""
    return "【补充检测要点（来自规则库 skill，用于强化对以下形态的识别）】\n" + "\n".join(hints)
