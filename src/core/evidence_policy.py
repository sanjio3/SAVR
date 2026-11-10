"""证据阶梯唯一真相源（M1，2026-10-20）。

背景：证据判定散在三处，口径漂移会导致「报表说 S4、闸门说不合格」的自相矛盾：
  - ``src/core/sink_value_gate.py::judge_sink_value`` —— 底层，返回 at_sink/absent/no_event；
  - ``src/cli/benchmark_cli.py::_apply_sink_value_gate_postpass`` —— 组级否决规则（三套）；
  - ``tools/eval_target.py::_evidence_of_group`` —— S4/S3/S2/S1 分桶。

本模块把「分桶」与「组级决策」抽成唯一真相源：
  - ``classify(spec, events)`` → :class:`Evidence`（kind ∈ S4/S3/S2/S1）；
  - ``decide_group(items, policy)`` → ``(decision, rule)``。

判据与原实现**逐条等价**：迁移时保持 rule 名（``value-gate-absent`` /
``value-gate-strict-c`` / ``value-gate-no-at-sink``）不变，供对账/报表兼容。
本模块为纯加法，暂不改任何现有调用路径；迁移与逐案 diff 验收另步进行。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

S4 = "S4"  # payload 出现在真 sink 实参 → 可确认
S3 = "S3"  # 族 sink 已到达但实参无 payload → 可否决（正反证）
S2 = "S2"  # 有探针事件但没到族 sink → 不改判
S1 = "S1"  # 零事件 → 不改判（证据缺失，不等于安全）

_RANK = {S4: 4, S3: 3, S2: 2, S1: 1}


def _canon(family: str) -> str:
    try:
        from src.core.sink_value_gate import canonical_family

        return canonical_family(family)
    except Exception:
        return str(family or "").strip().lower()


@dataclass(frozen=True)
class Evidence:
    """单条 spec 的证据阶梯。

    ``family`` 存 **规范族名**（canonical），便于组级族集合比较（与 benchmark_cli 的
    ``_fams`` 口径一致）。
    """

    kind: str
    family: str = ""
    matched_sink: str = ""
    matched_on: str = ""  # payload | identity | ""
    verdict: str = ""      # 原始 judge_sink_value verdict
    has_events: bool = False
    spec_id: Optional[int] = None

    @property
    def rank(self) -> int:
        return _RANK.get(self.kind, 0)


def classify(spec: Dict[str, Any], events: Sequence[Dict[str, Any]], *, judge=None) -> Evidence:
    """把单条 spec + 其 canary 事件分类为证据阶梯。

    spec 需含 ``taint_marker`` / ``family``（或 ``capability_family``）/ ``id``。
    ``judge`` 可注入（默认 ``sink_value_gate.judge_sink_value``），便于单测。

    映射（与 eval_target._evidence_of_group 逐条等价）：
      at_sink → S4；absent → S3；no_event 且有事件 → S2；no_event 且零事件 → S1。
    """
    if judge is None:
        from src.core.sink_value_gate import judge_sink_value as judge  # 延迟导入防循环
    marker = str(spec.get("taint_marker") or "")
    fam_raw = str(spec.get("family") or spec.get("capability_family") or "")
    evs = list(events or [])
    try:
        v = judge(evs, marker, family=fam_raw) or {}
    except Exception:
        v = {}
    verdict = str(v.get("verdict") or "")
    if verdict == "at_sink":
        kind = S4
    elif verdict == "absent":
        kind = S3
    elif evs:
        kind = S2
    else:
        kind = S1
    return Evidence(
        kind=kind,
        family=_canon(fam_raw),
        matched_sink=str(v.get("matched_sink") or ""),
        matched_on=str(v.get("matched_on") or ""),
        verdict=verdict,
        has_events=bool(evs),
        spec_id=spec.get("id"),
    )


@dataclass(frozen=True)
class Policy:
    """组级否决策略。默认值 = benchmark_cli 当前生产默认（全空 = 不否决）。"""

    allow_families: frozenset = frozenset()           # 值级闸适用族（canonical）
    strict_c_families: frozenset = frozenset()         # strict-C 族
    strict_enabled: bool = False                       # 旧严格模式开关
    strict_families: frozenset = frozenset()           # 旧严格模式族
    strict_covered_families: frozenset = frozenset()   # 族判别力达标（覆盖率）族
    strict_allow_no_event: bool = False                # 允许纯 no_event 否决（默认关）


def decide_group(items: Sequence[Evidence], policy: Policy) -> Tuple[str, str]:
    """返回 ``(decision, rule)``。decision ∈ {confirm, veto, keep}。

    复刻 ``benchmark_cli._apply_sink_value_gate_postpass`` 的三套否决规则（逐条等价）：
      ① 全部 S3（absent） → ``value-gate-absent``
      ② strict-C：族 ⊆ strict_c_families 且无 S4 且有 S3 且有事件 → ``value-gate-strict-c``
      ③ strict：族 ⊆ strict_families ∩ covered 且无 S4 且有事件且(allow_no_event 或 有 S3)
         → ``value-gate-no-at-sink``
    无命中：含 S4 → confirm；否则 keep。
    """
    if not items:
        return "keep", ""
    kinds = [e.kind for e in items]
    fams = {e.family for e in items}
    has_events = any(e.has_events for e in items)
    has_s4 = any(k == S4 for k in kinds)
    has_s3 = any(k == S3 for k in kinds)

    # ① 全部 absent（用例内所有 spec 的族 sink 都到达但实参无 payload）
    if all(k == S3 for k in kinds):
        return "veto", "value-gate-absent"
    # ② strict-C：≥1 absent 且无 at_sink ⇒ 否决（no_event 兄弟不阻挠）
    if (policy.strict_c_families and fams and fams <= policy.strict_c_families
            and not has_s4 and has_s3 and has_events):
        return "veto", "value-gate-strict-c"
    # ③ 旧严格模式（需族判别力达标 + 有正向反证，除非显式允许纯 no_event）
    if (policy.strict_enabled and fams and fams <= policy.strict_families
            and fams <= policy.strict_covered_families
            and not has_s4 and has_events
            and (policy.strict_allow_no_event or has_s3)):
        return "veto", "value-gate-no-at-sink"
    if has_s4:
        return "confirm", "at-sink"
    return "keep", ""


def best_kind(items: Sequence[Evidence]) -> str:
    """组内最强证据（S4 > S3 > S2 > S1），与 eval_target._evidence_of_group 等价。"""
    if not items:
        return S1
    return max((e.kind for e in items), key=lambda k: _RANK.get(k, 0))
