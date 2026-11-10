"""重放智能化（2026-10-02 落地）：把「失败原因」翻译成给 A2 / 合成器的**具体改进指令**，
并累积每一轮的尝试轨迹，让下一轮不再重复已被证明无效的打法。

此前缺的正是这一环：
- 回灌给 A2 的是自然语言 reason，A2 是静态分析器，重跑产出同一条假说（run 24 实证
  烧 47 分钟、gain = -7）。
- 运行时失败大多被 a2_rerun_actionable 挡在 A2 之外，学习信号根本没流回去。
- 重放侧只有"位置性"动作（换参数位/延长窗口/固定梯子下一阶），没有按失败原因改写策略。

现在：failure_class（结构化） + FilterSpec（净化器约束） + 轨迹记忆 → 生成 directive，
指令里明确"目标是谁、必须避开什么、已试过什么、下一步该做什么"，并据此放行定向 A2 重跑。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.core.sanitizer_miner import FilterSpec


# ---------------------------------------------------------------- 指令生成
def build_directive(failure_class: str, evidence: Optional[Dict[str, Any]] = None,
                    spec: Optional[FilterSpec] = None, memory: Optional["ReplayMemory"] = None,
                    family: str = "", endpoint: str = "", sink: str = "") -> Dict[str, Any]:
    """把失败原因翻译成可执行的改进指令（不是自然语言提示）。"""
    ev = evidence or {}
    status = ev.get("status_code")
    tried = list(memory.rejected_payloads()) if memory else []

    directive: Dict[str, Any] = {
        "failure_class": failure_class,
        "endpoint": endpoint,
        "family": family,
        "round": (memory.round() if memory else 0) + 1,
        "avoid": tried,
        "constraint": spec.to_dict() if spec is not None else None,
        "observed": {"status_code": status, "reached": ev.get("reached"),
                     "harmful": ev.get("d2_harmful"), "iast_state": ev.get("iast_state")},
    }

    if failure_class == "blocked":
        directive["target"] = "payload_synthesis"
        bits = []
        if spec is not None and spec.kind == FilterSpec.KIND_DENY and spec.tokens:
            bits.append("载荷必须不含这些被拒绝的片段：%s" % "、".join(repr(t) for t in spec.tokens[:12]))
        elif spec is not None and spec.kind == FilterSpec.KIND_ALLOW and spec.patterns:
            bits.append("载荷必须整体落入允许字符集：%s" % spec.patterns[0])
        else:
            bits.append("上一发被目标拒绝（HTTP %s），需换一种能绕过该校验的表达形态" % status)
        if sink:
            bits.append("并要求数据仍抵达 sink：%s" % sink)
        if tried:
            bits.append("已试过且无效的载荷不要再试：%s" % "、".join(tried[:6]))
        directive["instruction"] = "；".join(bits)

    elif failure_class == "route_unreachable":
        directive["target"] = "replay"
        directive["instruction"] = ("路由不通（HTTP %s）：这是放错位置而非被拦，"
                                    "应重推端点并换参数注入位置，不要升级载荷" % status)

    elif failure_class == "auth_missing":
        directive["target"] = "replay"
        directive["instruction"] = ("请求被鉴权墙挡回（HTTP %s）：先带会话/凭据重推，"
                                    "不是拦截也不是路由错，不要升级载荷" % status)

    elif failure_class == "arrived_unconfirmed":
        directive["target"] = "payload_synthesis"
        directive["instruction"] = ("数据已抵达 sink 但未被确证有害：需要能产生可观测影响"
                                    "（回显/OOB/执行副作用）的载荷，而非仅到达型探针")

    elif failure_class == "param_not_arrived":
        directive["target"] = "replay"
        directive["instruction"] = ("HTTP %s 但 canary 未抵达 sink：改参数注入位置或全参注入，"
                                    "先解决送达问题" % status)

    elif failure_class == "window_missed":
        directive["target"] = "replay"
        directive["instruction"] = "事件迟到：延长 I1 等待窗口后重放同一载荷"

    else:
        directive["target"] = "payload_synthesis"
        directive["instruction"] = "失败原因未结构化：按族默认约束重新合成载荷"

    return directive


# ---------------------------------------------------------------- 轨迹记忆
class ReplayMemory:
    """按 (endpoint, param) 累积每一轮的尝试与观测，供下一轮避免重复无效打法。"""

    def __init__(self, endpoint: str = "", param: str = "", rounds: Optional[List[Dict[str, Any]]] = None):
        self.endpoint = str(endpoint or "")
        self.param = str(param or "")
        self.rounds: List[Dict[str, Any]] = list(rounds or [])

    # ---- 序列化（落在 trigger_specs.raw_json.replay_intel，无需新表） ----
    def to_dict(self) -> Dict[str, Any]:
        return {"endpoint": self.endpoint, "param": self.param, "rounds": self.rounds}

    @staticmethod
    def from_dict(d: Any) -> "ReplayMemory":
        if not isinstance(d, dict):
            return ReplayMemory()
        return ReplayMemory(d.get("endpoint") or "", d.get("param") or "", d.get("rounds") or [])

    def round(self) -> int:
        return len(self.rounds)

    def record(self, tried: Optional[List[str]] = None, rejected: Optional[List[str]] = None,
               failure_class: str = "", observed: Optional[Dict[str, Any]] = None,
               directive: Optional[Dict[str, Any]] = None,
               payloads: Optional[List[str]] = None) -> None:
        # payloads 为 tried 的别名，兼容两种调用写法。
        _tried = tried if tried is not None else payloads
        self.rounds.append({
            "round": len(self.rounds) + 1,
            "tried": list(_tried or []),
            "rejected": list(rejected or []),
            "failure_class": failure_class,
            "observed": observed or {},
            "directive": directive or {},
        })

    def rejected_payloads(self) -> List[str]:
        out: List[str] = []
        for r in self.rounds:
            for p in (r.get("rejected") or []):
                if p not in out:
                    out.append(p)
            # 试过但仍失败的整批也记入 avoid（下一轮不必原样再来）
            for p in (r.get("tried") or []):
                if p not in out and (r.get("failure_class") in ("blocked", "arrived_unconfirmed")):
                    out.append(p)
        return out

    def tried_payloads(self) -> List[str]:
        out: List[str] = []
        for r in self.rounds:
            for p in (r.get("tried") or []):
                if p not in out:
                    out.append(p)
        return out
