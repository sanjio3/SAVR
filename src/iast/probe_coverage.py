"""探针插桩覆盖消歧。

问题（根因）：部分靶场 no-arrival 不是「请求没到/路由错/auth 挡」，而是「探针没织到该 spec 的
sink 类」。原状态把这两种语义
混为一谈，会误把「探针没织到」读成「靶场无漏洞」，污染精确率。

修法：探针侧上报「已织桩 sink 清单（coverage manifest）」，SAVR 侧比对 spec.expected_sink
与清单，把笼统 no-arrival 拆成三态：
  - probe_not_instrumented：期望 sink 不在清单 → 探针没覆盖此 sink（环境侧，不计为漏洞结论）
  - probe_unavailable：探针整体异常（已知必中 sink 的 liveness canary 也 no-arrival）→ 整批不可信
  - no-arrival（genuine）：探针覆盖到了、liveness 也到了，仍是 no-arrival → 才是「真没到」

探针侧（sec-probe.jar）为跨仓库，本模块只落 SAVR 侧消费逻辑；清单为空/未上报时保守回退原态，
绝不误读。
"""
from __future__ import annotations

from typing import Any, Iterable, Optional, Set

# 与 i2_feedback.RUNTIME_FIVE_CLASS / canary 状态不冲突：这是「spec 级诊断」，附加在 iast 块上。
PROBE_NOT_INSTRUMENTED = "probe_not_instrumented"
PROBE_UNAVAILABLE = "probe_unavailable"
GENUINE_NO_ARRIVAL = "no-arrival"


def _normalize_sink(sink_file: str) -> str:
    return (sink_file or "").replace("\\", "/").strip()


def refine_no_arrival_state(
    expected_sink_file: str,
    coverage_manifest: Optional[Iterable[str]],
    liveness_canary_reached: bool,
) -> str:
    """把笼统 no-arrival 拆成三态。

    coverage_manifest：探针上报的已织桩 sink 集合（sink_file / class.method）。为 None 表示探针
        未上报清单 → 无法区分，保守返回 genuine no-arrival（不误读）。
    liveness_canary_reached：已知必中已织桩 sink 的 canary 是否 sink-reached（探针整体健康探针）。
    """
    manifest: Set[str] = set()
    if coverage_manifest is not None:
        manifest = {_normalize_sink(s) for s in coverage_manifest if s}

    # 无清单：保守保持原态，避免凭空制造「探针未覆盖」结论
    if not manifest:
        return GENUINE_NO_ARRIVAL

    sink = _normalize_sink(expected_sink_file)
    if sink and sink not in manifest:
        return PROBE_NOT_INSTRUMENTED
    # sink 在清单（探针覆盖到了），但 liveness canary 整体没到 → 探针异常
    if not liveness_canary_reached:
        return PROBE_UNAVAILABLE
    return GENUINE_NO_ARRIVAL


def load_coverage_manifest(db: Any, session_id: Optional[int]) -> Optional[Set[str]]:
    """从 iast_sessions.coverage_manifest_json 读探针上报的织桩清单；缺失/解析失败返回 None。"""
    if session_id is None:
        return None
    try:
        import json as _json
        row = db.execute(
            "SELECT coverage_manifest_json FROM iast_sessions WHERE id=?",
            (int(session_id),), fetchone=True,
        )
        raw = (row or {}).get("coverage_manifest_json") if row else None
        if not raw:
            return None
        data = _json.loads(raw) if isinstance(raw, str) else raw
        items = data.get("sinks") if isinstance(data, dict) else data
        if not items:
            return None
        return {_normalize_sink(s) for s in items if s}
    except Exception:
        return None
