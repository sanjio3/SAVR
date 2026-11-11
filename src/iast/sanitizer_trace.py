"""v2 证据分层 —— 消毒器传播链关联薄层（A4，纯函数、无状态）。

设计定位（纠正 v1「新建中层」的误解）：消毒器观测（PropagateLibEscapeAdvice 等）已由探针
完成，本模块**只做关联与族相关性判断**，不重新插桩。

探针侧经 ``HookRuntime.currentSinkSanitizer`` 在 sink 实参级记录消毒器快照，格式：

    sink_sanitizer = "sanitizerId|family1,family2"

- 第一部分：消毒器标识（如 ``org.owasp.encoder.Encode.encodeForLDAP``）。
- 第二部分：该消毒器针对的漏洞族（逗号分隔）；空列表 / 通配 ``*`` 表示对全部族生效。

铁律（证据分层 v2 三条之一）：**证据缺失 ≠ 阴性**。无消毒记录绝不产阴性；
有消毒记录但针对的族不包含当前族（且非通配）也不产阴性（消毒器与本族注入正交，
不中和本族攻击）。只有「数据到了 sink 实参 且 消毒器针对本族」才构成合法的 definitive 阴性。
"""

from typing import Any, Dict, List, Optional

_WILDCARDS = ("*", "", "all")


def parse_sanitizer_record(raw: Any) -> Dict[str, Any]:
    """把探针 sink_sanitizer 字符串解析为结构化记录。

    返回 {"raw", "sanitizer_id", "families", "present"}。
    present=False 表示本 sink 实参无消毒记录（与「未采集到」同义 → 后端按证据缺失处理）。
    """
    s = (raw or "").strip()
    if not s:
        return {"raw": s, "sanitizer_id": "", "families": [], "present": False}
    parts = s.split("|", 1)
    sid = parts[0].strip()
    fams: List[str] = []
    if len(parts) > 1:
        fams = [f.strip().lower() for f in parts[1].split(",") if f.strip()]
    return {"raw": s, "sanitizer_id": sid, "families": fams, "present": bool(sid)}


def is_sanitized_for_family(raw: Any, family: str = "") -> bool:
    """本 sink 实参上的消毒器是否构成对指定族的合法阴性判据。

    规则（v2 铁律③）：
    - 无消毒记录 → False（证据缺失，绝不能当阴性）。
    - 有记录但针对族不包含当前族（且非通配）→ False（消毒器与本族注入正交，不中和本族攻击）。
    - 有记录且针对当前族（或通配）→ True（数据到了但被消毒，是合法阴性）。
    """
    rec = parse_sanitizer_record(raw)
    if not rec["present"]:
        return False
    fam = (family or "").strip().lower()
    fams = rec["families"]
    if not fams or any(w in _WILDCARDS for w in fams):
        # 未标注族（通配）：保守视为对当前族生效；调用方仍应经 sink 身份二次校验。
        return True
    return fam in fams


def is_sanitizer_present(raw: Any) -> bool:
    """仅判断 sink 实参上是否有任意消毒器记录（不区族）。供 compute_value_hit 标注 hit_sanitized。"""
    return parse_sanitizer_record(raw)["present"]
