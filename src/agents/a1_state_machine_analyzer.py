"""状态机/流程控制 静态分析。

核心本质：系统未严格校验业务流转的先后顺序或当前状态，允许「插队/倒退/跳跃/闭环破坏」。

识别「状态转换类操作」（取消订单、退款、改地址、发货、完成、审批、撤销等），若方法体内
未见当前状态前置校验（无 if(status==)/getStatus/assertState/stateMachine/guard 等），
即构成状态机校验缺失假说（STATE_MACHINE）。

含三类场景：
- 流程跳跃（跳过实名/绑卡直接提现；跳过支付直接调支付成功回调）
- 状态回退/逆向（已发货仍允许取消/改地址）
- 闭环破坏（退款并发撤销导致钱退状态却回滚）

均为 SAST 种子：产出假说交 D1 操作器做乱序/逆向重放验证，不追求 IAST 自主发现。

**定位：离线兜底（非主链路）。** 业务逻辑漏洞主链路为 ``A1BusinessLogicAIAgent``（LLM 语义识别）。
本分析器仅在未配置 LLM 时作为低成本启发式被调用，不在主链路中；CodeQL 在主链路承担辅助
结构验证（状态转换操作前是否经过当前状态守卫）。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块仅作离线兜底。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents._bl_common import has_token, safe_text, scan_spring_endpoints

# 状态转换类操作（函数名命中即视为状态跃迁入口）。
# 注意：refund 移交 abuse_dos（#33 退款滥用，按"无次数/额度/状态校验"判定），此处不含。
_STATE_TRANSITION_OP = re.compile(
    r"(?i)\b("
    r"cancelorder|cancel|cancelorderitem|"
    r"applyrefund|revokerefund|"
    r"modifyaddress|modifyaddr|updateaddress|changeaddress|"
    r"shiporder|ship|deliver|deliverorder|"
    r"completeorder|complete|finishorder|"
    r"approveorder|rejectorder|approve|reject|"
    r"closeorder|reopenorder|revoke|"
    r"updateorderstatus|setorderstatus|"
    r"confirmreceipt|confirmdelivery"
    r")\b"
)
# 当前状态前置校验 token（出现任一即视为有状态守卫）
_STATE_GUARD: Tuple[str, ...] = (
    "status ==", "state ==", "status.equals", "state.equals",
    "getstatus()", "getstate()", "currentstate", "order.status", "order.state",
    "assertstate", "requirestate", "validatestate", "checkstatus", "checkstate",
    "statemachine", "guard", "cantransition", "allowtransition", "transitionguard",
    "statusguard", "statematcher", "iforderstatus", "statusflow",
    "switch (status)", "switch(status)", "switch (state)", "switch(state)",
)


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回 状态机校验缺失 假说列表（带 HTTP 路由，可落 trigger_spec）。

    识别「状态转换类操作」（发货/完成/审批/撤销/改地址等），若方法体内未见当前状态前置
    校验（无 if(status==)/getStatus/assertState/状态机守卫 等）→ 假说。
    通过 scan_spring_endpoints 直接抽取真实 HTTP 路由，避免假说因无路由被漏斗丢弃。
    """
    content = safe_text(content)
    hypotheses: List[Dict[str, Any]] = []
    seen_routes: set = set()
    for route, http_method, blk, mname, line_idx in scan_spring_endpoints(content):
        if not route or route in seen_routes:
            continue
        if not _STATE_TRANSITION_OP.search(mname):
            continue
        if has_token(blk, _STATE_GUARD):
            continue  # 有状态守卫，不构成假说
        seen_routes.add(route)
        hypotheses.append({
            "vuln_type": "STATE_MACHINE",
            "category": "state_machine",
            "family": "state-machine",
            "entry_point": f"{path}:{line_idx}",
            "target_endpoint": route,
            "http_method": http_method,
            "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
            "required_control_point": "当前状态前置校验：操作前断言 status/state 处于允许转换的起点（assertState/状态机守卫），拒绝跳跃/逆向",
            "confidence": "medium",
            "evidence": f"状态转换操作({mname}) 路由={route} 且 方法体内未见当前状态前置校验（状态机跳步风险）",
        })
    return hypotheses


def analyze_sources(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量分析（与 A1 scan_files 输入形状对齐：[{path, content, language?}]）。"""
    out: List[Dict[str, Any]] = []
    for f in files or []:
        path = f.get("path") or f.get("file_path") or ""
        content = f.get("content") or f.get("source") or ""
        lang = f.get("language") or f.get("lang")
        out.extend(analyze_file(path, content, lang))
    return out
