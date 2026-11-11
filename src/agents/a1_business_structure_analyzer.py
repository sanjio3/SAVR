"""A1 业务族「结构特征」确定性检测。

背景：
    历史上**业务逻辑类 findings 的唯一来源是 A2 LLM**。这带来两个硬伤：

    1. **单点故障**：A2 一挂（如 audit_prompts 里 `/order/{id}` 触发 ``str.format``
       KeyError 被 ``analyze`` 的 except 吞掉），垂直越权/竞态/重放/状态机类
       findings 全部消失，只剩注入类 —— 且任务仍报 completed，极难察觉。
    2. **不可复现**：同一份代码两轮扫出的业务族候选可能完全不同，无法建立召回基线。

    修法：业务族里有一大批是**结构特征可确定性判定**的，不需要 LLM 语义理解：

    - handler 收资源 id 入参 + 按 id 直查对象 + 方法体内无任何归属校验 → IDOR 结构
    - 状态流转端点（ship/refund/cancel/complete...）直调状态变更方法、无状态前置判断 → 状态机跳步结构
    - 管理前缀路由（/admin、/ops、/manage...）上没有任何权限注解 → 垂直越权结构
    - 金额/数量入参直传下单/支付方法、服务端未取价重算 → 计算逻辑（金额篡改）结构

    这些判据全部基于 :mod:`src.core.route_resolver` 的静态路由索引，因此
    **两步存在先后依赖**：先有「哪个方法是哪个 HTTP handler、有哪些入参、有没有
    @PreAuthorize」的确定性事实，才能在其上做结构判定。

定位：
    确定性**宽网召回**（A1 侧），confidence 一律标 medium/low，verdict 待分析。
    A2 的职责转为**验真 / 剪 FP / 建证明**，不再是业务族的唯一生产者。

输出形状与 ``A1BusinessLogicAIAgent`` / ``a1_bola_analyzer`` 对齐，可直接喂
``A1PipelineService._hypo_to_vulnerability``。
"""
from __future__ import annotations

# 确定性结构检测：不依赖 LLM，A2 挂掉也能产出业务族候选。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional

from src.core.exploit_spec import canonical_business_logic_family
from src.core.route_resolver import RouteEntry, RouteIndex, build_route_index

__all__ = ["analyze_files", "analyze_route", "RULE_IDS"]

RULE_IDS = {
    "IDOR_STRUCTURE": "idor",
    "STATE_MACHINE_SKIP": "state_machine",
    "ADMIN_ROUTE_UNGUARDED": "vertical_privesc",
    "AMOUNT_TAMPERING": "calculation_logic",
}

# ---------------------------------------------------------------------------
# 结构特征：IDOR / 水平越权
# ---------------------------------------------------------------------------

# 资源 id 入参：{id} 路径变量、或 java 形参名以 Id/id 结尾（orderId/userId/productId）
_ID_PARAM_RE = re.compile(r"(?i)(^id$|^[a-z]+Id$|^[a-z]+_id$|^uuid$|^[a-z]+Uuid$)")

# 按 id 直查对象（ORM / Mapper / Service / SQL）
_BY_ID_ACCESS_RE = re.compile(
    r"""(?ix)
    (?:\w+\.)?
    (?:find|get|load|select|query|read|fetch|delete|remove|update)
    (?:by)?
    (?:_[a-z]+)?
    (?:id|byid|byuuid|one)
    \s*\(
    |\.find\s*\(\s*\w*id
    """
)

# 归属校验 / 授权判据：命中任一即视为"有控制点"，不构成 IDOR 结构
_OWNERSHIP_TOKENS = (
    "currentuser", "getcurrentuser", "getprincipal", "getauthentication",
    "securitycontext", "securityutils", "haspermission", "checkownership",
    "isowner", "owns", "verifyaccess", "assertcanaccess", "accesscontrol",
    "ownerid", "owner_id", "owner ==", "owner.equals", "userid ==",
    "getuserid()", "authorized", "acl", "rbac",
)

# ---------------------------------------------------------------------------
# 结构特征：状态机跳步
# ---------------------------------------------------------------------------

# 状态流转语义（匹配 handler 方法名或路由**末段**）。
# 只对末段匹配是刻意的：此前对整条路由匹配时，"/marketing/preview" 被 `mark\w*`
_STATE_TRANSITION_OP = re.compile(
    r"(?i)^("
    r"ship|cancel|refund|complete|approve|reject|confirm|settle|pay|close|"
    r"finish|revoke|activate|deactivate|lock|unlock|advance|transition|"
    r"updatestatus|setstatus|changestatus|submit|audit|"
    r"mark(?:as)?(?:paid|shipped|done|complete|closed)|dispatch|deliver"
    r")"
)


def _is_transition_endpoint(entry: "RouteEntry") -> bool:
    """handler 是否为状态流转端点：方法名或路由末段命中流转语义。"""
    if _STATE_TRANSITION_OP.search(entry.method_name or ""):
        return True
    last = (entry.route or "").rstrip("/").rsplit("/", 1)[-1]
    # 末段是路径变量（如 /order/{id}）时无语义可判，不认作流转端点
    if not last or last.startswith("{"):
        return False
    return bool(_STATE_TRANSITION_OP.search(last))

# 状态前置判断：命中即视为"有状态机约束"
_STATUS_GUARD_RE = re.compile(
    r"""(?ix)
    getstatus\s*\(\s*\)
    |\.status\b
    |status\s*==|status\s*\.equals
    |state\s*==|state\s*\.equals
    |checkstatus|assertstatus|validatestate|cantransition|istransitionvalid
    """
)

# ---------------------------------------------------------------------------
# 结构特征：垂直越权（管理端点无守卫）
# ---------------------------------------------------------------------------

_ADMIN_PREFIX_RE = re.compile(r"^/(admin|manage|manager|console|sys|system|ops|backoffice|boss)(/|$)")

# ---------------------------------------------------------------------------
# 结构特征：金额篡改 / 计算逻辑
# ---------------------------------------------------------------------------

_AMOUNT_PARAM_RE = re.compile(
    r"(?i)^("
    r"amount|payamount|total|totalamount|price|unitprice|money|fee|cost|"
    r"discount|couponamount|refundamount|quantity|qty|count|num|balance|points|score"
    r")$"
)

# 服务端取价重算：命中即视为"服务端有重算"，不构成金额篡改结构
_RECOMPUTE_RE = re.compile(
    r"""(?ix)
    getprice\s*\(
    |getunitprice\s*\(
    |\.price\b
    |recompute|recalculate|calcamount|calculatetotal|computeprice
    |findbyid\s*\([^)]*\)\s*\.\s*getprice
    """
)

# 金额流入的下单/支付类调用
_MONEY_SINK_CALL_RE = re.compile(
    r"(?i)\b(buynow|buy|checkout|pay|refund|transfer|withdraw|settlement|settle|placeorder|createorder|recharge)\s*\("
)


# ---------------------------------------------------------------------------
# 判定
# ---------------------------------------------------------------------------

def _has_ownership_check(body: str) -> bool:
    low = (body or "").lower()
    return any(tok in low for tok in _OWNERSHIP_TOKENS)


def _id_params(entry: RouteEntry) -> List[str]:
    """handler 上「资源 id」语义的入参（路径变量优先，其次 id 语义的查询参数）。"""
    names: List[str] = []
    for pv in entry.path_variables or []:
        if _ID_PARAM_RE.match(pv) and pv not in names:
            names.append(pv)
    for p in entry.params or []:
        if p.location == "infra" or not p.name:
            continue
        if _ID_PARAM_RE.match(p.name) and p.name not in names:
            names.append(p.name)
    return names


def _amount_params(entry: RouteEntry) -> List[str]:
    return [p.name for p in (entry.params or [])
            if p.name and p.location != "infra" and _AMOUNT_PARAM_RE.match(p.name)]


def analyze_route(entry: RouteEntry, body: str) -> List[Dict[str, Any]]:
    """对单个 HTTP handler 做业务族结构特征判定。"""
    out: List[Dict[str, Any]] = []
    base = {
        "file": entry.file,
        "line": entry.line,
        "target_endpoint": entry.route,
        "http_method": entry.method,
        "detection_method": "rule",
        "category": "",
    }
    body = body or ""

    # ---- R1：IDOR（资源 id 入参 + 按 id 直查 + 无归属校验）----
    idps = _id_params(entry)
    if idps and _BY_ID_ACCESS_RE.search(body) and not _has_ownership_check(body):
        out.append(dict(base, **{
            "vuln_type": "IDOR",
            "family": canonical_business_logic_family("idor"),
            "category": "水平越权",
            "vulnerable_param": idps[0],
            "confidence": "medium",
            "rule_name": "IDOR_STRUCTURE",
            "evidence": (
                f"handler {entry.qualified_name} 接收资源 id 入参 {idps[0]}，"
                f"方法体内存在按 id 直查（{_BY_ID_ACCESS_RE.search(body).group(0)[:60]}），"
                f"且未见任何归属/授权校验（无 CurrentUser/owner 比对/@PreAuthorize）"
            ),
        }))

    # ---- R2：状态机跳步（流转端点 + 无状态前置判断）----
    if _is_transition_endpoint(entry):
        if not _STATUS_GUARD_RE.search(body):
            sink = _MONEY_SINK_CALL_RE.search(body)
            out.append(dict(base, **{
                # vuln_type 刻意用「经 _norm_family 归一后仍是规范 token」的形态：
                # health 检查发现 "STATE_MACHINE_BYPASS" 会归一成 state_machine_bypass，
                # 既不在 DIFFERENTIAL_PROOF_FAMILIES（被判成注入族、业务差分门禁失效），
                # 也与 A2 侧同一漏洞的 vhash 不一致（重复 finding + 孤儿 spec）。
                "vuln_type": "STATE_MACHINE",
                "family": canonical_business_logic_family("state_machine"),
                "category": "状态机跳步",
                "vulnerable_param": (entry.path_variables[0] if entry.path_variables
                                     else (idps[0] if idps else "")),
                "confidence": "medium",
                "rule_name": "STATE_MACHINE_SKIP",
                "evidence": (
                    f"状态流转端点 {entry.method} {entry.route} 直接调用"
                    f"{sink.group(0) if sink else '状态变更方法'}，方法体内未见"
                    f"getStatus()/状态等值判断等前置约束，允许跳步执行"
                ),
            }))

    # ---- R3：垂直越权（管理前缀路由 + 无权限注解 + 应用无全站认证兜底）----
    # 应用可能在 Shiro 的 filterChainDefinitionMap 里配置全站认证兜底，此时管理端点
    # 缺注解不等于缺鉴权，直接报垂直越权会产生大量误报。
    # 现在要求「应用本身没有全站认证兜底」才允许报，否则只能算「缺细粒度权限」，
    # 那不是一个可确认的越权漏洞。
    if (_ADMIN_PREFIX_RE.search(entry.route or "") and not entry.has_guard
            and not getattr(entry, "app_requires_auth", False)):
        out.append(dict(base, **{
            "vuln_type": "VERTICAL_PRIVESC",
            "family": canonical_business_logic_family("vertical_privesc"),
            "category": "垂直越权",
            "vulnerable_param": (idps[0] if idps else ""),
            "confidence": "medium",
            "rule_name": "ADMIN_ROUTE_UNGUARDED",
            "evidence": (
                f"管理端点 {entry.method} {entry.route}（{entry.qualified_name}）"
                f"未标注任何权限注解（@PreAuthorize/@Secured/@RolesAllowed），"
                f"鉴权完全依赖上游过滤器"
            ),
        }))

    # ---- R4：金额篡改（金额入参直传下单/支付 + 服务端未取价重算）----
    amounts = _amount_params(entry)
    if amounts and _MONEY_SINK_CALL_RE.search(body) and not _RECOMPUTE_RE.search(body):
        out.append(dict(base, **{
            "vuln_type": "CALCULATION_LOGIC",
            "family": canonical_business_logic_family("calculation_logic"),
            "category": "金额篡改",
            "vulnerable_param": amounts[0],
            "confidence": "medium",
            "rule_name": "AMOUNT_TAMPERING",
            "evidence": (
                f"handler {entry.qualified_name} 直接采信客户端传入的 {amounts[0]}，"
                f"并传入下单/支付方法，方法体内未见服务端取价重算（getPrice/重算总额）"
            ),
        }))

    return out


def _file_content(files: List[Dict[str, Any]], path: str) -> str:
    for f in files or []:
        if (f or {}).get("path") == path:
            return f.get("content") or ""
    return ""


def analyze_files(
    files: List[Dict[str, Any]],
    route_index: Optional[RouteIndex] = None,
) -> List[Dict[str, Any]]:
    """批量分析：对每条静态路由做业务族结构特征判定。

    Args:
        files: ``[{"path":..., "content":...}, ...]``（与 A1 scan_files 同构）
        route_index: 已建好的路由索引；不给则内部构建

    Returns:
        业务族假说列表（形状与 A1BusinessLogicAIAgent / a1_bola_analyzer 对齐）。
    """
    index = route_index if route_index is not None else build_route_index(files)
    if not index:
        return []

    by_file: Dict[str, List[str]] = {}
    out: List[Dict[str, Any]] = []
    for entry in index.entries:
        lines = by_file.get(entry.file)
        if lines is None:
            content = _file_content(files, entry.file)
            if not content:
                try:
                    with open(entry.file, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    content = ""
            lines = content.split("\n")
            by_file[entry.file] = lines
        start = max(0, (entry.line or 1) - 1)
        end = entry.end_line or (start + 40)
        body = "\n".join(lines[start:max(end, start)])
        out.extend(analyze_route(entry, body))

    # 同 route + 同 family + 同 param 去重（多条类前缀组合会产生重复条目）
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for h in out:
        key = (h.get("target_endpoint"), h.get("http_method"), h.get("family"), h.get("vulnerable_param"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(h)
    return deduped


def analyze_sources(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """与 a1_bola_analyzer.analyze_sources 同签名的入口，便于 A1 统一调用。"""
    return analyze_files(files)
