"""垂直越权 + 跨模块/跨业务越权 静态分析（重构文档 §2.2 业务逻辑策略分析）。

垂直越权（vertical_privesc）：低权限用户执行了高权限操作。识别「敏感/管理类操作」
（删用户、改配置、审核、授权等）且方法体内未见角色/权限校验（无 @PreAuthorize / hasRole /
isAdmin / checkPermission 等）→ 假说。

跨模块/跨业务越权（cross_module_privesc）：子系统间 Token 未做作用域（Scope）/租户隔离，
或一个模块的处理器直接调用另一模块的内部服务/客户端且未做 scope 校验 → 假说。

均为 SAST 种子：产出假说交 D1 操作器做多身份/跨域重放验证，不追求 IAST 自主发现。
family 对齐：垂直/跨模块均归 privesc 族，便于 vulnerability_hash_v2 对齐。

**定位：离线兜底（非主链路）。** 业务逻辑漏洞主链路为 ``A1BusinessLogicAIAgent``（LLM 语义识别）。
本分析器仅在未配置 LLM 时作为低成本启发式被调用，不在主链路中；CodeQL 在主链路承担辅助
结构验证（参数是否经过角色/权限校验函数）。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块仅作离线兜底。
IS_PRIMARY_PATH = False

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents._bl_common import (
    extract_functions,
    has_token,
    extract_spring_route,
    scan_spring_endpoints,
)

logger = logging.getLogger(__name__)

# 强管理操作（函数名命中即视为高权限操作，无需再匹配管理路由）
_STRONG_PRIV_OP = re.compile(
    r"(?i)\b("
    r"deleteuser|removeuser|banuser|disableuser|enableuser|"
    r"grant|revoke|promote|demote|"
    r"approve|audit|"
    r"importusers|"
    r"createadmin|setrole|setpermission|assignrole|manage\w*|"
    r"settenant|switchtenant|tenantconfig|"
    # 订单状态类特权操作：审核/改状态/改他人订单（如 reviewOrder/updateOrderStatus）
    r"revieworder|revieworderstatus|approveorder|rejectorder|"
    r"updateorderstatus|modifyorder|changeorderstatus|setorderstatus|"
    r"updateorder|cancelorder|refundorder"
    r")\b"
)
# 弱配置变更操作：仅当函数体/路由命中管理路由时才视为垂直越权（避免普通配置读改写误报）
_CONFIG_MUTATION_OP = re.compile(r"(?i)\b(updateconfig|setconfig)\b")
_ADMIN_ROUTE = re.compile(r"(?i)(/admin/|/manage/|/console/|/internal/|/sys/|/api/audit|/config|/tenant/|/ops/)")

# 角色/权限校验 token（出现任一即视为有控制点）
_ROLE_CHECK: Tuple[str, ...] = (
    "hasrole", "hasRole", "preauthorize", "postauthorize", "rolesallowed", "@secured",
    "requirerole", "checkrole", "isadmin", "isAdmin", "role ==", "role.equals",
    "hasauthority", "checkpermission", "authorize", "rbac", "acl", "securityutils",
    "getprincipal", "@preauthorize", "@postauthorize", "@rolesallowed", "verifyrole",
    "assertrole", "requirepermission", "permissionchecker", "accessdecision",
)
# 仅做「身份认证」、未做「角色/权限校验」的信号 token（出现且 _ROLE_CHECK 缺失 ⇒ 缺授权控制点）
_AUTH_ONLY_CHECK: Tuple[str, ...] = (
    "loggedin", "isloggedin", "islogin", "checklogin", "isauthenticated", "isauth",
    "currentuser", "currentuserof", "getcurrentuser", "getuser", "getsessionuser",
    "getsubject", "securityutils.getsubject", "getprincipal", "securitycontext",
)
# 仅做身份认证的方法（典型：private boolean loggedIn(...) → 只判 != null，不判 role）
_AUTH_ONLY_METHOD = re.compile(r"(?i)(loggedin|isloggedin|checklogin|isauthenticated)\s*\(")

# 跨模块/跨租户调用（一个模块直接调另一模块的内部服务/客户端）
_CROSS_MODULE_CALL = re.compile(
    r"(?i)("
    r"resttemplate|feignclient|@feignclient|webclient|openfeign|"
    r"\w+client\.(get|post|put|delete|patch)|"
    r"httpclient\.(get|post|put|delete)|okhttp|dubbo|@dubboreference|"
    r"crossservice|remotecall|rpcclient|grpcclient|"
    r"micservicecall|intermodule"
    r")"
)
# 作用域/租户隔离校验 token
_SCOPE_CHECK: Tuple[str, ...] = (
    "tenantid", "tenant_id", "x-tenant-id", "validatescope", "checkscope", "scopecheck",
    "tenant =", "tenant.equals", "@multitenant", "scopetoken", "validatetenant",
    "checktenant", "tenantfilter", "tenantcontext", "scopeguard", "authscope",
)


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回 垂直越权 / 跨模块越权 假说列表。"""
    if not isinstance(content, str):
        # 非字符串内容（bytes/None/其他）统一规整为字符串，避免下游正则/分行走到 bytes 上崩溃
        if isinstance(content, (bytes, bytearray)):
            content = content.decode("utf-8", "ignore")
        else:
            content = str(content)
    if lang is None:
        lang = (path.rsplit(".", 1)[-1] if "." in path else "").lower()
    hypotheses: List[Dict[str, Any]] = []
    seen_routes: set = set()
    for fn in extract_functions(content, lang):
        name = fn["name"]
        body = fn["body"]
        low_body = body.lower()
        route, http_method = extract_spring_route(content, fn["start"], body)

        # ---- 垂直越权 ----
        # 判定「高权限操作」：①强管理操作名（删用户/授权/改订单状态/创建管理员等）；
        # ②配置变更 + 管理路由；③特权/运营后台路由（/admin|/ops|/manage 等）。
        # 判定「缺授权控制点」：方法体仅做了身份认证（loggedIn/CurrentUser.of 等），
        # 但没有任何角色/权限校验 token（@PreAuthorize/hasRole/isAdmin...）。
        # 二者同时成立 ⇒ 垂直越权（低权限用户可执行高权限操作）。
        is_priv = (
            _STRONG_PRIV_OP.search(name)
            or (_CONFIG_MUTATION_OP.search(name) and _ADMIN_ROUTE.search(body))
            or _ADMIN_ROUTE.search(route or body)
        )
        has_auth_only = has_token(low_body, _AUTH_ONLY_CHECK) and not has_token(low_body, _ROLE_CHECK)
        # 仅做身份校验的私有方法（如 private boolean loggedIn()）也算缺授权信号
        if not has_auth_only and _AUTH_ONLY_METHOD.search(body):
            has_auth_only = not has_token(low_body, _ROLE_CHECK)
        if is_priv and has_auth_only:
            route_note = f" 路由={route}" if route else "（未抽取到 HTTP 路由，无法落 trigger_spec）"
            if route:
                seen_routes.add(route)
            hypotheses.append({
                "vuln_type": "vertical_privesc",
                "category": "vertical_privesc",
                "family": "vertical_privesc",
                "entry_point": f"{path}:{fn['start']}",
                "target_endpoint": route,
                "http_method": http_method,
                "function": name,
                "required_control_point": "角色/权限校验：在 loggedIn() 之外显式校验当前主体角色（如 @PreAuthorize/hasRole/isAdmin/checkPermission）",
                "confidence": "medium",
                "evidence": f"高权限操作({name}) 仅做身份认证(loggedIn/CurrentUser) 未做角色/权限校验{route_note}",
            })

        # ---- 跨模块/跨业务越权（per-function，避免 body 越界到循环外）----
        if _CROSS_MODULE_CALL.search(body):
            if not has_token(low_body, _SCOPE_CHECK):
                hypotheses.append({
                    "vuln_type": "cross_module_privesc",
                    "category": "cross_module_privesc",
                    "family": "cross_module_privesc",
                    "entry_point": f"{path}:{fn['start']}",
                    "function": name,
                    "required_control_point": "作用域/租户隔离：调用跨模块服务前校验 scope/tenant，且网关注入的签名身份须被内部校验",
                    "confidence": "medium",
                    "evidence": "处理器直接调用跨模块/跨租户服务(Feign/RestTemplate/Dubbo 等) 且 未做 scope/tenant 校验",
                })

    # ---- Spring 路由感知补扫（extract_functions 对嵌套圆括号签名失配的兜底）----
    # 典型漏检：reviewOrder(@RequestParam(defaultValue="PAID") ...) 因签名含嵌套 '(' 未被
    # extract_functions 抽取。此处按 @XMapping 定位方法体（花括号配平，免签名括号干扰），
    # 复用同一套「特权操作 + 仅身份认证」判定，按路由去重，避免与上面 per-function 重复。
    if lang in (None, "", "java", "kt", "kotlin", "go", "scala"):
        for route, http_method, blk, mname, line_idx in scan_spring_endpoints(content):
            if route in seen_routes:
                continue
            low = blk.lower()
            is_priv = (
                _STRONG_PRIV_OP.search(low)
                or _ADMIN_ROUTE.search(route or "")
                or (_CONFIG_MUTATION_OP.search(low) and _ADMIN_ROUTE.search(blk))
            )
            has_auth_only = has_token(low, _AUTH_ONLY_CHECK) and not has_token(low, _ROLE_CHECK)
            if not has_auth_only and _AUTH_ONLY_METHOD.search(blk):
                has_auth_only = not has_token(low, _ROLE_CHECK)
            if is_priv and has_auth_only:
                seen_routes.add(route)
                hypotheses.append({
                    "vuln_type": "vertical_privesc",
                    "category": "vertical_privesc",
                    "family": "vertical_privesc",
                    "entry_point": f"{path}:{line_idx}",
                    "target_endpoint": route,
                    "http_method": http_method,
                    "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                    "required_control_point": "角色/权限校验：在 loggedIn() 之外显式校验当前主体角色（如 @PreAuthorize/hasRole/isAdmin/checkPermission）",
                    "confidence": "medium",
                    "evidence": f"高权限路由({route}) 方法体仅做身份认证(loggedIn/CurrentUser) 未做角色/权限校验 路由={route}",
                })
    return hypotheses


def analyze_sources(files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """批量分析（与 A1 scan_files 输入形状对齐：[{path, content, language?}]）。

    逐文件容错：单个文件解析异常不影响整体，避免「一个坏文件拖垮整次业务逻分析」
    （此前 extract_functions 返回 0 函数时 body 未绑定，曾导致 UnboundLocalError 全量吞掉）。
    """
    out: List[Dict[str, Any]] = []
    for f in files or []:
        path = f.get("path") or f.get("file_path") or ""
        content = f.get("content") or f.get("source") or ""
        lang = f.get("language") or f.get("lang")
        try:
            out.extend(analyze_file(path, content, lang))
        except Exception as _e:  # best-effort：单文件失败记日志、跳过
            logger.warning("[vertical_privesc] analyze_file skipped %s: %s", path, _e)
    return out
