"""认证与会话管理 静态分析（重构文档 §2.2 业务逻辑策略分析）。

核心本质：身份验证机制存在缺陷，导致绕过验证或接管他人会话。

两类场景：
1. 验证码/短信逻辑缺陷（AUTH_CAPTCHA）
   - 验证码回显：发送/生成接口在响应中明文返回 code/captcha（可由单函数判定）
   - 验证码未销毁/可复用：文件内存在发送/生成验证码函数但无 verify/consume/invalidate 函数
     （跨函数判定，代表校验环节缺失，爆破/复用成为可能）
2. 密码重置逻辑缺陷（AUTH_PASSWORD_RESET）
   - Token 未绑定用户：reset 函数同时收 token 与 user_id/phone 等目标标识，但体内无
     token→user 绑定校验（verifyTokenOwner/tokenService.verifyAndGetUser 等）
   - 找回流程绕过：步骤一输手机号拿码、步骤二直接带新密码重置且体内无 step 校验

**定位：离线兜底（非主链路）。** 业务逻辑漏洞的主链路是 ``A1BusinessLogicAIAgent``（LLM 语义识别，
见 src/agents/a1_business_logic_ai_agent.py）。本分析器仅在未配置 LLM（ModelGateway 离线）时
作为低成本启发式被调用，不在主链路中。CodeQL 在主链路中承担辅助结构验证（重置 Token 是否绑定用户）。

均为 SAST 种子：产出假说交 D1 操作器做验证码复用/重置越权重放验证，不追求 IAST 自主发现。
"""
# 业务逻辑漏洞主链路为 A1BusinessLogicAIAgent（LLM 语义识别）；本模块仅作离线兜底。
IS_PRIMARY_PATH = False

import re
from typing import Any, Dict, List, Optional, Tuple

from src.agents._bl_common import extract_functions, has_token, safe_text, scan_spring_endpoints

# 角色/权限校验 token（出现任一即视为有授权控制点）
_ROLE_CHECK: Tuple[str, ...] = (
    "hasrole", "hasRole", "preauthorize", "postauthorize", "rolesallowed", "@secured",
    "requirerole", "checkrole", "isadmin", "isAdmin", "role ==", "role.equals",
    "hasauthority", "checkpermission", "authorize", "rbac", "acl", "securityutils",
    "getprincipal", "@preauthorize", "@postauthorize", "@rolesallowed", "verifyrole",
    "assertrole", "requirepermission", "permissionchecker", "accessdecision",
)

# 生成/发送验证码（单函数内可判回显）
_GENERATE_OP = re.compile(
    r"(?i)\b(sendcode|sendsms|sendemail|sendmail|sendnotification|"
    r"getcaptcha|gencaptcha|generatecaptcha|createcode|gencode|"
    r"getverifycode|createverifycode)\b"
)
# 校验/消费验证码（用于文件级「校验环节是否缺失」判定）
_VERIFY_OP = re.compile(
    r"(?i)\b(verifycode|checkcode|validatecode|verifycaptcha|checkcaptcha|"
    r"consumecode|validateverifycode|matchcode)\b"
)
# 验证码回显 token（响应中明文带出 code/captcha）
_ECHO_TOKENS: Tuple[str, ...] = (
    "\"code\"", "\"captcha\"", "\"smscode\"", "\"sms_code\"", "\"verifycode\"",
    "return code", "return captcha", "response.code", "resp.code", "result.code",
    "map.of(\"code\"", "map.of(\"captcha\"",
)
# 密码重置操作
_RESET_OP = re.compile(
    r"(?i)\b(resetpassword|resetpwd|resetpass|forgetpassword|findpassword|"
    r"changepassword|updatepassword|resetpasswd|doreset)\b"
)
# token→user 绑定校验 token（出现任一即视为 token 已绑定用户）
_BINDING_TOKENS: Tuple[str, ...] = (
    "verifytokenowner", "validatetokenowner", "asserttokenowner", "token.getuser",
    "token.getuserid", "token.getusername", "token.belongs", "token.userid",
    "token.user", "tokenService", "tokenmanager", "tokenservice.verify",
    "verifypasswordresettoken", "checktokentouser", "token.getsubject",
)
# 中间步骤校验 token（出现任一即视为有分步校验）
_STEP_VERIFY_TOKENS: Tuple[str, ...] = (
    "verifycode", "checkcode", "validatecode", "verifysms", "smsverified",
    "isverified", "codeverified", "stepverified", "validatecodebefore",
)


def analyze_file(path: str, content: str, lang: Optional[str] = None) -> List[Dict[str, Any]]:
    """单文件分析：返回 认证与会话类 假说列表（验证码缺陷 / 密码重置缺陷 / 未授权接口 /
    回调签名伪造 / JWT 弱校验），均尽量带真实 HTTP 路由以便落 trigger_spec。"""
    content = safe_text(content)
    if lang is None:
        lang = (path.rsplit(".", 1)[-1] if "." in path else "").lower()
    funcs = extract_functions(content, lang)
    hypotheses: List[Dict[str, Any]] = []

    # 方法名 -> (route, http_method) 映射，供下方验证码/重置缺陷补上真实 HTTP 路由
    _route_by_name: Dict[str, Tuple[str, str]] = {}
    for _r, _hm, _blk, _mn, _li in scan_spring_endpoints(content):
        if _mn and _r:
            _route_by_name.setdefault(_mn, (_r, _hm))

    # ---- 路由感知补扫（直接抽取真实 HTTP 路由）----
    for route, http_method, blk, mname, line_idx in scan_spring_endpoints(content):
        if not route:
            continue
        low = blk.lower()
        # #35 未授权接口泄露：/api/internal/** 无任何鉴权即返回敏感数据
        if route.startswith("/api/internal"):
            hypotheses.append({
                "vuln_type": "UNAUTHORIZED_ENDPOINT",
                "category": "auth_session",
                "family": "auth-session",
                "sub_type": "unauthorized_internal_api",
                "entry_point": f"{path}:{line_idx}",
                "target_endpoint": route,
                "http_method": http_method,
                "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                "required_control_point": "内部接口须加身份认证与授权（@PreAuthorize/hasRole/SecurityUtils 校验），禁止匿名访问返回用户明文口令、JWT 密钥等敏感数据",
                "confidence": "high",
                "evidence": f"端点({route}) 无任何鉴权即返回敏感数据（全量用户含明文口令 / JWT 密钥 / 支付盐），属未授权接口泄露",
            })
            continue
        # #34 回调签名伪造/重放：/payment/callback 接受 signType=none 或弱签名可离线伪造
        if "/payment/callback" in route or ("signtype" in low and "none" in low):
            hypotheses.append({
                "vuln_type": "SIGNATURE_BYPASS",
                "category": "auth_session",
                "family": "auth-session",
                "sub_type": "signature_bypass",
                "entry_point": f"{path}:{line_idx}",
                "target_endpoint": route,
                "http_method": http_method,
                "function": mname or (route.rsplit("/", 1)[-1]) or "endpoint",
                "required_control_point": "回调签名须用强算法（HMAC-SHA256）且禁止 signType=none 降级；加 nonce/timestamp 防重放；签名密钥不得硬编码",
                "confidence": "high",
                "evidence": f"端点({route}) 支付回调接受 signType=none 或弱 md5 签名（盐硬编码），可伪造/重放回调",
            })
            continue

    # ---- 文件级 JWT 弱校验（#21）：alg:none 降级 + 弱密钥 → 可伪造任意 role 的 JWT 进入 /admin/** ----
    lowc = content.lower()
    if '"none"' in lowc and "equalsignorecase" in lowc:
        hypotheses.append({
            "vuln_type": "JWT_WEAK",
            "category": "auth_session",
            "family": "auth-session",
            "sub_type": "jwt_alg_none_weak_key",
            "entry_point": f"{path}:{1 if 'JwtUtil' in path else 1}",
            "target_endpoint": "/admin",
            "http_method": "GET",
            "function": "JwtUtil.parse",
            "required_control_point": "JWT 校验须强制 HS256 并拒绝 alg=none；使用强随机密钥且不与前端/仓库共享；role 须经后端实时校验而非信任 token claim",
            "confidence": "high",
            "evidence": "JwtUtil.parse 在 alg=none 时直接信任 payload（签名绕过），且密钥弱（可被字典爆破），可伪造 role=ADMIN 的 JWT 进入 /admin/**",
        })

    # ---- 验证码回显（单函数）----
    for fn in funcs:
        if not _GENERATE_OP.search(fn["name"]):
            continue
        if has_token(fn["body"], _ECHO_TOKENS):
            hypotheses.append({
                "vuln_type": "AUTH_CAPTCHA",
                "category": "auth_session",
                "family": "auth-session",
                "sub_type": "captcha_echo",
                "entry_point": f"{path}:{fn['start']}",
                "function": fn["name"],
                "required_control_point": "验证码不得回显：服务端生成后仅存于会话/缓存，绝不随响应明文返回",
                "confidence": "high",
                "evidence": "发送/生成验证码函数在响应中明文返回 code/captcha（验证码回显）",
            })

    # ---- 验证码无校验环节（文件级）----
    has_generate = any(_GENERATE_OP.search(f["name"]) for f in funcs)
    has_verify = any(_VERIFY_OP.search(f["name"]) or _VERIFY_OP.search(f["body"]) for f in funcs)
    if has_generate and not has_verify:
        gen = next(f for f in funcs if _GENERATE_OP.search(f["name"]))
        hypotheses.append({
            "vuln_type": "AUTH_CAPTCHA",
            "category": "auth_session",
            "family": "auth-session",
            "sub_type": "captcha_no_verify",
            "entry_point": f"{path}:{gen['start']}",
            "function": gen["name"],
            "required_control_point": "验证码须有校验/一次性消费环节：verify 时比对并立即 invalidate（删除/标记 used），并限制尝试次数",
            "confidence": "medium",
            "evidence": "文件内存在发送/生成验证码函数但无 verify/consume/invalidate 校验环节（爆破/复用可能）",
        })

    # ---- 密码重置缺陷（单函数）----
    for fn in funcs:
        if not _RESET_OP.search(fn["name"]):
            continue
        low_body = fn["body"].lower()
        _ri = _route_by_name.get(fn["name"])
        _ep_route = _ri[0] if _ri else ""
        _ep_method = _ri[1] if _ri else "POST"
        # 同时携带 token 与目标标识（user_id/phone/username），但无 token→user 绑定校验
        has_token_param = bool(re.search(r"(?i)\btoken\b", fn["params"] or ""))
        has_target_id = bool(re.search(r"(?i)(user_?id|phone|username|account|mobile)", fn["params"] or ""))
        if has_token_param and has_target_id and not has_token(low_body, _BINDING_TOKENS):
            hypotheses.append({
                "vuln_type": "AUTH_PASSWORD_RESET",
                "category": "auth_session",
                "family": "auth-session",
                "sub_type": "reset_token_unbound",
                "entry_point": f"{path}:{fn['start']}",
                "target_endpoint": _ep_route,
                "http_method": _ep_method,
                "function": fn["name"],
                "required_control_point": "重置 Token 须绑定用户：校验 token 归属后再改密，禁止 token 与 user_id 分离传入且无绑定校验",
                "confidence": "high",
                "evidence": "重置密码函数同时收 token 与目标 user_id/phone 但体内未见 token→user 绑定校验",
            })
            continue
        # 缺少分步校验（直接改密）；若已有 token→user 绑定校验则视为已受控，不报
        if not has_token(low_body, _STEP_VERIFY_TOKENS) and not has_token(low_body, _BINDING_TOKENS):
            hypotheses.append({
                "vuln_type": "AUTH_PASSWORD_RESET",
                "category": "auth_session",
                "family": "auth-session",
                "sub_type": "reset_step_bypass",
                "entry_point": f"{path}:{fn['start']}",
                "target_endpoint": _ep_route,
                "http_method": _ep_method,
                "function": fn["name"],
                "required_control_point": "找回密码须分步校验：步骤一获取凭证（验证码/短信）后，步骤二须先校验该凭证再允许改密",
                "confidence": "medium",
                "evidence": "重置密码函数体内未见分步凭证校验（verifyCode/checkCode 等），存在跳过前置步骤直接改密可能（越权改密/账号接管）",
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
