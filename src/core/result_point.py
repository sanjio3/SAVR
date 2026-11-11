"""结果点比对原语。

「结果点比对」这条通道（证明力 3）在 M4 建了注册表位，但一直是空的——D1 拿到了
响应体/响应头，D2 却只拿它当 `body[:500]` 的展示素材，从没真的**比对**过：
投放值与结果点对不对得上，没人回答。于是 XSS 只能靠 canary 到 sink 这种
「可达性」证据确认，把「回显被 html 转义了」的安全用例也抬成可利用。

本模块给三族补上真正的比对判据，外加语义差分的正交对：

  - XSS 三态：原样回显 = 确认有害；被转义/被编码 = 过滤器有效（真阴性，
    filtered_not_exploitable）；无回显 = 转两步重放（不是无害，是没看到）。
  - CRLF 单开判据：不看响应体，只看**响应头**里有没有被注入的那个头。
    这是本族的专属结果点，绝不能因为它「没有回显」就被当成无证据豁免掉。
  - SSTI 求值对：投 `{{7*7}}` 看响应里是不是 `49`——出现 `49` 且原文不出现
    才叫求值成功；只回显原文说明模板没渲染。
  - 语义差分正交对：双身份/双参数响应对照，结构差为主信号、相似度兜底，
    **长度差不采信**（页面里有时间戳/随机数，长度永远在抖，采信必误判）。

设计红线：
  1. 「没比对上」分两种，必须分开返回：
     - 比对上了但被转义/编码 → definitive=True（这是**结论**：过滤器有效）；
     - 压根没出现在结果点 → definitive=False（这是**没看到**，不是没有，转两步重放）。
     混为一谈会把「存储型 XSS 要两步才回显」的安全缺口误判成安全代码。
  2. 长度差不采信：见 _length_only_diff，写死在这里，别在别处重新发明。
"""
from __future__ import annotations

import html
import json
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, quote

# 回显三态
REFLECTED_RAW = "reflected_raw"          # 原样回显 → 可利用
REFLECTED_ESCAPED = "reflected_escaped"  # 被 HTML 转义 → 过滤器有效
REFLECTED_ENCODED = "reflected_encoded"  # 被 URL/实体编码 → 过滤器有效
ABSENT = "absent"                        # 结果点根本没有 → 转两步重放

# 模板求值三态
EVALUATED = "evaluated"        # 出现乘积、不出现原式 → 模板渲染了
ECHO_ONLY = "echo_only"        # 原式原样回显 → 模板没渲染
NOT_OBSERVED = "not_observed"  # 都没出现 → 转两步

_CRLF_HEADER_RE = re.compile(
    r"(?:%0[dD]%0[aA]|\r\n|\\r\\n|\r|\n)\s*([A-Za-z][A-Za-z0-9_-]*)\s*(?::|%3[aA])")
_TOKEN_RE = re.compile(r"[A-Za-z0-9]{12,}")
_EVAL_PATTERNS = (
    re.compile(r"\{\{\s*(\d{1,3})\s*\*\s*(\d{1,3})\s*\}\}"),      # Jinja / Twig / Freemarker
    re.compile(r"\$\{\s*(\d{1,3})\s*\*\s*(\d{1,3})\s*\}"),        # JSP EL / Thymeleaf
    re.compile(r"#\{\s*(\d{1,3})\s*\*\s*(\d{1,3})\s*\}"),         # OGNL / SpEL
    re.compile(r"<%=\s*(\d{1,3})\s*\*\s*(\d{1,3})\s*%>"),         # JSP scriptlet
)

_XSS_TOKENS = ("xss", "reflected", "html_injection")
_CRLF_TOKENS = ("crlf", "header_injection", "response_splitting", "http_header")
_SSTI_TOKENS = ("ssti", "template", "thymeleaf", "freemarker", "velocity", "jinja",
                "ognl", "spel", "el_injection", "expression")


def _norm_family(family: str) -> str:
    return str(family or "").strip().lower().replace("-", "_").replace(" ", "_")


def _has_token(family: str, tokens: Tuple[str, ...]) -> bool:
    f = _norm_family(family)
    return any(t in f for t in tokens)


def _payload_of(dast: Dict[str, Any]) -> str:
    d = dast or {}
    for key in ("attack_payload_used", "payload", "attack_payload"):
        v = d.get(key)
        if v:
            return str(v)
    return ""


def _body_of(dast: Dict[str, Any]) -> str:
    d = dast or {}
    return str(d.get("body") or d.get("response_summary") or "")


def _headers_of(dast: Dict[str, Any]) -> Dict[str, str]:
    d = dast or {}
    h = d.get("headers") or d.get("resp_headers") or {}
    if isinstance(h, dict):
        return {str(k).lower(): str(v) for k, v in h.items()}
    return {}


def _marker_tokens(payload: str) -> List[str]:
    """从载荷里取「能唯一标识这次投放」的标记串（canary / 长随机段）。

    12 位以上字母数字串足以区分于页面固有文案；短串（如 "alert(1)"）不做标记，
    否则页面里恰好有同名字符串就会误判回显。
    """
    if not payload:
        return []
    return [t for t in _TOKEN_RE.findall(payload)]


# ── XSS 三态 ──

def echo_state(payload: str, body: str) -> str:
    """投放值在响应体里的回显形态。"""
    if not payload or not body:
        return ABSENT
    for form in (payload, unquote(payload)):
        if form and form in body:
            return REFLECTED_RAW
    toks = _marker_tokens(payload)
    hit = [t for t in toks if t in body]
    if not hit:
        return ABSENT
    # 标记在但原文不在 → 被转义或被编码，都不是可利用回显
    for t in hit:
        if html.escape(t) != t and html.escape(t) in body:
            return REFLECTED_ESCAPED
    if html.escape(payload) in body:
        return REFLECTED_ESCAPED
    # 实体化痕迹：即便没逐字对上 escape(payload)（应用只转义了尖括号没转义引号），
    # 出现实体就说明输出侧做了 HTML 转义 —— 这才是真实世界里最常见的形态。
    if any(ent in body for ent in ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&amp;")):
        return REFLECTED_ESCAPED
    for t in hit:
        # 必须 quote(t) != t 才算「被编码」：纯字母数字的标记 quote 后是自身，
        # 不加这个守卫会把已转义的回显误判成编码（两者都不是可利用，但语义要分清）。
        if quote(t) != t and quote(t) in body:
            return REFLECTED_ENCODED
    # 标记出现但形式已变（多半是被实体化/过滤），保守判转义
    return REFLECTED_ESCAPED


def judge_xss(dast: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = _payload_of(dast)
    body = _body_of(dast)
    if not payload:
        return None
    st = echo_state(payload, body)
    if st == REFLECTED_RAW:
        return {"matched": True, "state": st, "definitive": True,
                "detail": f"投放值『{payload[:60]}』在响应体中原样回显（未转义、未编码）",
                "evidence": body[:300], "suggested_status": "confirmed_exploitable"}
    if st in (REFLECTED_ESCAPED, REFLECTED_ENCODED):
        return {"matched": False, "state": st, "definitive": True,
                "detail": (f"投放值在结果点出现但已被{'HTML 转义' if st == REFLECTED_ESCAPED else 'URL/实体编码'}"
                           "——过滤器有效，不构成可利用 XSS（真阴性）"),
                "evidence": body[:300], "suggested_status": "filtered_not_exploitable"}
    return {"matched": False, "state": ABSENT, "definitive": False,
            "detail": "投放值未出现在本次响应体中（存储型/二阶需两步重放，不代表无害）",
            "evidence": "", "suggested_status": None, "next_action": "two_step_replay"}


# ── CRLF 响应头单开判据 ──

def _injected_header_name(payload: str) -> str:
    m = _CRLF_HEADER_RE.search(payload or "")
    if m:
        return m.group(1)
    m = _CRLF_HEADER_RE.search(unquote(payload or ""))
    if m:
        return m.group(1)
    return ""


def judge_crlf(dast: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """CRLF 专判：只看响应头里有没有被注入的那个头名。

    「单开判据不豁免」：本族的结果点就是响应头，不是响应体。响应体里没回显
    不代表没有注入——若拿通用回显判据套它，会把所有响应头注入漏掉。
    """
    payload = _payload_of(dast)
    if not payload:
        return None
    headers = _headers_of(dast)
    body = _body_of(dast)
    name = _injected_header_name(payload)
    if name:
        if name.lower() in headers:
            return {"matched": True, "state": "header_injected", "definitive": True,
                    "detail": f"响应头中出现被注入的头『{name}={headers[name.lower()][:60]}』，"
                              "CRLF 注入已生效（响应头是结果点，与响应体回显无关）",
                    "evidence": f"{name}: {headers[name.lower()][:120]}",
                    "suggested_status": "confirmed_exploitable"}
        if re.search(r"(?im)^\s*" + re.escape(name) + r"\s*:", body):
            return {"matched": True, "state": "header_reflected_in_body", "definitive": True,
                    "detail": f"注入的头名『{name}』出现在响应体（服务端把伪造头写进了输出流）",
                    "evidence": body[:300], "suggested_status": "confirmed_exploitable"}
    # 无显式头名（载荷只带 CRLF 分隔）→ 退到「标记串是否出现在响应头值里」
    for tok in _marker_tokens(payload):
        for k, v in headers.items():
            if tok in v:
                return {"matched": True, "state": "marker_in_header", "definitive": True,
                        "detail": f"投放标记串出现在响应头『{k}』的值中，CRLF 注入已生效",
                        "evidence": f"{k}: {v[:120]}", "suggested_status": "confirmed_exploitable"}
    return {"matched": False, "state": ABSENT, "definitive": False,
            "detail": "响应头中未观测到注入头（可能被容器过滤或参数未进入响应头）",
            "evidence": "", "suggested_status": None}


# ── SSTI 求值对 ──

def judge_ssti(dast: Dict[str, Any], engines: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """模板注入求值对：投探针表达式看是不是回 `49`（而不是回原式）。

    M10 起按**引擎分桶**派发求值对：不同引擎的求值语法不同（SpEL/Thymeleaf `${7*7}`、
    OGNL `%{7*7}`、Pebble `{{ 7*7 }}`、FreeMarker 还要 `?c` 形态），拿一组求值对打所有
    引擎会同时造成漏报（语法不匹配的引擎永远算不出来）与误报（别的表达式恰好算出 49）。
    引擎由 A1 静态从 import / class 路径识别（不需要 LLM）；识别不出时走跨引擎兜底
    求值对，但置信度降级并留痕，不冒充「已识别引擎」。

    口径（与 XSS/CRLF 同一纪律）：原样回显 = 模板没求值 = **真阴性**，
    既不能抬成可利用，也不该掉成 no_evidence。
    """
    from src.core import ssti_engines as _se

    body = _body_of(dast)
    if not body:
        return None
    # 1) 先按 D1 实际投放的载荷原样判（它可能不是 7*7 而是别的算式）
    payload = _payload_of(dast)
    if payload:
        for pat in _EVAL_PATTERNS:
            m = pat.search(payload) or pat.search(unquote(payload))
            if not m:
                continue
            a, b = int(m.group(1)), int(m.group(2))
            expected = str(a * b)
            raw_expr = m.group(0)
            st = _se.judge(body, raw_expr, expected)
            if st == _se.SSTI_EVALUATED:
                return {"matched": True, "state": EVALUATED, "definitive": True,
                        "detail": f"模板求值成功：投放 {raw_expr} 得到 {expected}（原式未回显，说明表达式被引擎求值）",
                        "evidence": body[:300], "suggested_status": "confirmed_exploitable"}
            if st == _se.SSTI_LITERAL:
                return {"matched": False, "state": ECHO_ONLY, "definitive": True,
                        "detail": f"表达式 {raw_expr} 原样回显、未见求值结果 {expected}——模板未渲染（真阴性）",
                        "evidence": body[:300], "suggested_status": "filtered_not_exploitable"}
            break

    # 2) 没投放可判的载荷（或投放的不是算式）→ 按引擎桶回扫响应
    res = _se.judge_by_engine(body, engines)
    if res.get("state") == _se.SSTI_EVALUATED:
        return {"matched": True, "state": EVALUATED, "definitive": True,
                "detail": ("模板求值成功：%s 引擎求值对 %s → %s"
                           % (res.get("engine") or "未识别引擎（跨引擎兜底）",
                              res.get("payload"), res.get("expected"))),
                "evidence": body[:300], "suggested_status": "confirmed_exploitable",
                "ssti_engine": res.get("engine") or "",
                "engine_identified": bool(res.get("engine_identified"))}
    if res.get("state") == _se.SSTI_LITERAL:
        return {"matched": False, "state": ECHO_ONLY, "definitive": True,
                "detail": "模板表达式原样回显、未见任何引擎的求值结果——模板未渲染（真阴性）",
                "evidence": body[:300], "suggested_status": "filtered_not_exploitable",
                "ssti_engine": res.get("engine") or ""}
    return {"matched": False, "state": NOT_OBSERVED, "definitive": False,
            "detail": "未在响应中观测到求值对（可能需两步重放或引擎分桶不匹配）",
            "evidence": "", "suggested_status": None, "next_action": "two_step_replay",
            "ssti_tried": len(res.get("tried") or []),
            "ssti_engine_identified": bool(res.get("engine_identified"))}


# ── 语义差分正交对 ──

def _json_keys(text: str) -> Optional[set]:
    try:
        data = json.loads(text)
    except Exception:
        return None
    if isinstance(data, dict):
        return set(data.keys())
    return None


def _length_only_diff(a: str, b: str, similarity: float) -> bool:
    """长度差不采信：只有长度在变、内容几乎一致时不算语义差。

    页面里的时间戳、CSRF token、随机数会让长度永远在抖。采信长度差会把
    「同一页面的两次请求」判成「语义不同」，越权族会全线假阳。
    """
    if not a or not b:
        return False
    if len(a) == len(b):
        return False
    return similarity >= 0.9


def semantic_diff_pair(text_a: str, text_b: str, victim_markers: Optional[List[str]] = None,
                       status_a: Any = None, status_b: Any = None) -> Dict[str, Any]:
    """双身份 / 双参数响应对照。

    主信号是**结构差**（JSON key 集合 / 状态码），相似度只作兜底，长度差显式不采信。
    """
    a = str(text_a or "")
    b = str(text_b or "")
    markers = [m for m in (victim_markers or []) if m]
    hit = [m for m in markers if m and m in a]
    if hit:
        return {"matched": True, "detail": f"攻击者响应中出现受害者标识 {hit[:3]}（越权取回他人数据）",
                "similarity": None, "structure_diff": True, "length_only": False,
                "evidence": a[:300]}
    if status_a is not None and status_b is not None and int(status_a) != int(status_b):
        return {"matched": True,
                "detail": f"同一资源两次请求状态码不同（{status_a} vs {status_b}），语义不一致",
                "similarity": None, "structure_diff": True, "length_only": False,
                "evidence": f"{status_a} vs {status_b}"}
    ka, kb = _json_keys(a), _json_keys(b)
    if ka is not None and kb is not None and ka != kb:
        added = sorted(kb - ka)[:5]
        removed = sorted(ka - kb)[:5]
        return {"matched": True,
                "detail": f"响应结构不同（新增 {added} / 缺失 {removed}），语义不一致",
                "similarity": None, "structure_diff": True, "length_only": False,
                "evidence": a[:300]}
    if not a or not b:
        return {"matched": False, "detail": "对照样本缺失（未取到两次响应）",
                "similarity": None, "structure_diff": False, "length_only": False}
    sim = SequenceMatcher(None, a[:4000], b[:4000]).ratio()
    if sim >= 0.98:
        return {"matched": False, "detail": f"两次响应高度一致（相似度 {sim:.3f}），无语义差",
                "similarity": round(sim, 4), "structure_diff": False, "length_only": False}
    if _length_only_diff(a, b, sim):
        return {"matched": False,
                "detail": f"仅长度变化（相似度 {sim:.3f}）——长度差不采信（时间戳/随机数会抖）",
                "similarity": round(sim, 4), "structure_diff": False, "length_only": True}
    return {"matched": True, "detail": f"响应语义不同（相似度 {sim:.3f}）",
            "similarity": round(sim, 4), "structure_diff": False, "length_only": False,
            "evidence": a[:300]}


def evaluate_semantic_diff(dast: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """从 dast 证据里取（或算）语义差分结论。dast['semantic_diff'] 由 D1 直供时优先。"""
    d = dast or {}
    sd = d.get("semantic_diff")
    if isinstance(sd, dict) and sd:
        return sd
    pair = d.get("pair_responses")
    if isinstance(pair, (list, tuple)) and len(pair) >= 2:
        a = pair[0] if isinstance(pair[0], dict) else {"body": pair[0]}
        b = pair[1] if isinstance(pair[1], dict) else {"body": pair[1]}
        res = semantic_diff_pair(
            str(a.get("body") or ""), str(b.get("body") or ""),
            victim_markers=list(d.get("victim_markers") or []),
            status_a=a.get("status_code"), status_b=b.get("status_code"),
        )
        res["category"] = str(d.get("semantic_diff_category") or "pair")
        return res
    return None


# ── 分族派发 ──

def evaluate_result_point(family: str, dast: Dict[str, Any],
                          engines: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """按族派发结果点比对。无对应判据返回 None（通道不出结论，不臆断）。

    engines 是 M10 引入的引擎桶（A1 静态识别得到）：只有 SSTI 用得上，其它族忽略。
    也接受从 dast 里读（A1 把 ssti_engines 挂在 DastImpact 上的情形）。
    """
    d = dast or {}
    rpd = d.get("result_point_diff")
    if isinstance(rpd, dict) and rpd:
        return rpd
    if _has_token(family, _XSS_TOKENS):
        return judge_xss(d)
    if _has_token(family, _CRLF_TOKENS):
        return judge_crlf(d)
    if _has_token(family, _SSTI_TOKENS):
        _engs = engines or d.get("ssti_engines") or []
        if isinstance(_engs, str):
            _engs = [_engs]
        return judge_ssti(d, [str(x) for x in _engs if x])
    return None
