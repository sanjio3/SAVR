"""两步重放（存储型写→读配对）的数据结构与读端点定位（Part2 定稿本轮 M7，2026-10-03 落地）。

背景（为什么要两步，插桩为什么帮不上）：
    canary 是注进**请求参数**的（d1_service 把 taint_marker 注入请求），所以污点源是 HTTP
    请求参数，传播范围限于**请求内**。
      - 反射型：请求带 canary 进来、响应里出去，探针全程看得到，回显比对也搜得到。
      - 存储型：写入请求里 canary 进了 DAO，探针能看到「到达写 sink」；但读取请求的
        参数里根本没有 canary——它是**从数据库读出来的**。探针在读取侧没有污点可跟，
        除非把「数据库读」也当污点源，而那样等于所有 DB 读出来的数据都带污点 → 全线误报。
    要让污点跨请求存活，得在探针层做行级污点持久化，成本高且不通用。
    所以存储型的读取侧，**回显比对（搜我们投的 UUID 字符串）是唯一通用手段**。

两步重放解决的不是「取证问题」，而是**构造出那个读取请求**，让存进去的数据有机会进入响应。

读端点三级定位（2026-10-02 决议修正一，标记反查是兜底不是首选）：
    一级 静态分析侧（A1）：写接口判定 a1_template_xss_analyzer 已有（_collect_write_endpoints
         按实体字段 + DB 落库信号识别写接口），读接口是同一套逻辑的对称面，由 A1 一起给出。
    二级 LLM（A2）：静态给不出时由 A2 读代码补候选。
    三级 标记反查（兜底）：投带 UUID 唯一标记的值，把 GET 端点清单挨个请求一遍，
         看哪个响应里出现了这个 UUID。
    但三级要保留一项用途：即便静态给了读端点，也用 UUID 验一次「确实是从这个端点读出来的」，
    避免静态给的读端点根本不渲染该字段。

设计红线（改这个文件前必读）：
    1. **数据结构挂 spec.raw_json 的 replay_plan，不改表结构** —— 两步重放是试验性通道，
       一旦写表就得背一套 schema 兼容债。读的时候两边都试（显式 replay_plan 优先，
       退化到 spec 顶层字段），写的时候只写 raw_json。
    2. 脏数据用 UUID **自限标记**，不加删除步骤。存储型写进去的东西没有通用办法清理，
       删除接口本身可能不存在/需要权限/会误删别人的数据。靠 UUID 值本身「只是一次写」
       把污染面压到最小（写入的是我们自己的标记串，不是真漏洞 payload 的持久化）。
    3. 回显命中要分**三态**，不能只看「搜得到」：
       raw（原样出现）/ escaped（只出现实体化形态）/ absent。
       escaped 表示「到了但被转义」＝真阴性，绝不能当成可利用——这是 M5 同一条纪律
       （结果点被转义 = filtered_not_exploitable）。
"""
from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)

REPLAY_PLAN_VERSION = 1

# 自限标记形态：sastai-<16位hex>。
# 为什么不用完整 UUID（带连字符的 36 字符）：存储型回显可能被 HTML 转义、JSON 转义、
# 模板转义，串越长被截断/破坏的概率越高。16 位 hex 足够唯一（同一 spec 内唯一即可，
# 不需要跨任务全局唯一），且形态规整便于搜。
MARKER_PREFIX = "sastai"
_MARKER_RE = re.compile(r"^" + MARKER_PREFIX + r"-([0-9a-f]{16})$", re.IGNORECASE)


def make_self_limiting_marker() -> str:
    """生成一个自限标记（每次调用必不同，同一 spec 内可重复用于写/读配对）。"""
    return "%s-%s" % (MARKER_PREFIX, uuid4().hex[:16])


def is_marker(value: Any) -> bool:
    """值是不是本平台生成的自限标记（用于把回显里的标记与业务数据区分开）。"""
    return bool(_MARKER_RE.match(str(value or "").strip()))


def marker_id(marker: str) -> str:
    """从标记里取纯 id 段（sastai-abc123 → abc123），用于二次编码/拼接时保持短。"""
    m = _MARKER_RE.match(str(marker or "").strip())
    return m.group(1) if m else str(marker or "")


# ── 回显三态 ──
ECHO_RAW = "raw"              # 原样出现：可利用（存储型 XSS 必须走这条才算数）
ECHO_ESCAPED = "escaped"      # 只出现实体化形态：到 sink 了但被转义 → 真阴性
ECHO_ABSENT = "absent"        # 没出现：本次未能证明（可能是读取侧、可能是写没成功）

# HTML 实体化痕迹：命中即说明「框架做了转义输出」，不是可利用
_ENTITY_TOKENS = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&amp;")
# 常见转义输出函数 / 模板语法（读到即视为可能被转义）
_ESCAPE_HINTS = (
    "htmlspecialchars", "escapehtml", "encode(", "htmlescape",
    "th:text", "c:out", "f:outputtext", "out.print", "write(", "escapexml",
    "text(", "h(",
)


def classify_echo(body: Any, marker: str) -> str:
    """判定自限标记在响应体里的呈现形态：raw / escaped / absent。

    只认「整标记串」的三种形态，不做子串模糊匹配——模糊匹配会把业务里恰好同形的
    字符串算成我们的回显，那是伪造证据（平台铁律：全真实数据禁伪造）。
    """
    text = str(body or "")
    mk = str(marker or "")
    if not text or not mk:
        return ECHO_ABSENT
    # ① 原样出现 = raw（除非整串被实体化包裹）。必须**先**在这里收口返回：
    # 否则后面的实体化兜底分支会拿 `mk.replace("-", "&lt;")` 这种残缺变体去匹配
    # 正文里别处的 `&lt;` —— 实测 `a &lt; b <marker>` 会被误判成 escaped，
    # 而框架明明是原样输出、模板没转义，那是可利用（真阳性），判成 escaped 就是漏报。
    if mk in text:
        return ECHO_ESCAPED if _looks_escaped_around(text, mk) else ECHO_RAW
    # ② 标记被拆散/被实体化包裹（如 &lt;marker&gt;）：按「紧邻实体化」判定
    mid = marker_id(mk)
    if mid and mid in text:
        return ECHO_RAW if not looks_escaped_around_marker(text, mid) else ECHO_ESCAPED
    for _wrap in _escaped_wraps(mk):
        if _wrap in text:
            return ECHO_ESCAPED
    return ECHO_ABSENT


_ESCAPE_LEFT = ("&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&amp;", "'", '"')
_ESCAPE_RIGHT = ("&gt;", "&lt;", "&amp;", "&#39;", "&#x27;")


def _escaped_wraps(marker: str) -> List[str]:
    """标记被整体实体化包裹的候选形态（用于「原样串不在、只有实体串在」时判定 escaped）。

    组合数很小（左 7 × 右 6），且只在原样串缺失时才展开，不会拖慢热路径。
    """
    out: List[str] = []
    for l in _ESCAPE_LEFT:
        for r in _ESCAPE_RIGHT:
            out.append(l + marker + r)
    return out


def looks_escaped_around_marker(text: str, mid: str) -> bool:
    """id 段出现时，它两侧紧邻处是否已被实体化（判据同 _looks_escaped_around）。
    窗口同样取 4，理由见该函数注释。
    """
    idx = text.find(mid)
    if idx < 0:
        return False
    left4 = text[max(0, idx - 4):idx]
    right5 = text[idx + len(mid): idx + len(mid) + 5]
    return left4 in ("&lt;", "&gt;") or right5 in ("&lt;", "&gt;", "&amp;")


def _looks_escaped_around(text: str, marker: str) -> bool:
    """标记两侧**紧邻**（4 字符窗口）出现实体化痕迹 → 判定为转义输出。

    窗口必须正好是 4（`&lt;` / `&gt;` 都是 4 字符）：取不满 4 字符（如 3）会拼不出
    完整实体（`&lt;` 的最后 3 字符是 `lt;`）→ 转义形态永远判不出来；放宽到 8 则把
    正文别处的 `&lt;` 算进来——实测 `a &lt; b sastai-xxx` 被误判成 escaped，
    而框架是原样输出、模板没转义，那是有可利用的真阳性，判成 escaped 就是漏报。

    只认 `&lt;` 紧左 / `&gt;` 紧右 / `&amp;` 紧右：`<marker>` 这种原字符尖括号包裹是
    th:utext 原样输出的形态（XSS payload 本就是尖括号开头），必须判 raw。
    """
    idx = text.find(marker)
    if idx < 0:
        return False
    # 左取 4（`&lt;`/`&gt;` 都是 4 字符）、右取 5（`&amp;` 是 5 字符）—— 不对称是刻意的。
    left4 = text[max(0, idx - 4):idx]
    right5 = text[idx + len(marker): idx + len(marker) + 5]
    return left4 in ("&lt;", "&gt;") or right5 in ("&lt;", "&gt;", "&amp;")


def looks_escaped_code(body: Any) -> bool:
    """响应体是否整体呈现「转义输出痕迹」（供读取侧没法塞 marker 时兜底判形态）。"""
    text = str(body or "").lower()
    return any(tok in text for tok in _ENTITY_TOKENS)


# ── 读端点定位 ──
# DB 读信号：方法体里查过库（避免把纯页面渲染/静态转发算成读端点）
_DB_READ_TOKENS = (
    "select", "query", "getbyid", "getone", "findby", "mapper", "repository",
    "jdbctemplate", "hibernate", "entitymanager", "dao", "findall", "list(",
    "getby", "sqlsession",
)
_GET_METHODS = {"GET"}


def _norm_route(route: Any) -> str:
    r = str(route or "").strip()
    return r.lstrip("/")


def collect_read_endpoints(java_files: Iterable[Dict[str, Any]],
                           fields: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """静态侧收集「会对外读出实体字段」的 GET 端点（读接口 = 写接口判定的对称面）。

    字段来源优先级：
      1) 方法体里 model.addAttribute("field", ...) / model 里带出（Thymeleaf/模板渲染）；
      2) 方法体里查过库，且方法体 return 的视图名/对象与该字段相关（判据是字段名出现在
         方法体任意位置且查过库）；
      3) 表单/模板里引用了该字段的读取视图。

    只读出「方法体同时满足：读库信号 + 含目标字段名」的端点才算候选，避免把
    /login、/error 这类页面端点全算进来（会把标记反查的请求数烧爆）。

    返回：[{route, method, fields:set, db_read:bool, source:"model"|"return"|"form"}]
    """
    from src.agents._bl_common import scan_spring_endpoints

    want = {str(f or "").lower() for f in (fields or []) if f}
    eps: List[Dict[str, Any]] = []
    for f in java_files or []:
        content = f.get("content") or ""
        for route, http_method, block, mname, line in scan_spring_endpoints(content):
            if (str(http_method or "").upper()) not in _GET_METHODS:
                continue
            low = (block or "").lower()
            if not any(tok in low for tok in _DB_READ_TOKENS):
                continue
            fields: Set[str] = set()
            source = "return"
            for m in re.finditer(
                    r"\bmodel\.\w*[Aa]dd(?:Attribute|Object)\s*\(\s*[\"']([^\"']+)[\"']", block or ""):
                fields.add(str(m.group(1)))
            if want and (fields & want):
                source = "model"
            elif want:
                # 字段没在 model 里显式带出 → 判据退化为「方法体里出现过该字段名」+ 查过库
                if not any(w in low for w in want):
                    continue
                fields.update(want)
            elif fields:
                fields.update(fields)
            else:
                continue
            if not want:
                fields = set(fields)
            eps.append({
                "route": route,
                "method": "GET",
                "fields": fields,
                "db_read": True,
                "source": source,
                "function": mname or "",
                "line": line,
            })
    return eps


def match_read_endpoint(read_eps: List[Dict[str, Any]], field: str,
                        write_route: str = "") -> Tuple[str, str]:
    """为存储型字段找读端点。返回 (route, 定位方式)，定位方式是静态侧的说法（一级）。

    三级里最便宜的一级先走：写路由同路径的 GET（写 /comment 就读 GET /comment），
    这条零成本且命中率不低；其次才是全表按字段匹配。
    """
    field = str(field or "").lower()
    wr = _norm_route(write_route)
    if wr:
        # 同路径 GET：/comment → GET /comment（注意 /comments 这类集合路由不算同路径，
        # 否则会把列表页当成长页，标记反查时白跑一趟）
        for e in read_eps:
            if _norm_route(e.get("route")) == wr and e.get("method") == "GET":
                return e["route"], "same_path_get"
    if field:
        for e in read_eps:
            if field in {str(x).lower() for x in (e.get("fields") or [])}:
                if e.get("source") == "model":
                    return e["route"], "model_field"
                return e["route"], "read_hit"
    return "", "none"


def _norm_read_endpoint(read_endpoint: Any, read_source: str = "none") -> Dict[str, Any]:
    """归一化读端点字段：外部有时传 str、有时传 dict，plan 内恒为 dict（单一形态）。

    plan['read_endpoint'] 恒为 {'endpoint': str, 'source': str} —— D1 与 D2 都按这个
    形状读，两种传参都能归一化，避免上游传了 str 下游按 dict 取字段直接 KeyError。
    """
    if isinstance(read_endpoint, dict):
        return {
            "endpoint": str(read_endpoint.get("endpoint") or ""),
            "source": str(read_endpoint.get("source") or read_source or "none"),
        }
    return {"endpoint": str(read_endpoint or ""), "source": str(read_source or "none")}


def build_replay_plan(write_endpoint: str, write_method: str = "POST",
                      stored_field: str = "", read_endpoint: Any = "",
                      read_source: str = "none", marker: str = "") -> Dict[str, Any]:
    """构造 replay_plan（挂 spec.raw_json，不写表）。

    steps 里每一步有 端点/方法/参数/抽取规则 —— 都能在 raw_json 里自解释，
    不需要新列。抽取规则统一为「在响应体里找 marker」，读步骤额外带形态判定。
    """
    mk = marker or make_self_limiting_marker()
    return {
        "version": REPLAY_PLAN_VERSION,
        "enabled": bool(write_endpoint) and (bool(read_endpoint) or read_source == "probe_scan"),
        # 写这一步复用现有主重放的端点/参数；这里只登记「往哪个字段投什么值」
        "stored_field": str(stored_field or ""),
        "marker": mk,
        "steps": [
            {
                "role": "write",
                "method": str(write_method or "POST").upper(),
                "endpoint": str(write_endpoint or ""),
                "param": str(stored_field or ""),
                "value": mk,
                "extract": {"kind": "status_code", "needle": ""},
            },
            {
                "role": "read",
                "method": "GET",
                "endpoint": str(read_endpoint or ""),
                "param": "",
                "value": "",
                # 抽取规则：搜 marker 并定形态（raw/escaped/absent）
                "extract": {"kind": "substring", "needle": mk, "state": "raw|escaped|absent"},
            },
        ],
        # 读端点来源留痕：static（A1 静态）/ llm（A2 补）/ probe_scan（标记反查兜底）
        "read_endpoint": _norm_read_endpoint(read_endpoint, read_source),
    }


def plan_from_spec(spec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """从 spec（或 spec.raw_json）读回 replay_plan，两边都试。

    显式 replay_plan 优先；退化到 spec 顶层的 write_endpoint/read_endpoint 字段
    （历史 spec 与 A1 直出的假说都可能这么带），拼一个最小可用 plan。
    """
    spec = spec or {}
    raw = spec.get("raw_json") or {}
    if isinstance(raw, str):
        try:
            import json as _json
            raw = _json.loads(raw) if raw.strip() else {}
        except Exception:
            raw = {}
    if not isinstance(raw, dict):
        raw = {}

    plan = raw.get("replay_plan")
    if isinstance(plan, dict) and plan:
        # 归一化：上游可能只塞了 str 形态的 read_endpoint，统一成 dict，
        # 免得 D1/D2 两种读法各写一遍兼容分支。
        if isinstance(plan.get("read_endpoint"), str) or "read_endpoint_source" in plan:
            plan = dict(plan)
            plan["read_endpoint"] = _norm_read_endpoint(
                plan.get("read_endpoint"), plan.get("read_endpoint_source") or "static")
        return plan

    w_ep = raw.get("write_endpoint") or spec.get("write_endpoint") or ""
    r_ep = raw.get("read_endpoint") or spec.get("read_endpoint") or ""
    if w_ep or r_ep:
        field = raw.get("stored_field") or spec.get("vulnerable_param") or ""
        src = raw.get("read_endpoint_source") or ("static" if r_ep else "none")
        return build_replay_plan(w_ep, spec.get("http_method") or "POST", field, r_ep, src)

    return {}


def plan_to_spec(spec: Dict[str, Any], plan: Dict[str, Any]) -> Dict[str, Any]:
    """把 replay_plan 挂回 spec.raw_json（原地改 spec 并返回，调用方自行序列化）。"""
    spec = spec or {}
    raw = spec.get("raw_json")
    if isinstance(raw, str):
        try:
            import json as _json
            raw = _json.loads(raw) if raw.strip() else {}
        except Exception:
            raw = {}
    if not isinstance(raw, dict):
        raw = {}
    raw["replay_plan"] = plan
    spec["raw_json"] = raw
    return spec


def scan_read_candidates(candidates: Iterable[str], marker: str,
                         fetch: Callable[[str], Tuple[int, str]],
                         limit: int = 12) -> Dict[str, Any]:
    """三级兜底：标记反查 —— 挨个请求 GET 端点候选，看哪个响应里出现了这个 UUID。

    fetch(route) → (status_code, body)。命中即停（先命中的先报），避免把整个
    靶场端点表扫完拖长扫描时长。limit 是硬上限，宁可少报也不烧预算。
    返回 {endpoint, status_code, state, tried, exhausted}。
    """
    mk = str(marker or "")
    tried: List[str] = []
    for route in list(candidates or [])[: max(1, int(limit))]:
        route_s = str(route or "")
        if not route_s:
            continue
        tried.append(route_s)
        try:
            code, body = fetch(route_s)
        except Exception as exc:
            logger.debug("[replay_plan] 标记反查 GET %s 失败：%s", route_s, exc)
            continue
        state = classify_echo(body, mk)
        if state == ECHO_RAW:
            return {
                "endpoint": route_s, "status_code": code, "state": ECHO_RAW,
                "tried": tried, "exhausted": False, "source": "probe_scan",
            }
        if state == ECHO_ESCAPED:
            # 转义也算「读到了」，只是不可利用 —— 记下来免得重复扫
            return {
                "endpoint": route_s, "status_code": code, "state": ECHO_ESCAPED,
                "tried": tried, "exhausted": False, "source": "probe_scan",
            }
    return {
        "endpoint": "", "status_code": None, "state": ECHO_ABSENT,
        "tried": tried, "exhausted": bool(len(list(candidates or [])) <= max(1, int(limit))),
        "source": "probe_scan",
    }
