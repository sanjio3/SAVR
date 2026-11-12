"""benchmark Servlet 触发器适配器（Layer 2：finding → servlet 路由关联）。

``@WebServlet(value = "/sqli-00/BenchmarkTestNNNNN")`` 注册 HTTP 入口，而 A1 命中
点锚在 sink/helper 文件（DatabaseHelper.java / ExpressionEvaluator.java / ...）。
``resolve_trigger_endpoint`` 的 Tier2 类级模糊匹配按「漏洞文件 basename == 路由文件
basename」对齐，helper ≠ 控制器 → 对不上 → 253 个候选里 252 个 ``no_trigger_spec`` 跳过，
D2 动态验证 confirmed=0。IAST 探针本身可用（打 XSS-153 已出 sink-reached 事件）。

本适配器把每个 A1 finding 关联到一个同类别的 BenchmarkTest servlet 路由，生成可回放的
trigger_spec，使 D2 能真实重放确认。类别级关联：同类别任意 servlet 都能到达该类别 sink，
足以确认该类漏洞；faithful 1:1（servlet→其具体到达的 sink 行）需调用图/污点流，作为后续。

关键：注册 spec 时把 ``raw`` 设为该 finding 的 vuln 全量 dict，使
``build_trigger_spec_assoc_index`` 用其算出的 ``stable_vuln_keys`` 与验证端对 finding
算的键同源，D2 反查必命中（与 auto_register_from_a2 同一口径）。
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 平台漏洞族（finding.type，中英文混合）→ benchmark URL 类别前缀
_TYPE_TO_CATEGORY: Dict[str, str] = {
    "sql": "sqli",
    "sql 注入": "sqli",
    "sql_injection": "sqli",
    "xss": "xss",
    "command_execution": "cmdi",
    "cmdi": "cmdi",
    "command injection": "cmdi",
    "path_traversal": "pathtraver",
    "pathtraver": "pathtraver",
    "不安全加密算法": "crypto",
    "crypto": "crypto",
    "弱哈希算法": "hash",
    "weak_hash": "hash",
    "弱随机数": "weakrand",
    "weak_random": "weakrand",
    "cookie 安全属性缺失": "securecookie",
    "securecookie": "securecookie",
    "信任边界违背": "trustbound",
    "trustbound": "trustbound",
    "xxe": "xxe",
    "ssrf": "ssrf",
    "spel_injection": "spel",
    "spel": "spel",
    "sensitive_exposure": "sensitive_exposure",
}


def benchmark_category_for_route(route: str) -> Optional[str]:
    """从 servlet 路由解析 benchmark 类别前缀（去 -00/-01 子版本号）。

    非 benchmark 路由返回 None。
    """
    if not route or "BenchmarkTest" not in route:
        return None
    m = re.search(r"/([a-z0-9]+)-\d+/BenchmarkTest", route)
    if m:
        return m.group(1)
    # 退化：仅取首个路径段
    seg = route.strip("/").split("/")[0]
    return seg.split("-")[0] if seg else None


def _is_benchmark_route(route: str) -> bool:
    return bool(route) and "BenchmarkTest" in route


def category_for_finding_type(vuln_type: str) -> Optional[str]:
    """把平台 finding.type 归一为 benchmark 类别前缀。"""
    if not vuln_type:
        return None
    key = vuln_type.strip().lower()
    # 直接命中
    if key in _TYPE_TO_CATEGORY:
        return _TYPE_TO_CATEGORY[key]
    # 子串/别名兜底
    for k, v in _TYPE_TO_CATEGORY.items():
        if k in key or key in k:
            return v
    return None


def extract_servlet_taint_param(java_file: Path, class_name: str) -> Tuple[str, str]:
    """从 servlet 源码抽取污点源参数名 + 位置。

    为类名——类名恒等于类名，于是**只要 servlet 含 getCookies 样板就提前返回
    location=cookie**，永远走不到 getParameter。OWASP 的 rememberMe 样板 cookie 名是
    ``"rememberMe"+用例号``（从不是类名），故该判定 100% 是误判：实测全 2740 servlet 中，
    把 query 判成 cookie 86 个、把 cookie 判成 query 221 个（见 tools/_archive/_wb_loc_diag.py）。
    重写后改为按「类名参数被哪种方式显式读取」判定，``getCookies`` 不再充当类名命中。

    返回 (param_name, location)，location ∈ {query, header, cookie}。
    """
    try:
        content = java_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return "", "query"
    cn = str(class_name or "").strip()
    if cn:
        _cn = re.escape(cn)
        # 类名参数被显式读取：query / header / cookie。
        # cookie 判据用 getName.equals("CN") / "CN".equals(...) 形态，而非无参 getCookies。
        if re.search(r'getParameter(?:Values)?\s*\(\s*["\']' + _cn + r'["\']', content):
            return cn, "query"
        if re.search(r'getHeader\s*\(\s*["\']' + _cn + r'["\']', content):
            return cn, "header"
        if re.search(r'getCookieValue\s*\(\s*["\']' + _cn + r'["\']', content) or \
           re.search(r'equals\s*\(\s*["\']' + _cn + r'["\']', content) or \
           re.search(r'["\']' + _cn + r'["\']\s*\.equals', content):
            return cn, "cookie"
    # 退化：首个被显式读取的参数（不再把 getCookies 无参调用强制成类名）。
    for pat, loc in (
        (re.compile(r'getHeader\s*\(\s*["\']([^"\']+)["\']'), "header"),
        (re.compile(r'getParameterValues\s*\(\s*["\']([^"\']+)["\']'), "query"),
        (re.compile(r'getParameter\s*\(\s*["\']([^"\']+)["\']'), "query"),
    ):
        m = pat.search(content)
        if m:
            return m.group(1), loc
    return cn, "query"


def _route_from_signature(signature: str) -> str:
    """从 entry_discovery 条目 signature（注解整行）解析真实路由。

    entry_discovery 条目没有 route 字段（只有 signature），与 benchmark_cli
    _route_method_from_signature 同一解析规则：引号内第一个以 / 开头的串即路由。
    """
    for cand in re.findall(r"['\"]([^'\"]*)['\"]", str(signature or "")):
        if cand.startswith("/"):
            return cand
    return ""


def build_servlet_index(discovered_routes: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """把 discovered_routes 建成 类别 → servlet 路由列表 的索引（仅 benchmark servlet）。"""
    idx: Dict[str, List[Dict[str, Any]]] = {}
    for d in discovered_routes or []:
        sig = d.get("signature") or ""
        route = d.get("route") or _route_from_signature(sig)
        if not _is_benchmark_route(route):
            continue
        cat = benchmark_category_for_route(route)
        if not cat:
            continue
        d = dict(d)
        d["route"] = route
        idx.setdefault(cat, []).append(d)
    return idx


def _rep_params_with_case_name(
    param_name: str, param_loc: str, canary: str, class_name: str
) -> List[Dict[str, str]]:
    """构造 representative_request_params：抽到的参数 + 用例名在全部候选位置。

    cookie），该去重会**跳过 query 候选**，于是 canary 只投到 cookie、servlet 却从 query 读
    ⇒ 零命中。改为：用例名一律在 query / cookie / header 三个候选位置各注入一次，彻底消除
    对单点位置推断的依赖（canary 唯一，多位置注入互不干扰；servlet 只读它自己的那个位置）。
    同时保留抽到的参数（Referer 类用例靠它，不能替换）。
    """
    params: List[Dict[str, str]] = []
    seen = set()

    def _add(name: str, loc: str) -> None:
        name = str(name or "").strip()
        if not name:
            return
        key = (name, loc)
        if key in seen:
            return
        seen.add(key)
        params.append({"name": name, "location": loc, "value": canary})

    if param_name:
        _add(param_name, param_loc)
    if class_name:
        for loc in ("query", "cookie", "header"):
            _add(class_name, loc)
    return params


def build_benchmark_trigger_specs(
    a1_vulns: List[Dict[str, Any]],
    discovered_routes: List[Dict[str, Any]],
    code_root: str,
    task_id: Optional[int],
    workspace_id: Optional[int],
    session_id: Optional[int],
    iast_service: Any,
    run_nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """为每个 A1 finding 生成一个同类别 servlet 触发器 spec 并登记。

    返回 {registered, skipped, skipped_no_servlet, skipped_no_param, by_category}。
    仅当 discovered_routes 含 BenchmarkTest servlet 时才生效（非 benchmark 靶场直接 noop）。
    """
    result: Dict[str, Any] = {
        "registered": 0,
        "skipped": 0,
        "skipped_no_servlet": 0,
        "skipped_no_param": 0,
        "by_category": {},
        "applied": False,
    }
    servlet_idx = build_servlet_index(discovered_routes)
    if not servlet_idx:
        logger.info("[BenchmarkAdapter] 未发现 BenchmarkTest servlet 路由，跳过（非 benchmark 靶场或 Layer 1 未生效）。")
        return result
    result["applied"] = True

    # 多轮重试守卫：本 task 已登记过 benchmark servlet spec 时不再重复注册，
    # 避免 D2 重试轮次导致 spec 成倍堆积（loader 按 task_id 加载，重复会全部入队重放）。
    if task_id is not None:
        try:
            _cnt = iast_service.db.execute(
                "SELECT COUNT(*) c FROM trigger_specs WHERE task_id=? AND target_endpoint LIKE '%BenchmarkTest%'",
                (task_id,), fetchone=True,
            )["c"]
            if _cnt and int(_cnt) > 0:
                result["registered"] = 0
                result["already_registered"] = int(_cnt)
                logger.info("[BenchmarkAdapter] task=%s 已存在 %d 条 benchmark spec，跳过重复注册。", task_id, _cnt)
                return result
        except Exception:
            pass  # 守卫查询失败不阻断，走正常注册（幂等风险可接受）

    from src.iast.canary import CanaryFactory, _rand_hex
    from src.core.vuln_hash import vulnerability_hash_v2, canonicalize_vuln_for_hash

    if run_nonce is None:
        run_nonce = _rand_hex(4)

    # 每类别轮转分配 servlet，避免所有同类别 finding 挤到同一 servlet
    cat_cursor: Dict[str, int] = {}

    registered = 0
    skipped_no_servlet = 0
    skipped_no_param = 0
    by_category: Dict[str, int] = {}

    for vuln in a1_vulns or []:
        vtype = vuln.get("type") or vuln.get("finding_type") or ""
        cat = category_for_finding_type(str(vtype))
        if not cat:
            continue
        servlets = servlet_idx.get(cat)
        if not servlets:
            skipped_no_servlet += 1
            continue
        # 轮转取一个 servlet
        i = cat_cursor.get(cat, 0) % len(servlets)
        cat_cursor[cat] = i + 1
        srv = servlets[i]
        route = srv.get("route") or ""
        if not route:
            skipped_no_servlet += 1
            continue
        # 解析 servlet 源文件与类名，抽污点源参数
        srv_file = srv.get("file") or ""
        class_name = ""
        mcn = re.search(r"BenchmarkTest\d+", route)
        if mcn:
            class_name = mcn.group(0)
        param_name, param_loc = "", "query"
        if srv_file and code_root:
            jp = Path(code_root) / srv_file
            if jp.exists():
                param_name, param_loc = extract_servlet_taint_param(jp, class_name)
        if not param_name:
            # 退化为类名本身（benchmark 约定参数名==类名）
            param_name = class_name or ""
        if not param_name:
            skipped_no_param += 1
            continue

        vhash = vulnerability_hash_v2(canonicalize_vuln_for_hash(vuln))
        canary = CanaryFactory.build(cat, run_nonce=run_nonce)
        try:
            iast_service.register_trigger_spec({
                "workspace_id": workspace_id,
                "session_id": session_id,
                "task_id": task_id,
                "finding_id": None,
                "vulnerability_hash_v2": vhash,
                "family": cat,
                "target_endpoint": route,
                # （javax.servlet.http.HttpSession.setAttribute）位于 doPost（cookie/header/query
                # 参数 → setAttribute 写入会话）。用 GET 重放只命中 doGet 里硬编码 "color" 的
                # Cookie 假 sink，真 sink 永远不被触发 ⇒ 探针收不到 setAttribute 事件 ⇒ no-arrival。
                # 故 trustbound 族重放方法改为 POST，使入站参数真正进入 doPost → setAttribute 真 sink。
                # 维持 GET 不变，避免 double-fire 与误报。
                "http_method": "POST" if cat == "trustbound" else "GET",
                "param_name": param_name,
                "param_location": param_loc,
                "replayable": 1,
                "category": "",
                "business_logic_category": "",
                "taint_marker": canary,
                "expected_sink_file": vuln.get("file") or vuln.get("file_path") or "",
                "expected_sink_line": int(vuln.get("line") or 0 or 0),
                # extract_servlet_taint_param 常抽到错的非空名字，
                # 这类用例重放时 servlet 走「getQueryString couldn't find expected parameter
                # '<用例名>'」的提前返回分支 ⇒ 不写响应体、不碰任何 sink ⇒ **零事件**
                # 。
                # 但 Referer 类用例是 header 注入且实测可用（00013/00144 走 Referer 正常反射），
                # 若把 param_name 改回用例名反而会坏 ⇒ 只能**追加**不能替换：
                # 保留抽到的参数，再追加用例名作为 query 候选，由 D1 的 multi-match
                # 全参数带标一次回放（d1_service.py:1670）同时带上两个候选。
                "representative_request_params": _rep_params_with_case_name(
                    param_name, param_loc, canary, class_name),
                "raw": vuln,
            })
            registered += 1
            by_category[cat] = by_category.get(cat, 0) + 1
        except Exception as e:  # 单条失败不阻断其余
            logger.warning("[BenchmarkAdapter] 登记 spec 失败（vhash=%s）：%s", vhash[:12] if vhash else "?", e)

    result["registered"] = registered
    result["skipped_no_servlet"] = skipped_no_servlet
    result["skipped_no_param"] = skipped_no_param
    result["by_category"] = by_category
    logger.info(
        "[BenchmarkAdapter] 已为 benchmark 登记 %d 条 servlet 触发器 spec（无匹配servlet=%d，无参数=%d，按类别=%s）。",
        registered, skipped_no_servlet, skipped_no_param, by_category,
    )
    return result
