"""D2 证据通道注册表（Part2 定稿本轮 M4，2026-10-03 落地）。

背景（为什么要从 if-return 单链换成注册表）：
    d2_facade._verify_sink_result 原本是一条 if-return 单链——第一个命中的分支直接 return，
    后面所有分支压根不会执行。后果有三：
      1. 证明力被链序绑架：一条「探针 sink 断言」（证明力 2）只要排在前面，就能盖掉
         后面「语义差分」（证明力 3）的更强证据，链的书写顺序成了判据强度，这是错的。
      2. 通道互相隐身：带外回调只在反序列化那一支里查了一次（还是顺手写的），
         其他族即便收到了回调也不会被采信。
      3. 无法审计：落库的只有最终一句话 reason，看不出「跑了哪些通道、各自结论是什么」。

评审的三条（2026-10-02 决策丙）：
      - 六条通道按证明力分级：带外回调 4 > 结果点比对 3 = 语义差分 3 > 时间盲注 2 =
        探针 sink 断言 2 > 代码属性 1。
      - M7 落地后为「跨请求回显」（echo_marker）加第七条通道：证明力 3，与结果点同档
        但排序更前（priority 1 < 2）。理由见 CHANNEL_STRENGTH 里该键的注释。
      - **该族适用通道全跑，不短路**（决策丙：最鲁棒，请求数换判据完整）。
      - 冲突取证明力高者为主判据，并打冲突标记（不静默丢弃低阶的反证）。

设计红线（改这个文件前必读）：
      1. `definitive` 是仲裁的准入开关：**只有 definitive=True 的通道能当主判据**。
         「没观测到」不等于「无害」——带外没收到回调、时间盲注没达标，都是
         definitive=False（记进 evidence_channels 留痕，但不参与仲裁）。把这类
         「证据缺失」抬成 definitive 会大面积误杀真漏洞（尤其是探针没织到的族）。
      2. 兜底分支（channel="none"，证明力 0）永远参与仲裁且永远垫底，保证
         _verify_sink_result 恒有返回值，且任何正向证据都能盖过它。
      3. 同证明力靠 `priority` 定序（见 _CHANNEL_PRIORITY），必须是确定性的，
         否则同一批 spec 两次跑出两种结论。复刻原 if-return 的链序是唯一安全的排序依据。
      4. 重放预算 5 次/spec 含基线（评审）：预算不够时**按证明力从低到高砍通道**，
         绝不砍基线、绝不砍高阶通道。先判后投——用环境事实（facts）先收窄方言/通道，
         而不是穷举所有方言把预算烧光。
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# ── 六条证据通道与证明力分级 ──
# 证明力 = 「这条证据跨过多少层间接性」。带外回调是服务端主动出网找我，跨过了
# 响应回显/探针织点的全部不确定性，故最高；代码属性只是静态事实的运行时复述，最低。
CHANNEL_STRENGTH: Dict[str, int] = {
    "oob_callback": 4,        # 带外回调：服务端真的出网来找我（DNS/HTTP）
    # M7 跨请求回显：写入请求投的自限标记，在**另一次请求的响应**里被搜到。
    # 与 result_point_diff 同档（都是回显比对），但排得更前——它是存储型唯一通用手段：
    # 读取侧参数里根本没有 canary，探针在该侧无污点可跟（见 replay_plan 模块头），
    # 所以这条通道是「平台唯一证明存储型回显真实发生过」的证据。
    # 三态里只有 raw 是 definitive；escaped（到 sink 了但被转义）是真阴性，不得算正向证据。
    "echo_marker": 3,
    "result_point_diff": 3,   # 结果点比对：同一次请求的回显/响应体与投放值逐字节对得上
    "semantic_diff": 3,       # 语义差分：双身份/双参数对照，响应语义确实不同
    "time_blind": 2,          # 时间盲注：时延差分达标（旁证，非直接观测 sink）
    "probe_sink_assert": 2,   # 探针 sink 断言：canary 落在危险函数实参
    # M13「DAST 的浏览器扩展」（按需起 headless 浏览器，用完释放，非常驻）：
    # 它跨过了「服务端响应体」这一层——看的是**浏览器渲染后的 DOM**，前端脚本拼接出来的
    # 注入点只在这里才看得见。与带外同档（都是服务端/浏览器真的执行了我想让它执行的东西），
    # 但排序在带外之后：带外是服务端主动出网，浏览器那步仍可能被目标自己的 CSP/沙箱挡下。
    "browser_dom": 4,
    # 2026-10-10 新增「值级 sink 实参」（value_level_sink_arg）：
    # 我方投放的数据**真的出现在危险函数的实参值里**（不是探针那条 trace 级断言 canary_match）。
    # 这是当前唯一能分开「静默成功型 TP」与「共用 sink 的 FP」的可观测判据 —— 离线实测
    # run 25130 条真 FP **零穿透**，73 条真 TP 里覆盖 16~17 条。
    # 证明力取 4（与带外同档）：它跨过了「污点是否真的流到」与「值有没有被替换/参数化」两层
    # 不确定性；排序在带外(0)之后、浏览器 DOM 之前——它是服务端执行现场的一手比对。
    "value_level_sink_arg": 4,
    # 2026-10-10 新增「sink 现场异常签名」（sink_exception）：探针在家族真实危险 sink 现场
    # 抛出的异常类名属本族危险操作签名（如 SQL 注入触发 java.sql.SQLException、命令注入触发
    # java.io.IOException）。它是「危险操作真的执行并抛错」的一手事实，跨过了「污点是否抵达」
    # 的不确定性，与 canary 断言 / 值级命中正交，是独立的 definitive 阳性候选。
    # 证明力取 3（与结果点比对 / 语义差分同档）：它仍是「响应/执行现场」的观测，但信噪比低于
    # 带外/值级的一手比对；且本通道要求 genuine_sink_reached（sink 已通过家族身份校验）才准入，
    # 与探针断言共用同一道身份闸，不会自创误报通路。
    "sink_exception": 3,
    "code_property": 1,       # 代码属性：只证属性（算法/标志位/随机源），不证可利用
    "none": 0,                # 兜底：无任何通道产出证据（永远是垫底主判据）
}

CHANNEL_LABEL: Dict[str, str] = {
    "oob_callback": "带外回调",
    "echo_marker": "跨请求回显",
    "result_point_diff": "结果点比对",
    "semantic_diff": "语义差分",
    "time_blind": "时间盲注",
    "probe_sink_assert": "探针 sink 断言",
    "browser_dom": "浏览器渲染取证",
    "value_level_sink_arg": "值级 sink 实参",
    "sink_exception": "sink 异常签名",
    "code_property": "代码属性",
    "none": "无证据",
}

# 同证明力时的确定性定序（复刻原 if-return 链序，见设计红线 3）
# echo_marker 排在 result_point_diff 之前：跨请求回显比同请求回显更硬（它跨过了
# 「写成功」与「读渲染」两次完整的服务端处理，且读取侧的 IAST 完全盲区）。
_CHANNEL_PRIORITY: Dict[str, int] = {
    "oob_callback": 0,
    "echo_marker": 1,
    "semantic_diff": 2,
    "result_point_diff": 3,
    "probe_sink_assert": 4,
    # 值级 sink 实参排在浏览器 DOM 之前（两者同为证明力 4）：一个是服务端执行现场的一手比对，
    # 一个是渲染后的间接观察。browser_dom 由 6 顺延到 11 让位，二者相对次序未变（都只在
    # 同证明力组内比较），不存在既有裁决被改写的风险。
    "value_level_sink_arg": 6,
    "time_blind": 5,
    "browser_dom": 11,
    # sink_exception 排在 code_property(7) 与 none(9) 之后（同为 strength 3 内 priority 最大）：
    # 它是 strength-3 里**最弱**的正向通道——当它与同档良性通道（如对照实验差分判定给出的
    # harmful=False，priority 默认 9）冲突时，良性胜出（fail-open 优先，绝不为「异常签名」误杀
    # 一条高置信无差异的用例）；只有它独挑大梁（无任何其他 definitive 结论）时才当主判据。
    "sink_exception": 12,
    "code_property": 7,
    "none": 9,
}

# 每条通道需要额外消耗的重放次数（不含基线，基线恒占 1 次）
CHANNEL_REPLAY_COST: Dict[str, int] = {
    "oob_callback": 1,        # 伴随弹：搭在主重放上，单独计一次
    "echo_marker": 2,         # 两步重放：写一次 + 读一次（这是它的固有开销，压不掉）
    "result_point_diff": 1,
    "semantic_diff": 2,       # 攻击者身份 + 受害者身份两次
    "time_blind": 2,          # SLEEP(N) + 同结构 SLEEP(0) 基线
    "probe_sink_assert": 0,   # 复用 canary 主重放，不额外发
    "code_property": 0,       # 复用主重放观测到的算法/属性事件
    "browser_dom": 1,         # 开一次页面（比一次重放贵得多，故按 1 次计，且只在 DOM 族投）
    "value_level_sink_arg": 0,  # 复用 canary 主重放里探针已经记下的实参值，不额外发请求
    "sink_exception": 0,        # 复用主重放里探针 already 记录的 sink 异常，不额外发请求
    "none": 0,
}

DEFAULT_REPLAY_BUDGET = 5     # 评审：5 次/spec 含基线

# ── 通道适用性（按族）──
# 语义差分：双身份/双参数对照族
_SEMANTIC_DIFF_TOKENS = (
    "bola", "idor", "broken_access", "vertical_privesc", "horizontal_privesc",
    "privilege", "privesc", "authz", "access_control", "ldap", "xpath",
    "business_logic", "race", "price", "workflow", "state_machine",
)
# 时间盲注：能塞 sleep/延时的注入族
_TIME_BLIND_TOKENS = (
    "sqli", "sql_injection", "sql", "command", "command_injection",
    "command_execution", "rce", "code_injection", "nosql", "xpath", "ldap",
)
# 结果点比对：投放值能被原样回显/求值的族
_RESULT_POINT_TOKENS = (
    "xss", "ssti", "template", "crlf", "header_injection", "redirect",
    "open_redirect", "reflected", "path_traversal", "pathtraver", "file_read",
    "jsonp", "expression", "ognl", "spel", "el_injection",
)


def _value_hit_present(iast: Optional[Dict[str, Any]]) -> bool:
    """IAST 证据里是否存在值级命中事实（供通道适用性判定，不做结论判断）。"""
    if not isinstance(iast, dict) or not iast:
        return False
    if isinstance(iast.get("value_hit"), dict) and iast["value_hit"].get("hit"):
        return True
    for h in (iast.get("value_hits") or []):
        if isinstance(h, dict) and h.get("hit"):
            return True
    return False


def _norm_family(family: str) -> str:
    return str(family or "").strip().lower().replace("-", "_").replace(" ", "_")


def _has_token(family: str, tokens: Iterable[str]) -> bool:
    f = _norm_family(family)
    return any(tok in f for tok in tokens)


def _code_property_applicable(family: str) -> bool:
    """该族是否只在「代码属性层」可判（复用 family_verdict 的路由，单一真相源）。"""
    try:
        from src.core.family_verdict import route_for
        return route_for(family) != "dataflow"
    except Exception:
        return False


def is_code_property_family(family: str) -> bool:
    """对外入口：该族是否只在「代码属性层」可判（algorithm/attribute/random 路由）。"""
    return _code_property_applicable(family)


def _oob_applicable(family: str, facts: Optional[Dict[str, Any]] = None) -> tuple:
    """带外通道是否可用。返回 (applicable, reason)。

    按形态分别判：HTTP 形态端点就是后端自己，开箱即用；DNS 形态要公网域名，
    域名没配就 fail-open 保留通道（记 reason，不缩小证据面）——口径明确
    「域名到位前解析器配置 fail-open」。
    """
    try:
        from src.iast import oob_monitor as _oob
        mode = _oob.oob_mode()
    except Exception:
        return False, "oob_monitor_unavailable"
    if mode in ("disabled", ""):
        return False, "oob_disabled"
    try:
        avail = _oob.payload_for_family(family, "example.invalid", "token")
    except Exception:
        avail = None
    if not avail:
        return False, "no_morphology_for_family"
    return True, f"mode={mode}"


def _sleep_hint(evidence: Dict[str, Any]) -> float:
    try:
        return float((evidence or {}).get("sleep_seconds_hint") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _oob_token_present(evidence: Dict[str, Any]) -> bool:
    ev = evidence or {}
    return bool(ev.get("oob_token") or (ev.get("oob") or {}).get("token"))


def _echo_marker_ready(evidence: Optional[Dict[str, Any]] = None,
                       spec: Optional[Dict[str, Any]] = None) -> tuple:
    """跨请求回显通道是否可用。返回 (applicable, reason)。

    这条通道**不由族名决定**——它由 replay_plan 是否成立决定：存储型写读配对要真的
    有写端点、有读端点（静态/LLM 给的，或标记反查扫出来的）才投，不给族名硬塞。
    reason 里带 read_endpoint_source，对账时能看清是哪一级定位给出的读端点。
    """
    try:
        from src.core.replay_plan import plan_from_spec
    except Exception as exc:
        return False, "replay_plan_unavailable: %s" % exc
    plan = {}
    # 证据侧优先：D1 已经把 replay_plan 的读端点写进 DastImpact 时，说明这条路走通过
    ev_two_step = (evidence or {}).get("two_step") or {}
    if isinstance(ev_two_step, dict) and str((ev_two_step.get("read") or {}).get("endpoint") or ""):
        # D1 已经跑过两步重放：读端点在 read.endpoint 里（DastImpact.two_step 的形状）
        _r = ev_two_step.get("read") or {}
        plan = {
            "read_endpoint": {
                "endpoint": str(_r.get("endpoint") or ""),
                "source": str(ev_two_step.get("read_endpoint_source")
                              or _r.get("source") or "static"),
            }
        }
    elif isinstance(ev_two_step, dict) and ev_two_step.get("plan"):
        plan = ev_two_step["plan"]
    else:
        plan = plan_from_spec(spec) or {}
    ep = str(plan.get("read_endpoint") or "")
    if not ep:
        return False, "no_read_endpoint(%s)" % (plan.get("read_endpoint_source") or "none")
    return True, str(plan.get("read_endpoint_source") or "static")


def _browser_dom_applicable(family: str) -> tuple:
    """M13 浏览器通道是否值得投。返回 (applicable, reason)。

    只认「必须看渲染后 DOM 才下得了结论」的族（DOM XSS / 前端渲染型），
    且本机真有浏览器运行时才投。运行时是运行时状态，计划阶段只能按族先判后投，
    到 D2 执行时再补一次运行时判定（拿不到运行时就当证据缺失，绝不伪造）。
    """
    try:
        from src.core.browser_probe import is_dom_family
    except Exception as exc:
        return False, "browser_probe_unavailable: %s" % exc
    if not is_dom_family(family):
        return False, "not_a_dom_family"
    try:
        from src.core.browser_probe import backend_available
        ok, detail = backend_available()
    except Exception as exc:
        return False, "backend_check_failed: %s" % exc
    return (bool(ok), "runtime=%s" % detail) if ok else (False, "runtime_unavailable: %s" % detail)


def applicable_channels(family: str, facts: Optional[Dict[str, Any]] = None,
                        evidence: Optional[Dict[str, Any]] = None,
                        spec: Optional[Dict[str, Any]] = None,
                        iast: Optional[Dict[str, Any]] = None) -> List[str]:
    """该族适用的通道列表（按证明力降序）。

    适用性有**两个来源**，缺一不可：
      1. 族名（先判后投）：族决定了该族「值得」投哪些通道；
      2. 证据形态（证据驱动）：D1 真的投了 sleep 弹 / 带外弹 / 差分对，通道才成立。
    只看族名会把「族名缺失或归一失败」的 spec 一刀切掉（实测回归：family="" 时
    业务差分与时间盲注双双消失，两条既有用例直接挂掉）——族名是上游的主张，
    证据是已经发生的事实，事实优先。
    """
    ev = evidence or {}
    out: List[str] = []
    ok_oob, _why = _oob_applicable(family, facts)
    if ok_oob or _oob_token_present(ev):
        out.append("oob_callback")
    if _echo_marker_ready(ev, spec)[0]:
        out.append("echo_marker")
    if _has_token(family, _RESULT_POINT_TOKENS) or (ev.get("result_point_diff") or {}):
        out.append("result_point_diff")
    if (_has_token(family, _SEMANTIC_DIFF_TOKENS)
            or (ev.get("business_logic") or {}).get("confirmed")
            or (ev.get("semantic_diff") or {})):
        out.append("semantic_diff")
    if _has_token(family, _TIME_BLIND_TOKENS) or _sleep_hint(ev) > 0:
        out.append("time_blind")
    # P1 对照实验差分：D1 确实采集到对照结果（attempted）才适用，否则不臆断。
    _diff = ev.get("differential")
    if isinstance(_diff, dict) and _diff.get("attempted"):
        out.append("differential_confirm")
    ok_browser, _why_b = _browser_dom_applicable(family)
    if ok_browser:
        out.append("browser_dom")
    out.append("probe_sink_assert")   # 恒适用：canary 主重放本来就要发
    # 值级 sink 实参：**证据驱动**（与 differential_confirm 同一纪律）——只有 I1 真的比对到
    # 「我方投放数据在 sink 实参值里」这条事实才成立。它虽是零额外重放，但绝不能变成
    # 「没证据时也参与」的默认通道，否则 applicable_channels 的基线不变量（族名缺失且无
    # 证据时只剩 probe_sink_assert 一条）会被破坏，对账时也会谎报覆盖度。
    if _value_hit_present(iast):
        out.append("value_level_sink_arg")
    # B2 sink 异常签名（2026-10-10）：证据驱动（与值级通道同一纪律）——探针真的在 sink
    # 现场录得异常类名才参与（零额外重放）。缺这条会让已注册的评估器永远进不了计划
    # （F8 回归锁实测：sink_exception 从未出现在 evaluate_all 的通道清单里）。
    if str((iast or {}).get("sink_exception_class") or "").strip():
        out.append("sink_exception")
    if _code_property_applicable(family):
        out.append("code_property")
    out.sort(key=lambda c: (-CHANNEL_STRENGTH.get(c, 0), _CHANNEL_PRIORITY.get(c, 9)))
    return out


def plan_channels(family: str, facts: Optional[Dict[str, Any]] = None,
                  budget: int = DEFAULT_REPLAY_BUDGET,
                  evidence: Optional[Dict[str, Any]] = None,
                  spec: Optional[Dict[str, Any]] = None,
                  iast: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """重放预算内的通道投放计划（先判后投，超预算按证明力从低到高砍）。

    预算口径：5 次/spec **含基线**，故可用额度 = budget - 1。
    砍的顺序恒为「证明力最低的先砍」，绝不砍基线、绝不砍高阶通道——低阶通道
    （代码属性/探针断言）即便砍掉也不额外发请求，代价最小。
    """
    try:
        budget_i = int(budget)
    except (TypeError, ValueError):
        budget_i = DEFAULT_REPLAY_BUDGET
    if budget_i < 1:
        budget_i = 1
    usable = max(0, budget_i - 1)   # 基线恒占 1 次

    cands = applicable_channels(family, facts, evidence, spec, iast=iast)
    planned: List[str] = []
    dropped: List[Dict[str, Any]] = []
    spend = 0
    for ch in cands:
        cost = CHANNEL_REPLAY_COST.get(ch, 0)
        if spend + cost <= usable:
            planned.append(ch)
            spend += cost
        else:
            dropped.append({
                "channel": ch,
                "strength": CHANNEL_STRENGTH.get(ch, 0),
                "cost": cost,
                "reason": "over_budget",
            })
    return {
        "budget": budget_i,
        "usable": usable,
        "planned": planned,
        "dropped": dropped,
        "spend": spend,
        "baseline_cost": 1,
    }


def channel_participation(family: str, facts: Optional[Dict[str, Any]] = None,
                          evidence: Optional[Dict[str, Any]] = None,
                          spec: Optional[Dict[str, Any]] = None,
                          iast: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """该族的通道参与全景（含**没参与的**及原因），供报告口径诚实标注。

    ## 为什么需要这个函数（2026-10-07 实测发现）

    注册表里有 8 条通道，但**实际参与的可能只有 5~6 条**，而落库的只有最终那句
    `reason`，看不出「跑了哪些、每条结论是什么」。于是看报告的人会默认「六条通道都跑了」。

    真实案例：M13「DAST 浏览器扩展」（`browser_dom`，证明力 4，本是最高档）在 OWASP
    Benchmark 全集上**一条都不会触发**：
      1. `is_dom_family()` 只认 dom / client_side / javascript 等前端族，而全集是
         纯后端注入族（sqli / cmdi / pathtraver / ldapi …）；
      2. 本机 `playwright` 未安装，`backend_available()` 恒 False。
    两条各自都足以让它永不参与。机制本身是健康的（unavailable 三态如实上报、
    不伪造结论，红线没破），但**报告不标注就等于谎报覆盖度**。

    所以本函数把「注册了但没参与」显式列出来，让报告能写清
    `browser_dom：未参与（族不适用 / 运行时不可用）`，而不是让人误以为它跑过。

    返回：
        {"applicable": [...],   # 实际参与的通道（判据已满足）
         "inactive": [{"channel","label","strength","reason"}, ...]}
    """
    try:
        active = applicable_channels(family, facts, evidence, spec, iast=iast)
    except Exception as exc:  # pragma: no cover - 诊断接口不得影响主流程
        return {"applicable": [], "inactive": [], "error": str(exc)[:200]}
    active_set = set(active)
    inactive: list = []
    for ch in ("oob_callback", "echo_marker", "result_point_diff", "semantic_diff",
               "time_blind", "differential_confirm", "browser_dom",
               "value_level_sink_arg", "sink_exception", "probe_sink_assert", "code_property"):
        if ch in active_set:
            continue
        inactive.append({
            "channel": ch,
            "label": CHANNEL_LABEL.get(ch, ch),
            "strength": CHANNEL_STRENGTH.get(ch, 0),
            "reason": _inactive_reason(ch, family, facts),
        })
    return {"applicable": list(active), "inactive": inactive}


def _inactive_reason(ch: str, family: str, facts: Optional[Dict[str, Any]]) -> str:
    """给「没参与的通道」一个可读的、**基于真实判据**的原因（不臆测）。"""
    fam = _norm_family(family)
    if ch == "browser_dom":
        # 两条独立原因，逐一实测，不猜
        try:
            from src.core.browser_probe import backend_available, is_dom_family
        except Exception as exc:
            return "browser_probe 模块不可用：%s" % str(exc)[:120]
        if not is_dom_family(family or ""):
            return ("族不适用：browser_dom 只覆盖 DOM/前端族（%s 属后端族）"
                    "，需渲染后 DOM 才能下结论的场景才投" % (fam or "<空>"))
        avail, detail = backend_available()
        if not avail:
            return "族适用但运行时不可用：%s" % (detail or "unknown")
        return "族适用且运行时可用，但本条未进入计划（检查证据形态）"
    if ch == "oob_callback":
        ok, why = _oob_applicable(family, facts)
        return why or "带外未启用"
    if ch == "code_property":
        return "数据流族（该族主张需运行时可利用，不走属性层）"
    if ch == "probe_sink_assert":
        return "恒适用通道，不应缺失"
    if ch == "value_level_sink_arg":
        return ("已比对但本次记录的 sink 实参值里没有我方投放数据；"
                "该通道零额外重放，仅在真的比对到时才参与")
    if ch == "sink_exception":
        return ("本次 sink 现场未录得异常类名；该通道零额外重放，仅在探针真的录得异常时才参与")
    # 其余按族名判据
    tok = {
        "result_point_diff": (_RESULT_POINT_TOKENS, "投放值不可原样回显/求值"),
        "semantic_diff": (_SEMANTIC_DIFF_TOKENS, "无双身份/双参数对照语义"),
        "time_blind": (_TIME_BLIND_TOKENS, "该族不适用时间盲注"),
        "echo_marker": ((), "非存储型或无跨请求读取侧"),
    }.get(ch)
    if tok is None:
        return "本族不适用"
    tokens, why = tok
    if not tokens:
        return why
    return "%s（族 %s 未命中判据）" % (why, fam or "<空>")


# ── 通道评估器注册表 ──
_EVALUATORS: Dict[str, Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = {}


def register_evaluator(channel: str, fn: Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]) -> None:
    _EVALUATORS[channel] = fn


def make_outcome(channel: str, *, harmful: bool, sink_reached: bool,
                 confidence: str, reason: str, evidence: Any = "",
                 definitive: bool = True, **extra: Any) -> Dict[str, Any]:
    """统一通道产出结构。extra 里的字段原样带出（如 oob_confirmed / probe_asserted）。"""
    out = {
        "channel": channel,
        "channel_label": CHANNEL_LABEL.get(channel, channel),
        "strength": CHANNEL_STRENGTH.get(channel, 0),
        "priority": _CHANNEL_PRIORITY.get(channel, 9),
        "harmful": bool(harmful),
        "sink_reached": bool(sink_reached),
        "confidence": confidence,
        "reason": reason,
        "evidence": evidence,
        "definitive": bool(definitive),
    }
    out.update(extra)
    return out


def evaluate_all(family: str, iast_evidence: Dict[str, Any], dast_impact_evidence: Dict[str, Any],
                 facts: Optional[Dict[str, Any]] = None, spec: Optional[Dict[str, Any]] = None,
                 channels: Optional[Iterable[str]] = None,
                 budget: int = DEFAULT_REPLAY_BUDGET) -> List[Dict[str, Any]]:
    """全跑适用通道，不短路。每条通道的异常被吞掉并留痕，绝不拖垮整条裁决。"""
    ctx = {
        "family": family or "",
        "iast": iast_evidence or {},
        "dast": dast_impact_evidence or {},
        "facts": facts or {},
        "spec": spec or {},
    }
    plan = plan_channels(family, facts, budget, evidence=dast_impact_evidence,
                         spec=spec, iast=iast_evidence)
    outcomes: List[Dict[str, Any]] = []
    # 预算被砍掉的通道不是「跑过没结论」，而是「本轮没投」——单列留痕，
    # 免得对账时把「预算不足没投」误读成「投了没打中」。
    for d in plan.get("dropped") or []:
        outcomes.append(make_outcome(
            str(d.get("channel") or ""), harmful=False, sink_reached=False,
            confidence="low", definitive=False,
            reason=f"重放预算 {budget} 次不足，按证明力从低到高砍掉本通道（需 {d.get('cost')} 次）",
            dropped_over_budget=True))
    if channels:
        names = list(channels)
    else:
        names = list(plan.get("planned") or [])
    for name in names:
        fn = _EVALUATORS.get(name)
        if fn is None:
            continue
        try:
            res = fn(ctx)
        except Exception as _e:   # 单通道崩了只记 error，不短路整轮
            logger.warning("[D2][channel] %s 评估异常（跳过该通道）：%s", name, _e)
            outcomes.append(make_outcome(
                name, harmful=False, sink_reached=False, confidence="low",
                reason=f"通道评估异常：{_e}", definitive=False, error=str(_e)))
            continue
        if res:
            outcomes.append(res)
    # 兜底恒在（证明力 0），保证仲裁永远有主判据
    if "none" not in [o.get("channel") for o in outcomes]:
        _fn = _EVALUATORS.get("none")
        if _fn is not None:
            try:
                _fallback = _fn(ctx)
                if _fallback:
                    outcomes.append(_fallback)
            except Exception:
                pass
    return outcomes


def arbitrate(outcomes: List[Dict[str, Any]], budget: int = DEFAULT_REPLAY_BUDGET) -> Dict[str, Any]:
    """不短路仲裁：取证明力最高者为主判据，冲突取高并打标记。

    返回结构 = 主判据字段（harmful/sink_reached/confidence/reason/evidence）+ 审计字段：
      - primary_channel / evidence_strength：主判据来自哪条通道、证明力多少
      - evidence_channels：全部通道产出（含 definitive=False 的观测留痕）
      - channel_conflict / conflicting_channels：有哪些通道与主判据结论相反
    """
    outs = [o for o in (outcomes or []) if isinstance(o, dict)]
    definitive = [o for o in outs if o.get("definitive")]
    if not definitive:
        definitive = [make_outcome(
            "none", harmful=False, sink_reached=False, confidence="low",
            reason="无通道产出确定性结论", definitive=True)]
        outs = list(outs) + definitive

    best = min(definitive, key=lambda o: (-int(o.get("strength", 0)), int(o.get("priority", 9))))
    # 兜底通道（"none"）恒为 harmful=False，它跟任何正向结论都「相反」，
    # 把它算进冲突列表等于给每条确认都打上假冲突标记——必须排除。
    conflicts = [
        str(o.get("channel"))
        for o in definitive
        if str(o.get("channel")) != "none"
        and bool(o.get("harmful")) != bool(best.get("harmful"))
    ]

    verdict: Dict[str, Any] = {
        "harmful": bool(best.get("harmful")),
        "sink_reached": bool(best.get("sink_reached")),
        "confidence": best.get("confidence") or "low",
        "reason": best.get("reason") or "",
        "evidence": best.get("evidence") or "",
    }
    # 主判据自带的特征标记（oob_confirmed / probe_asserted / attack_degraded / ...）
    for k, v in best.items():
        if k in ("channel", "channel_label", "strength", "priority", "harmful",
                 "sink_reached", "confidence", "reason", "evidence", "definitive"):
            continue
        verdict[k] = v

    verdict.update({
        "primary_channel": best.get("channel"),
        "primary_channel_label": best.get("channel_label") or CHANNEL_LABEL.get(best.get("channel", ""), ""),
        "evidence_strength": int(best.get("strength", 0)),
        "evidence_channels": [
            {
                "channel": o.get("channel"),
                "label": o.get("channel_label") or CHANNEL_LABEL.get(o.get("channel", ""), ""),
                "strength": o.get("strength", 0),
                "definitive": bool(o.get("definitive")),
                "harmful": bool(o.get("harmful")),
                "sink_reached": bool(o.get("sink_reached")),
                "confidence": o.get("confidence") or "",
                "reason": str(o.get("reason") or "")[:300],
            }
            for o in outs
        ],
        "channel_conflict": bool(conflicts),
        "conflicting_channels": conflicts,
        "channels_run": [str(o.get("channel")) for o in outs],
        "replay_budget": budget,
    })
    return verdict


def verify_with_channels(family: str, iast_evidence: Dict[str, Any], dast_impact_evidence: Dict[str, Any],
                         facts: Optional[Dict[str, Any]] = None, spec: Optional[Dict[str, Any]] = None,
                         budget: int = DEFAULT_REPLAY_BUDGET) -> Dict[str, Any]:
    """一站式：按预算排通道 → 全跑不短路 → 仲裁取最高证明力。"""
    outcomes = evaluate_all(family, iast_evidence, dast_impact_evidence,
                            facts=facts, spec=spec, budget=budget)
    verdict = arbitrate(outcomes, budget=budget)
    verdict["channel_plan"] = plan_channels(family, facts, budget,
                                            evidence=dast_impact_evidence,
                                            iast=iast_evidence)
    return verdict


def strength_of(verdict: Dict[str, Any]) -> int:
    """从裁决结果里读证明力（无则 0）。供报告/对账按证明力分档统计。"""
    try:
        return int((verdict or {}).get("evidence_strength") or 0)
    except (TypeError, ValueError):
        return 0


# ── P1：对照实验差分确认（2026-10-10 落地）──
# 背景：OWASP Benchmark 安全/不安全用例共用同一危险函数 sink（探针在两侧都把 canary 断言到
# sink），故「canary 到 sink」(probe_sink_assert, strength 2) 无法区分真漏洞(TP)与误报(FP)。
# 唯一能区分的是**真实可观测影响**：不安全用例的有害载荷会在响应/时延上产生控制载荷没有的
# 差异（SQL 报错 / 命令回显 / 文件读出 / 时延差），安全用例的载荷被净化器中和后与控制一致。
#
# 设计红线（fail-open 优先，绝不零化仅到达 TP）：
#   1. 任何歧义 / 噪声（仅长度差、时间戳抖、单侧观测缺失）一律 attempted=False（fail-open）。
#   2. 只有「高置信无有害差异」（两载荷在错误签名 / 标记回显 / 到达 / 时延上一致）才给
#      harmful=False（真阴性，可降级误报）。
#   3. 只有「实验产生控制所没有的有害可观测差异」才给 harmful=True（真实利用）。
#   4. 比对维度刻意**不含 iast_reached 单边差**作为唯一判据——因为 safe/unsafe 两侧都到 sink，
#      单边到达差不具区分力；区分力只来自错误签名 / 标记回显 / 时延这类真实影响维度。
_DIFF_FAMILY_FORCE = (
    "sqli", "sql_injection", "sql", "cmdi", "command_execution", "command_injection",
    "command", "rce", "code_injection", "pathtraver", "path_traversal", "path",
    "ldapi", "ldap_injection", "ldap", "xpath", "xpath_injection", "xpathi",
    "deser", "deserialization", "ssti", "template",
)


def _norm_state(side: Dict[str, Any]) -> Dict[str, Any]:
    s = side or {}
    return {
        "err": bool(s.get("error_signature") or s.get("err_sig") or s.get("error")),
        "marker": bool(s.get("marker_seen") or s.get("marker")),
        "reach": bool(s.get("iast_reached") or s.get("sink_reached")
                      or s.get("matched_event_ids")),
        "el": float(s.get("elapsed_ms") or 0.0),
        # similar：调用方预计算的「两载荷响应结构高度相似(>=0.95)」标志，用于高置信无差异判定。
        "similar": bool(s.get("similar")),
        "has_signal": bool(s.get("iast_reached") or s.get("sink_reached")
                           or s.get("matched_event_ids") or s.get("error")
                           or s.get("marker_seen") or s.get("elapsed_ms")
                           or s.get("status_code") is not None),
    }


def differential_confirm(control: Dict[str, Any], experiment: Dict[str, Any],
                         family: str = "") -> Dict[str, Any]:
    """对照实验差分判定（P1 核心，纯函数、fail-open）。

    control   = 无害控制载荷的观测态
    experiment = 有害实验载荷的观测态
    每侧观测态可含：error_signature / marker_seen / iast_reached / matched_event_ids /
                    elapsed_ms / status_code / similar 等。

    返回 {"attempted", "harmful", "reason"}：
      - attempted=False  → 数据不足 / 歧义，fail-open（上游保留现状，绝不零化 TP）
      - attempted=True, harmful=True  → 实验产生控制所没有的有害可观测差异（真实利用）
      - attempted=True, harmful=False → **高置信**无有害差异（错误/标记/到达/时延一致且响应高度相似），真阴性

    安全纪律（绝不零化仅到达 TP）：harmful=False（降级误报）只在「高置信无差异」时给出——
    即错误签名 / 标记回显 / 到达 / 时延四项全一致，且响应结构高度相似（similar=True）。
    任何一项缺失 / 歧义（含静默成功型 TP：响应内容变了但无报错无标记，similar=False）
    一律 attempted=False fail-open 保留，避免把静默成功的真漏洞误杀。
    """
    if not isinstance(control, dict) or not isinstance(experiment, dict):
        return {"attempted": False, "harmful": False, "reason": "missing_state"}
    c = _norm_state(control)
    e = _norm_state(experiment)
    if not c["has_signal"] or not e["has_signal"]:
        return {"attempted": False, "harmful": False, "reason": "incomplete_observation"}

    # 实验有错误签名而控制没有 → 有害（SQL/命令报错、异常回显）
    if e["err"] and not c["err"]:
        return {"attempted": True, "harmful": True,
                "reason": "experiment_error_signature_absent_in_control"}
    # 实验到达真 sink 而控制未到（且两侧确有观测）→ 真实数据流只存在于有害载荷。
    # 注：marker_seen 不参与判定 —— 只有「控制」侧投的是裸 canary，实验侧投的是攻击载荷，
    # 所以 canary 是否回显只在控制侧为 True，c["marker"]/e["marker"] 天然不对等，不能作为一致/差异判据。
    if e["reach"] and not c["reach"]:
        return {"attempted": True, "harmful": True,
                "reason": "experiment_reached_sink_control_not"}
    # 实验时延显著高于控制（时间盲注 sleep 型，800ms 以上差分视为显著）
    if (e["el"] - c["el"]) >= 800.0 and e["el"] >= 1000.0:
        return {"attempted": True, "harmful": True, "reason": "experiment_time_delta"}

    # 高置信无差异：错误 / 到达 / 时延一致，且（剥值归一后）响应结构高度相似 → 真阴性。
    # similar 由调用方基于「参数值已剥除」的响应体比对预计算（>=0.95），避免把静默成功的真漏洞
    # （内容变了但无报错）误杀，也避免「参数值被回显」制造的人为不相似把安全用例误判成歧义。
    if (c["err"] == e["err"]) and (c["reach"] == e["reach"]) \
            and abs(e["el"] - c["el"]) < 800.0 \
            and c["similar"] and e["similar"]:
        return {"attempted": True, "harmful": False, "reason": "no_observable_difference"}
    # 其余（歧义 / 噪声 / 静默成功型）→ fail-open
    return {"attempted": False, "harmful": False, "reason": "ambiguous_fail_open"}


def register_differential_evaluator() -> None:
    """把 differential_confirm 注册为一条 evidence 通道（证明力 3，与结果点同档）。

    通道消费 dast_ev['differential']（由 D1 对照实验采集填充）：attempted 且 harmful → 正向。
    仅当 dast_ev 里确有对照实验结果时才产出，否则不臆断（不污染仲裁）。
    """
    def _eval(ctx):
        dast = (ctx or {}).get("dast") or {}
        diff = dast.get("differential")
        if not isinstance(diff, dict) or not diff.get("attempted"):
            return None
        harmful = bool(diff.get("harmful"))
        # 2026-10-09（r250 实证）：harmful=False（响应级无差异）绝不能进仲裁 —— OWASP 数据流族的
        # 「静默成功型 TP」与 FP 在 HTTP 响应层完全不可区分（两侧响应都是静态页，r250 把 33 个
        # 真 TP 连同 FP 一起降级，召回 69.8%→35.4%）。差分只在 harmful=True 时作为正向证据
        # 参与仲裁（strength 3，可压过 probe_sink_assert 的仅到达）；harmful=False 只留档不裁决。
        if not harmful:
            return None
        return make_outcome(
            "differential_confirm", harmful=True, sink_reached=True,
            confidence="high",
            reason=diff.get("reason") or "对照实验观测到有害差异",
            definitive=True, category=diff.get("reason", ""),
        )
    register_evaluator("differential_confirm", _eval)


# 通道注册表与证明力表同步（differential_confirm 与 result_point_diff 同档 strength 3，
# 但定序排在其后，避免压过结果点比对；它本身就是结果点的正交对照形态）。
if "differential_confirm" not in CHANNEL_STRENGTH:
    CHANNEL_STRENGTH["differential_confirm"] = 3
if "differential_confirm" not in CHANNEL_LABEL:
    CHANNEL_LABEL["differential_confirm"] = "对照实验差分"
if "differential_confirm" not in _CHANNEL_PRIORITY:
    # 唯一优先级 8：位于 code_property=7 与 none=9 之间，且高于 result_point_diff=3，
    # 保证同证明力（strength 3）定序时绝不与 probe_sink_assert=4 撞键，且不压过结果点比对。
    _CHANNEL_PRIORITY["differential_confirm"] = 8
if "differential_confirm" not in CHANNEL_REPLAY_COST:
    CHANNEL_REPLAY_COST["differential_confirm"] = 1
register_differential_evaluator()
