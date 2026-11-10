"""按族路由判定通道（I 组，2026-09-28 落地）。

背景（canary 结构性失效三族）：securecookie / weak_hash / weak_crypto 的「漏洞」不是
数据流事件（污点到达 sink），而是代码属性（Cookie flag 缺失、弱算法选择）。旧判定把
canary 到达任意 sink 就记 confirmed_exploitable，对这三族问错了问题——实测把大量
safe 用例也抬成 confirmed（G 分析：借 sink 26 条 / 无事件 13 条多来自这三族形态）。

三条通道：
- dataflow（默认）：现行 canary/taint 判据，不动。
- algorithm（weak_hash/weak_crypto）：判定 = 探针在 getInstance 类 hook 记录到算法参数，
  且算法名 ∈ 弱算法黑名单 → confirmed_code_property；到达算法 sink 但算法不弱 →
  confirmed_sink_control；无算法 sink 事件 → unconfirmed（此前借链路确认的假阳性就此出清）。
- attribute（securecookie 等）：判定 = Cookie.setSecure/setHttpOnly 的布尔参数断言
  （探针已记录参数，实测 source_value='[true]'/'[false]'）：false → confirmed_code_property；
  全 true → unconfirmed；无事件 → unconfirmed（证据不足，不臆断）。

终态语义：confirmed_code_property 是**独立终态**，不与 confirmed_exploitable 混用
（后者语义 = 运行时可利用证明）。对账主口径（确认层召回）只对 dataflow 族数
confirmed_exploitable；三失效族的恢复按 confirmed_code_property 另列。
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

# 新终态（独立语义，不并入 confirmed_exploitable）
CONFIRMED_CODE_PROPERTY = "confirmed_code_property"

_ALGO_FAMILY_TOKENS = ("weak_hash", "weak_crypto", "hash", "crypto", "weak-encryption")
_ATTRIBUTE_FAMILY_TOKENS = ("secure_cookie", "securecookie", "cookie_flags", "cookieflags")
# 2026-10-03（Part2 判据错配出清）：weak_random **必须单列**。
# 事故：本表原先没有 random 类 token，weak_random 落到默认 dataflow 通道；而 dataflow 的
# 判据是「canary 到 sink 即 confirmed_exploitable」—— 于是 run 46 实测 16 条 weak_random
# 全部被抬成 confirmed_exploitable。但「用了 java.util.Random」根本不是**可利用性**主张，
# 而是**代码属性**主张（非密码学安全随机源）：没有攻击者可控输入、没有可利用后果，
# 拿「运行时可利用证明」的终态去标它，就是问错了问题。
# 它与算法族还不一样：Random 没有 getInstance 那种算法名参数可判强弱，观测到即成立
# （OWASP 靶场 weakrand 的 vuln 用例用 java.util.Random，safe 用例用 SecureRandom）。
_RANDOM_FAMILY_TOKENS = ("weak_random", "weakrandom", "weak_rand", "insecure_random", "random")

# 算法选择 sink（探针 hook 记录 getInstance 的算法参数）
_ALGO_SINK_TOKENS = (
    "MessageDigest.getInstance", "Cipher.getInstance", "Mac.getInstance",
    "KeyGenerator.getInstance", "SecretKeyFactory.getInstance", "SecureRandom.getInstance",
)
# 弱算法黑名单（Java 名大小写不敏感；"SHA"/"SHA1"/"SHA-1" 均为 SHA-1）
_WEAK_ALGOS = {
    "md5", "md4", "sha", "sha1", "sha-1", "des", "desede", "3des",
    "rc2", "rc4", "arcfour", "blowfish", "md2",
}
_ATTRIBUTE_SINK_TOKENS = ("Cookie.setSecure", "Cookie.setHttpOnly")
# 2026-10-08 补 Cookie 构造器：OWASP Benchmark 的 securecookie **真漏洞形态是「new Cookie(...)
# 之后从不调用 setSecure/setHttpOnly」**，只认 setSecure/setHttpOnly 事件永远抓不到真漏洞
# （设了 flag 的反而是 safe 用例）⇒ 旧判据对本族系统性失效（run 246 实测 TP 确认率 1/6）。
# 探针侧同步补了 Cookie.<init> hook（ByteBuddyHookInstaller.installWeakCryptoHooks），
# 于是「有 Cookie.<init> 事件 且 无 setSecure(true)/setHttpOnly(true)」= flag 缺失的正向证据。
_COOKIE_CTOR_SINK_TOKENS = ("Cookie.<init>",)
# 弱随机源 sink（前缀匹配，取自 family_sink_registry 的专属 sink 表，单一真相源）
_RANDOM_SINK_TOKENS = ("java.util.Random.", "java.util.concurrent.ThreadLocalRandom.", "java.lang.Math.random")

_BOOL_RE = re.compile(r"true|false", re.IGNORECASE)


def _exclusive_sinks_for(family: str) -> Tuple[str, ...]:
    """取该族在「专属 sink 白名单」里的 sink 签名（拿不到返回空元组）。

    刻意复用 family_sink_registry.FAMILY_EXCLUSIVE_SINKS 而不是在这里另抄一份：
    那张表的三条硬约束（只收专属 sink、噪声 sink 不收）就是为了防「借 sink 误判」，
    判据错配出清恰恰需要同一份约束。
    """
    try:
        from src.core.family_sink_registry import FAMILY_EXCLUSIVE_SINKS
    except Exception:
        return ()
    f = str(family or "").lower().replace("-", "_")
    return tuple(FAMILY_EXCLUSIVE_SINKS.get(f) or ())


def route_for(family: str, events: Optional[Iterable[Dict[str, Any]]] = None) -> str:
    """族 → 判定通道。未知族一律 dataflow（现行判据），保证零回归。

    路由键优先级（2026-10-03 判据错配出清）：**实际观测到的 sink 签名 > 族名**。
    族名是上游 A2/A1 的**主张**，会被 LLM 自由命名带偏（实测 OWASP 平台族名与真值
    族名一致率仅 64.6%）；而 sink 签名是探针看到的**事实**。只对「专属 sink」认账
    （见 _exclusive_sinks_for），噪声 sink（Response.addHeader / Cookie.setHttpOnly /
    FileOutputStream）一律不算，否则会重演「借 sink 把别族判成自己」的误杀。
    """
    # 先看有没有该族的专属 sink 实证
    for ev in events or []:
        sink = str((ev or {}).get("sink_file") or "")
        if not sink:
            continue
        for token in _exclusive_sinks_for(family):
            if token in sink:
                return _ROUTE_BY_EXCLUSIVE_FAMILY.get(
                    str(family or "").lower().replace("-", "_"), "dataflow"
                )
    # 无实证才退回族名路由
    f = str(family or "").lower().replace("-", "_")
    if any(t in f for t in _RANDOM_FAMILY_TOKENS):
        return "random_source"
    if any(t in f for t in _ALGO_FAMILY_TOKENS):
        return "algorithm"
    if any(t in f for t in _ATTRIBUTE_FAMILY_TOKENS):
        return "attribute"
    return "dataflow"


# 有专属 sink 实证的族 → 该走哪条通道
_ROUTE_BY_EXCLUSIVE_FAMILY = {
    "weak_hash": "algorithm",
    "weak_crypto": "algorithm",
    "weak_random": "random_source",
    "secure_cookie": "attribute",
}


def _event_arg(ev: Dict[str, Any]) -> str:
    """从事件里抠出 hook 记录的参数串（source_value 优先，evidence_json.payload 兜底）。"""
    arg = str(ev.get("source_value") or "")
    if arg:
        return arg
    try:
        ej = json.loads(ev.get("evidence_json") or "{}")
        return str(ej.get("payload") or "")
    except Exception:
        return ""


def _first_token(arg: str) -> str:
    """抠出 hook 记录的算法/布尔首参数，统一小写。

    - 属性族：'[true]'/'[false]' -> 'true'/'false'。
    - 算法族 MessageDigest/Mac：'[SHA1, SUN]' -> 'sha1'；'[MD5]' -> 'md5'。
    - 算法族 Cipher（关键）：'[DES/CBC/PKCS5PADDING, SunJCE]' -> 'des'——
      探针上报的是完整「变换字符串」ALG/MODE/PADDING，必须按 '/' 切出基础算法名，
      否则 DES/3DES 会被误判为非弱算法（confirmed_sink_control），漏掉真实弱加密漏洞。
      （2026-09-28 修复：run 31 实测 9/15 算法族 spec 因未切分变换字符串而被错判。）
    """
    arg = arg.strip().strip("[]")
    if not arg:
        return ""
    tok = arg.split(",")[0].strip().strip("'\"")
    tok = tok.split("/")[0].strip().lower()  # Cipher 变换字符串 ALG/MODE/PADDING -> ALG
    return tok


def _classify_algorithm_events(events: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """算法族事件分类（单一真相源，judge_algorithm_family 与 judge_safe_implementation 共用）。

    返回 (algo_events, weak_hits, strong_seen)。拆分是为了让「算法不弱」这个事实
    只被解析一次：judge 拿它判 unconfirmed，judge_safe_implementation 拿它判
    「安全实现有正证据」，两处若各写一遍必然分叉。
    """
    algo_events = [
        ev for ev in (events or [])
        if any(t in str(ev.get("sink_file") or "") for t in _ALGO_SINK_TOKENS)
    ]
    weak_hits, strong_seen = [], []
    for ev in algo_events:
        algo = _first_token(_event_arg(ev))
        if not algo:
            continue
        (weak_hits if algo in _WEAK_ALGOS else strong_seen).append(algo)
    return algo_events, weak_hits, strong_seen


def _classify_attribute_events(events: Iterable[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], List[str]]:
    """属性族事件分类（单一真相源）。返回 (flag_events, ctor_events, false_flags, true_flags)。"""
    events = list(events or [])
    flag_events = [
        ev for ev in events
        if any(t in str(ev.get("sink_file") or "") for t in _ATTRIBUTE_SINK_TOKENS)
    ]
    ctor_events = [
        ev for ev in events
        if any(t in str(ev.get("sink_file") or "") for t in _COOKIE_CTOR_SINK_TOKENS)
    ]
    false_flags, true_flags = [], []
    for ev in flag_events:
        sink = str(ev.get("sink_file") or "")
        arg = _first_token(_event_arg(ev))
        if arg not in ("true", "false"):
            continue
        name = "secure" if "setSecure" in sink else "httponly"
        (false_flags if arg == "false" else true_flags).append(name)
    return flag_events, ctor_events, false_flags, true_flags


def judge_algorithm_family(events: Iterable[Dict[str, Any]]) -> Tuple[str, str]:
    """算法族判定。返回 (verification_status, judge_detail)。"""
    algo_events, weak_hits, strong_seen = _classify_algorithm_events(events)
    if not algo_events:
        return "unconfirmed", (
            "算法族族路由：canary 未观测到算法选择 sink（getInstance）事件，"
            "弱算法主张缺乏直接证据（旧判据的借链路确认已出清）"
        )
    if weak_hits:
        return CONFIRMED_CODE_PROPERTY, (
            f"算法族族路由：算法选择 sink 已到且算法参数 ∈ 弱算法黑名单（{sorted(set(weak_hits))}）"
            f" → confirmed_code_property"
        )
    if strong_seen or algo_events:
        # 强算法/参数未记录 ⇒ 弱算法主张不成立。必须判 unconfirmed：
        # 返回 confirmed_sink_control（确认态）会把 OWASP hash 的 safe 用例算成命中
        # （run 364 实测 41 条 FP 全部来自此分支，且 positive_evidence_rule 为空）。
        return "unconfirmed", (
            f"算法族族路由：算法选择 sink 已到但算法参数不弱（{sorted(set(strong_seen)) or '参数未记录'}）"
            " → 弱算法主张不成立，判为未确认"
        )
    return "unconfirmed", "算法族族路由：算法参数未记录（探针待补，见探针改进文档）"


def judge_attribute_family(events: Iterable[Dict[str, Any]]) -> Tuple[str, str]:
    """属性族（Cookie flag）判定。返回 (verification_status, judge_detail)。

    三条判据，按证据强度排序：
    ① flag 显式关闭（setSecure(false) / setHttpOnly(false)）→ 确证缺失。
    ② **Cookie 已创建但从未设置 flag**（只有 Cookie.<init> 事件，无任何 setSecure/setHttpOnly）
       → 确证缺失。这是 OWASP Benchmark securecookie 的主形态，2026-10-08 补。
    ③ flag 显式开启 → 主张不成立（safe 用例）。
    """
    events = list(events or [])
    flag_events, ctor_events, false_flags, true_flags = _classify_attribute_events(events)
    if false_flags:
        return CONFIRMED_CODE_PROPERTY, (
            f"属性族族路由：Cookie flag 显式关闭（{sorted(set(false_flags))}=false）"
            f" → confirmed_code_property"
        )
    # ② Cookie 已创建但从未设置 flag：创建事件存在、且没有任何一次 true 设置 ⇒ flag 缺失成立。
    # 注意顺序：必须在 true_flags 判据**之前**，否则「safe 用例既设了 true 又因框架内部创建
    # Cookie 而留下 <init> 事件」会被误判成缺失。
    if ctor_events and not true_flags:
        return CONFIRMED_CODE_PROPERTY, (
            f"属性族族路由：观测到 {len(ctor_events)} 次 Cookie 创建（Cookie.<init>）"
            " 但全程未调用 setSecure(true)/setHttpOnly(true) → flag 缺失成立"
            f" → confirmed_code_property"
        )
    if true_flags:
        return "unconfirmed", (
            f"属性族族路由：Cookie flag 显式开启（{sorted(set(true_flags))}=true）"
            " → 缺失 flag 主张不成立"
        )
    if not flag_events and not ctor_events:
        return "unconfirmed", (
            "属性族族路由：未观测到 Cookie 创建或 setSecure/setHttpOnly 事件，"
            "无法断言 flag 缺失（不臆断）"
        )
    return "unconfirmed", "属性族族路由：flag 参数未记录（探针待补）"


def judge_random_family(events: Iterable[Dict[str, Any]]) -> Tuple[str, str]:
    """弱随机源族判定。返回 (verification_status, judge_detail)。

    判据 = 探针观测到非密码学安全随机源被调用（java.util.Random / ThreadLocalRandom /
    Math.random）。观测到即成立 —— 这族没有「算法名参数」可判强弱，也没有攻击者可控
    输入，它是**代码属性**主张，终态只能是 confirmed_code_property，绝不能是
    confirmed_exploitable（后者语义 = 运行时可利用证明）。

    SecureRandom 不在 _RANDOM_SINK_TOKENS 里，故安全用例不会命中 → unconfirmed，
    正是「缺失主张不成立」的正确表达。
    """
    hits = sorted({
        str(ev.get("sink_file") or "")
        for ev in (events or [])
        if any(t in str(ev.get("sink_file") or "") for t in _RANDOM_SINK_TOKENS)
    })
    if hits:
        return CONFIRMED_CODE_PROPERTY, (
            f"弱随机源族路由：观测到非密码学安全随机源调用（{', '.join(hits[:3])}）"
            " → confirmed_code_property（代码属性，非运行时可利用证明）"
        )
    return "unconfirmed", (
        "弱随机源族路由：未观测到 java.util.Random / ThreadLocalRandom / Math.random 事件，"
        "「使用不安全随机源」的主张缺乏直接证据（旧判据借别族 sink 的确认已出清）"
    )


def judge_safe_implementation(family: str, events: Iterable[Dict[str, Any]]) -> Tuple[bool, str]:
    """算法/属性族「安全实现」正证据判定。返回 (is_safe_impl, rule)。

    为什么单独一个函数而不是复用 judge_* 的 unconfirmed：

    算法/属性族被 judge 判 unconfirmed 有两个来源，语义完全不同：
      ① 算法 sink 已到、算法参数不弱（或 Cookie flag 显式置 true）—— **有正证据的安全实现**；
      ② 什么都没观测到、或算法参数未记录 —— **无证据**。
    对账口径只认 suppressed_by_safe_verdict，所以算法族要真正把 FP 从检出集合清出去，
    必须写 suppressed；但只有 ① 能写：拿 ② 去抑制等于"没证据就诛心"，会把探针漏观测的
    真漏洞一并压掉（召回风险）。这与数据流族值级闸 absent（到达 sink 但实参无 payload，
    正证据）与 no_event（无事件，不动）的二分是同一套纪律。

    保护：任何 TP 主张命中（弱算法黑名单 / flag 显式 false）一律返回 False，永不抑制。
    random_source 族没有"正安全证据"可用（观测不到 Random ≠ 用了 SecureRandom）→ 恒 False，
    交由值级闸的 fail-open 语义兜底，不猜。
    """
    events = list(events or [])
    if not events:
        return False, ""
    route = route_for(family, events)
    if route == "algorithm":
        _algo_events, weak_hits, strong_seen = _classify_algorithm_events(events)
        if weak_hits:
            return False, ""  # 弱算法命中 = TP 主张，永不抑制
        if strong_seen:
            return True, "algorithm_not_weak:" + ",".join(sorted(set(strong_seen)))
        return False, ""  # 无算法 sink 事件 / 参数未记录 = 无证据，fail-open
    if route == "attribute":
        _flag_events, _ctor_events, false_flags, true_flags = _classify_attribute_events(events)
        if false_flags:
            return False, ""  # flag 显式关闭 = TP 主张，永不抑制
        if true_flags:
            return True, "cookie_flag_set_true:" + ",".join(sorted(set(true_flags)))
        return False, ""  # 只有 Cookie.<init> 无 flag 事件 = 证据不足（反而是 TP 主张方向），不抑制
    return False, ""


# 族路由准入状态集：只有这些状态才允许 judge_* 介入重判。
# no_evidence 刻意排除——「本轮什么都没观测到」时不许拿残留事件晋升。
# 2026-10-16（P-D 补）：把两个**已路由的正确终态**也纳入准入。
# 缺口：属性族 spec 由 D2/M4 的 code_property 通道拿到 confirmed_code_property 后，
# iast_state 仍是 sink-reached-probe（不是 family-route:*），而本准入集不含这两个终态
# ⇒ judge 根本不再跑，positive_evidence_rule 永远为空（对应修复计划 §1.3「226 条为空」）。
# 只放「已确认态」进来是安全的：judge 要么凭本族专属 sink 事件复证并把规则落库，
# 要么返回 unconfirmed；而 unconfirmed 仅当旧态是 confirmed_exploitable 时才被接受
# （见下方 apply_family_route 的 accepted 分支），所以 confirmed_code_property /
# confirmed_sink_control 不会被降级，只会补上「由哪条族专属规则背书」这一事实。
_JUDGE_ADMITTED_STATUSES = frozenset({
    "confirmed_exploitable", "unconfirmed", "sink_reached",
    "confirmed_code_property", "confirmed_sink_control",
})


def apply_family_route(
    family: str,
    verification_status: str,
    events: Iterable[Dict[str, Any]],
) -> Tuple[str, Dict[str, Any]]:
    """按族路由重判一条 spec（数据流族原样放行）。

    2026-10-08 准入放开（此前是「修法写了没接通」的关键一环）：
    原实现硬性要求 `verification_status == 'confirmed_exploitable'` 才允许 judge_* 介入，
    而 M4 通道注册表上线后，代码属性族（weak_hash/weak_crypto/weak_random/secure_cookie）
    的仲裁主判据变成 code_property（harmful=False），spec 停在 unconfirmed —— 于是它们
    **永远进不了 judge_***，既够不到 confirmed_exploitable，也没人把它们路由到
    confirmed_code_property，整族凭空掉成 unconfirmed（run 246 实测：weakrand TP 确认 0/2、
    securecookie TP 确认 1/6）。

    放开规则（仍不允许「没证据的晋升」，只是允许 judge 用**本族专属 sink 事件**说话）：
      - 准入状态集 = {confirmed_exploitable, unconfirmed, sink_reached}。`no_evidence` **不**在
        其中：它明示「本轮什么都没观测到」，此时即使残留事件也不得据此晋升（锁见
        tests/test_m3b_verdict_mismatch.py::test_non_exploitable_status_is_not_touched 与
        tests/test_family_route_watch.py::test_apply_family_route_only_touches_confirmed）。
      - judge 返回 confirmed_code_property / confirmed_sink_control → 接受（有专属事件背书）
      - judge 返回 unconfirmed → **仅当旧状态是 confirmed_exploitable 时**接受（出清假阳性）；
        其余状态维持原状，保住 no-arrival / no-iast-evidence 等归因线索不被覆盖。

    返回 (新状态, route_detail)。route_detail 带 positive_evidence_rule 供调用方落库。
    """
    events = list(events or [])
    route = route_for(family, events)
    if route == "dataflow":
        return verification_status, {"route": route, "applied": False}
    if verification_status not in _JUDGE_ADMITTED_STATUSES:
        return verification_status, {"route": route, "applied": False,
                                     "note": f"状态 {verification_status} 不在族路由准入集内"}
    if route == "algorithm":
        new_status, detail = judge_algorithm_family(events)
    elif route == "random_source":
        new_status, detail = judge_random_family(events)
    else:
        new_status, detail = judge_attribute_family(events)

    _RULE_BY_ROUTE = {
        "algorithm": "weak_algo_or_strong_algo_at_getinstance",
        "random_source": "non_crypto_random_source_called",
        "attribute": "cookie_flag_missing_or_false",
    }
    if new_status in (CONFIRMED_CODE_PROPERTY, "confirmed_sink_control"):
        accepted = True
    elif new_status == "unconfirmed":
        # confirmed_sink_control 也必须允许被族判据降级为 unconfirmed。
        # 背景：d2_judge 对算法族/属性族/随机族的**安全实现**（强算法 SHA-256、flag 已置真、
        # 强随机源）会给「观测到 sink 控制但未命中高影响」→ confirmed_sink_control。这类状态若
        # 不降级，会一直被对账/门禁当成「确认命中」计成 FP（run 364 hash 41 条 FP 全部是此
        # 状态，算法实为 SHA-256 等强算法）。原判据只放 confirmed_exploitable，导致后处理
        # 选不到、也降不动 confirmed_sink_control，P1 修复实际失效。
        # confirmed_exploitable 的原意（出清借链路确认的假阳性）保留不变。
        accepted = verification_status in ("confirmed_exploitable", "confirmed_sink_control")
    else:
        accepted = False
    if not accepted:
        return verification_status, {"route": route, "applied": False,
                                     "judge_status": new_status, "detail": detail,
                                     "note": "judge 未产出可采信结论，维持原状态"}
    return new_status, {"route": route, "applied": True,
                        "old_status": verification_status, "detail": detail,
                        "positive_evidence_rule": (
                            _RULE_BY_ROUTE.get(route, "")
                            if new_status == CONFIRMED_CODE_PROPERTY else ""
                        )}
