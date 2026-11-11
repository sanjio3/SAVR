"""族 ⇄ sink 证据注册表。

用途：用运行时探针捕获到的 sink 反查族名，纠正上游（A2 LLM 自由命名 / A1 规则映射）的
定族错误，并给出「族-证据一致性校验」的观测面。

  - 平台族名与 OWASP 真值族名一致率仅 64.6%（124/192 用例）。错不在归一层
    ，而在**上游定族**：21 条 hash/crypto/weakrand 被 LLM
    错叫成 sensitive_data_exposure，9 条被叫成 weak_password_storage，15 条 xpathi /
    ldapi / trustbound 被套成 path_traversal。
  - 但 sink 不能无脑当判据：Counter 显示 ``Cookie.setHttpOnly`` 横跨 20+ 族、
    ``Response.addHeader`` / ``FileOutputStream.<init>`` 亦如此（BenchmarkTest 每个用例
    都会写 cookie / 写响应 / 落文件）。这些是**跨请求噪声 sink**，绝不可进白名单，
    否则会把 weak_random（用例里也用到 MessageDigest）改判成 weak_hash——那才是真误杀。

设计三条硬约束（保守优先，绝不为了改判率牺牲正确性）：
  ① 本表只收「专属 sink」——只能被一个族合法主张的 sink；噪声 sink 一律不收。
  ② 当前族自己就有专属 sink 实证 → 不动（weak_random 有 Random.next* 就不许改成 weak_hash）。
  ③ 只有**泛化族/待定族**才允许被改判；数据流族（path_traversal / sql_injection /
     command_execution / xss …）一律不动，避免把真漏洞的族改坏。
"""

from typing import Any, Dict, List, Sequence, Tuple

# —— 专属 sink 白名单：族 → 只可能被该族合法主张的 sink 签名（前缀匹配）——
# 取值来自探针上报的 iast_events.sink_file（JVM 类名.方法，如
# ``java.security.MessageDigest.getInstance``）。刻意不收文件 IO（FileInputStream /
# FileOutputStream / RandomAccessFile / Paths.get）：它们对 path_traversal 是真 sink，
# 但在 OWASP 靶场里几乎每个用例都被织到，放进白名单会把各族统统改判成 path_traversal。
FAMILY_EXCLUSIVE_SINKS: Dict[str, Tuple[str, ...]] = {
    "weak_hash": (
        "java.security.MessageDigest.getInstance",
        "java.security.MessageDigest.digest",
        "org.apache.commons.codec.digest.DigestUtils",
    ),
    "weak_crypto": (
        "javax.crypto.Cipher.getInstance",
        "javax.crypto.Cipher.init",
        "javax.crypto.KeyGenerator.getInstance",
        "javax.crypto.spec.SecretKeySpec.<init>",
    ),
    "weak_random": (
        "java.util.Random.",
        "java.util.concurrent.ThreadLocalRandom.",
        "java.lang.Math.random",
    ),
    "command_execution": (
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder.start",
        "java.lang.ProcessBuilder.<init>",
    ),
    "sql_injection": (
        ".executeQuery",
        ".executeUpdate",
        ".execute(",
        ".prepareStatement",
        ".prepareCall",
        ".addBatch",
        ".createStatement",
    ),
    # 共用同一套 naming sink 元组——探针侧 InitialContext.lookup / DirContext.search
    # 事件对这四族是同构证据。此前 A2 产出族名是 jndi_injection / rmi，而表里只有
    "jndi_injection": (
        "javax.naming.directory.DirContext.search",
        "javax.naming.InitialContext.lookup",
        "javax.naming.Context.lookup",
        "javax.naming.NamingEnumeration",
    ),
    "xpathi": (
        "javax.xml.xpath.XPath.evaluate",
        "javax.xml.xpath.XPathExpression.evaluate",
    ),
    # 刻意不收 ``javax.servlet.http.Cookie.setSecure/setHttpOnly``：它们确实是 secure_cookie
    # 收进来会把 weak_password_storage / sensitive_data_exposure 这类泛化族统统改判成
    # secure_cookie，误杀面大于收益。宁可漏改，不可错改。
}

# 泛化 / 待定族：A2 自由命名的重灾区，允许被 sink 证据改判。
# 「none / unknown / unspecified / generic」是上游没给出族名时的占位，也在列。
VAGUE_FAMILIES = frozenset({
    "", "none", "unknown", "unspecified", "generic", "other",
    "sensitive_data_exposure", "weak_password_storage", "weak-password-generation",
    "insecure_configuration", "security-misconfiguration", "log_disclosure",
    "file_upload", "unauthorized-interface-leak",
    "cookie", "cookie-injection", "session-fixation",
})


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


# jndi 协议族共用同一套 naming sink 证据：family_sink_registry 是唯一归组入口，
# attack_context._payload_check_group 反向 import 本函数，禁止各自另立映射。
FAMILY_GROUP: Dict[str, str] = {
    "jndi_injection": "jndi_injection",
    "rmi": "jndi_injection",
    "ldapi": "jndi_injection",
    "ldap_injection": "jndi_injection",
}


def family_group(family: str) -> str:
    """返回族名的证据归组键：jndi 协议四族归同一组，其余族归自身。"""
    f = _norm(family)
    return FAMILY_GROUP.get(f, f)


def sink_hits_for(family: str, sinks: Sequence[str]) -> List[str]:
    """返回观测 sink 中命中该族专属白名单的签名列表（去重、保序）。

    查表前先经 family_group 归组：rmi/jndi_injection/ldapi 的专属 sink 就是
    jndi_injection 组的 naming sink 元组。
    """
    needles = FAMILY_EXCLUSIVE_SINKS.get(family_group(family)) or ()
    if not needles:
        return []
    out: List[str] = []
    lowered = tuple(n.lower() for n in needles)
    for s in sinks:
        ss = _norm(s)
        if not ss:
            continue
        for n in lowered:
            # 两侧都小写后比对：探针上报的是 JVM 原始大小写（MessageDigest），
            # 白名单按可读形式登记，直接比对会全表落空。
            if ss.startswith(n) or n in ss:
                if ss not in out:
                    out.append(ss)
                break
    return out


def resolve_family_from_sinks(sinks: Sequence[str]) -> Tuple[str, List[str], int]:
    """用观测 sink 反查族名。返回 (族名, 命中的 sink 列表, 命中数)。

    多个族的专属 sink 同时出现时取命中数最多者（并列取表序在前），这是「证据最强者胜」。
    无命中返回 ("", [], 0)。
    """
    best_fam = ""
    best_hits: List[str] = []
    for fam in FAMILY_EXCLUSIVE_SINKS:
        hits = sink_hits_for(fam, sinks)
        if len(hits) > len(best_hits):
            best_fam, best_hits = fam, hits
    return best_fam, best_hits, len(best_hits)


def is_vague_family(family: str) -> bool:
    """该族是否属于「泛化 / 待定」，允许被 sink 证据改判。"""
    return _norm(family) in VAGUE_FAMILIES


def reassign_family_by_sink_evidence(
    current_family: str, sinks: Sequence[str]
) -> Tuple[str, Dict[str, Any]]:
    """族-证据一致性校验 + 保守改判。返回 (最终族名, 校验明细)。

    明细恒非空（即便不改判），作为观测面落进 spec.raw_json.family_sink_check，
    供事后审计「平台族名与运行时 sink 证据是否自洽」。
    """
    cur = _norm(current_family)
    observed = [s for s in (_norm(x) for x in sinks) if s]
    own_hits = sink_hits_for(cur, observed)
    resolved, hits, n = resolve_family_from_sinks(observed)
    detail: Dict[str, Any] = {
        "current_family": cur,
        "observed_sinks": observed[:12],
        "own_exclusive_hits": own_hits[:8],
        "resolved_family": resolved,
        "resolved_sinks": hits[:8],
        "consistent": bool(own_hits) or (not resolved) or resolved == cur,
        "reassigned": False,
    }
    try:
        from src.core.normalize import is_business_logic_family  # 延迟导入防循环

        if is_business_logic_family(cur):
            detail["reason"] = "业务/差分族不走 sink 证据改判"
            return cur, detail
    except Exception:
        pass
    if own_hits:
        # 硬约束②：本族已有专属 sink 实证，任何他族 sink 都视为同用例内的旁路噪声。
        detail["reason"] = "本族有专属 sink 实证，维持原族名"
        return cur, detail
    if not resolved:
        detail["reason"] = "未观测到任何族的专属 sink，维持原族名"
        return cur, detail
    if resolved == cur:
        detail["reason"] = "反查结果与原族名一致"
        return cur, detail
    if not is_vague_family(cur):
        # 硬约束③：数据流族不动（path_traversal / sql_injection / xss … 凭噪声 sink 改判风险太高）。
        detail["reason"] = "原族为数据流族，保守起见不改判"
        return cur, detail
    detail.update({
        "reassigned": True,
        "reason": "原族为泛化/待定族且本族无专属 sink 实证，按运行时 sink 证据改判",
        "prior_family": cur,
    })
    return resolved, detail


# rmi/jndi_injection 若无任何 naming sink 运行时实证、且确认结论仅来自业务差分
# （iast_state=business-logic-confirmed、无 OOB），大概率是上游把垂直越权/未授权访问
# 却被定族成 rmi 并凭业务差分翻 confirmed。这类条目改判 broken_access_control。
JNDI_PROTOCOL_FAMILIES = frozenset({"rmi", "jndi_injection"})

BUSINESS_LOGIC_FALLBACK_FAMILY = "broken_access_control"


def reassign_protocol_family_by_business_logic(
    current_family: str,
    sinks: Sequence[str],
    iast_state: str = "",
    oob_confirmed: bool = False,
) -> Tuple[str, Dict[str, Any]]:
    """rmi/jndi 协议族的反向改判校验。返回 (最终族名, 校验明细)。

    改判条件（全部满足才动）：
      ① 族 ∈ {rmi, jndi_injection}（ldapi/ldap_injection 不动——OWASP 靶场有真 LDAP 用例）；
      ② 观测 sink 中无任何 jndi 组 naming sink 实证（sink_hits_for 为空）；
      ③ 无 OOB 带外确认；
      ④ 确认态仅来自业务差分（iast_state=business-logic-confirmed）。
    只改 spec.family + raw_json.family_reassign，不动 verification_status——
    业务差分确认本身仍然成立，错的只是「它是 rmi 漏洞」这一定族。
    """
    cur = _norm(current_family)
    observed = [s for s in (_norm(x) for x in sinks) if s]
    naming_hits = sink_hits_for(cur, observed)
    detail: Dict[str, Any] = {
        "rule": "protocol_family_business_logic",
        "current_family": cur,
        "naming_sink_hits": naming_hits[:8],
        "oob_confirmed": bool(oob_confirmed),
        "iast_state": _norm(iast_state),
        "reassigned": False,
    }
    if cur not in JNDI_PROTOCOL_FAMILIES:
        detail["reason"] = "非 rmi/jndi 协议族，本规则不适用"
        return cur, detail
    if naming_hits:
        detail["reason"] = "有 naming sink 运行时实证，维持 rmi/jndi 定族"
        return cur, detail
    if oob_confirmed:
        detail["reason"] = "有 OOB 带外确认，维持 rmi/jndi 定族"
        return cur, detail
    if _norm(iast_state) != "business-logic-confirmed":
        detail["reason"] = "确认链不是纯业务差分，本规则不适用"
        return cur, detail
    detail.update({
        "reassigned": True,
        "prior_family": cur,
        "reason": "rmi/jndi 族无 naming sink 实证且仅业务差分确认，改判访问控制类",
    })
    return BUSINESS_LOGIC_FALLBACK_FAMILY, detail
