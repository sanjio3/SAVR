"""
归一化工具：severity 大小写 + finding_type/source taxonomy 同义合并。

根因：A1 / A2 / SCA 各 agent 对 severity 与漏洞类型各自一套写法，导致 findings 表出现
HIGH/high、MEDIUM/medium 混用，以及「水平越权(idor)」vs「水平越权 (idor)」、
「金额篡改」/「支付金额篡改」/「业务逻辑类-支付金额篡改」等同义重复，统计被人为分裂。

本模块提供唯一权威归一函数，供 findings 写入路径与报告聚合处统一调用（本质解决，非展示层掩盖）。
"""
import os
import re
from typing import Dict, Optional, Tuple

# 业务/差分证明族归一走 exploit_spec.canonical_business_logic_family（underscore token 单一真相源）。
# 延迟导入避免与 exploit_spec 形成环（exploit_spec 当前不反向导入本模块）。
from src.core.exploit_spec import canonical_business_logic_family, is_business_logic_family

# 规范 severity 全集（大写）
_SEVERITY_CANON = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "UNKNOWN": "UNKNOWN",
}

# 同义写法 -> 规范 severity（小写匹配）
# 末四条来自 SCA 适配器（Trivy/OSV/Grype 的 NEGLIGIBLE/MODERATE/IMPORTANT/SEVERE），
_SEVERITY_ALIASES = {
    "critical": "CRITICAL",
    "crit": "CRITICAL",
    "high": "HIGH",
    "hi": "HIGH",
    "medium": "MEDIUM",
    "med": "MEDIUM",
    "low": "LOW",
    "lo": "LOW",
    "info": "INFO",
    "unknown": "UNKNOWN",
    "": "UNKNOWN",
    "none": "UNKNOWN",
    "negligible": "LOW",
    "moderate": "MEDIUM",
    "important": "HIGH",
    "severe": "CRITICAL",
}


def normalize_severity(sev: Optional[str]) -> str:
    """severity 统一为大写规范值。未知/空 -> UNKNOWN。"""
    if not sev:
        return "UNKNOWN"
    s = str(sev).strip().upper()
    if s in _SEVERITY_CANON:
        return s
    key = str(sev).strip().lower()
    return _SEVERITY_ALIASES.get(key, "UNKNOWN")


# finding_type / source 同义合并表（仅合并明确同义，避免误并）。
# 规则：去括号空格差异、收敛中文业务族前缀、收敛英文族大小写/写法。
_TYPE_ALIASES: Dict[str, str] = {
    # 括号空格差异
    "水平越权 (idor)": "水平越权(idor)",
    "水平越权 (idor) ": "水平越权(idor)",
    # 中文业务族前缀收敛（去掉「业务逻辑类-」冗余前缀，统一短名）
    "业务逻辑类-支付金额篡改": "支付金额篡改",
    "业务逻辑类-优惠券叠加/金额为负": "优惠券叠加/金额为负",
    "业务逻辑类-越权改密/账号接管": "越权改密/账号接管",
    "业务逻辑类-业务逻辑错误": "业务逻辑错误",
    # 金额篡改族
    "金额篡改": "支付金额篡改",
    # 英文族写法收敛
    "spel注入": "spel_injection",
    "spel injection": "spel_injection",
    "spel-injection": "spel_injection",
    "ssti（服务端模板注入）": "ssti",
    "ssti(服务端模板注入)": "ssti",
    "ssti": "ssti",
    "明文存储密码": "弱密码存储",
    "基础设施层-弱密码存储": "弱密码存储",
    "弱密码存储": "弱密码存储",
    "弱签名-/-可伪造": "弱签名可伪造",
    "弱签名-可伪造": "弱签名可伪造",
    "signature_bypass": "弱签名可伪造",
    "回调签名伪造/重放": "回调签名伪造/重放",
    "基础设施层-敏感信息泄露": "敏感信息泄露",
    "基础设施层-进程信息泄露": "进程信息泄露",
    "基础设施层-数据库信息泄露": "数据库信息泄露",
    "基础设施层-安全监控状态泄露": "安全监控状态泄露",
    "未授权接口泄露": "sensitive_data_exposure",
    "退款滥用": "退款滥用",
    "批量赋值提权": "批量赋值提权",
    "命令注入": "command_execution",
    "命令执行": "command_execution",
    "command-execution": "command_execution",
    "命令执行(command)": "command_execution",
    "sql注入": "sql_injection",
    "sql-injection": "sql_injection",
    "sql injection": "sql_injection",
    "xss": "xss",
    "XSS": "xss",
    "路径穿越": "path_traversal",
    "path-traversal": "path_traversal",
    "xxe": "xxe",
    "XXE": "xxe",
    "ssrf": "ssrf",
    "SSRF": "ssrf",
    "反序列化链": "deserialization",
    "Java 反序列化链": "deserialization",
    "deserialization": "deserialization",
    "expression-injection": "expression_injection",
    "表达式注入": "expression_injection",
    "垂直越权": "vertical_privesc",
    "vertical_privesc": "vertical_privesc",
    "vertical privesc": "vertical_privesc",
    "水平越权(idor)": "idor",
    "idor": "idor",
    "bola": "bola",
    "BOLA": "bola",
    "calculation_logic": "calculation_logic",
    "race_condition": "race_condition",
    "race condition": "race_condition",
    "并发竞争": "race_condition",
    "业务逻辑类-并发竞争": "race_condition",
    "state_machine": "state_machine",
    "状态机跳步": "state_machine",
    "jwt_weak": "jwt_weak",
    # JNDI lookup 误判为 XXE、且无对应规范 token；这里补上，供 a2_intelligent_agent 的
    # 族名证据修正与报告 by_type 归口。
    "jndi_injection": "jndi_injection",
    "jndi injection": "jndi_injection",
    "jndi注入": "jndi_injection",
    "log4j": "jndi_injection",
    "log4j rce": "jndi_injection",
    "log4j注入": "jndi_injection",
    "unauthorized_endpoint": "unauthorized_endpoint",
    "file-upload": "file_upload",
    "auth_password_reset": "auth_password_reset",
    "abuse_dos": "abuse_dos",
    "business_logic错误": "业务逻辑错误",
}


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 背景：旧实现只做精确字符串查表，未登记写法原样放行，导致同一族在 by_type 里裂成多个标签。
#   xxe 18 / xxe (xml external entity) 9
#   ssrf 44 / 基础设施层-ssrf 2 / infrastructure layer - ssrf 1
#   url重定向 7 / url redirect 3 / 基础设施层-url重定向 1
#   cors - insecure direct object reference (idor) 5 / idor 1 / infrastructure layer - ... 1
#   文件上传 2 / 文件上传-文件类型限制绕过 1 / 文件上传-文件内容检查不足 1
#   日志泄露 2 / 基础设施层-日志泄露 1 / 基础设施层-日志记录敏感信息 3
#   基础设施层-安全配置 3 / -安全配置不当 1 / -安全配置错误 1 / -不安全的域名配置 2 / -xml解析器安全配置 1
#   ssti (server-side template injection) 1（旧表只有全角括号写法，救不了）
# 三处此前各自为政的剥前缀实现（trigger_spec_registry.py、a2_intelligent_agent.py）就此收敛到本模块。

# 通用降级前缀：基础设施层- / 业务逻辑类- / infrastructure layer - 等，一律剥离。
_PREFIX_RE = re.compile(
    r"^\s*(?:基础设施层|业务逻辑类|业务逻辑层|infrastructure\s+layer|infra)\s*[-–—_:/：]*\s*",
    re.IGNORECASE,
)
# 括号内容：中英文圆括号，一律剥离（用于「xxe (xml external entity)」这类冗余注解）。
_PAREN_RE = re.compile(r"[（(][^（()）]*[)）]")
# 分隔符统一：下划线 / 连字符 / 各类破折号 / 多空白 → 单空格。
_SEP_RE = re.compile(r"[\s_\-–—]+")


def _canon_key(value: str) -> str:
    """把标签压成用于比对的规范键：剥前缀 → 去括号内容 → 小写 → 分隔符统一。"""
    v = str(value or "").strip()
    v = _PREFIX_RE.sub("", v)
    v = _PAREN_RE.sub(" ", v)
    v = v.lower()
    v = _SEP_RE.sub(" ", v).strip()
    return v


def strip_family_prefix(value: Optional[str]) -> str:
    """剥掉「基础设施层- / 业务逻辑类- / infrastructure layer -」等降级标记前缀。

    一份等价正则/循环，三处逻辑漂移。现统一由本函数提供，禁止各处再自写剥前缀。
    """
    return _PREFIX_RE.sub("", str(value or "").strip()).strip()


# 关键词族判定（按顺序匹配，命中即返回）。仅收录「同一概念的多种写法」，不做跨概念合并。
# 放在别名表之后，用于兜住别名表无法穷举的组合型标签。
_FAMILY_KEYWORDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("idor", ("insecure direct object reference", "idor", "水平越权", "bola", "越权访问对象")),
    # "xml外部实体注入 (xxe)" 经 _canon_key 去括号后为 "xml外部实体注入"，命不中
    # "xml 外部实体"（有空格），于是 by_type 里 "xxe" 与 "xml外部实体注入 (xxe)" 两标签并存。
    # 两侧同属 injection，本折叠不改变 derive_flow_type，属纯展示收敛。
    ("xxe", ("xml external entity", "xxe", "xml 外部实体", "xml外部实体", "外部实体注入")),
    ("ssti", ("server-side template injection", "ssti", "服务端模板注入")),
    ("ssrf", ("ssrf", "服务端请求伪造")),
    ("sql_injection", ("sql injection", "sql_injection", "sql注入", "sqli")),
    # "command injection" 必须显式登记：归一键会把 Command Injection / command_injection
    # 都压成 "command injection"，而它既不等于 "command execution" 也不在别名表里，
    # 原样落进 trigger_specs.family，D2 无模板。
    # 语义上 CodeQL 的 java/code-injection 命中的是 ScriptEngine/Groovy/Yaml 执行面，
    # 与 command_execution 同族；`code_injection` 本身不是平台已知族。
    ("command_execution", ("command_execution", "command-execution", "command execution", "command injection",
                           "code injection", "code-injection", "code_injection",
                           "命令注入", "命令执行", "os command")),
    ("path_traversal", ("path_traversal", "path-traversal", "path traversal", "路径穿越", "目录穿越")),
    ("deserialization", ("deserialization", "反序列化")),
    ("jndi_injection", ("jndi", "log4j")),
    ("xss", ("xss", "跨站脚本")),
    ("csrf", ("csrf", "跨站请求伪造")),
    # 于是同一漏洞在不同轮/不同 agent 下裂成多种写法，基准对账也按族 token 判「未入环」。
    # 实测漂移样本：'CRLF Injection'、'URL whitelist Bypass'、'JWT硬编码或弱密钥'、
    # 'broken access control'（A1 规则命中 CVE-2022-22978 时的族名）。
    # 本层只做「同一概念的多种写法」收敛，不做跨概念合并。
    ("crlf_injection", ("crlf", "crlf injection", "crlf注入", "http 响应拆分", "响应拆分")),
    ("url_whitelist_bypass", ("url_whitelist_bypass", "url whitelist bypass", "url白名单",
                              "url 白名单", "白名单绕过", "白名单校验绕过")),
    ("url_redirect", ("url_redirect", "url redirect", "url重定向", "open redirect", "url 重定向", "任意url跳转")),
    ("spel_injection", ("spel_injection", "spel injection", "spel", "spel-injection")),
    ("expression_injection", ("expression_injection", "expression-injection", "表达式注入", "ognl", "el 注入", "el注入")),
    ("file_upload", ("file_upload", "file-upload", "file upload", "文件上传")),
    ("weak_password_storage", ("弱密码存储", "明文存储密码", "weak password storage", "password storage")),
    ("cors", ("cors",)),
    ("jsonp_referer", ("jsonp", "referer")),
    # 注意：**不要**给 jwt 加裸针 "jwt"。'JWT安全漏洞'/'jwt伪造/权限提升' 这类标签在业务族表里
    # 已被归到 auth_session（business_logic 轴），裸针会先把它们抢到技术族、改变 flow_type。
    # JWT 真正缺的只有「弱密钥/硬编码」这一形态，它按平台既有设计属暴露轴的 weak-crypto
    # （见 exploit_spec._EXPOSURE_FAMILY_ALIASES 的 "jwt-硬编码或弱密钥": "weak-crypto"）。
    ("weak_crypto", ("jwt硬编码或弱密钥", "jwt弱密钥", "弱密钥", "硬编码密钥", "硬编码敏感信息",
                     "hardcoded key", "hardcoded secret", "weak key", "weak secret")),
    ("broken_access_control", ("broken access control", "访问控制失效", "访问控制缺失",
                              "权限校验缺失", "权限校验不当")),
    ("insecure_configuration", ("安全配置", "insecure configuration", "不安全的域名配置", "安全配置不当",
                                "安全配置错误", "解析器安全配置")),
    ("log_disclosure", ("日志泄露", "日志记录敏感信息", "日志信息泄露", "log disclosure", "sensitive log")),
    ("rmi", ("rmi", "远程方法调用", "java rmi")),
    ("authentication_session", ("认证与会话", "认证绕过", "auth bypass")),
    # weak-random-number-generation / 弱随机数生成），计数与真值匹配全部错配。
    ("weak_hash", ("弱哈希算法", "weak hash", "weak-hash", "不安全哈希", "弱散列",
                   "weak message digest", "弱摘要", "md5", "sha-1", "sha1")),
    # weak_crypto 已有条目（jwt硬编码/弱密钥），此处仅补加密算法侧写法（needle 命中即可）。
    ("weak_crypto", ("不安全加密算法", "未使用安全的加密算法", "加密算法使用不当",
                     "weak encryption", "insecure encryption", "unsafe crypto",
                     "弱加密算法", "des 加密", "rc4")),
    ("weak_random", ("弱随机数", "weak random", "weak-random", "随机数生成",
                     "weak-random-number-generation", "insecure randomness",
                     "predictable random", "不安全随机数")),
    ("trust_boundary_violation", ("信任边界违背", "trust boundary", "trustbound",
                                  "信任边界", "trust boundary violation")),
    ("secure_cookie", ("cookie 安全属性缺失", "cookie安全属性缺失", "securecookie",
                       "secure cookie", "cookie security configuration", "cookie-security-configuration",
                       "cookie 安全配置", "cookie path override", "cookie-path-override",
                       "cookie 属性缺失", "cookie 属性未设置")),
    ("sensitive_data_exposure", ("敏感数据存储", "敏感数据泄露", "未授权接口泄露",
                                 "sensitive data exposure", "sensitive exposure",
                                 "sensitive_exposure", "数据泄露", "敏感信息泄露",
                                 "未使用安全的密钥管理", "密钥管理")),
    ("ldap_injection", ("ldap注入", "ldap 注入", "ldap injection", "ldapi")),
    # "xpath-injection"，既不在 KNOWN_CANONICAL_FAMILIES（AP 幻觉过滤误判为未知族），也与
    # 真值命名空间（GT 11 族之一）。needle 命中即可，不跨概念合并。
    ("xpathi", ("xpath injection", "xpath-injection", "xpathi", "xpath 注入")),
)


def _build_canon_alias() -> Dict[str, str]:
    """由 _TYPE_ALIASES 的「值」反推规范键表：规范键 → 规范值。

    这样任何与已登记别名「归一后同形」的写法（前缀/括号/大小写/分隔符差异）都能命中，
    而不必为每种写法再手工登记一行。
    """
    out: Dict[str, str] = {}
    for alias, canon in _TYPE_ALIASES.items():
        out.setdefault(_canon_key(alias), canon)
        out.setdefault(_canon_key(canon), canon)
    return out


_TYPE_ALIAS_CANON: Dict[str, str] = _build_canon_alias()


def _build_nospace_alias() -> Dict[str, str]:
    """「去掉全部空白」后的别名兜底索引。

    ``SQL 注入``（带空格）。``_canon_key`` 只把连续空白压成一个空格、**不删空格**，
    于是 ``sql 注入`` 查不到 → 原样返回 → ``is_known_family`` 判 False
    → 被当成幻觉族过滤掉。

    处理方式：只做**兜底索引**（前三级精确/规范键都未命中时才查），
    构建时剔除「去空格后撞车但目标不一致」的键，避免引入新的错误映射。
    """
    idx: Dict[str, str] = {}
    clash = set()
    for alias, canon in _TYPE_ALIASES.items():
        for raw in (alias, canon):
            nk = re.sub(r"\s+", "", str(raw).lower())
            if not nk:
                continue
            prev = idx.get(nk)
            if prev is not None and prev != canon:
                clash.add(nk)
            idx[nk] = canon
    for nk in clash:
        idx.pop(nk, None)
    return idx


_TYPE_ALIAS_NOSPACE: Dict[str, str] = _build_nospace_alias()


def normalize_type(value: Optional[str]) -> str:
    """finding_type / source 统一为规范族名。

    判定顺序：精确别名 → 括号空格收敛别名 → 规则归一键查别名 → 关键词族判定 → 原样返回。
    未知标签仍然原样返回（不臆造族名），但已登记族的全部写法差异都会被收敛。
    """
    if not value:
        return ""
    v = str(value).strip()
    if not v:
        return ""

    # 1) 精确别名（保持历史行为，优先级最高）
    if v in _TYPE_ALIASES:
        return _TYPE_ALIASES[v]

    # 2) 括号空格收敛（兼容历史写法差异）
    collapsed = v.replace(" (", "(").replace(") ", ")")
    if collapsed in _TYPE_ALIASES:
        return _TYPE_ALIASES[collapsed]

    # 3) 规则归一键（剥前缀 + 去括号 + 小写 + 分隔符统一）后查别名表
    key = _canon_key(v)
    if key in _TYPE_ALIAS_CANON:
        return _TYPE_ALIAS_CANON[key]
    if key in _TYPE_ALIASES:
        return _TYPE_ALIASES[key]

    #      只在前三级都没命中时才走，且索引已剔除撞车键 ⇒ 不会覆盖已有的正确映射。
    key_ns = re.sub(r"\s+", "", key)
    if key_ns in _TYPE_ALIAS_NOSPACE:
        return _TYPE_ALIAS_NOSPACE[key_ns]

    # 4) 关键词族判定（组合型标签兜底）
    for canon, needles in _FAMILY_KEYWORDS:
        for n in needles:
            if n in key:
                return canon

    # 5) 原样返回：不臆造族名。至少要剥掉通用降级前缀，避免「基础设施层-xxx」与「xxx」
    #    因前缀差异再裂成两个标签（这是本轮噪声的主因之一）。
    return _PREFIX_RE.sub("", v).strip()


# source 维度同样存在同义重复，复用同一归一函数（source 取值与 finding_type 大量重叠）。
normalize_source = normalize_type


def normalize_family(raw: Optional[str]) -> str:
    """族名归一唯一入口。

    分派规则：
    - 业务/差分证明族（bolo/idor/vertical_privesc/...，即 ``canonical_business_logic_family``
      命中 ``DIFFERENTIAL_PROOF_FAMILIES``）→ 走 ``canonical_business_logic_family``（underscore token）。
    - 其余（注入/暴露/配置等技术族）→ 走 ``normalize_type``（已统一下划线规范名）。

    全项目所有「族名归一」必须调用本函数，禁止各处再自写归一或并保留第二套技术族别名表
    （旧 ``exploit_spec.canonical_family`` 已改为委托本函数）。
    """
    if not raw:
        return ""
    if is_business_logic_family(raw):
        return canonical_business_logic_family(raw)
    return normalize_type(raw)


# 任何族名经 normalize_family 后不在此集合内的，视为幻觉族/未知族：
# - attack_plan 生成时直接过滤（不进计划，不再膨胀 FP 分母）；
# - 分级输出中归入 suspicious 档而非 confirmed 档。
# 集合内容 = _FAMILY_KEYWORDS 的全部规范键 + _TYPE_ALIASES 的全部规范值 + 业务差分族
# 。
def _collect_canonical_families() -> frozenset:
    fams = {canon for canon, _ in _FAMILY_KEYWORDS}
    fams.update(_TYPE_ALIASES.values())
    fams.discard("")
    try:
        from src.core.exploit_spec import DIFFERENTIAL_PROOF_FAMILIES
        fams.update(DIFFERENTIAL_PROOF_FAMILIES)
    except Exception:  # pragma: no cover - exploit_spec 不可用时降级为纯技术族表
        pass
    return frozenset(fams)


KNOWN_CANONICAL_FAMILIES = _collect_canonical_families()


def is_known_family(raw: str) -> bool:
    """族名经归一后是否属于已知规范族（AP 幻觉族过滤的唯一判据）。"""
    if not raw:
        return False
    return normalize_family(raw) in KNOWN_CANONICAL_FAMILIES


# ============================================================================
#
# 为什么需要这一层：族名有两个上游来源，**两个都会错**，且归一表救不了错误的概念判定：
#   ① trigger_spec_registry 取 `payload_family or type`，而 payload_family 是 A2 自由文本产出、
#      没有任何归一表兜底。实测 /urlRedirect/* 的 finding.type 明明是对的 url_redirect，
#      却被 payload_family=ssrf 覆盖（优先级更高）→ spec.family=ssrf。
#   ② finding.type 本身也会错：/crlf/safecode 被判成「注入类-命令注入」(command_execution)、
#      /url/vuln/url_bypass 被判成 path_traversal。
# 单靠扩别名表修不了①（输入是错的概念，不是同一概念的另一种写法），所以补一层「按确定性证据
# 纠正」：路由 token / 源文件名 / sink API 是**客观事实**，不依赖 LLM 判断。
#
# 设计约束（务必遵守）：
#   - 只做「有确定证据」的纠正，规则针必须**强特异性**（crlf / urlredirect / url_bypass / jsonp
#     这类唯一归属 token），不得用 url、path、exec、inject 这类会跨族命中的泛词。
#   - 只改 spec 落库的 family 字段；**绝不参与 vuln_hash 计算**（调用点必须在 vhash 之后），
#     否则会让 spec 与 finding 的哈希绑定断裂。
#   - 纠正不静默：返回值带 original / rule / evidence，落库进 raw_json 供审计与回滚。
# ============================================================================

# (规范族名, 路由或文件名针, sink API 针, 可覆盖族集合[, 文件针可独立生效])
# 命中规则：路由/文件名针 命中 route（或 file）→ 命中；否则再看 sink API 针是否命中 sink。
#
# 第 5 项 file_dedicated（可选，缺省 False）：允许「文件名针」在**没有 route** 时独立生效。
# 仅授予「该文件是被测漏洞专用、文件内不存在他族真实漏洞」的规则——CRLF / URLRedirect 属此类，
# 且其可覆盖集合不含 xss，故 URLRedirect.java:88 的 getWriter 真实 XSS 不会被抢走（有测试锁定）。
# URLWhiteList.java 内确有他族漏洞且其可覆盖集合含 xss，故**不授予**，仍需 route 佐证。
#
# 回放）：早期版本把多数规则设成无条件覆盖，结果把**本来正确**的族名改窄，基准反而丢 5 类
# （/shiro/deserialize、/fastjson/deserialize、/xstream 的 family=deserialization 被改成 shiro/
# fastjson/xstream，而 JAVA_SEC_CODE 的族 token 恰恰是粗粒度的 deserial；/log4j 的 jndi_injection
# 被改成 log4j；/ssti/velocity 的 template-injection 被改成 ssti）。
# 更糟的一例：针 "xstream" 会命中文件名 **xlsxstreamerxxe.java**（子串），把 XXE 改成 XStream——
# 纯属误伤。故：
#   ① 只保留「有实测漂移证据、且证据针不会跨族误命中」的规则；其余一律不加。
#   ② 每条都必须给可覆盖集合，绝不用「无条件覆盖」。
#   ③ 纠正只会**放宽**到规范族 token 或修正到明确错族；不得把正确族名改窄。
_EVIDENCE_FAMILY_RULES: Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...], Optional[Tuple[str, ...]], ...], ...] = (
    ("crlf_injection", ("crlf", "crlfinjection"), (),
     ("command_execution", "command-injection", "command-execution", "xss", "generic", ""), True),
    # finding 16926/16927 实测），故**可覆盖集合刻意不含 xss** —— 文件针即便独立生效也抢不走它。
    # （findings 常无 route）的 URLWhiteList.java 全族卡在 path_traversal 纠不回来
    # —— 族名误归因「本体」在 spec 侧已修、findings 侧未修的正是这一条。
    # 现移除 xss 并授予 file_dedicated，xss 由「不在可覆盖集合内」这一屏障保护，两全。
    ("url_whitelist_bypass", ("url_bypass", "urlwhitelist", "url_whitelist"), (),
     ("ssrf", "path_traversal", "information-leak", "information-leakage", "generic", ""), True),
    # 可覆盖集合不含 xss → 即便文件针独立生效，URLRedirect.java:88 的真实 XSS 也不会被抢走。
    ("url_redirect", ("urlredirect", "url_redirect", "openredirect", "open_redirect"), (),
     ("ssrf", "path_traversal", "generic", ""), True),
    # 同类漂移的高发族（路由 token 就是类名，且当前族明显不相干；各自给紧集合）
    ("jsonp_referer", ("jsonp",), (),
     ("xss", "csrf", "deserialization", "path_traversal", "url_redirect",
      "unauthorized-access", "未授权接口泄露", "generic", "")),
    ("ssrf", ("ssrf", "dnsrebind", "openstream"), (),
     ("command_execution", "command-injection", "command-execution", "generic", "")),
    ("sql_injection", ("/jdbc", "/sqli"), (), ("generic", "idor", "")),
    ("spel_injection", ("/spel",), (), ("command_execution", "command-injection", "command-execution", "")),
    # sink API 证据（唯一诊断性 API，才允许单靠它纠正）
    ("url_redirect", (), ("sendredirect",), ("ssrf", "path_traversal", "generic", "")),
    # 端点（/black_path 仅出现在正则与 denyAll 规则里），spec 生成阶段合成 /black_path 路由后，
    # 用路由针 "black_path" 把被 A2 误标为 path_traversal / config-security 的族纠正回 auth_bypass，
    # 使其对账进 CVE 黄金项并可被 D1/D2 用 %0a 换行负载做真实运行时证明（200 vs 403）。
    ("auth_bypass", ("black_path", "cve-2022-22978"), (),
     ("config-security", "path_traversal", "security-misconfiguration",
      "cve-2022-22978", "broken-access-control", "generic", "")),
)

# 这类值**不携带任何概念信息**，因此一旦有确定性证据（路由/文件/sink）命中，一律允许被纠正——
# 不受各规则「可覆盖族集合」限制。否则会出现「证据明明命中 /jsonp，族名却停在 none」的死角，
# 注意：只含真正的「空值」，绝不含 xss/ssrf 等真实族名（真实族名仍需走可覆盖集合把关）。
_PLACEHOLDER_FAMILIES = frozenset({"none", "unknown", "n/a", "na", "null", "other"})


def correct_family_by_evidence(
    family: Optional[str],
    *,
    route: str = "",
    file: str = "",
    sink: str = "",
    allow_file_without_route: bool = False,
) -> Dict[str, str]:
    """按「路由 / 源文件名 / sink API」这类确定性证据纠正族名。

    返回 ``{"family", "original", "corrected", "rule", "evidence"}``：
    - ``family``：纠正后的族名（无证据或不需纠正时原样返回归一后的输入）。
    - ``corrected``：``"1"`` / ``"0"``（字符串，便于直接落进 raw_json）。
    - ``rule`` / ``evidence``：命中的规则与证据片段，供审计。

    行为约定：
    - 证据规则**按表顺序**首命中生效。
    - 命中后还要过第 4 项「可覆盖族集合」：``None`` = 无条件覆盖（路由 token 即类名）；
      显式集合 = 仅当当前族名在该集合内（含空串）才覆盖，否则保留 LLM 判断。
    - 无任何证据命中 → 原样返回（绝不猜）。
    - 输入为空 → 返回空族与 ``corrected="0"``（不臆造族名）。
    """
    original = normalize_family(family)
    out = {"family": original, "original": original, "corrected": "0", "rule": "", "evidence": ""}
    if not original:
        return out
    hay_route = str(route or "").lower()
    has_route = bool(hay_route.strip())
    # 文件名只取 basename，避免目录名（如 /sdl/SAVR/src/... 里的词）误命中。
    hay_file = str(file or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
    hay_sink = str(sink or "").lower()
    # 本函数的路由针/文件名针全部是「漏洞词出现在路由或文件名里」这一假设，
    # 而真实业务的路由是 /api/v1/order/detail、文件是 OrderServiceImpl.java，
    # 假设直接失效 ⇒ 族判定退回 LLM 自由文本。置 SAST_AI_NAME_PRIOR=0 关掉名字针，
    # 只保留 sink API 针（那是语义证据，不是命名巧合），用于量化「靠名字猜」占多少。
    _name_prior = str(os.environ.get("SAST_AI_NAME_PRIOR", "1")).strip().lower() not in (
        "0", "false", "no", "off")
    for rule in _EVIDENCE_FAMILY_RULES:
        canon, route_needles, api_needles, overrideable = rule[0], rule[1], rule[2], rule[3]
        # 第 5 项 file_dedicated：该规则的文件名针可否在无 route 时独立生效（见规则表注释）。
        file_dedicated = bool(rule[4]) if len(rule) > 4 else False
        hit = ""
        for n in route_needles if _name_prior else ():
            if n in hay_route:
                hit = f"route~{n}({route})"
                break
            # 文件名默认只作为**补充**证据：要求该 finding 已绑定入口（有 route），
            # 否则纯文件命中会把「同文件里另一类漏洞」也一起改族（实测 URLRedirect.java:88
            # 的 getWriter 更像 XSS，不该被 url_redirect 抢走）。
            # 例外：调用方显式开启 allow_file_without_route 且该规则被授予 file_dedicated
            # （findings 落库场景常无 route，只能靠文件名定位，故按需放开）。
            if (has_route or (allow_file_without_route and file_dedicated)) and n in hay_file:
                hit = f"file~{n}({hay_file})"
                break
        if not hit:
            for n in api_needles:
                if n and n in hay_sink:
                    hit = f"sink~{n}({sink})"
                    break
        if not hit:
            continue
        if canon == original:
            # 证据与当前族名一致：确认无误，不记为「纠正」（避免制造无意义的 diff）。
            # 注意此判断必须在「可覆盖集合」之前——一致是「证据覆盖率」统计的事实，
            # 与是否允许覆盖无关。
            out["rule"] = canon
            out["evidence"] = hit
            return out
        # 占位族名（none/unknown/...）不携带概念信息，有确定性证据时一律放行纠正。
        if overrideable is not None and original not in overrideable and original not in _PLACEHOLDER_FAMILIES:
            continue
        out.update({"family": canon, "corrected": "1", "rule": canon, "evidence": hit})
        return out
    return out
