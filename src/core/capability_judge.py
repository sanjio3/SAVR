"""安全能力识别：从代码里认出「这段涉及哪种安全能力」，而不是相信族标签。

## 为什么需要（族标错的通用解法）

族标签是 A1/A2 打上去的，**会标错**。实测同一条用例会被打出多个族
错的那部分没有任何判据能剔除 —— 于是用户看到「越权访问」去查 IDOR，
真实问题却是弱随机数。这会直接误导处置决策。

族分类是上游整体能力，短轮次改不动。但**裁决这一层可以不依赖族标签**：

    不看「这条被标成了什么族」，看「这段代码到底动了哪种安全能力」。

    随机数能力  → SecureRandom / ThreadLocalRandom / UUID / Math.random / new Random
    哈希能力    → MessageDigest / DigestUtils / md5Hex / SHA-*
    加密能力    → Cipher.getInstance / KeyGenerator / Mac
    输出编码能力 → ESAPI.encoder / Encode.for* / HtmlUtils / escapeHtml
    SQL 执行能力 → executeQuery / PreparedStatement / Statement
    Cookie 标志 → setSecure / setHttpOnly
    Session 写入 → getSession.setAttribute / putValue
    文件 / 路径  → new File / Paths.get / FileInputStream
    命令执行     → Runtime.exec / ProcessBuilder
    XML 解析     → DocumentBuilderFactory / SAXParser / XMLInputFactory
    LDAP 查询    → InitialDirContext / search(
    XPath 求值   → XPathFactory / xpath.evaluate
    反序列化     → readObject / XStream.fromXML / ObjectInputStream
    出网请求     → openConnection / HttpClient / RestTemplate

每种能力各自带「安全证据」与「危险信号」两组判据，全部来自 **Java 安全 API 的
通用语义**，与被测的是哪个项目、哪个基准无关。

## 用法一：抑制前的能力否决（族标错的止损）

    from src.core.capability_judge import danger_capabilities
    if danger_capabilities(window):
        ...  # 代码里有别的实锤危险信号，本条不许抑制

而输出处确实写了 `ESAPI.encoder.encodeForHTML(str)` —— 单看 xss 语义，
「输出已编码」的判定完全正确，错的是族标签。能力否决让裁决不再被错误标签牵着走。
这一层取代了原来写死在 safe_verdict 里的 `_CROSS_FAMILY_VETO`（只认 xss 一个族）。

## 用法二：族标签自洽校验（族标错的纠正）

    from src.core.capability_judge import capability_family_of, supports
    if not supports(family, window):
        hint = capability_family_of(window)   # 代码证据真正指向的族

族标签与窗口里的能力完全对不上时（标 xss 但窗口里既没有输出 API 也没有编码 API），
说明标签不可信，应该用能力证据给出的族去纠正展示。
"""
from __future__ import annotations

import logging
import re
from typing import Dict, FrozenSet, List, Tuple

logger = logging.getLogger("capability_judge")

Rule = Tuple[str, Tuple[str, ...], Tuple[str, ...]]


class Capability:
    """一种安全能力：怎么认出它、什么算安全、什么算实锤危险。"""

    __slots__ = ("name", "present", "safe", "danger", "family", "always_danger")

    def __init__(self, name: str, present: Tuple[str, ...],
                 safe: Tuple[str, ...] = (), danger: Tuple[str, ...] = (),
                 family: str = "", always_danger: bool = False) -> None:
        self.name = name
        self.present = present
        self.safe = safe
        self.danger = danger
        self.family = family or name
        self.always_danger = always_danger

    def detected(self, text: str) -> bool:
        return _any(self.present, text)

    def is_safe(self, text: str) -> bool:
        return bool(self.safe) and _any(self.safe, text) and not _any(self.danger, text)

    def is_danger(self, text: str) -> bool:
        if self.always_danger:
            return self.detected(text)
        if not self.detected(text) or not self.danger:
            return False
        if self.danger == ("__session_write_tainted__",):
            return _session_write_tainted(text)
        return _any(self.danger, text)


# ── Session 写入的污点判定（数据流太重，这里做两层赋值闭包，够用且保守）──
_EXT_API_INLINE = (
    r"getParameter\s*\(", r"getParameterValues\s*\(", r"getHeader\w*\s*\(",
    r"getCookies\s*\(", r"getQueryString\s*\(", r"getInputStream\s*\(", r"getReader\s*\(",
)
_SESSION_WRITE = re.compile(
    r"getSession\s*\(\s*\)\s*\.\s*(?:setAttribute|putValue|put)\s*\(([^;]{0,300})", re.IGNORECASE)
# 赋值语句的 LHS 变量名：`String param = ...` / `Cookie[] cookies = ...` / `param = ...`
_ASSIGN_LHS = re.compile(r"^\s*(?:[\w.<>\[\],\s]*?\s+)?([A-Za-z_]\w*)\s*=(?!=)")
# 语句级粗切：分号与花括号。跨行赋值（OWASP 里很常见）不会被切开。
_STMT_SPLIT = re.compile(r"[;{}]")


def _tainted_vars(text: str) -> FrozenSet[str]:
    """从外部输入 API 出发，做两层赋值闭包，算出「值可能被攻击者控制」的变量集。

    为什么按**语句**切而不是用 `[^;]{0,N}` 正则硬凑：后者里 `[^;]` 会跨换行，
    正则会在整个文件里游走，把 `java` / `If` / `javax` 这种词也当成被赋值的变量
    359 条 weak_random 抑制被无意义地全部否决）。
    """
    if not text:
        return frozenset()
    stmts = _STMT_SPLIT.split(text)
    tainted: set = set()
    for st in stmts:
        if not _any(_EXT_API_INLINE, st):
            continue
        m = _ASSIGN_LHS.match(st)
        if m:
            tainted.add(m.group(1))
    # 两层赋值闭包：param(污) → bar = param → bar(污)
    for _ in range(2):
        added = False
        for st in stmts:
            m = _ASSIGN_LHS.match(st)
            if not m:
                continue
            lhs = m.group(1)
            if lhs in tainted:
                continue
            rhs = st[m.end():]
            if set(re.findall(r"\b([A-Za-z_]\w*)\b", rhs)) & tainted:
                tainted.add(lhs)
                added = True
        if not added:
            break
    return frozenset(tainted)


def _session_write_tainted(text: str) -> bool:
    """写进 Session 的值是否来自外部输入。

        FP: request.getSession.setAttribute(cookieName, rememberMeKey);
            rememberMeKey = SecureRandom 生成  ⇒ 不否决（该 weak_random 抑制生效）
        TP: request.getSession.putValue(bar, "10340");
            bar 来自 request header          ⇒ 否决（保住 trust_boundary 真漏洞）
    """
    if not text:
        return False
    tainted = _tainted_vars(text)
    if not tainted:
        return False
    for m in _SESSION_WRITE.finditer(text):
        args = m.group(1)
        if _any(_EXT_API_INLINE, args):
            return True
        if set(re.findall(r"\b([A-Za-z_]\w*)\b", args)) & tainted:
            return True
    return False


def _any(pats: Tuple[str, ...], text: str) -> bool:
    if not text or not pats:
        return False
    for p in pats:
        try:
            if re.search(p, text, re.IGNORECASE):
                return True
        except re.error:  # pragma: no cover
            continue
    return False


# ── 能力表（判据全部是 Java 安全 API 通用语义，不含任何项目/基准特定符号）──
CAPABILITIES: Dict[str, Capability] = {
    "rng": Capability(
        "rng",
        present=(r"SecureRandom", r"ThreadLocalRandom", r"UUID\s*\.\s*randomUUID",
                 r"Math\s*\.\s*random\s*\(", r"new\s+Random\s*\(", r"\.nextInt\s*\(",
                 r"Random\s*\.\s*nextInt"),
        safe=(r"SecureRandom", r"ThreadLocalRandom", r"UUID\s*\.\s*randomUUID",
              r"Mac\s*\.\s*getInstance"),
        danger=(r"Math\s*\.\s*random\s*\(", r"new\s+(?!Secure)Random\s*\("),
        family="weak_random"),
    "hash": Capability(
        "hash",
        present=(r"MessageDigest", r"DigestUtils", r"md5Hex", r"sha1Hex", r"sha256Hex",
                 r"\bMD5\b", r"\bMD4\b", r"SHA-?1\b", r"SHA-?256\b", r"SHA-?512\b"),
        safe=(r"SHA-?(?:256|384|512)", r"SHA-?3\b", r"PBKDF2", r"bcrypt", r"scrypt",
              r"Argon2", r"sha256Hex"),
        danger=(r"\bMD5\b", r"\bMD4\b", r"SHA-?1\b", r"md5Hex", r"sha1Hex"),
        family="weak_hash"),
    "cipher": Capability(
        "cipher",
        present=(r"Cipher\s*\.\s*getInstance", r"KeyGenerator", r"Mac\s*\.\s*getInstance",
                 r"SecretKeySpec", r"Cipher\s*\.\s*(?:ENCRYPT|DECRYPT)_MODE"),
        safe=(r"AES\s*/\s*(?:GCM|CBC)", r"\bGCM\b", r"ChaCha20", r"PBKDF2",
              r"PBEWITH", r"SHA-?(?:256|512)"),
        danger=(r"\bDES\b", r"DESede", r"\bRC4\b", r"ARC4", r"Blowfish",
                r"\bECB\b", r"\bMD5\b"),
        family="weak_crypto"),
    "output_encoding": Capability(
        "output_encoding",
        present=(r"ESAPI\s*\.\s*encoder", r"encodeFor\w+", r"Encode\s*\.\s*for\w+",
                 r"HtmlUtils\s*\.\s*htmlEscape", r"escapeHtml\w*", r"StringEscapeUtils",
                 r"URLEncoder\s*\.\s*encode", r"getWriter\s*\(\s*\)", r"\.print\w*\s*\("),
        safe=(r"ESAPI\s*\.\s*encoder", r"encodeFor\w+", r"Encode\s*\.\s*for\w+",
              r"HtmlUtils\s*\.\s*htmlEscape", r"escapeHtml\w*", r"StringEscapeUtils"),
        danger=(),
        family="xss"),
    # 注意：sql_exec / file_path / cmd_exec / xpath / ldap / http_fetch 这几项**刻意不设**
    # danger —— 「字符串拼进了 sink」不是实锤配置错误，它恰恰是绝大多数用例的正常形态，
    # 否决只认「明确写错的安全配置」：setSecure(false)、DES、Math.random、MD5……
    "sql_exec": Capability(
        "sql_exec",
        present=(r"executeQuery", r"executeUpdate", r"\.execute\s*\(", r"createStatement",
                 r"PreparedStatement", r"prepareStatement", r"prepareCall"),
        safe=(r"PreparedStatement", r"prepareStatement"),
        danger=(),
        family="sql_injection"),
    "cookie_flag": Capability(
        "cookie_flag",
        present=(r"setSecure\s*\(", r"setHttpOnly\s*\(", r"new\s+Cookie\s*\(",
                 r"addCookie\s*\("),
        safe=(r"setSecure\s*\(\s*true\s*\)", r"setHttpOnly\s*\(\s*true\s*\)"),
        danger=(r"setSecure\s*\(\s*false\s*\)", r"setHttpOnly\s*\(\s*false\s*\)"),
        family="secure_cookie"),
    # 外部数据写进 HttpSession：trust_boundary。
    # **刻意不设 always_danger**：真实项目里 `session.setAttribute("k", 安全随机值)`
    # 是再正常不过的写法，出现即判危险会把 359 条 weak_random 抑制全部否决掉
    # 时才算实锤：那一刻写进去的值确实可能被攻击者控制。
    "session_write": Capability(
        "session_write",
        present=(r"getSession\s*\(\s*\)\s*\.\s*(?:setAttribute|putValue|put)\s*\(",
                 r"request\s*\.\s*getSession\s*\(\s*\)\s*\.\s*(?:setAttribute|putValue)\s*\("),
        safe=(),
        # 判据：写进 session 的**值**来自外部输入（见 _session_write_tainted）
        danger=(r"__session_write_tainted__",),
        family="trust_boundary_violation"),
    "file_path": Capability(
        "file_path",
        present=(r"new\s+File\s*\(", r"Paths\s*\.\s*get", r"FileInputStream",
                 r"FileOutputStream", r"new\s+RandomAccessFile", r"Files\s*\.\s*(?:read|write)"),
        safe=(r"getCanonicalPath\s*\(\s*\)", r"startsWith\s*\(\s*\w*(?:ROOT|BASE|base|root)\w*"),
        danger=(),
        family="path_traversal"),
    "cmd_exec": Capability(
        "cmd_exec",
        present=(r"Runtime\s*\.\s*getRuntime", r"ProcessBuilder", r"\.exec\s*\("),
        safe=(r"ALLOWED_", r"allowed_", r"whitelist", r"allowlist", r"isLetterOrDigit"),
        danger=(),
        family="command_execution"),
    "xml_parse": Capability(
        "xml_parse",
        present=(r"DocumentBuilderFactory", r"SAXParserFactory", r"XMLInputFactory",
                 r"XMLStreamReader", r"SAXReader", r"XmlUtils", r"TransformerFactory"),
        safe=(r"disallow-doctype-decl", r"setExpandEntityReferences\s*\(\s*false\s*\)",
              r"FEATURE_SECURE_PROCESSING", r"IS_SUPPORTING_EXTERNAL_ENTITIES",
              r"setFeature\s*\("),
        danger=(r"setExpandEntityReferences\s*\(\s*true\s*\)",
                r"IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*true"),
        family="xxe"),
    "ldap": Capability(
        "ldap",
        present=(r"InitialDirContext", r"DirContext", r"\.search\s*\(", r"SearchControls"),
        safe=(r"escapeLDAPSearchFilter", r"filter\s*=\s*\"[^\"\+]*\"\s*;"),
        danger=(),
        family="ldap_injection"),
    "xpath": Capability(
        "xpath",
        present=(r"XPathFactory", r"xpath\s*\.\s*evaluate", r"XPathExpression",
                 r"javax\s*\.\s*xml\s*\.\s*xpath"),
        safe=(r"compile\s*\(\s*\"[^\"\+]*\"\s*\)"),
        danger=(),
        family="xpathi"),
    "deserialize": Capability(
        "deserialize",
        present=(r"readObject\s*\(", r"ObjectInputStream", r"fromXML\s*\(",
                 r"XStream", r"readValue\s*\(", r"JSON\s*\.\s*parse", r"enableDefaultTyping"),
        safe=(),
        danger=(r"readObject\s*\(", r"fromXML\s*\(", r"enableDefaultTyping"),
        family="deserialization", always_danger=True),
    "http_fetch": Capability(
        "http_fetch",
        present=(r"openConnection\s*\(", r"new\s+URL\s*\(", r"HttpClient",
                 r"RestTemplate", r"HttpURLConnection", r"\.execute\s*\(\s*\)"),
        safe=(r"ALLOWED_HOSTS", r"allowlist", r"whitelist", r"InetAddress\s*\.\s*getByName"),
        danger=(),
        family="ssrf"),
}

# 族 → 支持它的能力（做族标签自洽校验用）
_FAMILY_TO_CAPS: Dict[str, Tuple[str, ...]] = {}
for _name, _cap in CAPABILITIES.items():
    _FAMILY_TO_CAPS.setdefault(_cap.family, ())
    _FAMILY_TO_CAPS[_cap.family] = tuple(_FAMILY_TO_CAPS[_cap.family]) + (_name,)

# 族的别名 → 规范族，做自洽校验时先归一
_FAMILY_ALIAS: Dict[str, str] = {
    "sqli": "sql_injection",
    "cmdi": "command_execution",
    "ldapi": "ldap_injection",
    "xpath_injection": "xpathi",
    "template-injection": "ssti",
    "trust_boundary": "trust_boundary_violation",
    "cookie": "secure_cookie",
}


def _norm_family(family: str) -> str:
    f = (family or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _FAMILY_ALIAS.get(f, f)


def capabilities_in(text: str) -> List[str]:
    """窗口里出现了哪些安全能力（按能力表顺序，稳定可审计）。"""
    if not text:
        return []
    return [name for name, cap in CAPABILITIES.items() if cap.detected(text)]


def danger_capabilities(text: str, skip: FrozenSet[str] = frozenset(),
                        skip_family: str = "") -> List[str]:
    """窗口里有**实锤危险信号**的能力名。

    skip：显式要跳过的能力名（已由抑制规则自己处理掉的）。
    skip_family：跳过「对应的族就是本条 spec 的族」的能力 —— 那种危险信号
    抑制规则自己已经判过了（例如 strong_rng_only 的 deny 就含 Math.random），
    再拿来否决等于同一条判据用两次。
    """
    if not text:
        return []
    fam = _norm_family(skip_family)
    out = []
    for name, cap in CAPABILITIES.items():
        if name in skip:
            continue
        if fam and _norm_family(cap.family) == fam:
            continue
        if cap.is_danger(text):
            out.append(name)
    return out


def safe_capabilities(text: str) -> List[str]:
    if not text:
        return []
    return [name for name, cap in CAPABILITIES.items() if cap.is_safe(text)]


def supports(family: str, text: str) -> bool:
    """族标签在窗口里有没有能力证据支撑。没有 ⇒ 标签不可信。"""
    if not text or not family:
        return False
    fam = _norm_family(family)
    caps = _FAMILY_TO_CAPS.get(fam) or ()
    if not caps:
        # 没登记能力的族（broken_access_control / business_logic 等）不做自洽校验：
        # 这类族本来就靠语义推断，没有稳定的 API 指纹，校验只会制造噪声。
        return True
    return any(CAPABILITIES[c].detected(text) for c in caps)


# 能力优先级：**越"到处都有"的能力排越后**。
# 一个 servlet 类几乎必然出现 getWriter/print（输出能力），但它说明不了任何问题；
# 而 Cipher.getInstance / MessageDigest / SecureRandom 这些是强特异性 API 签名。
# 按「字典顺序取第一个」的初版把 1774 个用例一律判成 xss（含全部 sqli 真漏洞），
# 就是因为这个优先级排反了。
# 逻辑），几乎必然出现，特异性极低 —— 原先排在高位，把它们一律当成 secure_cookie /
# trust_boundary，是 capability_family 系统性塌缩（34/35 静态侧缺少是族判错）的主因。
# 故把这两个「横切样板」能力压到**最低优先级**，只在「确实没有任何其他能力」时才判它们。
_PRIORITY: Tuple[str, ...] = (
    "rng", "hash", "cipher", "xml_parse", "deserialize", "ldap", "xpath",
    "cmd_exec", "http_fetch", "sql_exec", "file_path", "output_encoding",
    "cookie_flag", "session_write",
)


def capability_family_of(text: str) -> Tuple[str, List[str]]:
    """窗口的能力证据真正指向哪个族。

    返回 (族, 命中的能力名列表)。判据：
      1. 有**实锤危险信号**的能力优先 —— 那才是真实问题；
      2. 否则按 `_PRIORITY`（特异性从高到低）取第一个被认出的能力；
      3. 一种能力都没认出 → 返回 ("", [])，不给结论。
    """
    if not text:
        return "", []
    danger = danger_capabilities(text)
    if danger:
        return CAPABILITIES[danger[0]].family, danger
    caps = set(capabilities_in(text))
    for name in _PRIORITY:
        if name in caps:
            return CAPABILITIES[name].family, [name]
    return "", []
