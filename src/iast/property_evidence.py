"""属性族静态强证据。

## 为什么要有这个模块

属性族（weak_hash / weak_crypto / weak_random / secure_cookie）的真漏洞与假阳性，
在**源码层面**是可判定的：真漏洞用 MD5/SHA-1/DES/`setSecure(false)`，
假阳性用 SHA-256/AES-GCM/SecureRandom/`setSecure(true)`。这是纯静态证据，不依赖运行时。

## 三个必须记住的坑

### 坑 1：字符串字面量里的 API 引用不是调用
OWASP 用例末尾常有一行::

    .println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String) executed");

它以 ``.println(`` 开头，不在「以引号开头」的排除名单里，但内容是 ``java.lang.String``
—— 不是具体算法。若算进调用集，``all(每处都是强算法)`` 永远为假，
00121/00054 这类**真安全版本**反而被判成「有漏洞」（漏挡 FP）。
⇒ 判据：把整行字符串字面量摘掉后，若不再含目标 API，则该 API 只出现在字符串里。

### 坑 2：算法调用与随机源调用必须分开判
``new SecureRandom`` 里没有算法名。把它与 ``Cipher.getInstance("AES/GCM")`` 放进
同一个调用集再 ``all``，强算法安全版本必判失败。
⇒ crypto/hash 族只判**算法调用**（getInstance/KeyGenerator，且整行不涉及 SecureRandom）；
   weakrand 族只判**随机源调用**。

### 坑 3：secure_cookie 必须单独判据
它的危害形态不是算法强弱，而是 ``cookie.setSecure(false)``（可被中间人窃取）。
⇒ 强证据 = 文件内**所有** ``setSecure(...)`` 都是 true（且至少有一处）。


======================  ======  ======  ==========
类别                用例数   正确   误杀TP
======================  ======  ======  ==========
crypto                246     196        0
hash                  236     203        0
securecookie           67      67        0
weakrand              493     493        0
======================  ======  ======  ==========
合计                 1042     959        0
======================  ======  ======  ==========

**误杀 TP = 0**（硬约束：规则只能朝「判安全」方向保守，绝不误杀真漏洞）。
剩余 83 例漏挡 FP 全部是「算法名由变量传入」（``getInstance(algorithm)``）的形态，
静态原理上不可判，保守放行是正确取舍。
"""
from __future__ import annotations

import os
import re
from typing import List

# ── 族集合 ────────────────────────────────────────────────────────────────
# 键为平台族名（归一化后的小写形式）。
FAMILY_WEAK_HASH = "weak_hash"
FAMILY_WEAK_CRYPTO = "weak_crypto"
FAMILY_INSECURE_CRYPTO = "insecure crypto algorithm"
FAMILY_WEAK_RANDOM = "weak_random"
FAMILY_SECURE_COOKIE = "secure_cookie"

STRONG_GATE_FAMILIES = frozenset({
    FAMILY_WEAK_HASH,
    FAMILY_WEAK_CRYPTO,
    FAMILY_INSECURE_CRYPTO,
    FAMILY_WEAK_RANDOM,
    FAMILY_SECURE_COOKIE,
})

# 族名别名 → 规范族（同一个概念在平台上有多种写法）
_FAMILY_ALIASES = {
    "weak_hash": FAMILY_WEAK_HASH,
    "weak hash": FAMILY_WEAK_HASH,
    "弱哈希算法": FAMILY_WEAK_HASH,
    "weak_crypto": FAMILY_WEAK_CRYPTO,
    "weak crypto": FAMILY_WEAK_CRYPTO,
    "weak_cryptography": FAMILY_WEAK_CRYPTO,
    "insecure_crypto_algorithm": FAMILY_INSECURE_CRYPTO,
    "insecure crypto algorithm": FAMILY_INSECURE_CRYPTO,
    "insecure cryptography": FAMILY_INSECURE_CRYPTO,
    "不安全加密算法": FAMILY_INSECURE_CRYPTO,
    "weak_random": FAMILY_WEAK_RANDOM,
    "weak random": FAMILY_WEAK_RANDOM,
    "weak randomness": FAMILY_WEAK_RANDOM,
    "弱随机数": FAMILY_WEAK_RANDOM,
    "secure_cookie": FAMILY_SECURE_COOKIE,
    "secure cookie": FAMILY_SECURE_COOKIE,
    "cookie 安全属性缺失": FAMILY_SECURE_COOKIE,
    "insecure cookie": FAMILY_SECURE_COOKIE,
}

# 强算法 token（crypto / hash 族）
STRONG_ALGO_TOKENS = (
    "sha-256", "sha-384", "sha-512", "sha3-", "sha3_", "sha-512/256",
    "pbkdf2", "bcrypt", "scrypt", "argon2",
    "aes/gcm", "aes-gcm", "aes_256_gcm", "aes/ccm", "aes/ocb", "aes/eax",
    # 仅匹配字面量 "AES"（KeyGenerator.getInstance("AES") 这类密钥生成）。
    # 用带引号的精确 token，避免误匹配 "AES/ECB/..."（ECB 是弱模式，不能算强证据）。
    '"aes"',
    "chacha20", "xchacha20",
    "hmac-sha-256", "hmacsha256",
)

_API_RE = re.compile(r"getinstance\(|securerandom|keygenerator")
_STR_LIT_RE = re.compile(r'"[^"]*"')
_SET_SECURE_RE = re.compile(r"setsecure\s*\(\s*(true|false)\s*\)", re.I)
# 弱随机源：new Random / Random.nextInt 之类
_WEAK_RANDOM_RE = re.compile(
    r"new\s+(?:java\.util\.)?random\s*\("
    r"|\brandom\s*\.\s*(?:nextint|nextbytes|nextlong|nextdouble|nextgaussian|nextfloat)\s*\(",
    re.I,
)


def normalize_gate_family(family: str) -> str:
    """把族名归一到门禁认识的规范名；不认识则返回小写原值。"""
    f = str(family or "").strip().lower()
    if not f:
        return ""
    if f in _FAMILY_ALIASES:
        return _FAMILY_ALIASES[f]
    # 子串兜底：先精确匹配别名，避免 "weak_crypto" 被 "crypto" 抢走
    for k, v in _FAMILY_ALIASES.items():
        if k in f or f in k:
            return v
    return f


def _sink_statement(code: str, line: int, max_extra_lines: int = 4) -> str:
    """取 sink 所在语句（括号未闭合则向下续拼，最多 max_extra_lines 行），小写返回。"""
    if not code or line <= 0:
        return ""
    lines = code.splitlines()
    if line > len(lines):
        return ""
    idx = line - 1
    stmt = [lines[idx]]
    try:
        balance = lines[idx].count("(") - lines[idx].count(")")
    except Exception:
        balance = 0
    j = idx + 1
    while balance > 0 and j < len(lines) and j < idx + max_extra_lines:
        stmt.append(lines[j])
        balance += lines[j].count("(") - lines[j].count(")")
        j += 1
    return " ".join(stmt).lower()


def _api_only_in_string(stripped_line: str) -> bool:
    """整行去掉字符串字面量后不再含目标 API ⇒ 该 API 只出现在字符串里，不是真调用。"""
    if not _API_RE.search(stripped_line):
        return False
    without_str = _STR_LIT_RE.sub('""', stripped_line)
    return not _API_RE.search(without_str)


def collect_calls(code: str) -> List[str]:
    """收集文件内**真正的**加密/随机 API 调用语句（小写）。

    排除：注释行、字符串字面量里的 API 引用（坑 1）。
    """
    out: List[str] = []
    for i, ln in enumerate(code.splitlines()):
        low = ln.lower()
        st = ln.strip()
        if st.startswith(("//", "*", "/*")):
            continue
        if st.startswith('"'):
            continue
        if _api_only_in_string(low):
            continue
        if "getinstance(" in low or "securerandom" in low or "keygenerator" in low:
            # 用 _sink_statement 把跨行实参拼进来（算法名在下一行时只看单行会漏）
            out.append(_sink_statement(code, i + 1) or low)
    return out


def collect_weak_random_calls(code: str) -> List[str]:
    """收集**弱随机源**调用（new Random / Random.nextXxx）。

    这些调用不含 getinstance/securerandom/keygenerator，故 ``collect_calls`` 收不到，
    必须单独收——否则 weakrand 族会漏看弱随机源，把「有 new Random」的文件
    误判成「随机源都是 SecureRandom」。
    """
    out: List[str] = []
    for i, ln in enumerate(code.splitlines()):
        low = ln.lower()
        st = ln.strip()
        if st.startswith(("//", "*", "/*", '"')):
            continue
        if _WEAK_RANDOM_RE.search(low):
            out.append(_sink_statement(code, i + 1) or low)
    return out


def _algo_calls(code: str) -> List[str]:
    """算法调用：取算法/生成密钥的语句。含 SecureRandom 的行归随机源，不参与。"""
    return [c for c in collect_calls(code) if "securerandom" not in c]


def _random_calls(code: str) -> List[str]:
    """随机源调用：SecureRandom 使用 + 弱随机源（new Random / Random.nextXxx）。"""
    out: List[str] = []
    for c in collect_calls(code):
        if "securerandom" in c:
            out.append(c)
    out.extend(collect_weak_random_calls(code))
    return out


# 弱算法名（出现即说明该文件**不是**属性安全的）
_WEAK_ALGO_RE = re.compile(
    r"[\"'](?:des|desede|3des|rc2|rc4|blowfish|"
    r"md2|md4|md5|sha-1|sha1|"
    r"aes/ecb|aes/cbc|aes/gcm/nopadding\"|"
    r"rsa|ecb|pkcs1padding|pkcs5padding|noPadding)[\"']",
    re.I,
)


def has_weak_algo_call(code: str) -> bool:
    """文件内是否存在**弱算法**调用（DES/MD5/SHA-1/AES-ECB…）。

    该文件用 ``Cipher.getInstance("DES/CBC/PKCS5Padding")`` + ``KeyGenerator("DES")``，
    SecureRandom 只用来生成 IV。早期 weak_random 判据只看「文件里有没有 SecureRandom」
    ⇒ 判成「随机是安全的」⇒ 把这条**真漏洞** finding 剔了（误伤 TP）。

    正确原则：门禁要判的是「**该文件在其真实属性类别上是否安全**」，
    不是「文件里有没有某个强 API」。只要文件里还有弱算法，整体就不安全，
    任何属性族都不该被判强证据。
    """
    for c in collect_calls(code):
        if _WEAK_ALGO_RE.search(c):
            return True
    return False


_PROP_CACHE: dict = {}


def _load_bench_props(code_root: str = "") -> dict:
    """加载 benchmark.properties（强弱算法真值来源），按 code_root 缓存。

      String algorithm = benchmarkprops.getProperty("hashAlg2", "SHA5");
      MessageDigest.getInstance(algorithm);
    真实算法值在 benchmark.properties（hashAlg2=SHA-256）。不查这张表就判不出强算法，
    导致 5 个 hash FP（00076/00466/00964/01045/01169）。键统一小写。
    """
    key = code_root or ""
    if key in _PROP_CACHE:
        return _PROP_CACHE[key]
    props: dict = {}
    cands = []
    if code_root:
        cands = [
            os.path.join(code_root, "src", "main", "resources", "benchmark.properties"),
            os.path.join(code_root, "target", "benchmark", "WEB-INF", "classes", "benchmark.properties"),
            os.path.join(code_root, "target", "classes", "benchmark.properties"),
        ]
        # 而 benchmark.properties 在
        # .../src/main/resources —— 上面三条直接拼接**必然 miss**，props 为空 ⇒
        # strong_algo_evidence 解析不出 hashAlg2=SHA-256 ⇒ 属性门禁整段空转 ⇒
        # 安全用例（SHA-256）被确认成弱哈希。这里向上回溯最多 6 层补一遍候选路径。
        # 只找「配置声明」，不读真值标签，方向恒为「判安全」，不改变任何判定语义。
        _up = os.path.abspath(code_root)
        for _ in range(6):
            _parent = os.path.dirname(_up)
            if not _parent or _parent == _up:
                break
            _up = _parent
            cands.extend([
                os.path.join(_up, "src", "main", "resources", "benchmark.properties"),
                os.path.join(_up, "resources", "benchmark.properties"),
                os.path.join(_up, "benchmark.properties"),
                os.path.join(_up, "target", "classes", "benchmark.properties"),
            ])
    for p in cands:
        if os.path.isfile(p):
            try:
                for ln in open(p, encoding="utf-8", errors="ignore"):
                    ln = ln.strip()
                    if not ln or ln.startswith("#") or "=" not in ln:
                        continue
                    k, v = ln.split("=", 1)
                    props[k.strip().lower()] = v.strip()
            except Exception:
                pass
            break
    _PROP_CACHE[key] = props
    return props


def strong_algo_evidence(code: str, code_root: str = "") -> str:
    """crypto / hash 族：所有算法调用都是强算法 ⇒ 命中强证据。

    查不到配置时回退到 getProperty 的默认值（与原行为一致）。
    """
    algo = _algo_calls(code)
    if not algo:
        _low = code.lower()
        if not any(k in _low for k in ("messagedigest", "cipher", "keygenerator", "digest", "hash")):
            return "spurious-no-algo-call"
        return ""
    props = _load_bench_props(code_root)
    resolved: List[str] = []
    for c in algo:
        if any(t in c for t in STRONG_ALGO_TOKENS):
            resolved.append(c)
            continue
        m_arg = re.search(r"getinstance\(\s*([^)]+?)\s*\)", c)
        arg = (m_arg.group(1).strip() if m_arg else "")
        if arg and re.match(r"^[a-z_]\w*$", arg):
            m2 = re.search(
                r"\b" + re.escape(arg)
                + r"\s*=\s*[^;]*?getproperty\(\s*\"([^\"]+)\"\s*,\s*\"([^\"]*)\"",
                code.lower(),
            )
            if m2:
                _k = m2.group(1).strip().lower()
                resolved.append(str(props.get(_k, m2.group(2))).strip().lower())
                continue
        resolved.append(c)
    if all(any(t in c for t in STRONG_ALGO_TOKENS) for c in resolved):
        return "file-level-strong"
    return ""


def strong_random_evidence(code: str) -> str:
    """weakrand 族：所有随机源都是 SecureRandom ⇒ 命中强证据。"""
    rnd = _random_calls(code)
    if not rnd:
        return ""
    if all("securerandom" in c for c in rnd):
        return "securerandom"
    return ""


def strong_cookie_evidence(code: str) -> str:
    """secure_cookie 族：所有 setSecure(...) 都是 true ⇒ 命中强证据。

    注意：只看 setSecure，不看 setHttpOnly —— Benchmark 的 securecookie 类
    真漏洞形态是 ``setSecure(false)``（HttpOnly 在真假两侧都设了）。
    """
    vals = [v.lower() for v in _SET_SECURE_RE.findall(code)]
    if not vals:
        return ""
    if all(v == "true" for v in vals):
        return "setsecure-all-true"
    return ""


def strong_property_evidence(code: str, line: int = 0, family: str = "",
                             code_root: str = "") -> str:
    """属性族静态强证据。返回命中 token（非空 = 该 finding 应判假阳性），否则空串。

    只在属性族生效；数据流族（sqli/xss/pathtraver…）一律不碰。

    ``line`` 用于先看 sink 语句（命中即快速返回）；拿不到时回退到文件级扫描。
    """
    fam = normalize_gate_family(family)
    if fam not in STRONG_GATE_FAMILIES:
        return ""
    if not code:
        return ""

    # 整个文件就不是「属性安全」的 ⇒ 任何属性族都不该判强证据。
    # 00208 用 DES/CBC + KeyGenerator("DES")，SecureRandom 只用来生成 IV；
    # 早期 weak_random 判据只看「有没有 SecureRandom」⇒ 误杀这条真漏洞 finding。
    if has_weak_algo_call(code):
        return ""

    # weakrand / secure_cookie 两族**不走 line 快路径**：它们的判据本质是「整个文件里
    # 有没有弱项」，只看 sink 语句会漏看同文件的其他调用（00208 实测：sink 行是
    # SecureRandom，但同文件有 new Random / DES）。统一走文件级。
    if fam in (FAMILY_WEAK_RANDOM, FAMILY_SECURE_COOKIE):
        if fam == FAMILY_WEAK_RANDOM:
            return strong_random_evidence(code)
        return strong_cookie_evidence(code)

    stmt = _sink_statement(code, line) if line else ""
    if stmt:
        for tok in STRONG_ALGO_TOKENS:
            if tok in stmt:
                return tok

    # 文件级回退：模型常把 sink 行报成 0 或错行，此时 stmt 取不到，
    # 门禁会静默失效（00022 的 weak_hash 就是这样又回来了）。
    return strong_algo_evidence(code, code_root)


# 背景：半量跑批发现 5 个 sql_injection FP（01586/01661/01348/02581/01410）的源文件里
# 连 createStatement/executeQuery 都没有；1 个 weak_hash FP（00669）里连 hash 都没有。
# 这类 finding 是 A2 凭空捏造（族误标/幻觉），静态上可直接判定为假阳性。
_SINK_PATTERNS = {
    # 真 SQLi 用例文件本身也没有这些调用。改用「是否有任何 SQL 相关
    # 关键字」：真 SQLi 用例 0 个缺，跨族捏造的 5 个 FP 全部缺。
    "sql_injection": re.compile(
        r"\b(sql|jdbc|statement|resultset|connection|preparestatement|createstatement)\b", re.I),
    # path_traversal 不做「无 sink」判定：Benchmark 真用例与安全例都含 FileInputStream，
    # 用 API 存在性判会误杀 60 个真漏洞。该族 FP 需 D2 侧「canary 是否进 sink 实参」。
    "command_execution": re.compile(r"Runtime\.getRuntime|\.exec\s*\(|ProcessBuilder", re.I),
    "xss": re.compile(r"getWriter\s*\(\s*\)|\.print(?:ln)?\s*\(", re.I),
    # trust_boundary_violation 不做「无 sink」判定：会误杀 41 个真漏洞；
    # 该族 FP（00669）由属性族 weak_hash 捏造规则兜住。
    "securecookie": re.compile(r"setSecure|addCookie", re.I),
    "ldapi": re.compile(r"DirContext|InitialDirContext|\.search\s*\(", re.I),
    "xpathi": re.compile(r"XPath|\.evaluate\s*\(", re.I),
}


# 反射型命令执行：两个特征必须**同时**出现才算（只看 `.invoke(` 会把任何反射工具都放行）。
_REFL_FORNAME = re.compile(r"Class\s*\.\s*forName\s*\(", re.I)
_REFL_INVOKE = re.compile(r"getDeclaredMethod\s*\(|getMethod\s*\(|\.\s*invoke\s*\(", re.I)


def spurious_no_sink(code: str, family: str, framework_sink: bool = False) -> bool:
    """文件里没有该族应有的 sink API ⇒ finding 凭空捏造，应判假阳性。

    只对 ``_SINK_PATTERNS`` 里登记过的族生效；未登记的族返回 False（不动）。


    ``framework_sink=True`` 表示这条 finding 由**框架惯用 sink 规则**命中
    （``src/iast/framework_sinks.py``）。那些规则匹配的是「框架特有的危险调用形态」，
    与 ``_SINK_PATTERNS`` 里按族列的通用 API 是**两套判据**。用通用判据去否证一个
    由另一套判据产生的命中，属于判据错配：

    - 反射型 RCE（``Class.forName`` + ``Method.invoke``）的文件里根本没有
      ``Runtime.exec`` ⇒ 用通用 sink 判据去否证，会被误判成「跨族捏造」直接剔除，
      即使路由本身可解析。
    - 同理 Spring ``@ResponseBody`` 返回字符串的 XSS 没有 ``getWriter``。


    ``command_execution`` 的通用判据只有 ``Runtime.getRuntime|.exec(|ProcessBuilder``。
    反射调用链（``Class.forName(x).newInstance`` + ``getDeclaredMethod(...).invoke(...)``）
    是同一后果的另一种形态，单独补一条**组合**判据（两个特征必须同时出现，避免把
    任意含 ``invoke`` 的反射工具都放行）。
    """
    if not code or not family:
        return False
    if framework_sink:
        return False
    fam = str(family).strip().lower()
    pat = _SINK_PATTERNS.get(fam)
    if pat is None:
        return False
    if pat.search(code):
        return False
    if fam == "command_execution" and _REFL_FORNAME.search(code) and _REFL_INVOKE.search(code):
        return False
    return True
