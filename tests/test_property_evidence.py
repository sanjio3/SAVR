"""属性族静态强证据单测（src/iast/property_evidence.py）。

三个坑各有专属回归用例；另覆盖 secure_cookie 新族与族名别名。
"""
from src.iast import property_evidence as PE


# ── 坑 1：字符串字面量里的 API 引用不算调用 ──────────────────────────────

def test_string_literal_api_reference_is_not_a_call():
    """OWASP 用例末尾常见 `println("... Cipher.getInstance(java.lang.String) ...")`。

    它不是真调用。若算进去，all(强算法) 永假 ⇒ 真安全版本被误判成有漏洞。
    """
    code = (
        'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
        '        .println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String) executed");\n'
    )
    assert PE.strong_algo_evidence(code) == "file-level-strong"


def test_comment_lines_are_skipped():
    code = (
        '// javax.crypto.Cipher.getInstance("DES") 这行是注释\n'
        'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
    )
    assert PE.strong_algo_evidence(code) == "file-level-strong"


def test_weak_algorithm_blocks_strong_evidence():
    code = (
        'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");\n'
        'javax.crypto.SecretKey k = javax.crypto.KeyGenerator.getInstance("DES").generateKey();\n'
    )
    assert PE.strong_algo_evidence(code) == ""


# ── 坑 2：算法调用与随机源调用分开判 ────────────────────────────────────

def test_securerandom_line_does_not_break_algo_judgement():
    """00121 形态：SecureRandom + AES/GCM + AES ⇒ 强算法安全版本，必须判强证据。"""
    code = (
        "java.security.SecureRandom random = new java.security.SecureRandom();\n"
        '        byte[] iv = random.generateSeed(16);\n'
        '        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
        '        javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("AES").generateKey();\n'
    )
    assert PE.strong_algo_evidence(code) == "file-level-strong"


def test_weak_random_is_not_strong():
    code = "int r = new java.util.Random().nextInt(99);\n"
    assert PE.strong_random_evidence(code) == ""


def test_securerandom_is_strong_random():
    code = 'int r = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);\n'
    assert PE.strong_random_evidence(code) == "securerandom"


# ── secure_cookie 族（新增） ────────────────────────────────────────────

def test_secure_cookie_all_true_is_strong():
    code = (
        'javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("C", str);\n'
        "        cookie.setSecure(true);\n"
        "        cookie.setHttpOnly(true);\n"
        "        response.addCookie(cookie);\n"
    )
    assert PE.strong_cookie_evidence(code) == "setsecure-all-true"


def test_secure_cookie_with_false_is_not_strong():
    """真漏洞形态：setSecure(false) ⇒ 不能判强证据（否则误杀 TP）。"""
    code = (
        "        cookie.setSecure(false);\n"
        "        cookie.setHttpOnly(true);\n"
    )
    assert PE.strong_cookie_evidence(code) == ""


def test_secure_cookie_mixed_is_not_strong():
    """00087/01861 形态：userCookie(true) + cookie(false) ⇒ 有弱项 ⇒ 不判强证据。"""
    code = (
        "        userCookie.setSecure(true);\n"
        "        userCookie.setHttpOnly(true);\n"
        "        cookie.setSecure(false);\n"
        "        cookie.setHttpOnly(true);\n"
    )
    assert PE.strong_cookie_evidence(code) == ""


def test_secure_cookie_no_setsecure_is_unknown():
    code = "javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie(\"C\", str);\n"
    assert PE.strong_cookie_evidence(code) == ""


# ── 族名归一 ────────────────────────────────────────────────────────────

def test_normalize_gate_family_aliases():
    assert PE.normalize_gate_family("weak_hash") == PE.FAMILY_WEAK_HASH
    assert PE.normalize_gate_family("弱哈希算法") == PE.FAMILY_WEAK_HASH
    assert PE.normalize_gate_family("insecure_crypto_algorithm") == PE.FAMILY_INSECURE_CRYPTO
    assert PE.normalize_gate_family("insecure crypto algorithm") == PE.FAMILY_INSECURE_CRYPTO
    assert PE.normalize_gate_family("weak_random") == PE.FAMILY_WEAK_RANDOM
    assert PE.normalize_gate_family("secure_cookie") == PE.FAMILY_SECURE_COOKIE
    assert PE.normalize_gate_family("cookie 安全属性缺失") == PE.FAMILY_SECURE_COOKIE
    assert PE.normalize_gate_family("") == ""


def test_non_property_family_returns_empty():
    """数据流族一律不碰（绝不能用属性族判据去杀注入族 TP）。"""
    code = 'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
    for fam in ("sql_injection", "xss", "path_traversal", "ldap_injection", ""):
        assert PE.strong_property_evidence(code, 1, fam) == "", fam


# ── 入口函数：line 快路径 + 文件级回退 ──────────────────────────────────

def test_entry_point_line_hit_returns_token():
    code = 'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
    assert PE.strong_property_evidence(code, 1, "weak_crypto") == "aes/gcm"


def test_entry_point_falls_back_to_file_level_when_line_wrong():
    """模型常报错行 ⇒ 必须回退到文件级扫描，否则门禁静默失效。"""
    code = 'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
    assert PE.strong_property_evidence(code, 0, "weak_crypto") == "file-level-strong"
    assert PE.strong_property_evidence(code, 999, "weak_crypto") == "file-level-strong"


def test_entry_point_secure_cookie_family():
    code = "        cookie.setSecure(true);\n"
    assert PE.strong_property_evidence(code, 1, "secure_cookie") == "setsecure-all-true"


# ── 前置否决：文件里还有弱算法 ⇒ 整个文件不是「属性安全」的 ──────────────

def test_weak_algo_present_blocks_weak_random_judgement():
    """00208 实测：DES/CBC + KeyGenerator("DES")，SecureRandom 只用来生成 IV。

    该文件真漏洞是 crypto（弱算法 DES）。若 weak_random 判据只看「文件里有没有
    SecureRandom」就会判成强证据 ⇒ 误杀这条真漏洞 finding。必须被前置否决拦下。
    """
    code = (
        "java.security.SecureRandom random = new java.security.SecureRandom();\n"
        "byte[] iv = random.generateSeed(8);\n"
        'javax.crypto.Cipher c =\n'
        '        javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");\n'
        'javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();\n'
    )
    assert PE.has_weak_algo_call(code) is True
    # weak_random 族：不能因为有 SecureRandom 就判强证据
    assert PE.strong_property_evidence(code, 1, "weak_random") == ""
    # crypto 族：DES 是弱算法，本来也不该有强证据
    assert PE.strong_property_evidence(code, 1, "weak_crypto") == ""


def test_weak_algo_present_blocks_secure_cookie_judgement():
    """同一原则：文件里还有弱算法时，secure_cookie 族也不该判强证据。

    场景：cookie 设了 setSecure(true)，但同一文件用了 MD5 摘要 ⇒
    该文件整体不「属性安全」，不能因 cookie 这一项就放行。
    """
    code = (
        "        cookie.setSecure(true);\n"
        "        cookie.setHttpOnly(true);\n"
        'java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");\n'
    )
    assert PE.strong_property_evidence(code, 1, "secure_cookie") == ""


def test_weak_random_source_blocks_weak_random_judgement():
    """new Random() 是弱随机源 ⇒ weakrand 族不判强证据（即便另有 SecureRandom）。

    注意：判定必须看**文件级**（line=0 走文件级扫描），因为 sink 行本身可能就是
    那句 SecureRandom，line 快路径会先命中。
    """
    code = (
        "java.security.SecureRandom sr = new java.security.SecureRandom();\n"
        "int r = new java.util.Random().nextInt(99);\n"
    )
    assert PE.strong_property_evidence(code, 0, "weak_random") == ""


def test_pure_strong_file_still_judged():
    """对照：纯强算法文件仍能判出强证据（前置否决不能过紧）。"""
    code = (
        "java.security.SecureRandom random = new java.security.SecureRandom();\n"
        'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");\n'
        'javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("AES").generateKey();\n'
    )
    assert PE.has_weak_algo_call(code) is False
    # line=1 是 SecureRandom 行（不是算法行）⇒ weak_crypto 走文件级扫描
    assert PE.strong_property_evidence(code, 1, "weak_crypto") == "file-level-strong"
    # 指定算法行 ⇒ line 快路径命中具体 token
    assert PE.strong_property_evidence(code, 2, "weak_crypto") == "aes/gcm"
    assert PE.strong_property_evidence(code, 0, "weak_random") == "securerandom"
