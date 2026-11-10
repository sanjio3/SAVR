"""五类「能力空白」规则 + 容器顺序语义的单测（2026-09-24）。

crypto / hash / weakrand / securecookie / trustbound 这五类此前在规则库里
完全没有对应族，占 OWASP Benchmark 样本的 41.5%，严格口径 TPR 恒为 0。
本文件锁住它们的判定边界，以及污点传播里最精细的一条：顺序容器的 remove 移位。
"""

import os

import pytest

LOCAL_ROOT = os.environ.get("SAST_AI_SDL_ROOT", "")
pytestmark = [
    pytest.mark.external,
    pytest.mark.skipif(
        not LOCAL_ROOT,
        reason="external target sources required: set SAST_AI_SDL_ROOT to your local targets root",
    ),
]

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.a1_injection_heuristic import analyze_content, _java_tainted_vars  # noqa: E402

SAMPLE = os.path.join(LOCAL_ROOT, "owasp-code", "benchmark-sample-200",
                            "src", "main", "java", "org", "owasp", "benchmark", "testcode")


def types_of(content, path="T.java"):
    return sorted({(v.type, v.sink) for v in analyze_content(path, content, "java")})


def real(name):
    p = os.path.join(SAMPLE, name + ".java")
    return open(p, encoding="utf-8", errors="ignore").read() if os.path.isfile(p) else None


# ── crypto (CWE-327) ────────────────────────────────────────────────────

def test_crypto_weak_algorithm_detected():
    src = 'javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");'
    assert ("不安全加密算法", "弱加密套件") in types_of(src)


def test_crypto_keygenerator_des_detected():
    src = 'javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();'
    assert ("不安全加密算法", "弱加密套件") in types_of(src)


def test_crypto_ecb_mode_detected():
    src = 'Cipher.getInstance("DESede/ECB/PKCS5Padding");'
    assert ("不安全加密算法", "弱加密套件") in types_of(src)


def test_crypto_aes_gcm_not_reported():
    """AES/GCM 是安全选择，不得报——否则 crypto 假阳性全中。"""
    src = """
javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("AES").generateKey();
"""
    assert ("不安全加密算法", "弱加密套件") not in types_of(src)


# ── hash (CWE-328) ──────────────────────────────────────────────────────

def test_hash_md5_detected():
    src = 'java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");'
    assert ("弱哈希算法", "弱哈希算法") in types_of(src)


def test_hash_sha1_detected():
    src = 'md = java.security.MessageDigest.getInstance("SHA1", "SUN");'
    assert ("弱哈希算法", "弱哈希算法") in types_of(src)


def test_hash_sha256_not_reported():
    """SHA-256 / SHA-512 不得报。注意 "SHA" 也不能误伤 "SHA-256"。"""
    for algo in ("SHA-256", "SHA512"):
        src = f'MessageDigest md = MessageDigest.getInstance("{algo}");'
        assert ("弱哈希算法", "弱哈希算法") not in types_of(src), algo


# ── weakrand (CWE-330) ──────────────────────────────────────────────────

def test_weakrand_new_random_detected():
    src = "long l = new java.util.Random().nextLong();"
    assert ("弱随机数", "不安全随机源") in types_of(src)


def test_weakrand_math_random_detected():
    src = "double d = Math.random();"
    assert ("弱随机数", "不安全随机源") in types_of(src)


def test_weakrand_securerandom_not_reported():
    """SecureRandom 不得报。注意声明类型写成 java.util.Random 也要能识别。"""
    src = 'java.util.Random numGen = java.security.SecureRandom.getInstance("SHA1PRNG");'
    assert ("弱随机数", "不安全随机源") not in types_of(src)


# ── securecookie (CWE-614) ──────────────────────────────────────────────

def test_securecookie_set_secure_false_detected():
    src = "cookie.setSecure(false);"
    assert ("Cookie 安全属性缺失", "Cookie 未启用 Secure") in types_of(src)


def test_securecookie_set_secure_true_not_reported():
    src = "cookie.setSecure(true);"
    assert ("Cookie 安全属性缺失", "Cookie 未启用 Secure") not in types_of(src)


# ── trustbound (CWE-501) ────────────────────────────────────────────────

def test_trustbound_tainted_session_write_detected():
    src = """
String param = request.getParameter("x");
request.getSession().setAttribute(param, "10340");
"""
    assert ("信任边界违背", "session 写入外部可控数据") in types_of(src)


def test_trustbound_static_session_write_not_reported():
    """session 写静态键值不得报——否则 trustbound 假阳性全中。"""
    src = 'request.getSession().setAttribute("userid", "10340");'
    assert ("信任边界违背", "session 写入外部可控数据") not in types_of(src)


# ── 顺序容器的 remove 移位（污点传播最精细的一条）────────────────────────

def test_list_remove_shifts_index():
    """add(安全) add(污点) add(安全) remove(0) 之后，get(1) 取到的是安全值。

    Benchmark 刻意这么写。不模拟 remove 移位会把这条假阳性误判成污点。
    """
    src = """
String param = request.getParameter("x");
java.util.List<String> valuesList = new java.util.ArrayList<String>();
valuesList.add("safe");
valuesList.add(param);
valuesList.add("moresafe");
valuesList.remove(0);
String bar = valuesList.get(1);
response.getWriter().print(bar);
"""
    assert "bar" not in _java_tainted_vars(src)
    assert ("XSS", "response.getWriter 直出") not in types_of(src)


def test_list_get_tainted_index_still_tainted():
    """同一结构下 get(0) 取到的是污点，不能被 remove 逻辑误改成安全。"""
    src = """
String param = request.getParameter("x");
java.util.List<String> valuesList = new java.util.ArrayList<String>();
valuesList.add("safe");
valuesList.add(param);
valuesList.add("moresafe");
valuesList.remove(0);
String bar = valuesList.get(0);
"""
    assert "bar" in _java_tainted_vars(src)


def test_map_get_by_different_key_not_tainted():
    """put("keyA", tainted) 之后 get("keyB") 取的是别的键，不得判污。"""
    src = """
String param = request.getParameter("x");
java.util.HashMap<String, Object> m = new java.util.HashMap<String, Object>();
m.put("keyA", param);
String bar = (String) m.get("keyB");
"""
    assert "bar" not in _java_tainted_vars(src)


# ── 真实样本 ────────────────────────────────────────────────────────────

_REAL_CASES = [
    ("BenchmarkTest00119", ("不安全加密算法", "弱加密套件"), True),
    ("BenchmarkTest00778", ("不安全加密算法", "弱加密套件"), False),
    ("BenchmarkTest01247", ("弱哈希算法", "弱哈希算法"), True),
    ("BenchmarkTest00709", ("弱哈希算法", "弱哈希算法"), False),
    ("BenchmarkTest00167", ("弱随机数", "不安全随机源"), True),
    ("BenchmarkTest00178", ("弱随机数", "不安全随机源"), False),
    ("BenchmarkTest00903", ("Cookie 安全属性缺失", "Cookie 未启用 Secure"), True),
    ("BenchmarkTest00655", ("Cookie 安全属性缺失", "Cookie 未启用 Secure"), False),
    ("BenchmarkTest00426", ("信任边界违背", "session 写入外部可控数据"), True),
    ("BenchmarkTest00252", ("信任边界违背", "session 写入外部可控数据"), False),
]


def test_real_sample_cases():
    checked = 0
    for name, sig, should_hit in _REAL_CASES:
        c = real(name)
        if c is None:
            continue
        checked += 1
        hit = sig in types_of(c)
        assert hit == should_hit, f"{name} 期望命中={should_hit} 实际={hit}"
    assert checked >= 8, f"样本文件不足，仅校验 {checked} 个"


if __name__ == "__main__":
    import traceback
    fns = [(n, o) for n, o in sorted(globals().items()) if n.startswith("test_") and callable(o)]
    failed = 0
    for n, fn in fns:
        try:
            fn()
            print(f"  PASS  {n}")
        except Exception:
            failed += 1
            print(f"  FAIL  {n}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
