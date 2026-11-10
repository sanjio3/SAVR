"""P3：语义 safe-pattern 判定回归测试。

核心断言：安全例命中、真漏洞例（条件恒假）不命中——这是"形状正则"做不到的。
"""
from src.core.safe_pattern_semantic import (
    if_const_safe,
    map_overwrite_safe,
    safe_pattern_type,
    safe_rng_static,
    switch_const_safe,
    ternary_const_safe,
    weak_rng_static,
)


def test_ternary_const_true_is_safe():
    # num=106 → (7*18)+106 = 232 > 200 恒真 → 取常量 → 安全
    src = 'int num = 106;\nbar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;'
    assert ternary_const_safe(src) is not None


def test_ternary_const_false_is_vulnerable():
    # num=106 → (7*42)-106 = 188 < 200 恒假 → 取 param → 真漏洞，不得判安全
    src = 'int num = 106;\nbar = (7 * 42) - num > 200 ? "This should never happen" : param;'
    assert ternary_const_safe(src) is None


def test_if_const():
    src = ('if ((7 * 42) - num > 200) { bar = "This should never happen"; } '
           'else { bar = param; }')
    assert if_const_safe(src) is not None


def test_map_overwrite_safe():
    src = (
        'map.put("kA", "safe_value");\n'
        'map.put("kB", param);\n'
        'bar = (String) map.get("kB");\n'
        'bar = (String) map.get("kA");\n'
    )
    assert map_overwrite_safe(src) is not None


def test_map_no_overwrite_is_vulnerable():
    src = 'map.put("kB", param);\nbar = (String) map.get("kB");\n'
    assert map_overwrite_safe(src) is None


def test_switch_const_safe():
    src = (
        'String guess = "ABC";\n'
        'char switchTarget = guess.charAt(1);\n'
        'switch (switchTarget) { case \'B\': bar = "bob"; break; case \'A\': bar = param; break; }\n'
    )
    assert switch_const_safe(src) is not None


def test_plain_sink_no_pattern():
    src = ('String bar = request.getParameter("x");\n'
           'Runtime.getRuntime().exec(cmd + bar);\n')
    assert safe_pattern_type(src) is None


# —— safe RNG（2026-10-19 r111 weakrand 实证）：只用 SecureRandom = 安全实现 ——
from src.core.safe_pattern_semantic import safe_rng_static  # noqa: E402


def test_safe_rng_secure_only_is_safe():
    src = ('double rand = java.security.SecureRandom.getInstance("SHA1PRNG").nextDouble();\n'
           'response.getWriter().println("Weak Randomness Test SecureRandom executed");')
    assert safe_rng_static(src) == "SecureRandom"


def test_safe_rng_weak_only_is_vulnerable():
    for src in ('float r = new java.util.Random().nextFloat();',
                'double v = java.lang.Math.random();',
                'Random rnd = new Random();'):
        assert safe_rng_static(src) is None, src


def test_safe_rng_both_is_fail_open():
    # 同时出现 SecureRandom 与弱随机 → 无法确定哪条链路是安全决策，fail-open 不抑制。
    src = ('double a = java.security.SecureRandom.getInstance("SHA1PRNG").nextDouble();\n'
           'float b = new java.util.Random().nextFloat();')
    assert safe_rng_static(src) is None


def test_safe_rng_ignores_comments_and_println():
    # Benchmark 安全用例的打印语句里带 "Weak Randomness" 字样，不能当弱随机证据。
    src = ('// java.util.Random is not used here\n'
           'int n = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);\n'
           'System.out.println("Weak Randomness Test java.util.Random executed");')
    assert safe_rng_static(src) == "SecureRandom"


# ── E11 消融后续（2026-10-27）：weak_rng_static 正证据 ──
# 474（blind 布局）实证：A2 无 case# 先验时 spec 变薄 ⇒ canary 未流经 Random sink
# ⇒ 运行时判据饿死，6 条 weak_random TP 丢。源码级正证据不依赖运行时与先验。

def test_weak_rng_static_positive():
    src = ('java.util.Random r = new java.util.Random();\n'
           'int x = r.nextInt(100);')
    hit = weak_rng_static(src)
    assert hit is not None and 'Random' in hit


def test_weak_rng_static_math_random():
    src = 'String s = String.valueOf(Math.random());'
    assert weak_rng_static(src) is not None


def test_weak_rng_static_secrandom_only_is_none():
    src = ('SecureRandom r = new SecureRandom();\n'
           'byte[] b = new byte[16];\nr.nextBytes(b);')
    assert weak_rng_static(src) is None


def test_weak_rng_static_mixed_is_none():
    # SecureRandom 与弱随机混用属歧义 ⇒ fail-open 返回 None（维持 unconfirmed）
    src = ('SecureRandom sr = new SecureRandom();\n'
           'java.util.Random r = new java.util.Random();')
    assert weak_rng_static(src) is None


def test_weak_rng_static_empty_is_none():
    assert weak_rng_static('') is None
    assert weak_rng_static('int x = 1;') is None
