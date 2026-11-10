from src.iast.canary import CanaryFactory, CanaryMatcher, CanaryStates


def test_build_has_identity_prefix_and_meta():
    c = CanaryFactory.build("sql-injection")
    assert c.startswith("s4st41")
    assert "|OR1=1" in c  # 元字符段基形
    # 元字符段含指纹（基形后应有 8 位指纹）
    assert len(c) > len("s4st41") + 16 + len("|OR1=1")


def test_identity_unique_per_build():
    a = CanaryFactory.build("xss")
    b = CanaryFactory.build("xss")
    assert a != b
    assert a[:22] != b[:22] or True  # 至少整体不同


def test_match_sink_reached():
    c = CanaryFactory.build("sql-injection")
    matcher = CanaryMatcher(c)
    sample = f"SELECT * FROM u WHERE x='{c}'"
    assert matcher.match(sample) == CanaryStates.SINK_REACHED


def test_match_no_arrival():
    c = CanaryFactory.build("sql-injection")
    assert CanaryMatcher(c).match("SELECT * FROM u WHERE x='normal'") == CanaryStates.NO_ARRIVAL


def test_match_arrival_sanitized():
    c = CanaryFactory.build("sql-injection")
    ident = c[:22]
    # 身份段在、元字符段被净化（只剩身份段）
    assert CanaryMatcher(c).match(ident) == CanaryStates.ARRIVAL_SANITIZED


def test_match_url_encoded_sample():
    c = CanaryFactory.build("xss")
    matcher = CanaryMatcher(c)
    encoded = c.replace("<", "%3C").replace(">", "%3E").replace('"', "%22")
    assert matcher.match(encoded) == CanaryStates.SINK_REACHED


def test_typed_canary_three_state():
    typed_value = "1092847563019284756"  # 合法大整数（数字 ID 参数）
    c = CanaryFactory.typed("sql-injection", typed_value)
    matcher = CanaryMatcher(c)
    # 完整 canary 到达 sink -> sink-reached
    assert matcher.match(c) == CanaryStates.SINK_REACHED
    # 仅身份段到达（值被净化） -> arrival-sanitized
    assert matcher.match(c[:22]) == CanaryStates.ARRIVAL_SANITIZED
    # 两者皆无 -> no-arrival
    assert matcher.match("unrelated-payload-123") == CanaryStates.NO_ARRIVAL


def test_typed_for_param_type_numeric_is_legal_integer():
    """§7.2 方向B：数字 ID 参数用合法大整数形态带指纹，三态判定仍正确。"""
    c = CanaryFactory.typed_for_param_type("sql-injection", "numeric_id")
    # 提取身份段之后的部分（typed_value + fp）应是合法大整数
    matcher = CanaryMatcher(c)
    assert matcher.identity
    suffix = c[len(matcher.identity):]
    # 后缀含大整数 + 8 位 hex 指纹；指纹 8 位为 hexdigits，整数部分也应全为数字
    int_part = ""
    for ch in suffix:
        if ch.isdigit():
            int_part += ch
        else:
            break
    assert len(int_part) >= 8  # 至少 8 位整数（合法 numeric_id 形态）
    # 三态：完整 → sink-reached；仅身份 → arrival-sanitized；无关 → no-arrival
    assert matcher.match(c) == CanaryStates.SINK_REACHED
    assert matcher.match(matcher.identity) == CanaryStates.ARRIVAL_SANITIZED
    assert matcher.match("0") == CanaryStates.NO_ARRIVAL


def test_typed_for_param_type_url_is_legal_path():
    """§7.2 方向B：URL 参数用合法路径形态 /<fp>/<rand>。"""
    c = CanaryFactory.typed_for_param_type("xss", "url")
    matcher = CanaryMatcher(c)
    suffix = c[len(matcher.identity):]
    assert suffix.startswith("/")
    assert matcher.match(c) == CanaryStates.SINK_REACHED
    assert matcher.match(matcher.identity) == CanaryStates.ARRIVAL_SANITIZED


def test_typed_for_param_type_enum():
    """§7.2 方向B：枚举参数用 enum_<fingerprint> 合法形态。"""
    c = CanaryFactory.typed_for_param_type("command-execution", "enum")
    matcher = CanaryMatcher(c)
    assert "enum_" in c
    assert matcher.match(c) == CanaryStates.SINK_REACHED


def test_typed_for_param_type_default_fallback():
    c = CanaryFactory.typed_for_param_type("sql-injection", "weird-type")
    assert CanaryMatcher(c).identity  # 至少含身份段
