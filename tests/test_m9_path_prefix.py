"""M9 目录白名单（路径前缀类 kind）测试（2026-10-03）。

三条设计约束各有守卫：
  1. **不新增字段**：patterns 复用存 base_dir。
  2. **相对路径按 resolve 语义处理**：``Paths.get(base).resolve("a.txt")`` 是合法访问，
     判成逃逸就是提前丢掉真漏洞载荷（实打实的漏报）。
  3. **符号链接 fail-open**：Java 的 getCanonicalPath 解析符号链接，Python 模拟不了，
     所以这类 spec 恒置 has_normalization=True，不得据此判 non_bypassable，交运行时。
"""
from src.core.mechanism_library import intersect
from src.core.sanitizer_miner import (
    FilterSpec, _normalize_path, extract_filter_spec, extract_path_prefix_spec,
    path_escapes_base, simulate_filter, simulate_filter_safe,
)

_BODY = '''
public String read(String name) throws IOException {
   Path base = Paths.get("/var/www/html");
   Path p = base.resolve(name).normalize();
   if (!p.toRealPath().toString().startsWith(base.toString())) {
       throw new SecurityException("outside");
   }
   return new String(Files.readAllBytes(p));
}
'''


def test_extract_path_prefix_kind():
    spec = extract_path_prefix_spec(_BODY)
    assert spec.kind == FilterSpec.KIND_PATH_PREFIX
    assert spec.patterns == ["/var/www/html"]     # patterns 复用存 base_dir，无新增字段
    assert spec.is_known()


def test_extract_filter_spec_prefers_path_prefix():
    """目录白名单优先于字符集判定 —— 否则 base 字面量会混进黑名单 token。"""
    spec = extract_filter_spec(_BODY)
    assert spec.kind == FilterSpec.KIND_PATH_PREFIX
    assert "/var/www/html" not in (spec.tokens or [])


def test_canonical_path_marks_normalization_for_fail_open():
    """含 toRealPath/getCanonicalPath → has_normalization=True（符号链接不可模拟 → 不得判 non_bypassable）。"""
    spec = extract_path_prefix_spec(_BODY)
    assert spec.has_normalization is True
    assert "toRealPath" in (spec.note or "")


def test_normalization_set_even_without_canonical_call():
    """无条件置 has_normalization：目录白名单都涉及文件系统解析，静态判定一律不可信。

    宁可少判一条 non_bypassable（交运行时），也不能因静态近似误判而错杀真漏洞。
    """
    spec = extract_path_prefix_spec(
        'Path base = Paths.get("/srv/data"); Path p = base.resolve(name);')
    assert spec.kind == FilterSpec.KIND_PATH_PREFIX
    assert spec.has_normalization is True


def test_relative_path_is_resolved_under_base():
    """相对路径按 resolve 语义落到 base 之下 —— 判成逃逸就是提前丢掉真漏洞载荷。"""
    assert path_escapes_base("a.txt", "/var/www/html") is False
    assert path_escapes_base("sub/a.txt", "/var/www/html") is False
    assert simulate_filter(extract_path_prefix_spec(_BODY), "a.txt") is True


def test_dotdot_escapes_are_blocked():
    spec = extract_path_prefix_spec(_BODY)
    for payload, why in [
        ("../etc/passwd", "单层上跳"),
        ("../../etc/passwd", "多层上跳"),
        ("sub/../../etc/passwd", "绕子目录再上跳"),
        ("..\\..\\etc\\passwd", "Windows 反斜杠"),
        ("..%2f..%2fetc%2fpasswd", "URL 编码"),
        ("%2e%2e%2fetc%2fpasswd", "URL 编码点"),
        ("/etc/passwd", "绝对路径跳出"),
    ]:
        assert simulate_filter(spec, payload) is False, why


def test_path_inside_base_passes():
    spec = extract_path_prefix_spec(_BODY)
    assert simulate_filter(spec, "/var/www/html/x.jsp") is True
    assert simulate_filter(spec, "/var/www/html/a/b/c.jsp") is True


def test_intersect_keeps_all_bases_and_carries_deny_tokens():
    """目录 + 黑名单合并：base 全保留（交集语义），tokens 承载黑名单。"""
    spec = extract_path_prefix_spec(_BODY)
    merged = intersect([spec, FilterSpec(FilterSpec.KIND_DENY, tokens=["<script>"])])
    assert merged.kind == FilterSpec.KIND_PATH_PREFIX
    assert merged.patterns == ["/var/www/html"]
    assert merged.tokens == ["<script>"]
    # 两个条件都要满足
    assert simulate_filter(merged, "/var/www/html/ok.txt") is True
    assert simulate_filter(merged, "/var/www/html/<script>.txt") is False
    assert simulate_filter(merged, "/var/www/html/../../etc/passwd") is False


def test_intersect_multiple_path_specs_is_intersection_semantics():
    """多目录白名单并存：载荷必须同时落在每个 base 之内。"""
    a = FilterSpec(FilterSpec.KIND_PATH_PREFIX, patterns=["/var/www"])
    b = FilterSpec(FilterSpec.KIND_PATH_PREFIX, patterns=["/var/www/html"])
    merged = intersect([a, b])
    assert sorted(merged.patterns) == ["/var/www", "/var/www/html"]
    # 两个 base 都要满足
    assert simulate_filter(merged, "/var/www/html/x") is True
    assert simulate_filter(merged, "/var/www/other/x") is False


def test_normalize_path_dotdot_rules():
    assert _normalize_path("/var/www/html/../../etc/passwd") == "/var/etc/passwd"
    assert _normalize_path("/../../etc") == "/etc"          # 根之上吃掉（与 Java 一致）
    assert _normalize_path("file:///var/www/html/x") == "/var/www/html/x"
    assert _normalize_path("a/./b") == "a/b"


def test_no_base_dir_yields_unknown_spec():
    """抽不出基址就判不出，不硬凑 —— 空 spec 进索引只会污染求交。"""
    spec = extract_path_prefix_spec("String s = req.getParameter(\"x\");")
    assert not spec.is_known()
    assert spec.kind == FilterSpec.KIND_UNKNOWN


def test_simulate_filter_safe_agrees_on_path_kind():
    """path_prefix 不走正则，safe 版应给出确定结论而非 None。"""
    spec = extract_path_prefix_spec(_BODY)
    assert simulate_filter_safe(spec, "/var/www/html/x") is True
    assert simulate_filter_safe(spec, "/etc/passwd") is False


def test_roundtrip_through_dict():
    spec = extract_path_prefix_spec(_BODY)
    back = FilterSpec.from_dict(spec.to_dict())
    assert back is not None and back.kind == FilterSpec.KIND_PATH_PREFIX
    assert simulate_filter(back, "/etc/passwd") is False
