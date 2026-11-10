"""D1 multipart 一致性守卫的单测（2026-09-22 落地）。

为什么值得单独测：这条判定决定「canary 发到哪个线格式位」。判错的方向有两个，
且**两个方向都是静默的** —— 不会报错、不会崩溃，只表现为「该族永久 no-arrival」：

- 该判 multipart 却发去 query：目标侧 @RequestParam MultipartFile 拿不到值，sink 0 事件。
  这正是 run 31 spec 8773 / spec 8856（POST /file/upload/picture，param=file，loc=query）
  0 事件的真因。
- 不该判 multipart 却改了：把 /login 的 username、target-mall 的 /wallet/withdraw 这类
  正常表单流量从 query/body 挪进 multipart 体，目标侧同样取不到值 —— 等于自己制造漏检。
  实测 run 29/30/31 里「ct 空 + POST + loc∈{query,body,form}」有 56 条，所以「ct 为空」
  这一支必须是窄口，不能一律放行。

这里的断言值都取自上述实测 spec，不是构造出来的理想值。
"""

from __future__ import annotations

import pytest

from src.application.d1_service import _should_use_multipart


# ── 第一级：content_type 明确声明 multipart ──────────────────────────────
def test_declared_multipart_wins_over_query_location():
    """spec 8773 的真实取值：ct 声明 multipart，loc 却是 query → 必须改判。"""
    assert _should_use_multipart("multipart/form-data", "/file/upload/picture", "file", "query", "POST")


@pytest.mark.parametrize("loc", ["query", "body", "form"])
def test_declared_multipart_covers_all_conflicting_locations(loc):
    assert _should_use_multipart("multipart/form-data; boundary=x", "/file/upload/picture", "file", loc, "POST")


def test_declared_multipart_but_read_method_is_not_rewritten():
    """multipart 只对写方法有意义；GET 上声明 multipart 属登记错误，不猜。"""
    assert not _should_use_multipart("multipart/form-data", "/file/upload/picture", "file", "query", "GET")


def test_already_multipart_location_is_left_alone():
    """loc 已经是 multipart 时无需改判（避免重复处理）。"""
    assert not _should_use_multipart("multipart/form-data", "/file/upload/picture", "file", "multipart", "POST")


def test_header_and_cookie_locations_are_never_multipart():
    assert not _should_use_multipart("multipart/form-data", "/file/upload/picture", "file", "header", "POST")
    assert not _should_use_multipart("multipart/form-data", "/file/upload/picture", "file", "cookie", "POST")


# ── 第二级：content_type 为空时的极窄推断 ────────────────────────────────
def test_empty_content_type_on_upload_endpoint_is_inferred():
    """spec 8856 / 8529 的真实取值：ct 为空但与 8773 同端点同参数 → 同样必须改判。"""
    assert _should_use_multipart("", "/file/upload/picture", "file", "query", "POST")


def test_empty_content_type_on_login_is_not_inferred():
    """/login 的 username 是合法表单参数（56 条候选里的大多数都长这样），不得改写。"""
    assert not _should_use_multipart("", "/login", "username", "body", "POST")


def test_empty_content_type_on_business_endpoint_is_not_inferred():
    """target-mall 的资金类端点：参数名与上传无关 → 不得改写。"""
    assert not _should_use_multipart("", "/wallet/withdraw", "amount", "query", "POST")
    assert not _should_use_multipart("", "/order/buy", "productId", "query", "POST")


def test_empty_content_type_with_xml_body_param_is_not_inferred():
    """/order/import-xml 的 _body 是整包 XML，不是文件字段。"""
    assert not _should_use_multipart("", "/order/import-xml", "_body", "body", "POST")


def test_empty_content_type_needs_both_endpoint_and_param_hints():
    """只有一端像上传也不足以改写：端点像、参数不像 → 不改；参数像、端点不像 → 不改。"""
    assert not _should_use_multipart("", "/file/upload/picture", "path", "query", "POST")
    assert not _should_use_multipart("", "/profile/update", "file", "query", "POST")


# ── 第三级：声明了别的线格式时以声明为准 ────────────────────────────────
def test_other_declared_content_type_is_respected():
    """ct 明确写了 JSON / 表单编码时不得翻成 multipart —— 线格式以声明为准。"""
    assert not _should_use_multipart("application/json", "/file/upload/picture", "file", "body", "POST")
    assert not _should_use_multipart(
        "application/x-www-form-urlencoded", "/file/upload/picture", "file", "form", "POST"
    )


def test_missing_inputs_do_not_raise():
    """字段缺失（None/空）时返回 False，不应抛异常拖垮整批重放。"""
    assert not _should_use_multipart(None, None, None, None, None)  # type: ignore[arg-type]
    assert not _should_use_multipart("", "", "", "", "")


# ── 段/词元匹配（子串匹配的误判回归）────────────────────────────────────
def test_profile_endpoint_is_not_an_upload_endpoint():
    """回归：子串口径下 "file" in "/profile/update" 为真 → 曾把资料更新误判成上传。

    改用路径段匹配后，段 "profile" 不以 "file" 开头（pro ≠ fil），故不再命中。
    这条断言的价值在于钉住「不许退回子串匹配」。
    """
    assert not _should_use_multipart("", "/profile/update", "file", "query", "POST")
    assert not _should_use_multipart("", "/profile/avatar-from-url", "url", "query", "POST")


def test_camel_case_param_names_are_tokenized():
    """上传参数名常见驼峰/下划线写法，应能识别；不含文件词元的则不行。"""
    assert _should_use_multipart("", "/file/upload/picture", "uploadFile", "query", "POST")
    assert _should_use_multipart("", "/file/upload/picture", "picture_file", "query", "POST")
    assert not _should_use_multipart("", "/file/upload/picture", "profileId", "query", "POST")
