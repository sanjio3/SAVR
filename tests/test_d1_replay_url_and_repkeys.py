"""D1 重放两个「静默失效」缺陷的回归锁（2026-10-12，r81 实证）。

背景：OWASP xss 分片连续三代（315/316 → 317/318）d1.iast_arrivals 恒为 0。排查确认
是两个**不报错、只让通道空转**的缺陷，且既有测试都没覆盖真实形态：

① URL 拼接丢 context path（真根因）
   主重放通道写 ``urljoin(base_url + "/", path)``，而 path 恒带前导斜杠
   （spec.target_endpoint 形如 /xss-00/BenchmarkTest00030）。urljoin 对以 "/" 开头的
   相对 URL 按绝对路径处理 ⇒ 静默丢掉 base_url 的 context path：
       urljoin("http://h:8444/benchmark/", "/xss-00/BenchmarkTest00030")
         -> "http://h:8444/xss-00/BenchmarkTest00030"    # 404
   实测：无 /benchmark 前缀 404；带前缀 200 且原样反射。107/131 条重放全打在 Tomcat
   404 页上 ⇒ 事件表里只剩 Response.setHeader，真 sink（CoyoteWriter.write）几乎为零。
   既有测试用 service_url="http://app.local"（无 context path），所以从未暴露。
   已收敛为模块级 ``_join_url``，杜绝复发。

② multi-match 键名契约不匹配 ⇒ 4.7.2「全参数带标一次回放」从落地起从未生效
   两套契约并存：内存态（entry_discovery）param_name/param_location；DB 态
   （trigger_spec_registry 登记的 spec）name/location/value。D1 此前只读 param_name
   ⇒ 对 DB 态 spec 参数名恒为空串 ⇒ _inject 走 ``if not pname: return`` 空转。
   既有测试只造了内存态键名，所以也没暴露。
"""
from unittest.mock import patch

from src.application.d1_service import D1Service, _join_url


class FakeResponse:
    def __init__(self, status_code=200, text="ok"):
        self.status_code = status_code
        self.text = text
        self.headers = {}
        self.content = text.encode("utf-8")

    def json(self):
        try:
            import json as _json
            return _json.loads(self.text)
        except Exception:
            return {}


def _svc():
    return D1Service()


def _capture_and_replay(spec, target):
    """跑一次 replay，捕获真实发往网络的全部请求。

    注意：带攻击载荷时 D1 会发**多**个请求（主重放 + 响应回读 / 状态查询等），
    只保留最后一次会拿到回读端点的 URL（如 /xss-00），断言必然失真。故收集全部，
    由调用方按「存在某条请求满足条件」来断言。
    """
    captured = {"calls": []}

    def fake_request(method, url, params=None, headers=None, cookies=None,
                     json=None, data=None, **kw):
        captured["calls"].append({
            "method": method, "url": url, "params": params or {},
            "headers": headers or {}, "cookies": cookies or {},
            "json": json, "data": data,
        })
        captured.update(method=method, url=url, params=params or {},
                        headers=headers or {}, cookies=cookies or {},
                        json=json, data=data)
        return FakeResponse(200, "ok")

    with patch("requests.request", side_effect=fake_request), patch("time.sleep"):
        _svc().replay(spec, target)
    return captured


# ── ① _join_url：context path 必须保全 ────────────────────────────────────────

def test_join_url_preserves_context_path():
    """带 context path 时，spec 的绝对路径必须拼在其后而不是覆盖它。"""
    assert _join_url("http://127.0.0.1:8444/benchmark", "/xss-00/BenchmarkTest00030") == \
        "http://127.0.0.1:8444/benchmark/xss-00/BenchmarkTest00030"


def test_join_url_preserves_multi_level_context_path():
    assert _join_url("http://h:8080/a/b", "/api/v1/user") == "http://h:8080/a/b/api/v1/user"


def test_join_url_without_context_path_unchanged():
    """无 context path 的靶场（target-mall 等）行为必须完全不变。"""
    assert _join_url("http://app.local", "/api/search") == "http://app.local/api/search"


def test_join_url_idempotent_without_leading_slash():
    assert _join_url("http://h:8444/benchmark", "xss-00/BenchmarkTest00030") == \
        "http://h:8444/benchmark/xss-00/BenchmarkTest00030"


def test_join_url_tolerates_trailing_slash_on_base():
    assert _join_url("http://h:8444/benchmark/", "/xss-00/BenchmarkTest00030") == \
        "http://h:8444/benchmark/xss-00/BenchmarkTest00030"


def test_join_url_empty_base_falls_back_to_absolute_path():
    assert _join_url("", "/xss-00/BenchmarkTest00030") == "/xss-00/BenchmarkTest00030"


def test_replay_url_carries_context_path_end_to_end():
    """端到端复现 r81：service_url 带 /benchmark 时，发出的 URL 必须带 /benchmark。

    修复前该 URL 是 http://127.0.0.1:8444/xss-00/BenchmarkTest00030（404）。
    """
    spec = {
        "target_endpoint": "/xss-00/BenchmarkTest00030",
        "http_method": "GET",
        "param_name": "BenchmarkTest00030",
        "param_location": "query",
        "taint_marker": "s4st41a183ada0957233e3",
        "family": "xss",
        # 真实 spec 都带 A2 产出的攻击载荷；不带会被判 degraded_no_synthesis（不投假弹）
        # ⇒ 根本不发请求，URL 断言就无从谈起。
        "attack_payloads": ["<script>alert(1)</script>"],
    }
    target = {"service_url": "http://127.0.0.1:8444/benchmark"}
    cap = _capture_and_replay(spec, target)
    urls = [c["url"] for c in cap["calls"]]
    assert "http://127.0.0.1:8444/benchmark/xss-00/BenchmarkTest00030" in urls, urls
    # 所有请求都必须带 context path —— 修复前是 http://127.0.0.1:8444/xss-00/...（404）
    assert all(u.startswith("http://127.0.0.1:8444/benchmark") for u in urls), urls
    main = [c for c in cap["calls"]
            if c["url"].endswith("/xss-00/BenchmarkTest00030")][0]
    assert main["params"].get("BenchmarkTest00030"), main["params"]


# ── ② multi-match：DB 态键名 name/location/value 必须被真正注入 ────────────────

def test_multi_match_db_shape_keys_are_injected():
    """DB 态 spec（trigger_spec_registry 登记）用 name/location/value 三键。

    修复前 D1 只读 param_name ⇒ 参数名空串 ⇒ _inject 直接 return ⇒ 通道 100% 空转。
    """
    spec = {
        "target_endpoint": "/xss-00/BenchmarkTest00030",
        "http_method": "GET",
        "param_name": "BenchmarkTest00030",
        "param_location": "query",
        "taint_marker": "s4st41a183ada0957233e3",
        "family": "xss",
        "attack_payloads": ["<script>alert(1)</script>"],
        "representative_request_params": [
            {"name": "BenchmarkTest00030", "location": "query",
             "value": "s4st41a183ada0957233e3"},
            {"name": "Referer", "location": "header", "value": "s4st41a183ada0957233e3"},
        ],
    }
    target = {"service_url": "http://127.0.0.1:8444/benchmark"}
    cap = _capture_and_replay(spec, target)
    main = [c for c in cap["calls"]
            if c["url"].endswith("/xss-00/BenchmarkTest00030")]
    assert main, [c["url"] for c in cap["calls"]]
    main = main[0]
    assert main["url"].startswith("http://127.0.0.1:8444/benchmark/"), main["url"]
    # DB 态 query 参数必须真出现在 query 里（修复前这里不会带标）
    assert "BenchmarkTest00030" in main["params"], main["params"]
    # DB 态 header 参数必须真进 header（修复前不会）
    assert main["headers"].get("Referer"), main["headers"]


def test_multi_match_memory_shape_keys_still_work():
    """内存态键名 param_name/param_location 不能被兼容改动弄坏 —— 防回归。"""
    spec = {
        "target_endpoint": "/api/item",
        "http_method": "POST",
        "param_name": "id",
        "param_location": "query",
        "taint_marker": "CANARY_MAIN",
        "representative_request_params": [
            {"param_name": "id", "param_location": "query", "taint_marker": "CANARY_MAIN"},
            {"param_name": "name", "param_location": "body", "taint_marker": "CANARY_NAME"},
        ],
    }
    target = {"service_url": "http://app.local"}
    cap = _capture_and_replay(spec, target)
    assert "id" in cap["params"], cap["params"]
    assert (cap["json"] or {}).get("name") == "CANARY_NAME", cap["json"]
