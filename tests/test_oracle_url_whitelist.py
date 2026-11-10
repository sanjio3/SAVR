"""URL 白名单绕过 oracle 的回归锁（2026-11-04）。

## 背景

jsc 615 spec 237553：投 `http://evil.com%5cwww.joychou.org/a.html`，目标返回
302 且 `location=http://evil.com%5cwww.joychou.org/a.html` —— 服务端把攻击者 URL
原样写回了跳转目标，白名单校验确实被绕过。但此前没有任何判据消费这个证据，
该真值点恒判漏报（layer3_verdict：canary 已到 sink，D2 未确认）。

## 判据设计

- 只认 `Location` 头里出现**载荷自身的 host 片段**（正常白名单跳转只跳站内地址）；
- **不硬编码**攻击者域名：host 从载荷自身提取，换任何域都成立；
- 刻意不用 urlparse 拆 host：`evil.com\\@good.com` 会被拆成 userinfo + good.com，
  而绕过要的恰恰是攻击者写在前面的那一段。
"""
from src.iast.technique_oracle import (
    _payload_host,
    detect_technique,
    judge_attempts,
)


def _att(payload, hdr, status=302, no=2):
    return {"attempt_no": no, "status_code": status,
            "payload": payload, "resp_headers_digest": hdr}


class TestDetectTechnique:
    def test_url_whitelist_url_payload(self):
        assert detect_technique("url_whitelist_bypass", "http://evil.com/x") == "url_whitelist_location"

    def test_cors_not_stolen(self):
        """cors 的 URL 载荷仍归 cors_reflect，不被白名单分支吃掉。"""
        assert detect_technique("cors", "https://a.example.com") == "cors_reflect"

    def test_ssrf_not_stolen(self):
        assert detect_technique("ssrf", "http://169.254.169.254/") == "ssrf_echo"


class TestPayloadHost:
    def test_backslash_userinfo_takes_first_segment(self):
        # 关键：不能用 urlparse（会取 good.com），要取攻击者写在前面的 evil.com...
        assert _payload_host("http://evil.com%5cwww.joychou.org/a.html") == \
            "evil.com%5cwww.joychou.org"

    def test_plain_host(self):
        assert _payload_host("https://attacker.tld/p") == "attacker.tld"

    def test_not_url(self):
        assert _payload_host("no-scheme") == ""


class TestJudge:
    def test_location_reflects_payload_host_confirms(self):
        ok, tech, ev = judge_attempts("url_whitelist_bypass", [
            _att("http://evil.com%5cwww.joychou.org/a.html",
                 "content-length=0,location=http://evil.com%5cwww.joychou.org/a.html,pragma=no-cache")])
        assert ok is True
        assert tech == "url_whitelist_location"
        assert "evil.com" in ev["location"]

    def test_internal_redirect_not_confirmed(self):
        """跳到站内地址不算绕过。"""
        ok, _, _ = judge_attempts("url_whitelist_bypass", [
            _att("http://evil.com/x", "location=http://127.0.0.1:8080/login")])
        assert ok is False

    def test_no_location_header_not_confirmed(self):
        ok, _, _ = judge_attempts("url_whitelist_bypass", [
            _att("http://evil.com/x", "content-length=0,pragma=no-cache")])
        assert ok is False

    def test_empty_payload_not_confirmed(self):
        ok, _, _ = judge_attempts("url_whitelist_bypass", [
            _att("", "location=http://evil.com/x")])
        assert ok is False
