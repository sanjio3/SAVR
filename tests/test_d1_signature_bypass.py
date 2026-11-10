"""replay_signature_bypass（第九类，最正确最慢）确定性单测。

不用真实靶机：用 fake _send_one 模拟「只接受 alg:none 伪造 token 的服务端」与「拒绝一切的服务端」，
验证 replay_signature_bypass 的绕过检测/控制组/无证据三条链路。纯逻辑、可复现、不伪造外部结果。
"""
import base64
import json

import pytest

from src.application.d1_service import D1Service, _WEAK_JWT_SECRETS
from src.iast.orchestrator import DastImpact


def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _make_token(alg="HS256", payload=None, sig=b"x"):
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload or {"sub": "alice", "role": "user"}).encode()).rstrip(b"=").decode()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def _fake_send_factory(accept_alg_none: bool):
    """返回 fake _send_one：仅当 alg=none 时接受（accept_alg_none=True）；否则一律 401。"""
    def fake_send(self, method, url, query, headers, cookies, body, content_type):
        auth = headers.get("Authorization", "")
        token = auth.split(" ", 1)[-1].strip() if auth else ""
        if token == "invalid.invalid.invalid":
            return DastImpact(reached=True, status_code=401, body="unauthorized", response_summary="401")
        if not token or token.count(".") < 2:
            return DastImpact(reached=True, status_code=401, body="unauthorized", response_summary="401")
        try:
            hdr = json.loads(_b64url_decode(token.split(".", 2)[0]))
        except Exception:
            return DastImpact(reached=True, status_code=401, body="bad token", response_summary="401")
        if accept_alg_none and hdr.get("alg") == "none":
            return DastImpact(reached=True, status_code=200, body="ok welcome admin", response_summary="200")
        return DastImpact(reached=True, status_code=401, body="unauthorized", response_summary="401")
    return fake_send


def _run(accept_alg_none: bool, token=_make_token("HS256")):
    svc = D1Service(gateway=None)
    svc._send_one = _fake_send_factory(accept_alg_none).__get__(svc, D1Service)
    spec = {
        "jwt_token": token,
        "target_endpoint": "/admin/users",
        "http_method": "GET",
        "auth_header_name": "Authorization",
        "auth_scheme": "Bearer",
    }
    target = {"service_url": "http://localhost:8092"}
    return svc.replay_signature_bypass(spec, target)


def test_signature_bypass_detects_alg_none():
    out = _run(accept_alg_none=True)
    assert out["confirmed"] is True
    assert out["verdict"] == "confirmed"
    assert "alg:none (原 payload)" in out["confirmed_variants"]
    # 控制组（乱码 token）应被拒，说明仅绕过变体有效
    assert out["control_accepted"] is False
    assert out["variants_tried"] >= 1
    assert "alg:none" in out["reason"]


def test_signature_bypass_no_evidence_when_all_rejected():
    out = _run(accept_alg_none=False)
    assert out["confirmed"] is False
    assert out["verdict"] == "no_evidence"
    assert out["confirmed_variants"] == []
    assert "未" in out["reason"] or "拒绝" in out["reason"]


def test_signature_bypass_missing_token():
    svc = D1Service(gateway=None)
    out = svc.replay_signature_bypass({"target_endpoint": "/x"}, {"service_url": "http://x"})
    assert out["confirmed"] is False
    assert out["variants_tried"] == 0


def test_weak_secret_wordlist_present():
    assert isinstance(_WEAK_JWT_SECRETS, list) and len(_WEAK_JWT_SECRETS) > 0
