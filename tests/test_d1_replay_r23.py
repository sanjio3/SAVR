"""R23 第一刀（A1+B+A2）DAST 差分自证回归测试。

全部以 mock 桩驱动（不触网、不依赖探针闸门），确定性验证 6 个漏报漏洞
（#19 /cart/remove、#20 /address/delete、#22 /ops/user/delete、#23 /ops/order/review、
#24 /profile/password、#25 /profile/update）在 D1 重放层可被 DAST 差分确认。

核心修复点：
- B 门禁：VICTIM_FROM_POOL 哨兵在重放期落成真实 victim 资源 id + 强指纹。
- A2：IDOR 端点（redirect/无响应体）改走 before/after 可观测副作用差分，不再卡 data_leak 腿。
- #25：/profile/update 走批量赋值 role 升高差分（不再是负数扫串语义错配）。
- A1：/ops/* 仅判登录，普通攻击者 token 即可被接受（垂直越权确认）。
"""
import sys
import os
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.iast.orchestrator import DastImpact
from src.application.d1_service import D1Service


class _Router:
    """状态化 HTTP 桩：模拟 target-mall 真实行为，驱动 before/after 差分。"""

    def __init__(self, base_url):
        self.base = base_url
        self.address_deleted = False
        self.cart_deleted = False
        self.role_elevated = False
        self.password_changed = False

    def _path(self, url):
        return urlsplit(url).path

    def send(self, method, url, query, headers, cookies, body, content_type):
        path = self._path(url)
        method = (method or "GET").upper()
        q = query or {}
        b = body if isinstance(body, dict) else {}

        # 枚举 / 读回购物车（HTML）
        if method == "GET" and path == "/cart":
            if self.cart_deleted:
                return DastImpact(reached=True, status_code=200,
                                 body='<div>购物车是空的</div>', response_summary="empty")
            return DastImpact(reached=True, status_code=200,
                             body='<tr><td><input type="hidden" name="id" value="5"/></td></tr>',
                             response_summary="cart with item 5")
        # 枚举 / 读回地址
        if method == "GET" and path.startswith("/address"):
            if path == "/address" or path == "/address/":
                return DastImpact(reached=True, status_code=404, body="", response_summary="404")
            n = path.rsplit("/", 1)[-1]
            if self.address_deleted and n == "1":
                return DastImpact(reached=True, status_code=200,
                                 body='{"ok":false,"msg":"address not found"}', response_summary="gone")
            return DastImpact(reached=True, status_code=200,
                             body='{"ok":true,"address":{"id":%s,"userId":1}}' % n, response_summary="ok")
        # 读回 profile role
        if method == "GET" and path.startswith("/api/profile/"):
            role = "ADMIN" if self.role_elevated else "USER"
            return DastImpact(reached=True, status_code=200,
                             body='{"id":1,"username":"alice","role":"%s"}' % role, response_summary="role=%s" % role)
        # 批量赋值提权
        if method == "POST" and path == "/profile/update":
            self.role_elevated = True
            return DastImpact(reached=True, status_code=302,
                             body="", response_summary="redirect")
        # 越权改密
        if method == "POST" and path == "/profile/password":
            self.password_changed = True
            return DastImpact(reached=True, status_code=302,
                             body="", response_summary="redirect")
        # 登录：成功 302，失败 200（重新渲染登录页）
        if method == "POST" and path == "/login":
            ok = (b.get("password") == "PwnedBySAST@2026" and self.password_changed)
            if ok:
                return DastImpact(reached=True, status_code=302, body="", response_summary="redirect")
            return DastImpact(reached=True, status_code=200,
                             body='<div>用户名或密码错误</div>', response_summary="login page")
        # 仅判登录的高权端点（垂直越权）
        if method == "POST" and (path == "/ops/user/delete" or path == "/ops/order/review"):
            return DastImpact(reached=True, status_code=200,
                             body='{"ok":true}', response_summary="ok")
        # 攻击请求（cart/address 删除）
        if method == "POST" and path == "/cart/remove":
            self.cart_deleted = True
            return DastImpact(reached=True, status_code=302, body="", response_summary="redirect")
        if method == "POST" and path == "/address/delete":
            self.address_deleted = True
            return DastImpact(reached=True, status_code=200,
                             body='{"ok":true,"deletedId":1}', response_summary="ok")
        return DastImpact(reached=True, status_code=200, body="", response_summary="")


def _make_d1(base_url):
    d1 = D1Service(db=None, gateway=None)  # 临时库随后置空，跳过 B 门禁回写
    d1.db = None
    router = _Router(base_url)
    d1._send_one = router.send
    return d1, router


ATTACKER = {
    "username": "bob",
    "user_id": "2",
    "auth_headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjIsInJvbGUiOiJVU0VSIn0.xxx"},
}
VICTIM = {
    "username": "alice",
    "user_id": "1",
    "auth_headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsInJvbGUiOiJVU0VSIn0.yyy"},
}


def test_19_cart_remove_side_effect():
    d1, _ = _make_d1("http://127.0.0.1:8092")
    spec = {
        "id": 38, "target_endpoint": "/cart/remove", "http_method": "POST",
        "param_name": "id", "param_location": "query",
        "victim_resource_id": "VICTIM_FROM_POOL", "victim_identifiers": "[]",
        "taint_marker": "",
    }
    target = {"service_url": "http://127.0.0.1:8092"}
    out = d1.replay_bola(spec, target, accounts={"attacker": ATTACKER, "victim": VICTIM})
    assert out["confirmed"] is True, out
    assert out["observed_side_effect"] is True, out
    assert out["victim_resource_id"] == "5", out  # B 门禁枚举到真实购物车项 id
    assert out["data_leak_confirmed"] is False  # redirect 无响应体，data_leak 正确为 False


def test_20_address_delete_side_effect():
    d1, _ = _make_d1("http://127.0.0.1:8092")
    spec = {
        "id": 32, "target_endpoint": "/address/delete", "http_method": "POST",
        "param_name": "id", "param_location": "query",
        "victim_resource_id": "VICTIM_FROM_POOL", "victim_identifiers": "[]",
        "taint_marker": "",
    }
    target = {"service_url": "http://127.0.0.1:8092"}
    out = d1.replay_bola(spec, target, accounts={"attacker": ATTACKER, "victim": VICTIM})
    assert out["confirmed"] is True, out
    assert out["observed_side_effect"] is True, out
    assert out["victim_resource_id"] == "1", out  # B 门禁探测到 alice 的地址 id


def test_24_profile_password_side_effect():
    d1, _ = _make_d1("http://127.0.0.1:8092")
    spec = {
        "id": 138, "target_endpoint": "/profile/password", "http_method": "POST",
        "param_name": "id", "param_location": "query",
        "victim_resource_id": "VICTIM_FROM_POOL", "victim_identifiers": "[]",
        "taint_marker": "",
    }
    target = {"service_url": "http://127.0.0.1:8092"}
    out = d1.replay_bola(spec, target, accounts={"attacker": ATTACKER, "victim": VICTIM})
    assert out["confirmed"] is True, out
    assert out["observed_side_effect"] is True, out


def test_22_vertical_user_delete():
    d1, _ = _make_d1("http://127.0.0.1:8092")
    spec = {
        "id": 76, "target_endpoint": "/ops/user/delete", "http_method": "POST",
        "param_name": "uid", "param_location": "query",
        "victim_resource_id": "", "victim_identifiers": "[]", "taint_marker": "",
    }
    target = {"service_url": "http://127.0.0.1:8092"}
    out = d1.replay_vertical(spec, target, accounts={"attacker": ATTACKER, "victim": VICTIM})
    assert out["confirmed"] is True, out
    assert out["plain_confirmed"] is True, out  # 普通攻击者（仅登录）即被接受


def test_23_vertical_order_review():
    d1, _ = _make_d1("http://127.0.0.1:8092")
    spec = {
        "id": 77, "target_endpoint": "/ops/order/review", "http_method": "POST",
        "param_name": "orderId", "param_location": "query",
        "victim_resource_id": "", "victim_identifiers": "[]", "taint_marker": "",
    }
    target = {"service_url": "http://127.0.0.1:8092"}
    out = d1.replay_vertical(spec, target, accounts={"attacker": ATTACKER, "victim": VICTIM})
    assert out["confirmed"] is True, out
    assert out["plain_confirmed"] is True, out


def test_25_mass_assignment_role_elevated():
    d1, _ = _make_d1("http://127.0.0.1:8092")
    spec = {
        "id": 69, "target_endpoint": "/profile/update", "http_method": "POST",
        "param_name": "id", "param_location": "query",
        "victim_resource_id": "", "victim_identifiers": "[]", "taint_marker": "",
    }
    target = {"service_url": "http://127.0.0.1:8092"}
    out = d1.replay_calculation(spec, target, accounts={"attacker": ATTACKER, "victim": VICTIM})
    assert out["confirmed"] is True, out
    assert out["mass_assignment_role_elevated"] is True, out
    assert out["before_role"] == "USER" and out["after_role"] == "ADMIN", out


if __name__ == "__main__":
    test_19_cart_remove_side_effect()
    test_20_address_delete_side_effect()
    test_24_profile_password_side_effect()
    test_22_vertical_user_delete()
    test_23_vertical_order_review()
    test_25_mass_assignment_role_elevated()
    print("ALL R23 FIRST-CUT TESTS PASSED")
