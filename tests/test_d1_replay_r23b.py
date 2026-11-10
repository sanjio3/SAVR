"""R23 第二~四刀（A3/A4/A5/A6）DAST 原生差分回归测试。

全部用状态化 HTTP 桩替代 D1Service._send_one，确定性、不触网。
覆盖靶场真实端点语义（已读源码实证）：
- A3 (#30/#31) /order/buy、/order/checkout 金额篡改（amount 直接采信 → payAmount 被接管）
- A5 (#32)     /order/{id}/ship 状态机跳步（未付款直接 SHIPPED）
- A4 (#26/#27/#28/#29) /seckill 超卖、/coupon/claim 超发、/wallet/withdraw|transfer 超额扣减
- A6 (#34)     /payment/callback 签名伪造（signType=none 绕过 + canary 金额接管）

隔离：用 monkeypatch 在类级打桩并自动还原，避免污染其它测试文件（verify() 内部会新建
D1Service 实例，必须类级打桩才能覆盖）。
断言口径：replay 返回 confirmed/observed_side_effect/business_confirmed 即自证，
不依赖探针闸门（直击 RC-B/RC-C 根因）。
"""

import re
import json

import pytest

from src.iast.orchestrator import DastImpact
from src.application import d1_service as d1
from src.iast import business_logic


def _imp(status, body="", location=None, reached=True):
    h = {}
    if location:
        h["Location"] = location
    return DastImpact(reached=reached, status_code=status, body=body, headers=h,
                     response_summary="status=%s; body=%s" % (status, str(body)[:120]))


class _Router:
    """靶场 target-mall 状态化桩：按真实端点语义维护订单/库存/领券/余额。"""

    def __init__(self):
        self.orders = {}                 # id(str) -> {status,totalAmount,payAmount,orderNo}
        self.oid = 0
        self.stock = {"1": 5}            # productId -> remainStock
        self.claims = {}                 # (uid,code) -> count
        self.balances = {"1": 100.0, "2": 50.0}
        self.uid = "1"

    def __call__(self, method, url, query, headers, cookies, body, content_type):
        q = dict(query or {})
        m = re.search(r"https?://[^/]+(/.*)$", url) or re.search(r"^(/.*)$", url)
        path = (m.group(1) if m else url).split("?")[0].lstrip("/")

        if method == "POST" and path == "order/buy":
            self.oid += 1
            amt = q.get("amount")
            total = 99.0
            pay = float(amt) if amt not in (None, "") else total
            no = "NO%d" % self.oid
            self.orders[str(self.oid)] = {"status": "CREATED", "totalAmount": total,
                                          "payAmount": pay, "orderNo": no}
            return _imp(302, "", location="/order/%d" % self.oid)
        if method == "POST" and path == "order/checkout":
            self.oid += 1
            amt = q.get("amount")
            total = 199.0
            pay = float(amt) if amt not in (None, "") else total
            no = "NO%d" % self.oid
            self.orders[str(self.oid)] = {"status": "CREATED", "totalAmount": total,
                                          "payAmount": pay, "orderNo": no}
            return _imp(302, "", location="/order/%d" % self.oid)
        if method == "GET" and re.match(r"order/\d+$", path):
            oid = re.search(r"order/(\d+)", path).group(1)
            o = self.orders.get(oid)
            if not o:
                return _imp(404, "not found")
            html = ('订单 <span>%s</span>\n状态：<span class="tag">%s</span>\n'
                    '订单金额：<span class="price">¥%s</span>\n'
                    '实付金额：<span class="price">¥%s</span>') % (
                        o["orderNo"], o["status"], o["totalAmount"], o["payAmount"])
            return _imp(200, html)
        if method == "POST" and re.match(r"order/\d+/ship", path):
            oid = re.search(r"order/(\d+)/ship", path).group(1)
            if oid in self.orders:
                self.orders[oid]["status"] = "SHIPPED"
            return _imp(302, "", location="/order/%s" % oid)
        if method == "POST" and path == "payment/callback":
            no = q.get("orderNo")
            amt = q.get("amount")
            st = q.get("status")
            stype = q.get("signType")
            oid = next((k for k, v in self.orders.items() if v["orderNo"] == no), None)
            if oid and stype == "none":
                self.orders[oid]["status"] = st if st else "PAID"
                if amt is not None:
                    self.orders[oid]["payAmount"] = float(amt)
                return _imp(200, json.dumps({"ok": True, "orderNo": no, "status": st}))
            return _imp(200, json.dumps({"ok": False, "msg": "invalid sign"}))
        if method == "POST" and path == "seckill":
            pid = q.get("productId", "1")
            qty = int(q.get("quantity", "1"))
            s = self.stock.get(pid, 0)
            self.stock[pid] = s - qty          # 非原子扣减：并发下可转负（超卖）
            return _imp(200, json.dumps({"ok": True, "productId": pid, "sold": qty,
                                         "remainStock": self.stock[pid]}))
        if method == "POST" and path == "coupon/claim":
            code = q.get("code", "TEST")
            key = (self.uid, code)
            self.claims[key] = self.claims.get(key, 0) + 1
            return _imp(200, json.dumps({"ok": True, "myCount": self.claims[key]}))
        if method == "GET" and path == "coupon/my":
            cnt = sum(v for k, v in self.claims.items() if k[0] == self.uid)
            return _imp(200, json.dumps({"count": cnt, "claims": []}))
        if method == "POST" and path == "wallet/withdraw":
            amt = float(q.get("amount", "1"))
            self.balances[self.uid] -= amt
            return _imp(200, json.dumps({"ok": True, "newBalance": self.balances[self.uid]}))
        if method == "POST" and path == "wallet/transfer":
            amt = float(q.get("amount", "1"))
            self.balances[self.uid] -= amt     # 仅扣转出方，模拟双重消费
            return _imp(200, json.dumps({"ok": True, "newBalance": self.balances[self.uid]}))
        if method == "GET" and path == "wallet/balance":
            return _imp(200, json.dumps({"userId": self.uid, "balance": self.balances[self.uid]}))
        return _imp(404, "no route: %s %s" % (method, path))


@pytest.fixture
def router(monkeypatch):
    r = _Router()
    monkeypatch.setattr(
        d1.D1Service, "_send_one",
        lambda self, method, url, query, headers, cookies, body, ct: r(
            method, url, query, headers, cookies, body, ct))
    return r


TARGET = {"service_url": "http://target-mall"}
ACCOUNTS = {"attacker": {"user_id": "1", "username": "attacker", "auth_headers": {}, "auth_cookies": {}}}


def test_30_order_buy_amount_tamper(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/order/buy", "http_method": "POST", "category": "calculation_logic"}
    r = svc.replay_calculation(spec, TARGET, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["amount_tampering"] is True
    assert r["observed_side_effect"] is True
    assert r["before_total"] == "99.0"
    assert r["after_pay"] == "0.0"            # amount=0 被采信，金额被篡改为攻击者值


def test_31_order_checkout_amount_tamper(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/order/checkout", "http_method": "POST", "category": "calculation_logic"}
    r = svc.replay_calculation(spec, TARGET, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["amount_tampering"] is True
    assert r["after_pay"] == "0.0"
    assert r["before_total"] == "199.0"


def test_32_state_machine_ship_skip(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/order/{id}/ship", "http_method": "POST", "category": "state_machine"}
    r = svc.replay_state_machine(spec, TARGET, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["state_machine_skip"] is True
    assert r["before_status"] == "CREATED"    # 未付款
    assert r["after_status"] == "SHIPPED"     # 直接发货，跳过 PAID


def test_26_seckill_oversell(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/seckill", "http_method": "POST", "category": "race",
            "param_value": "1", "quantity": "1"}
    r = svc.replay_race(spec, TARGET, concurrency=10, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["race_kind"] == "seckill-oversell"


def test_27_coupon_overclaim(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/coupon/claim", "http_method": "POST", "category": "race",
            "param_value": "TEST"}
    r = svc.replay_race(spec, TARGET, concurrency=5, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["race_kind"] == "coupon-overclaim"


def test_28_wallet_withdraw_overspend(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/wallet/withdraw", "http_method": "POST", "category": "race",
            "param_value": "30"}
    r = svc.replay_race(spec, TARGET, concurrency=5, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["race_kind"] == "wallet-overspend"


def test_29_wallet_transfer_overspend(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/wallet/transfer", "http_method": "POST", "category": "race",
            "param_value": "30", "to_user_id": "2"}
    r = svc.replay_race(spec, TARGET, concurrency=5, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["race_kind"] == "wallet-overspend"


def test_34_callback_signature_forgery(router):
    svc = d1.D1Service(db=None)
    spec = {"target_endpoint": "/payment/callback", "http_method": "POST"}
    r = svc.replay_callback_signature_forgery(spec, TARGET, accounts=ACCOUNTS)
    assert r["confirmed"] is True, r
    assert r["signature_forged"] is True
    assert r["before_status"] == "CREATED"
    assert r["after_status"] == "PAID"
    assert r["after_pay"] == "0.01"            # canary 金额被回调接管


def test_34_callback_dispatch_guard(router):
    """验证 /payment/callback 无论归类（auth_session）都经端点守卫路由到签名伪造差分。"""
    spec = {"target_endpoint": "/payment/callback", "http_method": "POST"}
    # category=auth_session 是 DB 中 /payment/callback 的真实归类之一
    r = business_logic.verify("auth_session", spec, TARGET, accounts=ACCOUNTS, db=None)
    assert r["confirmed"] is True, r
    assert r["signature_forged"] is True


def test_no_class_pollution():
    """确认 monkeypatch 已还原：D1Service._send_one 不再是测试桩。"""
    assert d1.D1Service._send_one.__name__ == "_send_one"
