"""业务逻辑漏洞 六大类 落地验证（重构文档 §2.2 / §7.9，对照 many_md/业务逻辑漏洞.MD）。

覆盖：
- 五个 SAST 分析器（垂直/跨模块越权、状态机、计算逻辑、认证会话、滥用 DoS）各自的「命中 / 不命中」。
- D1 六个重放验证器（replay_vertical / replay_cross_module / replay_state_machine /
  replay_calculation / replay_auth_session / replay_abuse_dos）的「confirmed / no_evidence」，
  均用 mock HTTP 替代真实目标。
- src/iast/business_logic.py 的 analyze（按类目分发） / verify（按类目分发） / status（全类目）。
"""
import unittest
from unittest import mock

import pytest

from src.agents.a1_abuse_dos_analyzer import analyze_file as analyze_abuse
from src.agents.a1_auth_session_analyzer import analyze_file as analyze_auth
from src.agents.a1_calculation_logic_analyzer import analyze_file as analyze_calc
from src.agents.a1_state_machine_analyzer import analyze_file as analyze_state
from src.agents.a1_vertical_privesc_analyzer import analyze_file as analyze_vertical
from src.agents.a1_bola_analyzer import analyze_file as analyze_bola
from src.application.d1_service import D1Service
from src.iast import business_logic as bl


# ---------------- SAST 分析器用例 ----------------
JAVA_VERTICAL_HIT = """
public class AdminController {
    public void deleteUser(@RequestParam String uid, HttpServletRequest req) {
        // 只做身份认证、未校验角色（垂直越权反模式：低权限用户可执行高权限操作）
        if (!loggedIn(req)) { return; }
        userRepository.deleteById(uid);
    }
}
"""
JAVA_VERTICAL_MISS = """
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(@RequestParam String uid) {
    userRepository.deleteById(uid);
}
"""
JAVA_CROSS_MODULE_HIT = """
public class ForumController {
    public Order refund(@RequestBody RefundReq req) {
        return restTemplate.postForObject(internalUrl, req, Order.class);
    }
}
"""
JAVA_CROSS_MODULE_MISS = """
public class ForumController {
    public Order refund(@RequestBody RefundReq req) {
        validateScope(req.getTenantId());
        return restTemplate.postForObject(internalUrl, req, Order.class);
    }
}
"""
# 各业务分析器只产出「带真实 HTTP 路由」的假说（见 a1_state_machine_analyzer 与
# _bl_common.scan_spring_endpoints），这是刻意设计：无路由的假说会被后续漏斗丢弃。
# 因此夹具必须带 Spring 映射注解，否则产出的恒为空集，测的就不是分析器。
JAVA_STATE_HIT = """
    @PostMapping("/order/{orderId}/cancel")
    public void cancelOrder(@PathVariable String orderId) {
        orderRepository.cancel(orderId);
    }
"""
JAVA_STATE_MISS = """
    @PostMapping("/order/{orderId}/cancel")
    public void cancelOrder(@PathVariable String orderId) {
        Order o = orderRepository.findById(orderId);
        if (o.getStatus() != Status.SHIPPED) {
            orderRepository.cancel(orderId);
        }
    }
"""
JAVA_CALC_HIT = """
public Order checkout(@RequestBody Cart cart) {
    int qty = cart.getQuantity();
    BigDecimal total = cart.getPrice().multiply(BigDecimal.valueOf(qty));
    orderRepository.save(total);
}
"""
JAVA_CALC_MISS = """
public Order checkout(@RequestBody Cart cart) {
    int qty = cart.getQuantity();
    if (qty <= 0) throw new IllegalArgumentException("bad qty");
    BigDecimal total = cart.getPrice().multiply(BigDecimal.valueOf(qty));
    orderRepository.save(total);
}
"""
JAVA_AUTH_HIT = """
public Map<String,Object> getCaptcha(String phone) {
    String code = genCode();
    return Map.of("code", code);
}
public void resetPassword(String token, String userId, String newPwd) {
    userRepository.updatePassword(userId, newPwd);
}
"""
JAVA_AUTH_MISS = """
public void sendSms(String phone) {
    String code = genCode();
    smsService.send(phone, code);
    redis.set(phone + ":code", code, 60);
}
public boolean verifyCode(String phone, String code) {
    String stored = redis.get(phone + ":code");
    boolean ok = stored != null && stored.equals(code);
    if (ok) redis.delete(phone + ":code");
    return ok;
}
public void resetPassword(String token, String newPwd) {
    String userId = tokenService.verifyAndGetUser(token);
    userRepository.updatePassword(userId, newPwd);
}
"""
JAVA_ABUSE_HIT = """
public void sendSms(String phone) {
    smsService.send(phone, "hi");
}
"""
JAVA_ABUSE_MISS = """
@RateLimit(perSecond = 1)
public void sendSms(String phone) {
    smsService.send(phone, "hi");
}
"""


def _types(hypos):
    return {h["vuln_type"] for h in hypos}


# ---- 垂直越权 ----
def test_vertical_hit():
    hypos = analyze_vertical("AdminController.java", JAVA_VERTICAL_HIT, "java")
    assert any(h["vuln_type"] == "vertical_privesc" for h in hypos)


def test_vertical_miss_with_role_check():
    hypos = analyze_vertical("AdminController.java", JAVA_VERTICAL_MISS, "java")
    assert hypos == []


# ---- 跨模块越权 ----
def test_cross_module_hit():
    hypos = analyze_vertical("ForumController.java", JAVA_CROSS_MODULE_HIT, "java")
    assert any(h["vuln_type"] == "cross_module_privesc" for h in hypos)


def test_cross_module_miss_with_scope_check():
    hypos = analyze_vertical("ForumController.java", JAVA_CROSS_MODULE_MISS, "java")
    assert all(h["vuln_type"] != "cross_module_privesc" for h in hypos)


# ---- 状态机 ----
def test_state_machine_hit():
    hypos = analyze_state("OrderController.java", JAVA_STATE_HIT, "java")
    assert any(h["vuln_type"] == "STATE_MACHINE" for h in hypos)


def test_state_machine_miss_with_guard():
    hypos = analyze_state("OrderController.java", JAVA_STATE_MISS, "java")
    assert hypos == []


# ---- 计算逻辑 ----
def test_calculation_hit():
    hypos = analyze_calc("Checkout.java", JAVA_CALC_HIT, "java")
    assert any(h["vuln_type"] == "CALCULATION_LOGIC" for h in hypos)


def test_calculation_miss_with_validation():
    hypos = analyze_calc("Checkout.java", JAVA_CALC_MISS, "java")
    assert hypos == []


# ---- 认证会话 ----
def test_auth_session_hit():
    hypos = analyze_auth("AuthController.java", JAVA_AUTH_HIT, "java")
    types = _types(hypos)
    assert "AUTH_CAPTCHA" in types
    assert "AUTH_PASSWORD_RESET" in types


def test_auth_session_miss():
    hypos = analyze_auth("AuthController.java", JAVA_AUTH_MISS, "java")
    assert hypos == []


# ---- 滥用 DoS ----
def test_abuse_dos_hit():
    hypos = analyze_abuse("NotifyController.java", JAVA_ABUSE_HIT, "java")
    assert any(h["vuln_type"] == "ABUSE_DOS" for h in hypos)


def test_abuse_dos_miss_with_ratelimit():
    hypos = analyze_abuse("NotifyController.java", JAVA_ABUSE_MISS, "java")
    assert hypos == []


# ---------------- D1 重放验证器用例（mock HTTP） ----------------
class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


def test_d1_vertical_confirmed():
    spec = {"target_endpoint": "/api/admin/deleteUser", "http_method": "POST",
            "param_name": "uid", "param_location": "body", "param_value": "5"}
    target = {"service_url": "http://t"}
    accounts = {"attacker": {"auth_headers": {"Authorization": "Bearer low"}}}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_vertical(spec, target, accounts=accounts)
    assert out["confirmed"] is True
    assert out["verdict"] == "confirmed"


def test_d1_vertical_no_evidence():
    spec = {"target_endpoint": "/api/admin/deleteUser", "http_method": "POST",
            "param_name": "uid", "param_location": "body", "param_value": "5"}
    target = {"service_url": "http://t"}
    accounts = {"attacker": {"auth_headers": {"Authorization": "Bearer low"}}}

    def fake(method, url, **kwargs):
        return _Resp(403, "forbidden")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_vertical(spec, target, accounts=accounts)
    assert out["confirmed"] is False


def test_d1_cross_module_confirmed():
    spec = {"target_endpoint": "/api/mall/refund", "http_method": "POST"}
    target = {"service_url": "http://t", "auth_context": {"auth_headers": {"Authorization": "Bearer forum-token"}}}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_cross_module(spec, target)
    assert out["confirmed"] is True


def test_d1_state_machine_confirmed():
    spec = {"target_endpoint": "/api/order/cancel", "http_method": "POST"}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_state_machine(spec, target)
    assert out["confirmed"] is True


def test_d1_calculation_confirmed():
    spec = {"target_endpoint": "/api/checkout", "http_method": "POST",
            "param_name": "quantity", "param_location": "body", "variant_value": "-1"}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, '{"total": -10, "status":"success"}')
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_calculation(spec, target)
    assert out["confirmed"] is True
    assert out["negative_total_observed"] is True


def test_d1_calculation_no_evidence():
    spec = {"target_endpoint": "/api/checkout", "http_method": "POST",
            "param_name": "quantity", "param_location": "body", "variant_value": "-1"}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, '{"total": 100, "status":"success"}')
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_calculation(spec, target)
    assert out["confirmed"] is False
    assert out["negative_total_observed"] is False


def test_d1_auth_session_confirmed():
    spec = {"target_endpoint": "/api/reset", "http_method": "POST",
            "body": {"userId": "victim", "code": "1234", "newPwd": "x"}}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_auth_session(spec, target)
    assert out["confirmed"] is True


def test_d1_abuse_dos_confirmed():
    spec = {"target_endpoint": "/api/sendSms", "http_method": "POST"}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_abuse_dos(spec, target, concurrency=5)
    assert out["confirmed"] is True
    assert out["throttled_count"] == 0


def test_d1_abuse_dos_no_evidence():
    spec = {"target_endpoint": "/api/sendSms", "http_method": "POST"}
    target = {"service_url": "http://t"}

    def fake(method, url, **kwargs):
        return _Resp(429, "too many requests")
    with mock.patch("requests.request", side_effect=fake):
        out = D1Service().replay_abuse_dos(spec, target, concurrency=5)
    assert out["confirmed"] is False
    assert out["throttled_count"] == 5


# ---------------- 编排层 analyze / verify / status ----------------
def test_bl_status_all_categories():
    st = bl.business_logic_status()
    assert st["delivered"] is True
    cats = st["categories"]
    for c in ("bola", "vertical_privesc", "cross_module_privesc", "state_machine",
              "calculation_logic", "auth_session", "abuse_dos"):
        assert cats[c]["supported"] is True


@pytest.fixture
def _force_offline_gateway(monkeypatch):
    """本测试验证离线启发式分类（六大类全覆盖），不应依赖在线 LLM。
    resolve_llm_config 会从磁盘 config.yaml 补 llm 段，Ollama 在线时 gateway 会变在线、
    改走 LLM 路径（8B 未必能稳定吐出全部类目）→ 断言失败。强制离线以锁定确定性路径。"""
    import src.core.model_gateway as mg
    monkeypatch.setattr(mg.ModelGateway, "is_offline", property(lambda self: True))


@pytest.mark.usefixtures("_force_offline_gateway")
def test_bl_analyze_covers_all_categories():
    files = [
        {"path": "AdminController.java", "content": JAVA_VERTICAL_HIT, "language": "java"},
        {"path": "ForumController.java", "content": JAVA_CROSS_MODULE_HIT, "language": "java"},
        {"path": "OrderController.java", "content": JAVA_STATE_HIT, "language": "java"},
        {"path": "Checkout.java", "content": JAVA_CALC_HIT, "language": "java"},
        {"path": "AuthController.java", "content": JAVA_AUTH_HIT, "language": "java"},
        {"path": "NotifyController.java", "content": JAVA_ABUSE_HIT, "language": "java"},
    ]
    hypos = bl.analyze(files)
    cats = {h["category"] for h in hypos}
    for c in ("vertical_privesc", "cross_module_privesc", "state_machine",
              "calculation_logic", "auth_session", "abuse_dos"):
        assert c in cats


def test_bl_verify_dispatch_vertical():
    spec = {"target_endpoint": "/api/admin/deleteUser", "http_method": "POST",
            "param_name": "uid", "param_location": "body", "param_value": "5"}
    target = {"service_url": "http://t"}
    accounts = {"attacker": {"auth_headers": {"Authorization": "Bearer low"}}}

    def fake(method, url, **kwargs):
        return _Resp(200, "ok")
    with mock.patch("requests.request", side_effect=fake):
        out = bl.verify("vertical_privesc", spec, target, accounts=accounts)
    assert out["confirmed"] is True


# ---------------- Q2：非 ORM 形态业务逻辑漏洞离线补位（java-quote 类内存态靶场）----------------
JAVA_MASS_ASSIGNMENT_HIT = """
public class QuoteService {
    private Map<String, Object> userConfig = new HashMap<>();
    public void importConfig(Map<String, Object> config) {
        if (config == null) return;
        userConfig.putAll(config);   // 外部 Map 整体并入内部状态，无字段校验
    }
}
"""
JAVA_SENSITIVE_EXPOSE_HIT = """
public class QuoteService {
    private Map<String, Object> quoteCache = new HashMap<>();
    public Map<String, Object> getQuoteCache() {
        return quoteCache;   // 直接返回内部可变容器引用
    }
}
"""
JAVA_MASS_ASSIGNMENT_MISS = """
public class SafeService {
    private final Map<String, Object> config = new HashMap<>();
    public void importConfig(Map<String, Object> config) {
        if (config == null) return;
        String name = (String) config.get("name");   // 仅取白名单字段
        if (name != null) this.config.put("name", name);
    }
}
"""


def test_q2_bola_mass_assignment_detected():
    """Q2：外部 Map 整体 putAll 进内部状态应被识别为不安全对象存储 / Mass Assignment。"""
    hypos = analyze_bola("Svc.java", JAVA_MASS_ASSIGNMENT_HIT, "java")
    types = {h["vuln_type"] for h in hypos}
    assert "MASS_ASSIGNMENT" in types, hypos
    assert any(h.get("category") == "不安全对象存储" for h in hypos), hypos


def test_q2_bola_sensitive_exposure_detected():
    """Q2：getter 直接返回内部可变容器引用应被识别为敏感对象暴露。"""
    hypos = analyze_bola("Svc.java", JAVA_SENSITIVE_EXPOSE_HIT, "java")
    types = {h["vuln_type"] for h in hypos}
    assert "SENSITIVE_EXPOSURE" in types, hypos


def test_q2_bola_mass_assignment_whitelisted_fields_not_flagged():
    """Q2：只取白名单字段写入内部状态（无整体 putAll）不应误报 Mass Assignment。"""
    hypos = analyze_bola("Safe.java", JAVA_MASS_ASSIGNMENT_MISS, "java")
    assert all(h["vuln_type"] != "MASS_ASSIGNMENT" for h in hypos), hypos


if __name__ == "__main__":
    unittest.main()
