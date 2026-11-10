"""SCA 驱动选弹接入 D1 投弹链路的测试（2026-08-29）。

锁死三件事：
1. 补位只在「A2 确实没造出真弹」时发生，A2 有弹时不抢戏；
2. 三道闸（可达性 / 弹药库 / 自检）任一不过都必须返回空，让 D1 老实降级；
3. 补位成功后 D1 投出去的是真 gadget，attack_degraded 必须为 False。
"""
import base64
import json
import os

import pytest

from src.iast import attack_context
from src.iast import gadget_builder as _gb


def _gadget_toolchain_ready() -> bool:
    """造弹闭环需要本地 JDK 与 commons-collections jar（第三方二进制不入库）。"""
    try:
        return bool(_gb._resolve_java()) and os.path.isfile(_gb._CC_JAR)
    except Exception:  # noqa: BLE001
        return False


needs_gadget_toolchain = pytest.mark.skipif(
    not _gadget_toolchain_ready(),
    reason="需要本地 JDK 与 commons-collections jar（第三方二进制不入库）",
)

# 合法的 Java 序列化流（AC ED 00 05 开头），供 SCA 补位成功路径的伪造 forge 返回，
# 以通过 selfcheck 门（评审第 3 点：废弹必须被拒，真弹必须过自检）。
REAL_GADGET_B64 = base64.b64encode(b"\xac\xed\x00\x05serializedpayload").decode()


# --------------------------------------------------------------------------- fakes


class FakeDB:
    """最小 DB 桩：只回应 sca_components 与 workspaces 两张表的查询。"""

    def __init__(self, components=None, target_path="D:/proj/app"):
        self.components = components or []
        self.target_path = target_path
        self.queries = []

    def execute(self, sql, params=None, fetchone=False, fetchall=False):
        self.queries.append(sql)
        if "sca_components" in sql:
            rows = [dict(c) for c in self.components]
            return rows if fetchall else (rows[0] if rows else None)
        if "workspaces" in sql:
            row = {"target_path": self.target_path}
            return row if fetchone else [row]
        return None


class FakeForge:
    def __init__(self, payloads=None, reason="ok", source="library"):
        self.payloads = payloads or []
        self.reason = reason
        self.source = source
        self.calls = []

    def forge_from_sca(self, components, family=None, code_root=None, command=None):
        self.calls.append({"components": components, "family": family,
                           "code_root": code_root, "command": command})
        return {
            "payloads": self.payloads,
            "selected_chain": {"id": "cc6"} if self.payloads else None,
            "reachability": {"reachable": bool(self.payloads)},
            "reason": self.reason,
            "source": self.source if self.payloads else "none",
            "degraded": not self.payloads,
        }


# --------------------------------------------------------------------------- 前置门控


def test_skip_for_non_gadget_family():
    """文本族不做 SCA 补位——对它做可达性判定纯属浪费，还可能引入假阴性。"""
    db = FakeDB(components=[{"ecosystem": "maven", "name": "x:y", "version": "1.0"}])
    forge = FakeForge(payloads=["SHOULD_NOT_BE_USED"])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "sqli", "workspace_id": 1}, db=db, forge=forge)
    assert out == []
    assert forge.calls == []


def test_skip_when_family_missing():
    db = FakeDB(components=[{"ecosystem": "maven", "name": "x:y", "version": "1.0"}])
    forge = FakeForge(payloads=["X"])
    assert attack_context.sca_forge_attack_payloads({}, db=db, forge=forge) == []
    assert forge.calls == []


def test_skip_when_no_sca_components():
    db = FakeDB(components=[])
    forge = FakeForge(payloads=["X"])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=db, forge=forge)
    assert out == []
    assert forge.calls == []


@needs_gadget_toolchain
def test_transformer_gadget_built_via_sca_gadget_lib_without_code_root():
    """方案 1a SCA 兜底：deserialization + SCA 确认 commons-collections 在 classpath，
    即便 poc_chain 未标注 transformer 签名、且 code_root 为空，也强制按 ctf-java-quote 模式
    造真 gadget（构造器自带 commons-collections jar，无需 code_root / 代码可达性判定）。
    这是方案 1a 相对旧「code_root 空就跳过」的关键升级：不再因 A2 文本标注缺失而漏造 gadget。
    """
    db = FakeDB(components=[{"ecosystem": "maven", "name": "commons-collections:commons-collections",
                             "version": "3.1"}], target_path="")
    forge = FakeForge(payloads=["X"])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=db)
    assert len(out) == 1
    assert out[0].startswith("rO0AB")  # 合法 Java 序列化流（AC ED 00 05）
    # 方案 1a 拦截了，不应再走 ysoserial/弹药库 forge
    assert forge.calls == []


def test_skip_when_db_is_none():
    forge = FakeForge(payloads=["X"])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=None, forge=forge)
    assert out == []


# --------------------------------------------------------------------------- 正常路径


def test_forge_is_called_with_components_family_and_code_root():
    """SCA 补位（ysoserial/弹药库）路径：deserialization 族、SCA 未确认 commons-collections
    （方案 1a 不拦截）、且有 code_root 时，才走可达性判定 + ysoserial 选弹。
    用「非 gadget 库」组件，确保方案 1a 的 transformer 构造器不会抢在前面。
    """
    comps = [{"ecosystem": "maven", "name": "com.example:other-lib",
              "version": "1.0"}]  # 非 gadget 库 → 方案 1a 不拦截
    db = FakeDB(components=comps, target_path="D:/proj/app")
    forge = FakeForge(payloads=[REAL_GADGET_B64])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=db, forge=forge, command="id")
    assert out == [REAL_GADGET_B64]
    assert forge.calls[0]["family"] == "deserialization"
    assert forge.calls[0]["code_root"] == "D:/proj/app"
    assert forge.calls[0]["command"] == "id"
    assert forge.calls[0]["components"] == comps


@needs_gadget_toolchain
def test_sca_gadget_lib_triggers_transformer_builder():
    """回归：deserialization + SCA 确认 commons-collections，但 poc_chain 未标注 transformer 签名时，
    方案 1a 必须仍能强制造真 gadget——解决 A2 文本标注不稳定导致 gadget 偶发漏造、D1 退化为纯 canary
    的问题（ctf-java-quote /debug/import 反序列化在 run 12/run 13 上曾因此 no-arrival）。
    """
    db = FakeDB(components=[{"ecosystem": "maven", "name": "commons-collections:commons-collections",
                             "version": "3.1"}], target_path="")
    # poc_chain 只有 readObject，没有 commonscollections / transformer.transform 签名
    spec = {"category": "deserialization", "workspace_id": 1,
            "poc_chain_json": json.dumps([
                {"stage": "source", "node": "ois.readObject()",
                 "signature": "ObjectInputStream.readObject()"}])}
    out = attack_context.sca_forge_attack_payloads(spec, db=db)
    assert len(out) == 1
    assert out[0].startswith("rO0AB")  # 合法 Java 序列化流


def test_explicit_code_root_overrides_workspace():
    db = FakeDB(components=[{"ecosystem": "maven", "name": "x:y", "version": "1.0"}],
                target_path="D:/from/workspace")
    forge = FakeForge(payloads=[REAL_GADGET_B64])
    attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1},
        db=db, code_root="D:/explicit", forge=forge)
    assert forge.calls[0]["code_root"] == "D:/explicit"


def test_sca_forge_selfcheck_rejects_fake_payload():
    """评审第 3 点：SCA 补位造出的非合法序列化流必须被 selfcheck 门拒掉（报错而非降级）。"""
    db = FakeDB(components=[{"ecosystem": "maven", "name": "x:y", "version": "1.0"}])
    forge = FakeForge(payloads=["NOT_A_REAL_SERIALIZATION"])
    with pytest.raises(RuntimeError):
        attack_context.sca_forge_attack_payloads(
            {"category": "deserialization", "workspace_id": 1}, db=db, forge=forge)


def test_empty_forge_result_yields_empty_list():
    db = FakeDB(components=[{"ecosystem": "maven", "name": "x:y", "version": "1.0"}])
    forge = FakeForge(payloads=[], reason="可达性不过")
    assert attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=db, forge=forge) == []


def test_forge_exception_is_swallowed_and_degrades():
    class Boom:
        def forge_from_sca(self, *a, **k):
            raise RuntimeError("forge down")

    db = FakeDB(components=[{"ecosystem": "maven", "name": "x:y", "version": "1.0"}])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=db, forge=Boom())
    assert out == []


def test_db_failure_is_swallowed_and_degrades():
    class BadDB:
        def execute(self, *a, **k):
            raise RuntimeError("db down")

    forge = FakeForge(payloads=["X"])
    out = attack_context.sca_forge_attack_payloads(
        {"category": "deserialization", "workspace_id": 1}, db=BadDB(), forge=forge)
    assert out == []


# --------------------------------------------------------------------------- D1 端到端集成


class _Resp:
    status_code = 200
    text = "ok"
    # 2026-09-28（测试桩对齐）：补 headers，与真实 requests.Response 对齐。
    headers = {}


@pytest.fixture
def captured_request(monkeypatch):
    captured = {}

    def fake_request(method, url, **kw):
        captured.update(method=method, url=url, params=kw.get("params"),
                        json_body=kw.get("json"), data=kw.get("data"),
                        headers=kw.get("headers"))
        return _Resp()

    monkeypatch.setattr("src.application.d1_service.requests.request", fake_request)
    return captured


def _spec(**over):
    spec = {
        "http_method": "POST",
        "target_endpoint": "api/deser",
        "param_name": "data",
        "param_location": "body",
        "taint_marker": "CANARY_ABC",
        "category": "deserialization",
        "workspace_id": 1,
        # A2 只产出占位串 —— 这正是 SCA 补位要救的场景
        "attack_payloads_json": json.dumps(["base64(serialized_object)"]),
    }
    spec.update(over)
    return spec


def test_d1_uses_sca_forged_payload_when_a2_only_has_placeholder(monkeypatch, captured_request):
    """核心：A2 只有占位串时，SCA 补位造出真 gadget，D1 投真弹且不算降级。"""
    from src.application.d1_service import D1Service

    monkeypatch.setattr(attack_context, "sca_forge_attack_payloads",
                        lambda spec, db=None, **kw: ["FORGED_GADGET_BYTES"])

    impact = D1Service(db=FakeDB())._replay_attack(
        _spec(), {"service_url": "http://127.0.0.1:8899"})

    assert impact.attack_degraded is False
    assert impact.attack_payload_used == "FORGED_GADGET_BYTES"
    # 真弹在参数位，canary 在请求头 —— 双通道互不干扰
    assert captured_request["json_body"] == {"data": "FORGED_GADGET_BYTES"}
    assert captured_request["headers"]["X-SASTAI-Trace"] == "CANARY_ABC"


def test_d1_degrades_when_sca_forge_also_fails(monkeypatch, captured_request):
    """补位也造不出弹才是真降级：投 canary，标 attack_degraded。"""
    from src.application.d1_service import D1Service

    monkeypatch.setattr(attack_context, "sca_forge_attack_payloads",
                        lambda spec, db=None, **kw: [])

    impact = D1Service(db=FakeDB())._replay_attack(
        _spec(), {"service_url": "http://127.0.0.1:8899"})

    assert impact.attack_degraded is True
    assert impact.attack_payload_used == ""
    assert captured_request["headers"]["X-SASTAI-Trace"] == "CANARY_ABC"


def test_d1_does_not_call_sca_forge_when_a2_has_real_payload(monkeypatch, captured_request):
    """A2 已经造出真弹时，SCA 补位不抢戏（payload 构造优先归 A2）。"""
    from src.application.d1_service import D1Service

    called = []

    def should_not_run(spec, db=None, **kw):
        called.append(spec)
        return ["SCA_GADGET"]

    monkeypatch.setattr(attack_context, "sca_forge_attack_payloads", should_not_run)

    impact = D1Service(db=FakeDB())._replay_attack(
        _spec(attack_payloads_json=json.dumps(["REAL_A2_PAYLOAD"])),
        {"service_url": "http://127.0.0.1:8899"})

    assert called == []
    assert impact.attack_degraded is False
    assert captured_request["json_body"] == {"data": "REAL_A2_PAYLOAD"}
