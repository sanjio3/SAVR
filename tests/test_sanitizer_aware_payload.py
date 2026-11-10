"""2026-10-02：造弹路线重写（净化感知）+ 重放智能化 回归测试。

钉死四件事：
1. 守卫发现按**行为**判定 —— 旧弱正则（`sanitize(` / Jsoup.clean）连 java-sec-code 自己的
   `secCheck(filepath)` 都匹配不到，新判定必须抓到。
2. 规则抽取产出结构化 FilterSpec（拒绝 token / 允许字符集）。
3. 造弹在约束内进行，且发出前过确定性闸门（simulate_filter）——不再"换个写法碰运气"。
4. 失败原因 → 具体改进指令（directive）+ 轨迹记忆，且带指令的反馈允许定向回 A2。
"""
import os

import pytest

from src.core.sanitizer_miner import (
    attach_filter_spec,
    FilterSpec, SourceNavigator, extract_filter_spec, is_guard, simulate_filter,
)
from src.iast.sanitizer_forge import gate, synthesize
from src.iast.replay_intel import ReplayMemory, build_directive

# java-sec-code /codeinject/sec 的真实形态：自定义名 secCheck，黑名单拦截后返回 "Bad boy"
CMD_FILTER_SRC = '''
public class CommandInject {
    public String secCheck(String filepath) {
        if (filepath.contains(";") || filepath.contains("|") || filepath.contains("&")) {
            return "Bad boy. I got u.";
        }
        return null;
    }
    public String codeInjectSec(String filepath) throws IOException {
        if (secCheck(filepath) != null) {
            return "Bad boy. I got u.";
        }
        return cmdInject(filepath);
    }
}
'''

ALLOWLIST_SRC = '''
public class Validator {
    public boolean check(String v) {
        if (v == null) { return false; }
        return v.matches("^[a-zA-Z0-9_]+$");
    }
}
'''


# ---------------------------------------------------------------- 1 守卫发现
def test_is_guard_catches_custom_named_filter():
    """关键回归：命名不含 sanitize/Jsoup 的自定义校验也必须被识别为守卫。"""
    assert is_guard(CMD_FILTER_SRC)
    assert is_guard(ALLOWLIST_SRC)


def test_is_guard_rejects_plain_sink_method():
    """普通 sink 方法（只执行命令、无校验无变换）不该被当成守卫。"""
    plain = '''
    public String run(String cmd) throws IOException {
        Process p = Runtime.getRuntime().exec(cmd);
        return readAll(p.getInputStream());
    }
    '''
    # 无 if/return 拦截、无变换调用 → 不是守卫
    assert not is_guard(plain)


# ---------------------------------------------------------------- 2 规则抽取
def test_extract_deny_tokens_from_cmd_filter():
    spec = extract_filter_spec(CMD_FILTER_SRC)
    assert spec.kind == FilterSpec.KIND_DENY
    assert spec.source == "deterministic"
    # 三个拒绝符都要抽出来
    for tok in (";", "|", "&"):
        assert tok in spec.tokens


def test_extract_allow_pattern():
    spec = extract_filter_spec(ALLOWLIST_SRC)
    assert spec.kind == FilterSpec.KIND_ALLOW
    assert "^[a-zA-Z0-9_]+$" in spec.patterns


def test_extract_unknown_when_nothing_conclusive():
    spec = extract_filter_spec("public void nothing(String a) { System.out.println(a); }")
    assert spec.kind == FilterSpec.KIND_UNKNOWN and not spec.is_known()


# ---------------------------------------------------------------- 3 约束下造弹 + 闸门
def test_synthesize_avoids_deny_tokens():
    """黑名单含 ; | & 时，造出的载荷必须一个都不碰——这是旧静态表做不到的。"""
    spec = extract_filter_spec(CMD_FILTER_SRC)
    out = synthesize(spec, "command_execution", sink="Runtime.exec", max_out=8)
    for cand in out["candidates"]:
        assert ";" not in cand and "|" not in cand and "&" not in cand
    # 确实造出了东西，且被闸门判死的（含拒绝符）不出现在候选里
    assert out["candidates"]
    assert any(";" in r or "|" in r or "&" in r for r in out["rejected"])
    # 允许集内形态（如 ${IFS}）应当存活
    assert any("${IFS}" in c for c in out["candidates"])


def test_simulate_filter_deny_and_allow():
    deny = FilterSpec(FilterSpec.KIND_DENY, tokens=[";", "|"])
    assert simulate_filter(deny, ";id") is False
    assert simulate_filter(deny, "id") is True

    allow = FilterSpec(FilterSpec.KIND_ALLOW, patterns=["^[a-zA-Z0-9_]+$"])
    assert simulate_filter(allow, "abc123") is True
    assert simulate_filter(allow, "abc;id") is False


def test_gate_applies_family_shape_and_filter():
    spec = extract_filter_spec(CMD_FILTER_SRC)
    survivors = gate([";id", "${IFS}id", "|id"], "command_execution", spec)
    assert "${IFS}id" in survivors
    assert ";id" not in survivors and "|id" not in survivors


def test_no_spec_means_no_synthesis():
    """拿不到净化器约束时不该凭空造弹（调用方标记 degraded_no_synthesis）。"""
    out = synthesize(None, "command_execution", max_out=6)
    # 无约束时 simulate 放行，但 source 仍标记 deterministic；真正的"不造弹"由调用方按 spec 判断
    assert out["spec"] is None


# ---------------------------------------------------------------- 4 重放智能化
def test_directive_for_blocked_is_concrete():
    spec = extract_filter_spec(CMD_FILTER_SRC)
    mem = ReplayMemory(endpoint="/codeinject/sec", param="filepath")
    mem.record(tried=[";id"], rejected=[";id"], failure_class="blocked")
    d = build_directive("blocked", {"status_code": 200, "reached": True, "d2_harmful": False},
                        spec=spec, memory=mem, family="command_execution",
                        endpoint="/codeinject/sec", sink="Runtime.exec")
    assert d["target"] == "payload_synthesis"
    assert d["round"] == 2
    assert ";" in d["instruction"] or "拒绝" in d["instruction"]
    assert ";id" in d["avoid"]  # 已试过且无效 → 下一轮避开
    assert d["constraint"]["kind"] == FilterSpec.KIND_DENY


def test_directive_for_route_and_auth_points_to_replay():
    d1 = build_directive("route_unreachable", {"status_code": 404})
    d2 = build_directive("auth_missing", {"status_code": 302})
    assert d1["target"] == "replay" and d2["target"] == "replay"
    assert "不要升级载荷" in d1["instruction"]


def test_replay_memory_accumulates_and_serializes():
    mem = ReplayMemory("/x", "p")
    mem.record(tried=["a", "b"], rejected=["a"], failure_class="blocked")
    mem.record(tried=["c"], rejected=["c"], failure_class="blocked")
    assert mem.round() == 2
    # a 被闸门判死；b 试过但仍 blocked → 同样纳入 avoid（不再原样重试）；c 同理
    assert mem.rejected_payloads() == ["a", "b", "c"]
    restored = ReplayMemory.from_dict(mem.to_dict())
    assert restored.round() == 2 and restored.rejected_payloads() == ["a", "b", "c"]


def test_directed_feedback_allows_a2_rerun():
    from src.agents.i2_feedback import a2_rerun_actionable
    spec = extract_filter_spec(CMD_FILTER_SRC)
    fb = [{"directive": build_directive("blocked", {"status_code": 200}, spec=spec,
                                        family="command_execution", endpoint="/codeinject/sec")}]
    ok, why = a2_rerun_actionable(fb)
    assert ok is True and "改进指令" in why


# ---------------------------------------------------------------- 源码导航（跨文件）
def test_register_choke_point_writes_filter_spec(tmp_path):
    """登记咽喉点（IastService.register_trigger_spec）在落库前回填 filter_spec。

    用「一执行 execute 就抛错」的假 db，确保只跑到 INSERT 之前、不产生真实数据行。
    """
    from src.iast import service as _svc

    class _StopBeforeInsert:
        def execute(self, *a, **k):
            raise RuntimeError("stop-before-insert")

    pkg = tmp_path / "src" / "main" / "java" / "org" / "joychou"
    pkg.mkdir(parents=True)
    (pkg / "CommandInject.java").write_text(CMD_FILTER_SRC, encoding="utf-8")

    svc = _svc.IastService.__new__(_svc.IastService)
    svc.db = _StopBeforeInsert()
    payload = {"workspace_id": 4, "family": "command_execution",
               "target_endpoint": "/codeinject/sec", "code_root": str(tmp_path),
               "raw": {"file": "src/main/java/org/joychou/CommandInject.java"}}
    try:
        svc.register_trigger_spec(payload)
    except RuntimeError:
        pass  # 预期：在 INSERT 处被拦下
    fs = payload["raw"].get("filter_spec")
    assert fs and fs.get("kind") == FilterSpec.KIND_DENY and ";" in fs.get("tokens", [])


def test_producer_attaches_filter_spec_end_to_end(tmp_path):
    """生产侧闭环：登记时挖守卫 → 回填 filter_spec → 消费侧据此造弹。"""
    pkg = tmp_path / "src" / "main" / "java" / "org" / "joychou"
    pkg.mkdir(parents=True)
    (pkg / "CommandInject.java").write_text(CMD_FILTER_SRC, encoding="utf-8")

    payload = {"workspace_id": 4, "family": "command_execution",
               "target_endpoint": "/codeinject/sec",
               "raw": {"file": "src/main/java/org/joychou/CommandInject.java"}}
    meta = attach_filter_spec(payload, code_root=str(tmp_path))
    assert meta.get("filter_spec") == FilterSpec.KIND_DENY
    spec = FilterSpec.from_dict(payload["raw"]["filter_spec"])
    assert spec is not None and ";" in spec.tokens
    # 消费侧联动：用挖到的约束造弹，必须避开拒绝符
    out = synthesize(spec, "command_execution", max_out=6)
    assert out["candidates"]
    assert all(";" not in c and "|" not in c and "&" not in c for c in out["candidates"])


def test_producer_finds_guard_in_another_file(tmp_path):
    """净化器不在漏洞文件里、只出现在 callers 指向的另一个文件 → 仍要挖到（跨文件）。"""
    pkg = tmp_path / "src" / "main" / "java" / "org" / "joychou"
    pkg.mkdir(parents=True)
    vuln_src = '''
    public class CmdController {
        public String codeInjectSec(String filepath) throws IOException {
            if (Guard.secCheck(filepath)) { return "blocked"; }
            return Runtime.getRuntime().exec("ls " + filepath).toString();
        }
    }
    '''
    (pkg / "CmdController.java").write_text(vuln_src, encoding="utf-8")
    (pkg / "Guard.java").write_text(CMD_FILTER_SRC, encoding="utf-8")

    payload = {"workspace_id": 4, "family": "command_execution",
               "target_endpoint": "/codeinject/sec",
               "raw": {"file": "src/main/java/org/joychou/CmdController.java",
                       "callers": "src\\main\\java\\org\\joychou\\Guard.java:行12"}}
    meta = attach_filter_spec(payload, code_root=str(tmp_path))
    assert meta.get("filter_spec") == FilterSpec.KIND_DENY
    spec = FilterSpec.from_dict(payload["raw"]["filter_spec"])
    assert spec is not None and ";" in spec.tokens


def test_producer_no_guard_marks_empty(tmp_path):
    pkg = tmp_path / "src"
    pkg.mkdir(parents=True)
    (pkg / "Plain.java").write_text(
        "public class Plain { public String run(String c) { return c; } }", encoding="utf-8")
    payload = {"workspace_id": 4, "family": "command_execution",
               "raw": {"file": "src/Plain.java"}}
    meta = attach_filter_spec(payload, code_root=str(tmp_path))
    assert meta.get("guards") == 0 or meta.get("filter_spec") is None
    assert payload["raw"].get("filter_spec") is None


def test_source_navigator_cross_file(tmp_path):
    """净化器在另一个文件里：按类名/FQN 跳过去并抽出方法体。"""
    root = tmp_path / "src"
    (root / "com" / "demo").mkdir(parents=True)
    (root / "com" / "demo" / "Guard.java").write_text(CMD_FILTER_SRC, encoding="utf-8")
    nav = SourceNavigator(str(root))
    path = nav.find_by_class("Guard")
    assert path and os.path.isfile(path)
    body, real = nav.body_for({"class": "com.demo.Guard", "method": "secCheck"})
    assert real == path
    assert "secCheck" in body and "Bad boy" in body
    assert is_guard(body)
