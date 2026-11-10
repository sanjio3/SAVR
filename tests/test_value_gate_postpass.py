"""Phase 2 值级 sink 实参闸 post-pass 的单测。

锁住三条行为约定（r102 cmdi 真值验证过的口径）：
  1. 用例级聚合：某 endpoint 的**全部** spec 都判 absent 才否决；
  2. 任一 spec 判 at_sink 或 no_event → 整个用例保留（不误杀真报 / 证据不足不动）；
  3. 默认只对 command_execution 生效，族白名单可用环境变量扩展；总开关可关。
"""
from __future__ import annotations

import importlib

import pytest

IDENT_A = "s4st41" + "a" * 16
IDENT_B = "s4st41" + "b" * 16
IDENT_C = "s4st41" + "c" * 16
IDENT_D = "s4st41" + "d" * 16
PAYLOAD = "7*7"


def _marker(ident: str, payload: str = PAYLOAD) -> str:
    return f"{ident}PAYLOAD{payload}"


class FakeSDB:
    """最小 sdb 替身：支持本 post-pass 用到的一条 SELECT / 一条 SELECT / 一条 UPDATE。"""

    def __init__(self, specs, events):
        self.specs = specs
        self.events = events
        self.updates = []

    def execute(self, sql, params=None, fetchall=False):
        s = " ".join(str(sql).split())
        if s.startswith("SELECT id, target_endpoint"):
            return [dict(x) for x in self.specs if not x.get("suppressed_by_safe_verdict")]
        if s.startswith("SELECT sink_file, source_value, evidence_json FROM iast_events"):
            return list(self.events.get(params[1], []))
        if s.startswith("UPDATE trigger_specs SET suppressed_by_safe_verdict=1"):
            # 2026-10-18：UPDATE 参数改为 (iast_state, spec_id)，取末位 id
            self.updates.append(params[-1])
            return None
        return [] if fetchall else None


def _spec(sid, endpoint, marker, family="command_execution", sink="BenchmarkTest00006.java"):
    return {
        "id": sid,
        "target_endpoint": endpoint,
        "expected_sink_file": sink,
        "taint_marker": marker,
        "family": family,
        "capability_family": family,
        "verification_status": "confirmed_exploitable",
        "suppressed_by_safe_verdict": 0,
    }


@pytest.fixture()
def cli():
    return importlib.import_module("src.cli.benchmark_cli")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE", "1")
    monkeypatch.delenv("SAST_AI_VALUE_GATE_FAMILIES", raising=False)


def test_all_absent_vetoes_whole_case(cli):
    specs = [
        _spec(1, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_A)),
        _spec(2, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_A)),
    ]
    # 真 sink 已到达，但实参里是常量命令（没有 payload）
    events = {IDENT_A: [{"sink_file": "java/lang/Runtime.exec",
                         "source_value": "[[cmd.exe, /c, echo bar]]",
                         "evidence_json": "{}"}]}
    sdb = FakeSDB(specs, events)
    n = cli._apply_sink_value_gate_postpass(1, sdb)
    assert n == 2
    assert sorted(sdb.updates) == [1, 2]


def test_at_sink_keeps_case(cli):
    specs = [
        _spec(1, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_A)),
        _spec(2, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_B)),
    ]
    events = {
        IDENT_A: [{"sink_file": "java/lang/Runtime.exec",
                   "source_value": f"[[cmd.exe, /c, echo {PAYLOAD}]]", "evidence_json": "{}"}],
        IDENT_B: [{"sink_file": "java/lang/Runtime.exec",
                   "source_value": "[[cmd.exe, /c, echo bar]]", "evidence_json": "{}"}],
    }
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_no_event_does_not_veto(cli):
    specs = [_spec(1, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_C))]
    sdb = FakeSDB(specs, {})  # 没有任何事件 → no_event
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_non_allowlisted_family_skipped(cli):
    # 2026-10-19：ldap_injection 已按族验收（run 403 at_sink 100% / absent 纯度 100%）
    # 纳入默认族，故这里改用仍不在默认名单的 securecookie（属性族，走 family_route
    # safe_impl 通道而非值级闸）。
    specs = [_spec(1, "/securecookie-00/BenchmarkTest00100", _marker(IDENT_D), family="securecookie")]
    events = {IDENT_D: [{"sink_file": "javax.servlet.http.Cookie.setSecure",
                         "source_value": "[color]", "evidence_json": "{}"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_family_allowlist_env_extends(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "command_execution,sql_injection")
    specs = [_spec(1, "/sqli-00/BenchmarkTest00100", _marker(IDENT_D), family="sql_injection")]
    events = {IDENT_D: [{"sink_file": "java/sql/Statement.execute",
                         "source_value": "SELECT * FROM USERS", "evidence_json": "{}"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 1
    assert sdb.updates == [1]


def test_master_switch_off(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE", "0")
    specs = [_spec(1, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_A))]
    events = {IDENT_A: [{"sink_file": "java/lang/Runtime.exec",
                         "source_value": "[[cmd.exe, /c, echo bar]]", "evidence_json": "{}"}]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_already_suppressed_specs_ignored(cli):
    sp = _spec(1, "/cmdi-00/BenchmarkTest00006", _marker(IDENT_A))
    sp["suppressed_by_safe_verdict"] = 1
    events = {IDENT_A: [{"sink_file": "java/lang/Runtime.exec",
                         "source_value": "[[cmd.exe, /c, echo bar]]", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0


# ── 2026-10-18 值级闸 token 校准（按探针实测 sink_file 扩张四族）行为测试 ──
# 用真实 DB 形态（点号包路径）的 sink_file 字符串，锁住新 token 真正接入判定。

def test_sql_mybatis_new_token_at_sink_keeps(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "sql_injection")
    sp = _spec(1, "/sqli-00/BenchmarkTest00100", _marker(IDENT_A), family="sql_injection")
    events = {IDENT_A: [{"sink_file": "org.apache.ibatis.executor.CachingExecutor.query",
                         "source_value": f"SELECT * FROM t WHERE x='{PAYLOAD}'", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_sql_mybatis_new_token_absent_veto(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "sql_injection")
    sp = _spec(1, "/sqli-00/BenchmarkTest00100", _marker(IDENT_A), family="sql_injection")
    # 真 sink 已到达，但实参是常量 SQL（无 payload）→ absent → 否决
    events = {IDENT_A: [{"sink_file": "org.apache.ibatis.executor.CachingExecutor.query",
                         "source_value": "SELECT * FROM t WHERE x='bar'", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 1
    assert sdb.updates == [1]


def test_xss_println_new_token_at_sink_keeps(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "xss")
    sp = _spec(1, "/xss-00/BenchmarkTest00200", _marker(IDENT_A), family="xss")
    events = {IDENT_A: [{"sink_file": "org.apache.catalina.connector.CoyoteWriter.println",
                         "source_value": f"<html>{PAYLOAD}</html>", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_trustbound_session_setattribute_new_token_keeps(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
    sp = _spec(1, "/trustbound-00/BenchmarkTest00300", _marker(IDENT_A),
               family="trust_boundary_violation")
    events = {IDENT_A: [{"sink_file": "org.apache.catalina.session.StandardSession.setAttribute",
                         "source_value": f"[{PAYLOAD}, 10340]", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_xpath_impl_new_token_keeps(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "xpath_injection")
    sp = _spec(1, "/xpathi-00/BenchmarkTest00400", _marker(IDENT_A), family="xpath_injection")
    events = {IDENT_A: [{"sink_file": "com.sun.org.apache.xpath.internal.jaxp.XPathImpl.evaluate",
                         "source_value": f"/root[contains(.,'{PAYLOAD}')]", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_bypass_sink_never_matches_dataflow_token(cli, monkeypatch):
    # Response.setHeader 是旁路 sink，绝不能因 payload 在其中就被判 at_sink/否决
    monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "xss,sql_injection")
    sp = _spec(1, "/xss-00/BenchmarkTest00200", _marker(IDENT_A), family="xss")
    # 唯一事件是无关节点 setHeader，且含 payload —— 应 no_event（不否决，证据不足）
    events = {IDENT_A: [{"sink_file": "org.apache.catalina.connector.Response.setHeader",
                         "source_value": f"Location: {PAYLOAD}", "evidence_json": "{}"}]}
    sdb = FakeSDB([sp], events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


class TestStrictVeto:
    """2026-10-18 严格模式（opt-in）：到达应用但无 at_sink → 否决。

    三重守卫：族覆盖（同 task 该族已有 at_sink）+ 到达（canary 有事件）+ 无 at_sink。
    只对 SAST_AI_VALUE_GATE_STRICT_FAMILIES 生效（默认 trust_boundary_violation,xss）。
    """

    def _tb(self, sid, ep, ident):
        return _spec(sid, ep, _marker(ident), family="trust_boundary_violation")

    def _cov(self, ident):
        return {"sink_file": "org.apache.catalina.session.StandardSessionFacade.setAttribute",
                "source_value": f"[userid, {_marker(ident)}]", "evidence_json": "{}"}

    def _noise(self):
        return {"sink_file": "javax.servlet.http.Cookie.<init>",
                "source_value": "[JSESSIONID, abc]", "evidence_json": "{}"}

    def _absent(self, ident):
        """族 sink 已到达，但实参里没有我方 payload → verdict=absent。"""
        return {"sink_file": "org.apache.catalina.session.StandardSessionFacade.setAttribute",
                "source_value": "[userid, someone-else]", "evidence_json": "{}"}

    def test_strict_vetoes_arrived_case_without_at_sink(self, cli, monkeypatch):
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        # 本例族覆盖 = 1 at_sink / 2 判定 = 0.5，显式放宽阈值以隔离「覆盖守卫」的干扰
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.5")
        sp_cov = self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)
        # 混合用例：一条 absent（反证）+ 一条 no_event ⇒ 基础规则不触发，只有严格模式能砍
        sp_fp = self._tb(2, "/tb/BenchmarkTest00002", IDENT_B)
        sp_np = self._tb(3, "/tb/BenchmarkTest00002", IDENT_C)
        sdb = FakeSDB([sp_cov, sp_fp, sp_np],
                      {IDENT_A: [self._cov(IDENT_A)], IDENT_B: [self._absent(IDENT_B)],
                       IDENT_C: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 2
        assert sorted(sdb.updates) == [2, 3]

    def test_strict_off_by_default(self, cli, monkeypatch):
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.delenv("SAST_AI_VALUE_GATE_STRICT", raising=False)
        sp_cov = self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)
        sp_fp = self._tb(2, "/tb/BenchmarkTest00002", IDENT_B)
        sdb = FakeSDB([sp_cov, sp_fp], {IDENT_A: [self._cov(IDENT_A)], IDENT_B: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
        assert sdb.updates == []

    def test_strict_requires_family_coverage(self, cli, monkeypatch):
        # 同 task 该族没有任何 at_sink → 探针可能没织到该族 sink → 不否决
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        sp_fp = self._tb(2, "/tb/BenchmarkTest00002", IDENT_B)
        sdb = FakeSDB([sp_fp], {IDENT_B: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
        assert sdb.updates == []

    def test_strict_requires_arrival_evidence(self, cli, monkeypatch):
        # canary 零事件（重放未送达）→ 不是「非可利用证据」→ 不否决
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.5")
        sp_cov = self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)
        sp_fp = self._tb(2, "/tb/BenchmarkTest00002", IDENT_B)
        sdb = FakeSDB([sp_cov, sp_fp], {IDENT_A: [self._cov(IDENT_A)]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
        assert sdb.updates == []

    def test_strict_not_applied_to_other_family(self, cli, monkeypatch):
        # sql_injection 不在严格族名单 → 到达但无 at_sink 也不否决
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "sql_injection")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        sp_cov = _spec(1, "/s/BenchmarkTest00001", _marker(IDENT_A), family="sql_injection")
        sp_fp = _spec(2, "/s/BenchmarkTest00002", _marker(IDENT_B), family="sql_injection")
        sdb = FakeSDB([sp_cov, sp_fp], {
            IDENT_A: [{"sink_file": "org.hsqldb.jdbc.JDBCStatement",
                       "source_value": f"SELECT '{_marker(IDENT_A)}'", "evidence_json": "{}"}],
            IDENT_B: [{"sink_file": "javax.servlet.http.Cookie.<init>",
                       "source_value": "[JSESSIONID, abc]", "evidence_json": "{}"}],
        })
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
        assert sdb.updates == []


    def test_strict_blocked_when_family_coverage_below_threshold(self, cli, monkeypatch):
        """回归锁（2026-10-18 实战咬人）：族覆盖不足时严格模式必须闭嘴。

        事故：r107 的 run 386 是**补 compile hook 之前**跑的 xpathi，7/15 个 TP 被判
        absent（覆盖率 47%），但族里存在 at_sink ⇒ 旧守卫「≥1 条 at_sink」放行 ⇒
        严格模式误杀 8 个真 TP（对账抑损 8）。
        现在守卫是覆盖率阈值（默认 0.6），本例 1/3 = 33% → 必须不否决。
        """
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.6")
        # 2026-10-20（阶段1扩族）：trust_boundary_violation 已纳入 strict-C，混合用例会先命中
        # strict-C。本测试只验「旧 strict 模式的覆盖率守卫」，故显式把 strict-C 隔离回旧集。
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_C_FAMILIES",
                           "ldap_injection,sql_injection,command_execution")
        # 注意：这里必须用**混合用例**（absent + no_event）来隔离「严格模式」的作用——
        # 全 absent 的用例会被基础规则直接否决，测不出守卫。
        sp_cov = self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)      # at_sink 用例
        sp_a2 = self._tb(2, "/tb/BenchmarkTest00002", IDENT_B)       # 混合用例：absent
        sp_n2 = self._tb(3, "/tb/BenchmarkTest00002", IDENT_C)       # 混合用例：no_event
        sp_a3 = self._tb(4, "/tb/BenchmarkTest00003", IDENT_B)       # 混合用例：absent
        sp_n3 = self._tb(5, "/tb/BenchmarkTest00003", IDENT_C)       # 混合用例：no_event
        sdb = FakeSDB(
            [sp_cov, sp_a2, sp_n2, sp_a3, sp_n3],
            {IDENT_A: [self._cov(IDENT_A)], IDENT_B: [self._absent(IDENT_B)],
             IDENT_C: [self._noise()]},
        )
        # 用例级判别力 = 1 at_sink / (1 + 2 个含 absent 的用例) = 0.33 < 0.6 → 严格模式必须闭嘴
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
        assert sdb.updates == []

    def test_strict_allowed_when_coverage_meets_threshold(self, cli, monkeypatch):
        """对照组：同样的族，覆盖率 3/4 = 75% ≥ 0.6 → 严格模式应生效并否决无 at_sink 的用例。"""
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.6")
        specs = [self._tb(1, "/tb/BenchmarkTest00001", IDENT_A),
                 self._tb(2, "/tb/BenchmarkTest00002", IDENT_A),
                 self._tb(3, "/tb/BenchmarkTest00003", IDENT_A)]
        # 三个 at_sink 用例 + 一个混合用例（absent + no_event）⇒ 用例级 3/4 = 0.75 ≥ 0.6 → 放行
        sp_fp = self._tb(4, "/tb/BenchmarkTest00004", IDENT_B)
        sp_np = self._tb(5, "/tb/BenchmarkTest00004", IDENT_C)
        sdb = FakeSDB(specs + [sp_fp, sp_np],
                      {IDENT_A: [self._cov(IDENT_A)], IDENT_B: [self._absent(IDENT_B)],
                       IDENT_C: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 2
        assert sorted(sdb.updates) == [4, 5]


    def test_strict_coverage_is_case_level_not_spec_level(self, cli, monkeypatch):
        """回归锁（2026-10-18 二次修正）：判别力必须按**用例**算，不能被多 spec 结构稀释。

        r109 实测：xpathi 的 TP 用例每条有 6 个 spec，只有 1–2 个 at_sink。按 spec 级算
        覆盖率只有 28/80 = 35% ⇒ 守卫误判「判据不可信」而闭嘴，14 个 FP 用例全部漏杀。
        按用例级算：到达族 sink 的用例里 15 个有 payload、10 个没有 = 60% ⇒ 正常放行。

        本例：1 个 at_sink 用例（含 6 个 spec，其中 5 个 no_event）+ 1 个 absent 用例
        ⇒ 用例级 1/2 = 0.5（阈值 0.5 → 放行）；spec 级只有 1/7 = 14%（会误拦）。
        """
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.5")
        specs = [self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)]
        # 同案再挂 5 个「零事件」spec，把 spec 级分母拉大
        for i in range(5):
            specs.append(self._tb(10 + i, "/tb/BenchmarkTest00001", IDENT_B))
        sp_fp = self._tb(2, "/tb/BenchmarkTest00002", IDENT_B)
        sp_np = self._tb(3, "/tb/BenchmarkTest00002", IDENT_C)
        sdb = FakeSDB(specs + [sp_fp, sp_np],
                      {IDENT_A: [self._cov(IDENT_A)], IDENT_B: [self._absent(IDENT_B)],
                       IDENT_C: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 2, (
            "用例级判别力 1/2=0.5 应放行；若按 spec 级 1/8=12.5% 会被误拦")
        assert sorted(sdb.updates) == [2, 3]


    def test_strict_does_not_veto_pure_no_event_by_default(self, cli, monkeypatch):
        """默认收紧（2026-10-18 用户质询后）：纯 no_event 不是反证，不得据此否决。

        「没有 at_sink」有两种：absent（族 sink 到了、payload 不在实参 = 反证）与
        no_event（连族 sink 都没到 = 没证据）。把后者当安全是「以证据缺失推定安全」，
        真实项目上会砍真漏洞。r109 里严格模式砍的 24 案中有 8 案属此类。
        """
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.5")
        monkeypatch.delenv("SAST_AI_VALUE_GATE_STRICT_ALLOW_NO_EVENT", raising=False)
        sp_cov = self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)
        sp_ne = self._tb(2, "/tb/BenchmarkTest00002", IDENT_C)   # 只有非族 sink 噪声
        sdb = FakeSDB([sp_cov, sp_ne],
                      {IDENT_A: [self._cov(IDENT_A)], IDENT_C: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
        assert sdb.updates == []

    def test_strict_allows_no_event_when_explicitly_opted_in(self, cli, monkeypatch):
        """显式开启 SAST_AI_VALUE_GATE_STRICT_ALLOW_NO_EVENT=1 才恢复旧的激进行为。"""
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "trust_boundary_violation")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT", "1")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_MIN_COVERAGE", "0.5")
        monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_ALLOW_NO_EVENT", "1")
        sp_cov = self._tb(1, "/tb/BenchmarkTest00001", IDENT_A)
        sp_ne = self._tb(2, "/tb/BenchmarkTest00002", IDENT_C)
        sdb = FakeSDB([sp_cov, sp_ne],
                      {IDENT_A: [self._cov(IDENT_A)], IDENT_C: [self._noise()]})
        assert cli._apply_sink_value_gate_postpass(1, sdb) == 1
        assert sdb.updates == [2]


class TestDefaultFamilies:
    """回归锁（2026-10-18 收口）：默认族必须覆盖已实证的 6 族。

    否则真实扫描（backend 进程内、读不到命令行 env）拿不到任何值级闸收益，
    r106~r109 的精度提升就只是"离线补跑"的假象。
    """

    def test_default_includes_all_validated_families(self, cli, monkeypatch):
        monkeypatch.delenv("SAST_AI_VALUE_GATE_FAMILIES", raising=False)
        fams = {__import__("src.core.sink_value_gate", fromlist=["canonical_family"]).canonical_family(f)
                for f in cli._value_gate_families()}
        for need in ("sql_injection", "trust_boundary_violation", "xpath_injection",
                     "xss", "path_traversal", "xxe",
                     # 2026-10-19（r111 ldapi 验收）：at_sink 100% / absent 纯度 100% → 纳入。
                     "ldap_injection"):
            assert need in fams, f"默认族缺少 {need}"

    def test_env_can_narrow(self, cli, monkeypatch):
        monkeypatch.setenv("SAST_AI_VALUE_GATE_FAMILIES", "sql_injection")
        assert cli._value_gate_families() == ("sql_injection",)


# —— strict-C（2026-10-19）：≥1 absent 且无 at_sink ⇒ 否决，no_event 兄弟不再阻挠 ——
# 按族验收：ldap_injection / sql_injection / command_execution 纳入；path_traversal 排除（会误杀 16 TP）。

def _absent_event(sink_file):
    return {"sink_file": sink_file, "source_value": "[base, filter]", "evidence_json": "{}"}


def test_strict_c_vetoes_absent_with_no_event_sibling(cli, monkeypatch):
    monkeypatch.delenv("SAST_AI_VALUE_GATE_STRICT_C_FAMILIES", raising=False)
    specs = [
        _spec(1, "/ldapi-00/BenchmarkTest00530", _marker(IDENT_A), family="ldap_injection"),
        _spec(2, "/ldapi-00/BenchmarkTest00530", _marker(IDENT_B), family="ldap_injection"),
    ]
    events = {IDENT_A: [_absent_event("javax.naming.directory.InitialDirContext.search")]}  # IDENT_B 无事件
    sdb = FakeSDB(specs, events)
    n = cli._apply_sink_value_gate_postpass(1, sdb)
    assert n == 2 and sorted(sdb.updates) == [1, 2]


def test_strict_c_excludes_path_traversal(cli, monkeypatch):
    """path_traversal 实测 11 FP / 16 TP —— 绝不纳入 strict-C。"""
    monkeypatch.delenv("SAST_AI_VALUE_GATE_STRICT_C_FAMILIES", raising=False)
    specs = [
        _spec(1, "/pathtraver-00/BenchmarkTest00100", _marker(IDENT_A), family="path_traversal"),
        _spec(2, "/pathtraver-00/BenchmarkTest00100", _marker(IDENT_B), family="path_traversal"),
    ]
    events = {IDENT_A: [_absent_event("java.io.FileInputStream.<init>")]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
    assert sdb.updates == []


def test_strict_c_keeps_case_with_at_sink(cli, monkeypatch):
    monkeypatch.delenv("SAST_AI_VALUE_GATE_STRICT_C_FAMILIES", raising=False)
    specs = [
        _spec(1, "/ldapi-00/BenchmarkTest00100", _marker(IDENT_A), family="ldap_injection"),
        _spec(2, "/ldapi-00/BenchmarkTest00100", _marker(IDENT_B), family="ldap_injection"),
    ]
    events = {
        IDENT_A: [_absent_event("javax.naming.directory.InitialDirContext.search")],
        IDENT_B: [{"sink_file": "javax.naming.directory.InitialDirContext.search",
                   "source_value": f"[base, {PAYLOAD}]", "evidence_json": "{}"}],
    }
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0


def test_strict_c_env_can_disable(cli, monkeypatch):
    monkeypatch.setenv("SAST_AI_VALUE_GATE_STRICT_C_FAMILIES", "")
    specs = [
        _spec(1, "/ldapi-00/BenchmarkTest00530", _marker(IDENT_A), family="ldap_injection"),
        _spec(2, "/ldapi-00/BenchmarkTest00530", _marker(IDENT_B), family="ldap_injection"),
    ]
    events = {IDENT_A: [_absent_event("javax.naming.directory.InitialDirContext.search")]}
    sdb = FakeSDB(specs, events)
    assert cli._apply_sink_value_gate_postpass(1, sdb) == 0
