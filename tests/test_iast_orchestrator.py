"""触发事务编排器 + a3_facade.verify_via_iast_trigger 集成测试（重构文档 3.12 / 3.12.x）。

用注入的 clock / sleep / event_source / dast_operator 让时序确定、可快速运行，不依赖真实 DB 与探针。
"""
import pytest

from src.iast.canary import CanaryFactory, CanaryMatcher
from src.iast.orchestrator import (
    DastImpact,
    STATUS_FINALIZED,
    STATUS_PROVISIONAL,
    STATE_SINK_REACHED,
    STATE_NO_ARRIVAL,
    STATE_ARRIVAL_SANITIZED,
    TriggerTransactionOrchestrator,
    WindowConfig,
    reset_orchestrator,
)
from src.agents.d2_facade import D2Agent
from src.agents.runtime_contract import normalize_external_target


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self):
        return self.t


def fake_sleep_advances(clock: FakeClock):
    # 每次 sleep(p) 把时钟推进 p，使轮询循环在有限步内结束。
    def sleep(p):
        clock.t += p
    return sleep


class FakeDast:
    def __init__(self, impact: DastImpact = None):
        self.calls = 0
        self.last_spec = None
        self.last_target = None
        self.impact = impact or DastImpact()

    def replay(self, spec, target):
        self.calls += 1
        self.last_spec = spec
        self.last_target = target
        return self.impact


class FakeDastMulti:
    """§4.7.2 D1 支持 replay_multi：同 endpoint 组一次回放，返回 per-spec DastImpact。"""
    def __init__(self):
        self.group_calls = 0
        self.last_group_specs = None
        # 2026-10-03：跨 endpoint 的各组是提交到线程池**并行**执行的
        # （orchestrator._process_group，2026-09-26 分片并行改造），完成顺序由调度决定。
        # 只记 last_group_specs 时，断言「最后完成的组是哪个」本质是断言调度顺序 —— 竞态。
        # 改为记录全部组，断言按 endpoint 的成员集合（与顺序无关）。
        self.all_group_specs = []

    def replay_multi(self, specs, target):
        self.group_calls += 1
        self.last_group_specs = list(specs)
        self.all_group_specs.append(list(specs))
        return [DastImpact(reached=True, status_code=200) for _ in specs]


def _canary():
    return CanaryFactory.build("command-execution")


def _spec(canary, hid="h1"):
    return {"vulnerability_hash_v2": hid, "taint_marker": canary}


def _spec_at(canary, hid, endpoint, method="GET"):
    return {"vulnerability_hash_v2": hid, "taint_marker": canary,
            "target_endpoint": endpoint, "http_method": method}


@pytest.fixture(autouse=True)
def _reset():
    reset_orchestrator()
    yield
    reset_orchestrator()


def test_early_stop_on_sink_reached():
    clock = FakeClock(0.0)
    canary = _canary()
    # 首次轮询即返回 sink-reached 事件 → 早停
    def event_source(c, since_id, limit):
        return [{"id": 1, "canary_state": STATE_SINK_REACHED}]
    orch = TriggerTransactionOrchestrator(
        dast_operator=FakeDast(DastImpact(reached=True, status_code=200)),
        event_source=event_source,
        window_cfg=WindowConfig(t_max=20.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    assert res.status == STATUS_PROVISIONAL
    v = res.per_hypothesis["h1"]
    assert v.state == STATE_SINK_REACHED
    assert v.matched_event_ids == [1]
    assert v.provisional is True
    assert orch.get_transaction(res.transaction_id).dast_impact.reached is True


def test_no_arrival_then_provisional_timeout():
    clock = FakeClock(0.0)
    canary = _canary()
    def event_source(c, since_id, limit):
        return []  # 全程无事件
    orch = TriggerTransactionOrchestrator(
        dast_operator=FakeDast(),
        event_source=event_source,
        window_cfg=WindowConfig(t_max=2.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    assert res.status == STATUS_PROVISIONAL
    assert res.per_hypothesis["h1"].state == STATE_NO_ARRIVAL


def test_status_provisional_not_finalized_immediately():
    clock = FakeClock(0.0)
    canary = _canary()
    orch = TriggerTransactionOrchestrator(
        event_source=lambda c, s, l: [],
        window_cfg=WindowConfig(t_max=1.0, poll_interval=0.5, backfill_ttl=300.0),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    tx = orch.get_transaction(res.transaction_id)
    assert tx.status == STATUS_PROVISIONAL
    # 回填有效期未到 → finalize 不触发
    assert orch.finalize_expired(now=clock.t + 10.0) == []
    assert tx.status == STATUS_PROVISIONAL
    # 超过回填有效期 → finalize
    finalized = orch.finalize_expired(now=clock.t + 400.0)
    assert res.transaction_id in finalized
    assert tx.status == STATUS_FINALIZED
    assert tx.backfill_eligible is False


def test_backfill_unidirectional_upgrade():
    clock = FakeClock(0.0)
    canary = _canary()
    orch = TriggerTransactionOrchestrator(
        event_source=lambda c, s, l: [],
        window_cfg=WindowConfig(t_max=1.0, poll_interval=0.5, backfill_ttl=300.0),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    # 窗口内 no-arrival
    assert orch.get_transaction(res.transaction_id).verdicts["h1"].state == STATE_NO_ARRIVAL
    # 迟到 sink-reached 事件 → 升级（submit_backfill_event 按身份段匹配，同 run_transaction 归一化）
    cident = CanaryMatcher.find_identity(canary)
    upgraded = orch.submit_backfill_event(cident, STATE_SINK_REACHED, event_id=77)
    assert upgraded == ["h1"]
    v = orch.get_transaction(res.transaction_id).verdicts["h1"]
    assert v.state == STATE_SINK_REACHED
    assert 77 in v.matched_event_ids
    # 反向降级禁止：再提交 no-arrival 不应改变
    orch.submit_backfill_event(cident, STATE_NO_ARRIVAL, event_id=78)
    assert orch.get_transaction(res.transaction_id).verdicts["h1"].state == STATE_SINK_REACHED


def test_backfill_ignored_after_finalize():
    clock = FakeClock(0.0)
    canary = _canary()
    orch = TriggerTransactionOrchestrator(
        event_source=lambda c, s, l: [],
        window_cfg=WindowConfig(t_max=1.0, poll_interval=0.5, backfill_ttl=300.0),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    orch.finalize_expired(now=clock.t + 400.0)
    # finalize 后再回填不再改变裁定（按身份段匹配）
    assert orch.submit_backfill_event(CanaryMatcher.find_identity(canary), STATE_SINK_REACHED, event_id=99) == []
    assert orch.get_transaction(res.transaction_id).verdicts["h1"].state == STATE_NO_ARRIVAL


def test_multi_hypothesis_partial_hit():
    clock = FakeClock(0.0)
    c1 = _canary()
    c2 = _canary()
    def event_source(canary, since_id, limit):
        # run_transaction 会对 taint_marker 做 find_identity 抽取身份段后轮询，故此处按身份段匹配。
        if canary == CanaryMatcher.find_identity(c1):
            return [{"id": 5, "canary_state": STATE_SINK_REACHED}]
        return []
    orch = TriggerTransactionOrchestrator(
        event_source=event_source,
        window_cfg=WindowConfig(t_max=20.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(c1, "hA"), _spec(c2, "hB")])
    assert res.per_hypothesis["hA"].state == STATE_SINK_REACHED
    assert res.per_hypothesis["hB"].state == STATE_NO_ARRIVAL
    mm = res.multi_match_summary
    assert mm["hypotheses"] == 2
    assert "hA" in mm["sink_reached"]
    assert "hB" in mm["no_arrival"]


def test_dast_operator_called_per_spec():
    clock = FakeClock(0.0)
    dast = FakeDast(DastImpact(reached=True, status_code=200))
    orch = TriggerTransactionOrchestrator(
        dast_operator=dast,
        event_source=lambda c, s, l: [],
        window_cfg=WindowConfig(t_max=1.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    c1, c2 = _canary(), _canary()
    orch.run_transaction({"app_name": "mall"}, [_spec(c1, "hA"), _spec(c2, "hB")])
    assert dast.calls == 2


class FakeIastService:
    """给 facade 集成测试用的轻量 iast_service 桩，仅实现 poll_events_by_canary。"""
    def __init__(self, events_by_canary):
        self._events = events_by_canary  # canary -> list[{"id","canary_state"}]

    def poll_events_by_canary(self, canary, since_id=0, limit=50,
                              app_name=None, agent_id=None, trace_id=None):
        return [e for e in self._events.get(canary, []) if e["id"] > since_id]


def test_facade_verify_via_iast_trigger_end_to_end():
    canary = _canary()
    # run_transaction 按身份段轮询，故 FakeIastService 的键须是身份段。
    fake_iast = FakeIastService({CanaryMatcher.find_identity(canary): [{"id": 1, "canary_state": STATE_SINK_REACHED}]})
    dast = FakeDast(DastImpact(reached=True, status_code=200))
    facade = D2Agent({})
    target = normalize_external_target({"service_url": "http://127.0.0.1:11000", "app_name": "mall", "agent_id": "probe-x"})
    vr = facade.verify(
        vulnerability={"family": "command-execution"},
        project_context={},
        external_target=target.to_dict(),
        trigger_spec=_spec(canary, "h1"),
        iast_service=fake_iast,
        dast_operator=dast,
    )
    assert vr.final_state == "confirmed_attributable"
    # v2 A5/Point5（2026-10-10）：reached(L1) 不再冒充 impact_observed(L4)；
    # 「唯一依据是探针断言到达」属运行时能力边界 —— 落 confirmed_runtime 档
    # （final_state 保持 confirmed_attributable），但不置 exploitable（须语义层证据）。
    assert vr.exploitable is False
    assert "运行时能力边界" in (vr.reason or "")
    assert vr.iast_evidence.get("state") == STATE_SINK_REACHED
    assert vr.dast_impact_evidence.get("impact_observed") is False


def test_facade_falls_back_without_iast_service():
    # 未注入 iast_service → 缺少 trigger_spec 直接给出 no_evidence 通道，不产生异常。
    facade = D2Agent({})
    target = normalize_external_target({"service_url": "http://127.0.0.1:11000"})
    vr = facade.verify(
        vulnerability={"family": "command-execution"},
        project_context={},
        external_target=target.to_dict(),
        trigger_spec=_spec(_canary(), "h1"),
    )
    assert vr is not None
    # 无 app_name/agent_id 且未注入 iast_service → 走缺 trigger_spec / 环境未就绪兜底通道，不产生异常
    assert vr.final_state in ("", "no_evidence")


# ---- §3.14 编排器层廉价复探 hook ----

def test_readiness_probe_blocks_replay_when_not_ready():
    clock = FakeClock(0.0)
    dast = FakeDast(DastImpact(reached=True, status_code=200))

    def probe(target):
        return {"ready": False, "block_reason": "目标不可达"}

    orch = TriggerTransactionOrchestrator(
        dast_operator=dast,
        event_source=lambda c, s, l: [],
        readiness_probe=probe,
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    result = orch.run_transaction(
        {"service_url": "http://x", "app_name": "a", "agent_id": "b"},
        [_spec(_canary(), "h1")],
    )
    assert dast.calls == 0  # 未就绪 → 不调 replay（阻断发流量）
    assert result.raw_dast_impact["blocked"] is True
    assert "目标不可达" in result.raw_dast_impact["error"]


def test_readiness_probe_passes_when_ready():
    clock = FakeClock(0.0)
    dast = FakeDast(DastImpact(reached=True, status_code=200))

    def probe(target):
        return {"ready": True}

    orch = TriggerTransactionOrchestrator(
        dast_operator=dast,
        event_source=lambda c, s, l: [],
        readiness_probe=probe,
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    result = orch.run_transaction({"service_url": "http://x"}, [_spec(_canary(), "h1")])
    assert dast.calls == 1
    assert result.raw_dast_impact["blocked"] is False
    assert result.raw_dast_impact["reached"] is True


def test_multi_match_groups_by_endpoint_calls_replay_multi():
    """§4.7.2：同 endpoint 多假说 → D1.replay_multi 一次调用；不同 endpoint → 两次调用。"""
    clock = FakeClock(0.0)
    c1, c2 = _canary(), _canary()
    dast = FakeDastMulti()
    orch = TriggerTransactionOrchestrator(
        dast_operator=dast,
        event_source=lambda c, s, l: [],
        window_cfg=WindowConfig(t_max=0.0, poll_interval=0.0),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    specs = [
        _spec_at(c1, "hA", "/api/x"),
        _spec_at(c2, "hB", "/api/x"),
        _spec_at(_canary(), "hC", "/api/y", method="POST"),
    ]
    orch.run_transaction({"app_name": "mall"}, specs)
    assert dast.group_calls == 2  # /api/x 一组 + /api/y 一组
    # 按 endpoint 归组后比对成员集合（并行执行，完成顺序不可断言）
    by_ep = {}
    for g in dast.all_group_specs:
        eps = {s.get("target_endpoint") for s in g}
        assert len(eps) == 1, "同一次 replay_multi 只能打同一个 endpoint"
        by_ep[eps.pop()] = sorted(s["vulnerability_hash_v2"] for s in g)
    assert by_ep == {"/api/x": ["hA", "hB"], "/api/y": ["hC"]}


def test_multi_match_early_stop_waits_until_all_hypotheses_match():
    """§4.7.2：早停条件改为全部 N 假说至少到 arrival-sanitized/sink-reached；未齐时继续等。"""
    clock = FakeClock(0.0)
    c1, c2 = _canary(), _canary()
    # 第一轮：c1 命中 sink-reached，c2 无事件；第二轮（clock 推进后）：c2 命中 arrival-sanitized。
    def event_source(c, since_id, limit):
        # run_transaction 按身份段轮询，故用 find_identity 归一化比较。
        if c == CanaryMatcher.find_identity(c1) and clock.t < 0.5:
            return [{"id": 1, "canary_state": STATE_SINK_REACHED}]
        if c == CanaryMatcher.find_identity(c2) and clock.t >= 0.5:
            return [{"id": 2, "canary_state": STATE_ARRIVAL_SANITIZED}]
        return []
    orch = TriggerTransactionOrchestrator(
        dast_operator=FakeDast(DastImpact(reached=True)),
        event_source=event_source,
        window_cfg=WindowConfig(t_max=20.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(c1, "hA"), _spec(c2, "hB")])
    # hA 已 sink-reached；hB 已 arrival-sanitized → 都已非 no-arrival → 早停条件满足
    assert res.per_hypothesis["hA"].state == STATE_SINK_REACHED
    assert res.per_hypothesis["hB"].state == STATE_ARRIVAL_SANITIZED


def test_multi_match_no_early_stop_when_one_hypothesis_unmatched():
    """§4.7.2 反例：若某个假说始终无事件，不应早停；窗口耗尽才退出。"""
    clock = FakeClock(0.0)
    c1, c2 = _canary(), _canary()
    def event_source(c, since_id, limit):
        if c == CanaryMatcher.find_identity(c1):
            return [{"id": 1, "canary_state": STATE_SINK_REACHED}]
        return []  # c2 永远无事件
    orch = TriggerTransactionOrchestrator(
        dast_operator=FakeDast(DastImpact(reached=True)),
        event_source=event_source,
        window_cfg=WindowConfig(t_max=2.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(c1, "hA"), _spec(c2, "hB")])
    assert res.per_hypothesis["hA"].state == STATE_SINK_REACHED
    assert res.per_hypothesis["hB"].state == STATE_NO_ARRIVAL


def test_readiness_probe_absent_replays_normally():
    # 未注入 readiness_probe → 不复探，正常 replay（向后兼容）。
    clock = FakeClock(0.0)
    dast = FakeDast(DastImpact(reached=True, status_code=200))
    orch = TriggerTransactionOrchestrator(
        dast_operator=dast,
        event_source=lambda c, s, l: [],
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    result = orch.run_transaction({"service_url": "http://x"}, [_spec(_canary(), "h1")])
    assert dast.calls == 1
    assert result.raw_dast_impact["blocked"] is False


def test_wait_window_prefers_richest_path_event():
    """I1 链路符合性应选中 taint_path 最丰富的到达事件，而非陈旧空路径事件。

    直接阻断点：_wait_window 原先把「第一个」升级事件（可能是上一轮残留的空路径事件）
    stash 成 matched_event_detail，导致 chain_conformance 永远 conforms=False。
    """
    clock = FakeClock(0.0)
    canary = _canary()
    stale_empty = {"id": 1, "canary_state": STATE_SINK_REACHED, "taint_path": []}
    rich = {"id": 2, "canary_state": STATE_SINK_REACHED,
            "taint_path": [{"role": "transform", "origin": "java.util.Base64$Decoder.decode"}]}
    def event_source(c, since_id, limit):
        return [stale_empty, rich]
    orch = TriggerTransactionOrchestrator(
        dast_operator=FakeDast(DastImpact(reached=True, status_code=200)),
        event_source=event_source,
        window_cfg=WindowConfig(t_max=20.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    v = res.per_hypothesis["h1"]
    assert v.state == STATE_SINK_REACHED
    # 选中的命中事件应为路径最丰富者（id=2），而非空路径陈旧事件（id=1）。
    # matched_event_detail 写在事务态 verdict 上（per_hypothesis 副本已脱敏），故从 transaction 读。
    tv = orch.get_transaction(res.transaction_id).verdicts["h1"]
    assert tv.matched_event_detail.get("id") == 2
    assert len(tv.matched_event_detail.get("taint_path") or []) == 1


def test_wait_window_watermark_excludes_stale_events():
    """水位线应剔除本事务启动前的历史事件，只命中本事务产生的事件（§3.12 事件隔离）。"""
    clock = FakeClock(0.0)
    canary = _canary()
    stale_empty = {"id": 50, "canary_state": STATE_SINK_REACHED, "taint_path": []}
    stale_rich = {"id": 51, "canary_state": STATE_SINK_REACHED,
                  "taint_path": [{"role": "transform", "origin": "java.util.Base64$Decoder.decode"}]}
    new_rich = {"id": 150, "canary_state": STATE_SINK_REACHED,
                "taint_path": [{"role": "transform", "origin": "java.util.Base64$Decoder.decode"},
                               {"role": "sink", "origin": "org.springframework.http.converter.StringHttpMessageConverter.writeInternal"}]}
    called_with = {}
    def event_source(c, since_id, limit):
        called_with["since_id"] = since_id
        # 模拟 DB：只返回 id > since_id 的事件（同 poll_events_by_canary 语义）
        pool = [stale_empty, stale_rich, new_rich]
        return [e for e in pool if e["id"] > since_id]
    def watermark():
        return 100  # 本事务启动前的 MAX(id)
    orch = TriggerTransactionOrchestrator(
        dast_operator=FakeDast(DastImpact(reached=True, status_code=200)),
        event_source=event_source,
        window_cfg=WindowConfig(t_max=20.0, poll_interval=0.5),
        clock=clock,
        sleep=fake_sleep_advances(clock),
        event_watermark_provider=watermark,
    )
    res = orch.run_transaction({"app_name": "mall"}, [_spec(canary)])
    # 轮询起点应为水位线 100，历史遗留事件被排除
    assert called_with["since_id"] == 100
    # 命中的应为本事务产生的 rich 事件（id=150），而非历史遗留事件
    tv = orch.get_transaction(res.transaction_id).verdicts["h1"]
    assert tv.matched_event_detail.get("id") == 150
    assert res.per_hypothesis["h1"].matched_event_ids == [150]
