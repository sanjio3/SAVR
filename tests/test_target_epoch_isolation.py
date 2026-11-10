"""靶场实例纪元批次隔离（item 三，2026-09-21）。

背景：D2 批次重放期间靶场可能被看门狗重启（run 23 实证：java-sec-code 17:24:22 优雅
退出、新 JVM 17:30~17:31 才起完 Spring Boot，重放窗口正落在停机 + 启动区间内）。停机
窗口内重放的 spec 拿不到任何证据，会落 no_evidence（「永久非漏洞」结论），污染对账与
差分门禁。修法：把落在停机/重启窗口内的 spec 标 invalidated（可重试）。

本用例全部用注入时钟 + 注入采样，不碰真实网络/进程/DB。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.iast.target_epoch import (  # noqa: E402
    TargetEpochTracker,
    port_of_url,
    spec_invalidation_reason,
)


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = float(t)

    def __call__(self) -> float:
        return self.t

    def adv(self, d: float) -> None:
        self.t += float(d)


def _make(clk, script, **kw):
    """script: 按采样顺序弹出的 dict(epoch=, process_ok=, service_ok=, phase=)。"""
    seq = list(script)

    def proc_probe(port):
        s = seq.pop(0)
        return s.get("epoch", ""), s.get("process_ok", True)

    def http_probe(url, tms):
        return (200, True)

    return TargetEpochTracker(
        "http://127.0.0.1:8080", db=None, clock=clk,
        process_probe=proc_probe, http_probe=http_probe,
        probe_phase_reader=lambda: "READY", interval=0.01,
        confirm_bad=2, confirm_good=2, **kw,
    )


def _run(tr, clk, n):
    """首拍走 start（与生产一致），其余走 feed，每拍推进 5s。"""
    tr.start(background=False)
    for _ in range(n):
        clk.adv(5)
        tr.feed(tr.sample_once())
    return tr.report()


def test_epoch_stable_means_clean():
    clk = FakeClock()
    tr = _make(clk, [{"epoch": "pid:1@100.0"}] * 3)
    rep = _run(tr, clk, 2)
    assert rep["downtime_windows"] == []
    assert rep["verdict"] == "clean"
    assert rep["baseline_epoch"] == "pid:1@100.0"
    assert rep["restarts"] == 0
    assert tr.overlaps(990, 1010) is None


def test_restart_opens_and_closes_window():
    clk = FakeClock()
    tr = _make(clk, [
        {"epoch": "pid:1@100.0"},              # t=1000 基线（好）
        {"epoch": "", "process_ok": False},    # t=1005 坏 1（进程消失）
        {"epoch": "", "process_ok": False},    # t=1010 坏 2 → 开窗
        {"epoch": "pid:2@200.0"},              # t=1015 新实例，纪元切换
        {"epoch": "pid:2@200.0"},              # t=1020 好 1
        {"epoch": "pid:2@200.0"},              # t=1025 好 2 → 关窗
        {"epoch": "pid:2@200.0"},              # t=1030 好
    ])
    rep = _run(tr, clk, 6)
    assert len(rep["downtime_windows"]) == 1, rep
    assert abs(tr.windows[0].down_at - 1005.0) < 1e-6   # 窗口起点 = 第一坏样本
    assert abs(tr.windows[0].up_at - 1025.0) < 1e-6     # 窗口终点 = 第 2 个好样本
    assert rep["verdict"] == "target_restarted"
    assert rep["restarts"] == 1
    # 重启后的新实例必须被采纳为健康基线，否则新实例会被永久判坏（窗口关不上）。
    assert rep["active_epoch"] == "pid:2@200.0"


def test_overlap_matrix_with_pre_down_guard():
    clk = FakeClock()
    tr = _make(clk, [
        {"epoch": "pid:1@100.0"},
        {"epoch": "", "process_ok": False},
        {"epoch": "", "process_ok": False},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
    ])
    _run(tr, clk, 5)
    assert tr.overlaps(1007, 1009) is not None        # 窗口内
    assert tr.overlaps(1000, 1030) is not None        # 横跨
    assert tr.overlaps(991, 992) is not None          # 停机前 15s 保护带内
    assert tr.overlaps(970, 980) is None              # 保护带之外
    assert tr.overlaps(1030, 1040) is None            # 恢复之后


def test_single_transient_blip_does_not_open_window():
    clk = FakeClock()
    tr = _make(clk, [
        {"epoch": "pid:9@1.0"},
        {"epoch": "pid:9@1.0", "process_ok": False},   # 单次坏
        {"epoch": "pid:9@1.0"},                        # 立刻好
        {"epoch": "pid:9@1.0", "process_ok": False},   # 又一次单坏
        {"epoch": "pid:9@1.0"},
    ])
    rep = _run(tr, clk, 4)
    assert rep["downtime_windows"] == []
    assert rep["verdict"] == "clean"


def test_undeterminable_never_invalidates():
    """纪元整体不可判定（无 psutil / 无可达进程）→ 不清空既有结论（fail-safe）。"""
    clk = FakeClock()
    tr = _make(clk, [{"epoch": "", "process_ok": False}] * 3)
    rep = _run(tr, clk, 2)
    assert rep["epoch_available"] is False
    assert rep["verdict"] == "undeterminable"
    assert rep["downtime_windows"] == []
    assert tr.overlaps(1000, 1010) is None


class _FakeResult:
    def __init__(self, final_state: str = "", dast=None, iast=None):
        self.final_state = final_state
        self.dast_impact_evidence = dast or {}
        self.iast_evidence = iast or {}


def test_invalidation_reason_three_sources():
    clk = FakeClock()
    tr = _make(clk, [
        {"epoch": "pid:1@100.0"},
        {"epoch": "", "process_ok": False},
        {"epoch": "", "process_ok": False},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
    ])
    _run(tr, clk, 5)

    assert spec_invalidation_reason(_FakeResult("target_unhealthy"), None, 1, 2).startswith("target_unhealthy")
    assert spec_invalidation_reason(
        _FakeResult("", {"target_unhealthy": True, "reason": "A0 环境未就绪"}), None, 1, 2
    ).startswith("target_unhealthy")
    assert spec_invalidation_reason(_FakeResult("no_evidence"), tr, 1000, 1030).startswith("batch_isolation")
    # 窗口之外的健康结论保持原样（不误标）
    assert spec_invalidation_reason(_FakeResult("no_evidence"), tr, 970, 980) == ""
    assert spec_invalidation_reason(_FakeResult("confirmed"), None, 970, 980) == ""


def test_positive_evidence_vetoes_invalidation():
    """run 26 实测回归：dast_impact 的 target_unhealthy 是跨步骤粘性 OR，
    不能凭它否定一条已带「靶场内部探针抵达 sink」证据的确认结论。

    实测形状（15/15 全为此形）：final_state=runtime_confirmed、
    verification_decision.verification_status=confirmed_exploitable、
    iast_evidence.state=sink-reached-probe、dast_impact_evidence.target_unhealthy=True。
    """
    noisy = {"target_unhealthy": True, "reason": None}
    # ① sink-reached-probe + dast 噪声标志 + 已确认 → 必须不失效
    r1 = _FakeResult("runtime_confirmed", noisy, {"state": "sink-reached-probe"})
    assert spec_invalidation_reason(r1, None, 1, 2, pre_status="confirmed_exploitable") == ""
    # ② iast 抵达态 + 噪声标志 → 不失效
    r2 = _FakeResult("", noisy, {"state": "iast-reached"})
    assert spec_invalidation_reason(r2, None, 1, 2) == ""
    # ③ 只有 final_state 是确认态 + 噪声标志 → 不失效
    r3 = _FakeResult("confirmed_attributable", noisy)
    assert spec_invalidation_reason(r3, None, 1, 2) == ""
    # ④ iast_reached 显式为真 + 噪声标志 → 不失效
    r4 = _FakeResult("", noisy, {"iast_reached": True})
    assert spec_invalidation_reason(r4, None, 1, 2) == ""


def test_no_positive_evidence_still_invalidates():
    """没有正向证据时，粘性 OR 仍可采信（这类确实该失效重试，而不是落 no_evidence）。"""
    noisy = {"target_unhealthy": True, "reason": None}
    r = _FakeResult("", noisy, {"state": ""})
    assert spec_invalidation_reason(r, None, 1, 2).startswith("target_unhealthy")
    # A0 明确阻断（final_state=target_unhealthy，无证据）仍失效
    r2 = _FakeResult("target_unhealthy", {"target_unhealthy": True}, {})
    assert spec_invalidation_reason(r2, None, 1, 2).startswith("target_unhealthy")


def test_positive_evidence_vetoes_window_overlap_too():
    """窗口相交同样不得覆盖正向证据：探针能上报抵达，靶场当时就是活的。"""
    clk = FakeClock()
    tr = _make(clk, [
        {"epoch": "pid:1@100.0"},
        {"epoch": "", "process_ok": False},
        {"epoch": "", "process_ok": False},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
    ])
    _run(tr, clk, 5)
    r = _FakeResult("runtime_confirmed", {}, {"state": "sink-reached-probe"})
    assert spec_invalidation_reason(r, tr, 1000, 1030) == ""
    # 无证据的同窗口结论仍然失效
    assert spec_invalidation_reason(_FakeResult("no_evidence"), tr, 1000, 1030).startswith("batch_isolation")


def test_clean_epoch_vetoes_target_unhealthy_flag():
    """run 31 实测回归（2026-09-22）：纪元明确 clean 时，target_unhealthy 类判据一律不成立。

    实测形状：run 31 的 12+15 条 spec 因 dast_impact_evidence.target_unhealthy（跨步骤粘性
    OR —— 单次重放请求重试 3 次全失败即置位）被判 invalidated，但它们携带的 target_epoch
    是 verdict=clean / restarts=0 / downtime_windows=[]，**没有任何靶场不可用证据**。
    按项目铁律 invalidated 会被排除出对账与差分门禁 → 长期系统性压低 D2 数字
    （run 26/27/28/30 的 target_unhealthy 全都伴生 clean + 空窗口）。

    修法：纪元**明确** clean 且无停机窗口时否决该失效判定，退回 D2 原裁决。
    """
    clk = FakeClock()
    tr = _make(clk, [{"epoch": "pid:41840@100.0"}] * 3)
    rep = _run(tr, clk, 2)
    assert rep["verdict"] == "clean"
    assert rep["downtime_windows"] == []
    assert rep["restarts"] == 0

    # ① final_state=target_unhealthy：clean 纪元下不成立
    assert spec_invalidation_reason(_FakeResult("target_unhealthy"), tr, 1, 2) == ""
    # ② dast_impact.target_unhealthy（粘性噪声标志）：clean 纪元下同样不成立
    assert spec_invalidation_reason(
        _FakeResult("", {"target_unhealthy": True, "reason": "dast replay failed"}), tr, 1, 2
    ) == ""
    # ③ 无 tracker 时保持旧行为（不能因为「拿不到纪元」就一律放行失效判定）
    assert spec_invalidation_reason(_FakeResult("target_unhealthy"), None, 1, 2).startswith("target_unhealthy")


def test_undeterminable_epoch_does_not_veto():
    """纪元不可判定（探针未回报进程身份）时**不**否决失效判定。

    这是刻意选择的保守侧：undeterminable 是「无证据」，不能反过来当作「靶场没坏」的证明。
    否则真停机且探针同时失联的场景会被误判成「永久非漏洞」（no_evidence），比误标
    invalidated 更危险（前者会被当成误报治理依据）。
    """
    clk = FakeClock()
    tr = _make(clk, [{"epoch": "", "process_ok": False}] * 3)
    rep = _run(tr, clk, 2)
    assert rep["verdict"] == "undeterminable"
    assert spec_invalidation_reason(
        _FakeResult("", {"target_unhealthy": True, "reason": "dast replay failed"}), tr, 1, 2
    ).startswith("target_unhealthy")
    assert spec_invalidation_reason(_FakeResult("target_unhealthy"), tr, 1, 2).startswith("target_unhealthy")


def test_clean_epoch_still_honours_window_isolation():
    """clean 判定不得「顺手」放行真正与停机窗口相交的 spec（两者互不干扰）。"""
    clk = FakeClock()
    tr = _make(clk, [
        {"epoch": "pid:1@100.0"},
        {"epoch": "", "process_ok": False},
        {"epoch": "", "process_ok": False},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
        {"epoch": "pid:2@200.0"},
    ])
    _run(tr, clk, 5)
    assert tr.report()["downtime_windows"], "本 tracker 应已开出停机窗口"
    # 有窗口 → clean 不成立 → 窗口内的结论仍然失效。
    # 注意判据顺序：dast_impact.target_unhealthy（③）先于窗口相交（④）命中，
    # 故带该标志的结果报 target_unhealthy，不带标志的报 batch_isolation —— 两者都算失效。
    _with_flag = spec_invalidation_reason(
        _FakeResult("", {"target_unhealthy": True, "reason": "x"}), tr, 1000, 1030
    )
    assert _with_flag.startswith("target_unhealthy"), _with_flag
    assert spec_invalidation_reason(_FakeResult("target_unhealthy"), tr, 1000, 1030).startswith("target_unhealthy")
    assert spec_invalidation_reason(_FakeResult("no_evidence"), tr, 1000, 1030).startswith("batch_isolation")


def test_port_of_url():
    assert port_of_url("http://127.0.0.1:8080/x") == 8080
    assert port_of_url("https://a.example/x") == 443
    assert port_of_url("http://a.example/x") == 80
    assert port_of_url("") is None
