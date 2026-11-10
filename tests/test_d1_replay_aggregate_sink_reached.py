"""D1 重放聚合口径：canary 抵达 sink 必须走 is_sink_reached() 统一判据。

回归背景（2026-09-16 R28 全量 run 10）：D2 重放心跳计数器曾硬编码
``state == "sink-reached"``，把探针显式断言态 ``sink-reached-probe`` 全部漏掉。
实测 454 条 canary 事件里 415 条是 probe 态——前端 sink_reached 显示 0，
而 iast_events 里 sink_reached=1 有 454 行，自相矛盾。

本测试把三种形态钉死，防止任一侧再次退化成硬编码字符串比较：
1. sink-reached 计入；
2. sink-reached-probe 计入（最容易漏的一条）；
3. no-arrival / no-iast-evidence / 空态 不计入。
"""

from src.cli.benchmark_cli import _aggregate_d1_replay
from src.iast.canary import is_sink_reached


def _v(state, *, spec=True, impact=False):
    return {
        "trigger_spec_provided": spec,
        "iast_evidence": {"state": state},
        "dast_impact_evidence": {"reached": impact},
        "trigger_spec_detail": {
            "endpoint": "/order/{id}",
            "http_method": "GET",
            "param_name": "id",
            "param_location": "path",
            "family": "sql_injection",
            "canary_identity": "s4st41deadbeef0000",
            "source": "a2",
            "vulnerability_hash_v2": "0123456789abcdef0123",
        },
    }


def test_unified_predicate_accepts_both_reached_states():
    assert is_sink_reached("sink-reached") is True
    assert is_sink_reached("sink-reached-probe") is True
    assert is_sink_reached("no-arrival") is False
    assert is_sink_reached("no-iast-evidence") is False
    assert is_sink_reached("") is False
    assert is_sink_reached(None) is False


def test_arrivals_count_probe_asserted_state():
    """sink-reached-probe 必须计入 IAST arrival——历史 bug 正是漏了这一态。"""
    out = _aggregate_d1_replay([_v("sink-reached-probe")])
    assert out["iast_arrivals"] == 1
    assert out["candidate_count"] == 1
    assert out["status"] == "completed"


def test_arrivals_mix_of_states():
    out = _aggregate_d1_replay(
        [
            _v("sink-reached"),
            _v("sink-reached-probe"),
            _v("sink-reached-probe"),
            _v("no-arrival"),
            _v("no-iast-evidence"),
            _v(""),
        ]
    )
    assert out["iast_arrivals"] == 3
    assert out["candidate_count"] == 6
    assert out["finding_count"] == 0


def test_no_arrival_states_never_count():
    out = _aggregate_d1_replay([_v("no-arrival"), _v("no-iast-evidence")])
    assert out["iast_arrivals"] == 0
    assert out["candidate_count"] == 2


def test_impacts_and_skipped_status():
    out = _aggregate_d1_replay([_v("sink-reached", impact=True)])
    assert out["finding_count"] == 1
    assert out["replayed_specs_detail"][0]["endpoint"] == "/order/{id}"

    skipped = _aggregate_d1_replay([_v("sink-reached", spec=False)])
    assert skipped["status"] == "skipped"
    assert skipped["candidate_count"] == 0


def test_heartbeat_counter_matches_aggregate_semantics():
    """重放心跳与 D1 聚合必须用同一判据。

    心跳那段在 run_d2_verify 闭包里不好直接调用，这里退而求其次：
    源码里不得再出现对 sink 态的硬编码字符串比较。改动该文件若重新引入
    ``== "sink-reached"``，本测试立刻失败。
    """
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "cli" / "benchmark_cli.py"
    # 用 AST 精确判定：只看真正的 `x == "sink-reached"` 比较节点。
    # 注释与 docstring 里提到这个字符串是正常的（都在解释这个坑本身），不该误伤。
    tree = ast.parse(src.read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, ast.Eq) and isinstance(comparator, ast.Constant):
                if comparator.value == "sink-reached":
                    offenders.append(f"第 {node.lineno} 行")
    assert not offenders, f"发现硬编码 sink 态比较，应改用 is_sink_reached()：{offenders}"


def test_runner_accepts_replay_reconciled_status():
    """补捞后回写的 replay_reconciled 心跳必须被前端文案接受。

    若 task_runner 只认 replaying/replay_done，补捞心跳覆盖掉 replay_done 之后
    前端反而什么都不显示——比原来的偏低数字更糟。

    2026-09-22：心跳的**载体**从 d2 改为 d1。D1 已能据 replay_progress 显示实时状态，
    而 d2 只该报自己的核验进度；断言口径随载体一起迁移，防止再退回「两行同播一件事」。
    """
    from src.infrastructure.task_runner import ScanTaskRunner

    done = {"replayed": 206, "total": 206, "confirmed": 74, "sink_reached": 0,
            "current_endpoint": "", "status": "replay_done"}
    reconciled = {"replayed": 206, "total": 206, "confirmed": 80, "sink_reached": 36,
                  "current_endpoint": "", "status": "replay_reconciled"}

    p_done = ScanTaskRunner._build_pipeline({"replay_progress": done}, {})
    p_rec = ScanTaskRunner._build_pipeline({"replay_progress": reconciled}, {})
    msg_done = p_done["d1"]["message"]
    msg_rec = p_rec["d1"]["message"]

    assert "sink_reached=0" in msg_done
    assert "sink_reached=36" in msg_rec
    assert "补捞" in msg_rec
    # 心跳已表示重放收尾：D1 必须是终态，否则依赖门禁会把 d2 改写成「等待 d1 完成」
    assert p_done["d1"]["status"] == "completed"
    assert p_rec["d1"]["status"] == "completed"
    assert p_rec["d2"]["status"] != "blocked"
