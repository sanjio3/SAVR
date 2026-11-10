"""#4② 进度键折叠回归：i2_rerun→a2、d2_verify_progress→d2（文案 + metrics）。

2026-09-16 待请示批准落地。此前 i2_rerun 与 d2_verify_progress 两键从不被任何
_build_pipeline 读取，前端永不可见「闭环第 N 轮 / D2 验证第 i 轮」。本测试把折叠口径
钉死，防止任一侧退化回「只读 phases / stage_results」。
"""

from src.cli.scan_task_runner import _build_pipeline as cli_build_pipeline
from src.infrastructure.task_runner import ScanTaskRunner as InfraScanTaskRunner


def _progress():
    return {
        "phases": {
            "phase4": {"status": "running", "details": "A2 进行中"},
            "phase5": {"status": "running", "details": "D2 进行中"},
        },
        "stage_results": {},
        "a2_progress": {"total": 92, "done": 90, "status": "closed_loop_rerun"},
        "i2_rerun": {"iteration": 3, "max_iterations": 3, "status": "running", "a2_feedback": 6},
        "replay_progress": {
            "total": 172,
            "replayed": 172,
            "confirmed": 73,
            "sink_reached": 63,
            "status": "replay_reconciled",
        },
        "d2_verify_progress": {"status": "running", "iteration": 2, "exploitable_count": 73},
    }


def test_task_runner_folds_i2_rerun_and_d2_verify():
    options = {"enable_a2": True, "enable_verification": True}
    p = InfraScanTaskRunner._build_pipeline(_progress(), options)
    # i2_rerun 折入 a2 文案与 metrics
    assert "闭环第 3/3 轮" in p["a2"]["message"]
    assert "重跑中" in p["a2"]["message"]
    assert p["a2"]["metrics"].get("closed_loop_iteration") == 3
    assert p["a2"]["metrics"].get("closed_loop_status") == "running"
    # a2_progress 指标
    assert p["a2"]["metrics"].get("progress_done") == 90
    assert p["a2"]["metrics"].get("progress_total") == 92
    # d2_verify_progress 折入 d2 文案与 metrics
    assert "D2 验证第 2 轮" in p["d2"]["message"]
    assert p["d2"]["metrics"].get("d2_verify_iteration") == 2
    assert p["d2"]["metrics"].get("d2_verify_exploitable_count") == 73
    # replay 心跳：2026-09-22 起归还 D1 行。
    # 原先挂 d2 是因为 D1 运行期恒为 pending、没有可播报的载体；走查修好 D1 的实时状态后，
    # 心跳留在 d2 会让「D1 操作器」与「D2 校验器」两行同时播报同一件事（同屏矛盾）。
    assert "已重放 172/172" in p["d1"]["message"]
    assert "sink_reached=63" in p["d1"]["message"]
    # d1 运行期状态不能再是 pending：否则依赖门禁会把真的在跑的 d2 改写成 blocked，
    # 并把 d2 的文案覆盖成「等待 d1 完成」（run 32 走查实证的同屏矛盾）
    assert p["d1"]["status"] == "completed", "replay_done / replay_reconciled 表示重放已收尾"
    # d2 只报自己的核验进度，不复述重放计数
    assert "已重放" not in p["d2"]["message"]


def test_scan_task_runner_folds_same():
    options = {"enable_a2": True, "enable_verification": True}
    p = cli_build_pipeline(_progress(), options)
    assert "闭环第 3/3 轮" in p["a2"]["message"]
    assert p["a2"]["metrics"].get("closed_loop_iteration") == 3
    assert "D2 验证第 2 轮" in p["d2"]["message"]
    assert p["d2"]["metrics"].get("d2_verify_iteration") == 2


def test_missing_keys_no_crash():
    # 四键全缺时不应抛错，也不该出现进度文案
    p = InfraScanTaskRunner._build_pipeline(
        {"phases": {}, "stage_results": {}},
        {"enable_a2": True, "enable_verification": True},
    )
    assert p["a2"]["message"] == ""
    assert p["d2"]["message"] == ""


def test_d1_shows_running_during_replay_and_does_not_block_d2():
    """运行期 D1 必须显示 running，且不得把真在跑的 D2 拖成 blocked。

    2026-09-22 真实浏览器走查实证（run 32 运行期快照）：
      d1: pending / d2: blocked("等待 d1 完成") / d2.metrics.replay_* 却在推进。
    D1 与 D2 共用 verify 链路，``stage_results.d1`` 只在收尾写盘，运行期恒为 pending；
    于是前端在「已重放 189 条」的同时把 D1 显示成「未开始」，依赖门禁又把 D2 的文案
    覆盖成「等待 d1 完成」，唯一的心跳被抹掉 —— 同一屏出现「运行中 · D2 校验器」与
    「D2 等待上游」并存。本测试把「运行期以实时进度为准、收尾以 stage_results 为准」钉死。
    """
    progress = {
        "phases": {"phase5": {"status": "running", "details": "D2 进行中"}},
        "stage_results": {},
        "replay_progress": {"total": 189, "replayed": 164, "confirmed": 139,
                            "sink_reached": 108, "status": "replaying"},
    }
    options = {"enable_verification": True}
    p = InfraScanTaskRunner._build_pipeline(progress, options)
    assert p["d1"]["status"] == "running", "重放进行中 D1 不能显示成 pending/未开始"
    assert p["d2"]["status"] == "running", "依赖门禁不得把真在跑的 D2 改写成 blocked"
    assert "已重放 164/189" in p["d1"]["message"]

    # 重放收尾 → D1 转 completed，d2 门禁随之解除
    progress["replay_progress"]["status"] = "replay_done"
    p2 = InfraScanTaskRunner._build_pipeline(progress, options)
    assert p2["d1"]["status"] == "completed"
    assert p2["d2"]["status"] == "running"

    # 收尾写盘后 stage_results.d1.message 是最终真值，不该被 replay 心跳顶替
    progress["stage_results"] = {"d1": {"status": "completed", "message": "终态结论"}}
    p3 = InfraScanTaskRunner._build_pipeline(progress, options)
    assert p3["d1"]["status"] == "completed"
    assert p3["d1"]["message"] == "终态结论"

    # 无 replay 心跳但 verify 阶段已在跑：D1 至少已入链路，不能是 pending
    p4 = InfraScanTaskRunner._build_pipeline(
        {"phases": {"phase5": {"status": "running"}}, "stage_results": {}}, options
    )
    assert p4["d1"]["status"] == "running"

    # 未启用验证 → skipped（门禁语义不变）
    p5 = InfraScanTaskRunner._build_pipeline(
        {"replay_progress": progress["replay_progress"]},
        {"enable_verification": False, "enable_idor": False},
    )
    assert p5["d1"]["status"] == "skipped"
