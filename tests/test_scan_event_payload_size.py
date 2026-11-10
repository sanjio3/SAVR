"""进度事件 payload 体积上限（2026-10-04 P0，`scan_task_events` 膨胀 9.02GB 的回归锁）。

实测（20:00，`data/` 24GB / `app.db` 11GB）：`scan_task_events.payload_json` 合计 **9.02GB**，
占 app.db 的 83%。`task_progress` 67,424 条、平均 43.9KB、**最大 2.42MB**，单条构成：

    stage_results  1,239.1 KB  ├ d2 599.6 KB（verifications_detail 341.3KB / scheduling 257.4KB）
                                 ├ attack_plan 428.2 KB（entries 427.3KB）
                                 └ d1 117.5 KB（replayed_specs_detail 117.3KB）
    pipeline       1,185.6 KB

`task_runner._slim_stage_map` 是事件瘦身的唯一入口（`task_runner.py:374-386` 调用），
但它只剥了 `metrics.tool_result` / `stage.tool_result` 里的 SCA 工具结果
（2026-09-14 那轮瘦身，载荷降 94.6%），**没碰上面这些明细数组** ⇒ 单条仍能到 2.42MB。

前端契约：`frontend/src/domain/task-view.ts`、`pages/TaskDetailPage.vue`、
`stores/workspaces.ts` 只消费 stage 的**状态与计数**（status / message / finding_count /
candidate_count / replayed_count / plan_count / by_family），不消费明细数组 ⇒ 可以安全裁掉。

本文件锁两条：
1. 任何 stage 的**单个字段**序列化超过阈值就必须被替换成紧凑占位（带原长度计数），
   否则进度事件会再次把整份流水线快照灌进 DB；
2. 裁剪必须保留状态与计数键（前端契约），且对**非明细**的小字段必须原样保留。
"""
import json

from src.infrastructure.task_runner import _slim_stage_map

# 单字段裁剪阈值（字节）。实测明细数组单条 300–900B、条数 400–600，
# 阈值取 4KB：既能压掉明细数组，又不会误伤 by_family / status 这类小结构。
MAX_FIELD_BYTES = 4096
# 裁剪后整份 stage_map 的体积上限。实测最坏 2.42MB，预算 64KB 仍有 30 倍余量。
MAX_TOTAL_BYTES = 64 * 1024

# 前端真正消费的键：这些必须原样保留（by_family 是族级计数聚合，体积小且要展示）
KEEP_KEYS = ("status", "message", "finding_count", "candidate_count",
             "replayed_count", "plan_count", "by_family", "duration_seconds",
             "updated_at", "docker_used", "runtime_enriched")


def _detail_entry(i):
    """模拟一条明细记录：真实里带 payload / request / response / trace，体积 300–900B。"""
    return {
        "index": i,
        "spec_id": f"/sqli-00/BenchmarkTest{i:05d}",
        "payload": "s4st41" + f"{i:016x}" + "UNION SELECT password FROM users--" * 3,
        "request": {"method": "POST", "path": "/benchmark", "body": "x" * 200},
        "response": {"status": 500, "body": "y" * 300},
        "trace": [f"step-{j}" for j in range(10)],
    }


def _realistic_stage_map():
    """按实测形状构造 stage_results（键名与体积都对齐线上真实事件）。"""
    return {
        "d2": {
            "status": "running",
            "message": "D2 统一验证进行中",
            "duration_seconds": 4211.5,
            "docker_used": False,
            "verifications_detail": [_detail_entry(i) for i in range(421)],
            "scheduling": {
                "total": 421, "done": 118, "pending": 303,
                "channels": {f"ch{i}": {"planned": i, "done": i // 2} for i in range(7)},
                "history": [{"ts": i, "spec": f"/xpathi-00/BenchmarkTest{i:05d}",
                             "state": "confirmed"} for i in range(300)],
            },
            "by_family": {"sqli": 120, "xpathi": 60, "cmdi": 40},
        },
        "attack_plan": {
            "status": "completed",
            "message": "攻击计划生成完成",
            "plan_count": 580,
            "runtime_enriched": True,
            "entries": [_detail_entry(i) for i in range(580)],
            "by_family": {"sqli": 200, "cmdi": 120},
        },
        "d1": {
            "status": "completed",
            "message": "重放完成",
            "replayed_count": 391,
            "candidate_count": 402,
            "finding_count": 318,
            "replayed_specs_detail": [_detail_entry(i) for i in range(391)],
        },
        "i2": {
            "status": "pending",
            "message": "",
            "entries": [_detail_entry(i) for i in range(200)],
        },
        "a2_poc": {"status": "completed", "message": "A2 PoC 完成", "count": 169},
    }


def _size(obj):
    return len(json.dumps(obj, ensure_ascii=False).encode("utf-8"))


def test_stage_map_stays_under_budget():
    """裁剪后整份 stage_map 必须落在预算内（当前 2.4MB 量级 ⇒ 红灯）。"""
    raw = _realistic_stage_map()
    slim = _slim_stage_map(raw)
    assert _size(slim) <= MAX_TOTAL_BYTES, (
        f"stage_map 裁剪后仍有 {_size(slim) / 1024:.1f}KB，超出 "
        f"{MAX_TOTAL_BYTES / 1024:.0f}KB 预算；明细数组没被裁掉"
    )


def test_bulk_fields_replaced_with_counted_stub():
    """超阈值的字段必须被换成带原长度的紧凑占位，而不是原样留着。"""
    slim = _slim_stage_map(_realistic_stage_map())
    d2 = slim["d2"]
    assert "verifications_detail" not in d2, "421 条明细（341KB）没被裁掉"
    stub = d2.get("verifications_detail_trimmed") or d2.get("verifications_detail")
    assert isinstance(stub, dict), "裁剪后应保留一个占位（便于前端知道「有明细但已折叠」）"
    # 占位里要能读出原始条数/体积，否则前端与事后审计都失去「有多少明细」的判据
    text = json.dumps(stub, ensure_ascii=False)
    assert "421" in text, f"占位未保留原始条数 421：{text[:200]}"
    assert _size(stub) <= MAX_FIELD_BYTES, "占位本身不该再是明细数组"


def test_frontend_contract_keys_preserved():
    """前端只读状态与计数 ⇒ 这些键必须原样保留，裁剪不许误伤。"""
    raw = _realistic_stage_map()
    slim = _slim_stage_map(raw)
    for stage, keys in (
        ("d2", ("status", "message", "duration_seconds", "by_family", "docker_used")),
        ("attack_plan", ("status", "message", "plan_count", "by_family", "runtime_enriched")),
        ("d1", ("status", "message", "replayed_count", "candidate_count", "finding_count")),
    ):
        for k in keys:
            assert k in slim[stage], f"stage_results.{stage} 丢了前端需要的 {k}"
            assert slim[stage][k] == raw[stage][k], f"stage_results.{stage}.{k} 被改动了"
    assert _size(slim["d2"]["by_family"]) <= MAX_FIELD_BYTES, "by_family 不该被裁"


def test_small_fields_untouched():
    """小字段（未超阈值）必须原样保留，避免把有用信息也抹掉。"""
    raw = _realistic_stage_map()
    slim = _slim_stage_map(raw)
    assert slim["a2_poc"] == raw["a2_poc"], "a2_poc 体积很小，应完全不动"
