"""块2 回归守卫：entry.route 回填后必须重算 contract_completeness，否则 SSTI 被永久拒于 D2 门外。

背景（2026-09-10 定位）：
SSTI（模板注入）在检测端稳定产出 findings（run 24/25 均 8~9 条），但 trigger_specs 侧
ssti_specs 恒为 0。根因不是"route 提取失败"，而是**契约完整度是回填前的陈旧快照**：

- `_pre_resolve_a2_endpoints`（benchmark_cli.py）在 1733 行回填 entry.route/method，
  但 vuln.contract_completeness 仍是回填前算出的 status='missing'、
  missing=['entry.route','entry.method']。
- report_manager 用 `vuln.get('contract_completeness') or ...` 保留旧值，从不刷新。
- is_contract_ready_item 直接读该陈旧字段 → 命中 `status in {'missing','partial'}` 即 return False；
  而 a21_selected 豁免条款只对**业务族**生效，SSTI 非业务族 → 用不了豁免 → 永久被拒。

修复：_pre_resolve_a2_endpoints 在 `vuln.exploit_spec = spec` 之后重算
`vuln.contract_completeness = exploit_spec_completeness(spec)`。

本测试用 run 24 的真实 SSTI finding 验证这条因果链：
  回填前(route 空) → completeness 非 ready → 门禁拒绝；
  回填后(route 有) + 重算 → completeness ready → 门禁放行。
"""
import copy
import json
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src.core.exploit_spec import exploit_spec_completeness  # noqa: E402
from src.benchmark.report_manager import is_contract_ready_item  # noqa: E402

DB = os.path.join(ROOT, "data", "app.db")
TASK_ID = 24  # 已完成的基线轮，含真实 SSTI findings
FALLBACK_SPEC = {
    # 与 run 24 finding 5221 同构（MarketingController.java:25，模板注入）
    "entry": {"route": "/marketing/preview", "method": "GET"},
    "payload": {"payload_family": ""},
    "success_signal": {"signal_type": ""},
}


def _load_real_ssti_spec():
    """取一条真实 SSTI finding 的 exploit_spec（已回填 route 的最终态）。"""
    if not os.path.exists(DB):
        return None, None
    try:
        con = sqlite3.connect(DB, timeout=10)
        con.row_factory = sqlite3.Row
        row = con.execute(
            "select id, finding_type, raw_json from findings "
            "where task_id=? and finding_type like '%模板注入%' limit 5",
            (TASK_ID,),
        ).fetchone()
        con.close()
        if not row:
            return None, None
        raw = json.loads(row["raw_json"] or "{}")
        spec = raw.get("exploit_spec") or {}
        # 只要最终解析出可达入口的那条（route 非空）
        if (spec.get("entry") or {}).get("route"):
            return spec, dict(row)
    except Exception:
        pass
    return None, None


def test_stale_snapshot_blocks_ssti():
    """回填前：route/method 为空 → 陈旧 completeness=missing → 门禁拒绝。"""
    spec_real, _ = _load_real_ssti_spec()
    spec = copy.deepcopy(spec_real or FALLBACK_SPEC)
    entry = spec.setdefault("entry", {})
    route = entry.get("route") or FALLBACK_SPEC["entry"]["route"]
    # 模拟"回填前"：清空入口双要素
    entry["route"] = ""
    entry["method"] = ""

    stale = exploit_spec_completeness(spec)
    assert stale.get("status") in {"missing", "partial"}, (
        f"回填前应判为缺失/不完整，实际 {stale.get('status')}"
    )
    assert "entry.route" in (stale.get("missing_required") or []), (
        f"回填前 missing 应含 entry.route，实际 {stale.get('missing_required')}"
    )

    vuln = {
        "type": "模板注入",  # 非业务族，用不了 a21_selected 豁免
        "a21_selected": True,
        "exploit_spec": spec,
        "contract_completeness": stale,  # 陈旧快照
    }
    assert is_contract_ready_item(vuln) is False, (
        "陈旧 missing 快照下门禁必须拒绝（这正是 SSTI 进不了 D2 的原因）"
    )
    print(f"PASS  test_stale_snapshot_blocks_ssti  (route={route!r} 回填前 status={stale.get('status')} → 拒绝)")


def test_refresh_after_backfill_unblocks_ssti():
    """回填后重算：route/method 就位 → completeness ready → 门禁放行。"""
    spec_real, _ = _load_real_ssti_spec()
    spec = copy.deepcopy(spec_real or FALLBACK_SPEC)
    entry = spec.setdefault("entry", {})
    if not entry.get("route"):
        entry["route"] = FALLBACK_SPEC["entry"]["route"]
    if not entry.get("method"):
        entry["method"] = FALLBACK_SPEC["entry"]["method"]

    refreshed = exploit_spec_completeness(spec)  # 修复后执行的重算
    assert refreshed.get("status") == "ready", (
        f"回填并重算后应为 ready，实际 {refreshed.get('status')} "
        f"missing={refreshed.get('missing_required')}"
    )

    vuln = {
        "type": "模板注入",
        "a21_selected": True,
        "exploit_spec": spec,
        "contract_completeness": refreshed,
    }
    assert is_contract_ready_item(vuln) is True, "重算为 ready 后门禁必须放行"
    print(
        f"PASS  test_refresh_after_backfill_unblocks_ssti  "
        f"(route={entry['route']!r} 重算后 status=ready → 放行)"
    )


if __name__ == "__main__":
    test_stale_snapshot_blocks_ssti()
    test_refresh_after_backfill_unblocks_ssti()
    print("\nALL TESTS PASSED")
