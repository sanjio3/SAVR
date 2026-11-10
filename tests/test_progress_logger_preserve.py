"""回归：ScanProgressLogger 的进度写入不得抹掉扫描编排写入的扩展字段。

背景（2026-09-22 run 33/34 实证）：`_load_json` 原用固定白名单
('stage_results','reports','hitl','external_target') 保留扩展字段，
`target_epoch` / `replay_progress` / `d2_verify_progress` / `a2_progress` / `i2_rerun`
不在名单内，于是被 update_phase / add_vulnerability / update_stats 的
「读 → 改 → 全量写」静默抹掉。D2 期间写入的 `target_epoch`
（「本批次是否横跨靶场重启」的权威结论）因此丢失，使 D2 可对账性无法在产物里审计。

本测试锁定：任意未知扩展键在进度写入后必须原样保留。
"""
import json
import os

from src.core.progress_logger import ScanProgressLogger


def _read_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def test_update_phase_preserves_unknown_extension_keys(tmp_path):
    out = str(tmp_path / "run-99")
    lg = ScanProgressLogger(out)

    # 模拟扫描编排（benchmark_cli._update_scan_progress_metadata）写入的扩展键
    path = os.path.join(out, "scan_progress.json")
    data = _read_json(path)
    data["target_epoch"] = {"verdict": "clean", "restarts": 0, "downtime_windows": []}
    data["replay_progress"] = {"total": 189, "replayed": 189, "status": "replay_done"}
    data["d2_verify_progress"] = {"status": "running", "iteration": 1}
    data["a2_progress"] = {"done": 130}
    data["i2_rerun"] = {"iteration": 1, "max_iterations": 3}
    data["stage_results"] = {"d2": {"scheduling": {"candidates": 228, "selected": 189}}}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    # 触发 progress_logger 的常规写入路径（原先正是在这里抹掉扩展键）
    lg.update_phase("phase5", "completed", "D2 统一验证完成")

    after = _read_json(path)
    for key in ("target_epoch", "replay_progress", "d2_verify_progress", "a2_progress", "i2_rerun"):
        assert key in after, "扩展键被抹掉：%s" % key
    assert after["target_epoch"]["verdict"] == "clean"
    assert after["replay_progress"]["replayed"] == 189
    assert after["i2_rerun"]["max_iterations"] == 3
    # 既有契约不受影响
    assert after["stage_results"]["d2"]["scheduling"]["selected"] == 189
    assert after["phases"]["phase5"]["status"] == "completed"
    assert "timestamp" in after and "stats" in after and "vulnerabilities" in after


def test_add_vulnerability_and_update_stats_also_preserve(tmp_path):
    out = str(tmp_path / "scan-100")
    lg = ScanProgressLogger(out)
    path = os.path.join(out, "scan_progress.json")
    data = _read_json(path)
    data["target_epoch"] = {"verdict": "clean"}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    lg.add_vulnerability({"type": "SQLi", "file": "A.java", "line": 1, "verdict": "真"})
    lg.update_stats({"total": 1})
    assert _read_json(path)["target_epoch"] == {"verdict": "clean"}
