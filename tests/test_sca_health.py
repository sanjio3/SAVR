"""SCA 健康度推导：防止「全部工具失败却被记为 0 漏洞 = 扫描通过」。

背景（2026-09-24）：run 47 的 SCA 三工具全挂（osv 解析 pom 失败 / trivy 下载 vuln DB 失败 /
grype 超时），却记录 status=completed、vulnerability_count=0，与「扫出来确实没有漏洞」无法区分，
直接污染了一整轮回归基线。本文件锁住 _derive_sca_health 的四档判定。
"""

from src.application.sca_asset_service import _derive_sca_health


def _tr(tool, status):
    return {"tool": tool, "status": status}


def test_all_tools_failed():
    r = _derive_sca_health({
        "tool_results": [
            _tr("osv-scanner", "failed"),
            _tr("trivy", "failed"),
            _tr("grype", "failed"),
        ],
    })
    assert r["sca_health"] == "all_tools_failed"
    assert sorted(r["tools_failed"]) == ["grype", "osv-scanner", "trivy"]
    assert r["tools_succeeded"] == []
    assert any("全部 SCA 工具执行失败" in w for w in r["warnings"])


def test_partial_tools_failed():
    r = _derive_sca_health({
        "tool_results": [
            _tr("osv-scanner", "failed"),
            _tr("grype", "completed"),
        ],
    })
    assert r["sca_health"] == "partial_tools_failed"
    assert r["tools_failed"] == ["osv-scanner"]
    assert r["tools_succeeded"] == ["grype"]
    assert r["warnings"] == []  # 部分失败不写全失败告警


def test_some_completed_is_ok():
    r = _derive_sca_health({
        "tool_results": [_tr("grype", "completed")],
    })
    assert r["sca_health"] == "ok"
    assert r["tools_failed"] == []
    assert r["tools_succeeded"] == ["grype"]


def test_no_tool_results_untouched():
    # skipped / 未实际跑工具：不置评，避免误报
    r = _derive_sca_health({"status": "skipped", "findings": []})
    assert r["sca_health"] is None
    assert r["warnings"] == []
