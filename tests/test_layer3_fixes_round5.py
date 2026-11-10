"""jsc 625 红线误报回归锁：响应层 oracle 单独放行需做族归属校验（2026-11-06）。

625 四档对账：召回确实改善（相对 624 重放文件级/文件+族均 +8.3pp，漏点 8→6），
但红线误报从 623/624 的 0 条涨到 3 条，确认级误报 5.3%→11.3%，踩了用户红线。

三条误报全是「值被回显」类弱信号 + 泛化族 + sink 文件与该族语义不符：
- `Log4j.java / xss / reflection_raw`：端点 /log4j 回显 `<sastxss1>`，真值族是 jndi_injection。
- `OriginFilter.java / cors / acao_reflect`：/cors/vuln/origin 回显 Origin 头。
- `URLWhiteList.java / url_redirect / location_reflect`：同一端点同时产出泛化族
  url_redirect 与更具体族 url_whitelist_bypass，泛化族不在真值集。

同时不能一刀切砍掉所有纯回显信号——`Cors.java/cors`、`XSS.java/xss`、
`URLRedirect.java/url_redirect` 是文件名与族一致的正确确认，必须保留。
故判据为：强因果信号直接放行；纯回显弱信号且 spec 属于泛化族时，要求 sink
文件名含族语义提示词；更具体族（canonical 后与原始族不同）不校验；
sink_file 缺失时 fail-open。
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _gate(family, signal, sink_file, state="exploitable", rule=""):
    from src.cli.benchmark_cli import _oracle_gate_signal
    return _oracle_gate_signal(family, state, signal, rule, sink_file)


def test_strong_causal_signals_are_always_admitted():
    """差分/时延/文件签名/错误回显/WS 回显是强因果观测，不看文件名。"""
    cases = [
        ("ssrf", "error_reflect", "SSRF.java"),
        ("ssrf", "internal_url_reflect", "SSRF.java"),
        ("command_execution", "websocket_echo", "WebSocketsCmdEndpoint.java"),
        ("command_execution", "time_delay", "CommandInject.java"),
        ("path_traversal", "file_signature", "PathTraversal.java"),
        ("sql_injection", "boolean_diff", "SQLI.java"),
    ]
    for fam, sig, sink in cases:
        assert _gate(fam, sig, sink) == sig, (fam, sig, sink)


def test_625_redline_false_positives_are_rejected():
    """三条真实红线误报必须被挡下（族误标 + 文件名不含族提示词）。"""
    assert _gate("xss", "reflection_raw", "Log4j.java") == ""
    assert _gate("cors", "acao_reflect", "OriginFilter.java") == ""
    assert _gate("url_redirect", "location_reflect", "URLWhiteList.java") == ""
    # 同类：WebSocket 控制器被挂成 xss 反射
    assert _gate("xss", "reflection_raw", "WebSockets.java") == ""


def test_correct_reflection_confirmations_are_preserved():
    """文件名与族一致的正确确认不能被误伤（召回不回退）。"""
    assert _gate("cors", "acao_reflect", "Cors.java") == "acao_reflect"
    assert _gate("xss", "reflection_raw", "XSS.java") == "reflection_raw"
    assert _gate("url_redirect", "location_reflect", "URLRedirect.java") == "location_reflect"


def test_specific_family_bypasses_filename_check():
    """url_whitelist_bypass 是更具体族，canonical 后变成 url_redirect，
    原始族 != canonical ⇒ 不做文件名提示词校验，625 的白名单绕过收敛点保留。"""
    assert _gate("url_whitelist_bypass", "location_reflect",
                 "URLWhiteList.java") == "location_reflect"


def test_missing_sink_file_is_fail_open():
    """观测列缺失时不得把整族拦死。"""
    assert _gate("xss", "reflection_raw", "") == "reflection_raw"
    assert _gate("cors", "acao_reflect", "") == "acao_reflect"


def test_gate_signal_requires_state_and_family_match():
    """强信号也不能绕过 inconclusive / 空信号 / 跨族三道基本校验。"""
    assert _gate("ssrf", "error_reflect", "SSRF.java", state="inconclusive") == ""
    assert _gate("ssrf", "", "SSRF.java") == ""
    assert _gate("xss", "error_reflect", "XSS.java") == ""
    assert _gate("command_execution", "websocket_echo", "X.java",
                 state="not_exploitable") == ""


def test_positive_evidence_rule_fallback_uses_same_check():
    """oracle_state 未回灌时从 rule 恢复，且同样过族归属校验。"""
    from src.cli.benchmark_cli import _oracle_gate_signal

    assert _oracle_gate_signal("ssrf", "", "", "oracle:error_reflect", "SSRF.java") == "error_reflect"
    assert _oracle_gate_signal("xss", "", "", "oracle:reflection_raw", "Log4j.java") == ""
    assert _oracle_gate_signal("xss", "", "", "oracle:reflection_raw", "XSS.java") == "reflection_raw"


def test_three_gate_paths_share_the_same_predicate():
    """硬闸 / 迟到证据回补 / oracle 升级必须同源，且都能拿到 sink 文件。"""
    text = _src("src/cli/benchmark_cli.py")
    assert text.count("_oracle_gate_signal(") >= 4, "三处放行路径未使用统一判据"
    assert "expected_sink_file" in text
    assert "_ORACLE_FAMILY_FILE_HINTS" in text
    assert "_ORACLE_WEAK_REFLECTION_SIGNALS" in text


def test_response_only_signals_exclude_pure_reflections():
    """允许绕过到达态门槛的集合不得含纯回显信号（no-arrival 旁路）。"""
    from src.cli.benchmark_cli import _RESPONSE_ONLY_ORACLE_SIGNALS

    assert "reflection_raw" not in _RESPONSE_ONLY_ORACLE_SIGNALS
    assert "acao_reflect" not in _RESPONSE_ONLY_ORACLE_SIGNALS
    assert "header_injected" not in _RESPONSE_ONLY_ORACLE_SIGNALS
    assert "error_reflect" in _RESPONSE_ONLY_ORACLE_SIGNALS
    assert "websocket_echo" in _RESPONSE_ONLY_ORACLE_SIGNALS
