"""闭环 A2 重跑结果合并的回归锁（2026-10-07，r62 pathtraver-1 事故）。

背景：``_merge_a2_results`` 原实现按文件「整份替换」（``by_file[f] = r``）。
A2 闭环重跑为省 LLM 只重跑部分文件，且重跑产物常比原始少（LLM 未对全部假说复答），
整份替换会把 base 里「没被重跑到 / 重跑未复答」的假说一并清掉。

实测后果：r62 的 pathtraver-1 分片 findings 表完整（134 用例），但合并后登记输入收窄，
trigger_specs 只剩 75 用例，丢 59 个用例、其中 33 条真值 TP，召回 100%→54.2%（-45.8pp）。

本文件锁死「合并必须是并集」这条不变式，防止回退到整份替换。
"""
import pytest

from src.cli.benchmark_cli import _merge_a2_results, _vuln_identity


class _V:
    """最小漏洞假説桩：只需具备 file / line / type 与 to_dict。"""

    def __init__(self, file, line, type_):
        self.file = file
        self.line = line
        self.type = type_

    def to_dict(self):
        return {"file": self.file, "line": self.line, "type": self.type}


class _Res:
    """最小扫描结果桩：只需具备 file 与 vulnerabilities。"""

    def __init__(self, file, vulns):
        self.file = file
        self.vulnerabilities = list(vulns)


def _total(results):
    return sum(len(getattr(r, "vulnerabilities", []) or []) for r in results)


def test_merge_keeps_base_when_rerun_is_narrower():
    """重跑只复答 1 条时，base 的另 2 条必须保留（不能整份替换）。"""
    base = [_Res("A.java", [
        _V("A.java", 1, "path_traversal"),
        _V("A.java", 2, "path_traversal"),
        _V("A.java", 3, "cmdi"),
    ])]
    rerun = [_Res("A.java", [_V("A.java", 1, "path_traversal")])]

    out = _merge_a2_results(base, rerun)
    assert _total(out) == 3, f"重跑收窄不应丢 base 假说：期望 3 条，实得 {_total(out)} 条"


def test_merge_rerun_overrides_same_identity():
    """同身份键（file,line,type）的假说应被重跑结果覆盖，且总数不膨胀。"""
    _old = _V("A.java", 1, "path_traversal")
    _new = _V("A.java", 1, "path_traversal")
    _new.type = "path_traversal"  # 同键

    base = [_Res("A.java", [_old])]
    rerun = [_Res("A.java", [_new])]

    out = _merge_a2_results(base, rerun)
    assert _total(out) == 1, "同键应覆盖而非并列"
    assert out[0].vulnerabilities[0] is _new, "同键应取重跑侧的新结果"


def test_merge_appends_vulns_only_in_rerun():
    """重跑新发现的假说应追加进并集。"""
    base = [_Res("A.java", [_V("A.java", 1, "path_traversal")])]
    rerun = [_Res("A.java", [
        _V("A.java", 1, "path_traversal"),
        _V("A.java", 9, "xss"),
    ])]

    out = _merge_a2_results(base, rerun)
    assert _total(out) == 2, f"重跑新增应追加：期望 2 条，实得 {_total(out)} 条"


def test_merge_no_rerun_returns_base_unchanged():
    """无重跑结果时原样返回全量（D2 验证范围不得缩小）。"""
    base = [_Res("A.java", [_V("A.java", 1, "path_traversal")]),
            _Res("B.java", [_V("B.java", 5, "cmdi")])]
    out = _merge_a2_results(base, [])
    assert _total(out) == 2
    assert [r.file for r in out] == ["A.java", "B.java"], "应保持全量集合的文件顺序"


def test_merge_does_not_shrink_total():
    """不变式：合并后假说总数不得小于 base（缩小即召回丢失通道）。"""
    base = [
        _Res("A.java", [_V("A.java", 1, "path_traversal"), _V("A.java", 2, "cmdi")]),
        _Res("B.java", [_V("B.java", 7, "sqli")]),
    ]
    rerun = [_Res("A.java", [_V("A.java", 1, "path_traversal")])]

    n_base = _total(base)
    assert _total(_merge_a2_results(base, rerun)) >= n_base


def test_vuln_identity_distinguishes_line_and_type():
    """身份键须能区分同文件的不同行/不同族，否则并集会互相覆盖。"""
    a = _V("A.java", 1, "path_traversal")
    b = _V("A.java", 2, "path_traversal")
    c = _V("A.java", 1, "cmdi")
    assert _vuln_identity(a) != _vuln_identity(b)
    assert _vuln_identity(a) != _vuln_identity(c)
