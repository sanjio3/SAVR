"""泛化比较工具 --json 输出的回归锁（2026-11-08）。

历史缺陷：measure()['attrib'] 用 (base, family) 元组作 key 供 render() 做逐点
归因，而 `json.dump(payload, ..., default=list)` 遇到非字符串 dict key 直接抛
`TypeError: keys must be str, int, float, bool or None, not tuple`。L1'
真实对账时首次触发：文本报告已完整打印，机器可读结果却没写出来，EXIT=1。

修法只在序列化侧：to_jsonable() 把 tuple key 归一成 "base|family"、把 set/tuple
转成 list。measure() 的返回结构、render() 的查询方式、红线判定与例外放行逻辑
一律不变。
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if os.path.join(ROOT, "tools") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "tools"))
import generalization_compare as G  # noqa: E402


CONFIG = os.path.join(ROOT, "config", "generalization.yaml")


def _var(items):
    return {
        "task_id": 638,
        "truth": "java_sec_code_truth_v2.csv",
        "denominator": 24,
        "fp_replay": len(items),
        "fp_replay_items": [tuple(k) for k in items],
        "fp_replay_keys": sorted({(str(a), str(b)) for a, b in items}),
        "attrib": {("fileupload.java", "file_upload"): ["sink-reached", "no-arrival"]},
        "hits": {"rep_fam": [("a.java", "x")]},
        "strict_hits": {("b.java", "y")},
    }


def test_to_jsonable_converts_tuple_keys():
    out = G.to_jsonable({("a.java", "xss"): ["sink-reached"]})
    assert out == {"a.java|xss": ["sink-reached"]}
    assert json.loads(json.dumps(out)) == out


def test_to_jsonable_handles_nested_sets_and_tuples():
    payload = {
        "variant": {"strict_hits": {("b.java", "y")}, "keys": [("a.java", "x")]},
        "gate": {"redline_pass": True, "count": 0},
    }
    out = G.to_jsonable(payload)
    assert out["variant"]["strict_hits"] == [["b.java", "y"]]
    assert out["variant"]["keys"] == [["a.java", "x"]]
    assert out["gate"] == {"redline_pass": True, "count": 0}
    json.dumps(out)  # must not raise


def test_to_jsonable_keeps_plain_scalars_and_lists():
    assert G.to_jsonable(None) is None
    assert G.to_jsonable(3) == 3
    assert G.to_jsonable("x") == "x"
    assert G.to_jsonable([1, {"k": (1, 2)}]) == [1, {"k": [1, 2]}]


def _run_cli(monkeypatch, tmp_path, var, with_exceptions=False):
    monkeypatch.setattr(G, "measure", lambda *a, **k: dict(var))
    monkeypatch.setattr(G, "render", lambda *a, **k: "")
    monkeypatch.setattr(G.J, "load_known_unreachable", lambda: [])
    if not with_exceptions:
        monkeypatch.setattr(G, "load_pre_registered_exceptions", lambda path: [])
    out = tmp_path / "cmp.json"
    monkeypatch.setattr(sys, "argv", [
        "generalization_compare.py",
        "--baseline", "637", "--variant", "638", "--mode", "blind",
        "--truth", G.DEFAULT_TRUTH, "--json", str(out),
    ])
    rc = G.main()
    assert rc == 0
    return json.loads(out.read_text(encoding="utf-8"))


def test_cli_json_writes_parsable_payload_with_tuple_attrib(monkeypatch, tmp_path):
    payload = _run_cli(monkeypatch, tmp_path, _var([]))
    assert payload["mode"] == "blind"
    assert payload["gate"]["redline_pass"] is True
    assert payload["gate"]["fp_replay_raw"] == 0
    assert payload["variant"]["attrib"] == {
        "fileupload.java|file_upload": ["sink-reached", "no-arrival"]}
    assert payload["variant"]["strict_hits"] == [["b.java", "y"]]


def test_cli_json_preserves_exception_gate_result(monkeypatch, tmp_path):
    """带 tuple key 的 attrib + 真实预登记例外同时存在时，JSON 与判定都要正确。"""
    var = _var([("log4j.java", "xss")])
    payload = _run_cli(monkeypatch, tmp_path, var, with_exceptions=True)
    assert payload["gate"]["fp_replay_raw"] == 1
    assert payload["gate"]["fp_replay_effective"] == 0
    assert payload["gate"]["redline_pass"] is True
    assert payload["gate"]["exception_matched"][0]["id"] == "L1_log4j_xss"
    assert payload["gate"]["exception_violations"] == []
