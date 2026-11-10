"""jsc 627→628 回归锁：四个剩余真值点的结构性根因。

627 正式四档对账是「重放档 75.0%→87.5%（文件级）/ 70.8%→83.3%（文件+族）、
红线误报 0/55」，但逐点表里 fastjson.java 与 fileupload.java 是**真退步**，
xstreamrce.java / qlexpress.java 仍是零重放。本文件锁住四类修复：

  1. raw-body 端点判定与线格式映射：主请求、baseline、补投、oracle 探测臂同源；
  2. 按 sink 解析器类型产出专用首发弹，并把 sca_forge 的 rO0AB... 换下首发位；
  3. 文本型反序列化器把异常 catch 成 status=200 时，阴臂失败仍要被识别；
  4. file_upload 族有真弹，multipart 文件名带身份段，sink 事件可稳定归属。

证据边界（必须保持）：deser_object_accepted 只证明「攻击者可控输入被解析器
完整处理」，不等于 RCE 命令执行。红线门控仍要挡住 625 那三条错配误报。

活靶场实测基准（2026-11-06，登录态 + 裸串 data= 投递）：
  /fastjson/deserialize  {"name":"SASTAI_DESER_x"}                → 200 SASTAI_DESER_x
  /xstream               <java.lang.String>SASTAI_ORACLE</…>       → 200 xstream
  /vuln1                 111 * 7                                   → 200 777
  /file/upload           multipart                                 → 302 /file/status
而修复前的 json={'_body': 'rO0AB…'} 分别得到 NPE / 500 / 500。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "data" / "app.db"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _spec(family: str, sink: str, endpoint: str, *,
          param_name: str = "_body", param_location: str = "body",
          content_type: str = "", spec_id: str = "238831") -> dict:
    return {
        "family": family,
        "expected_sink_file": "src/main/java/org/joychou/controller/" + sink,
        "target_endpoint": endpoint,
        "id": spec_id,
        "taint_marker": "s4st41abcdef0123456",
        "param_name": param_name,
        "param_location": param_location,
        "content_type": content_type,
    }


# ── 1. raw-body 判定与线格式映射 ────────────────────────────────────────


def test_raw_body_judgment_hits_three_endpoints_only():
    from src.application.d1_service import needs_raw_body_payload

    assert needs_raw_body_payload("deserialization", "_body", "body", "")
    assert needs_raw_body_payload("deserialization", "xml", "body", "")
    assert needs_raw_body_payload("expression_injection", "requestBody", "body", "")
    assert needs_raw_body_payload("expression_injection", "_body", "body", "text/plain")

    # 这三处是 627 已确认的点，绝不能被新判定改道
    assert not needs_raw_body_payload("deserialization", "data", "query", "")
    assert not needs_raw_body_payload("deserialization", "rememberMe", "cookie", "")
    assert not needs_raw_body_payload("sql_injection", "_body", "body", "")
    # 声明了结构化线格式 ⇒ 端点读的是命名对象字段，不是整段裸串
    assert not needs_raw_body_payload("deserialization", "_body", "body",
                                      "application/json")
    assert not needs_raw_body_payload("deserialization", "file", "form",
                                      "multipart/form-data")


def test_body_data_json_never_wraps_raw_string_in_json_quotes():
    from src.application.d1_service import body_data_json

    assert body_data_json("111 * 7", "") == ("111 * 7", None)
    assert body_data_json('{"name":"x"}', "") == ('{"name":"x"}', None)
    assert body_data_json({"_body": "x"}, "") == (None, {"_body": "x"})
    assert body_data_json({"a": "1"}, "application/x-www-form-urlencoded") == (
        {"a": "1"}, None)
    assert body_data_json(None, "") == (None, None)


def test_d1_main_baseline_and_oracle_all_share_the_wire_helper():
    src = _read("src/application/d1_service.py")
    assert "def needs_raw_body_payload(" in src
    assert "def body_data_json(" in src
    # 主发送 / baseline / 抗抖动 / 方法回退 / 绕过变体 / 对照 / _send_one / oracle
    assert src.count("body_data_json(") >= 9, src.count("body_data_json(")
    # 旧的双分支写法若残留，raw-body 会重新被 json= 包一层
    assert '_json = body if (body is not None and "form" not in content_type.lower())' not in src
    assert "needs_raw_body_payload(fam, param_name, ploc, content_type)" in src


def test_d1_skips_json_object_normalization_and_canary_append_for_raw_body():
    src = _read("src/application/d1_service.py")
    # Fastjson 专用弹是合法 JSON 对象串，不能被当成「A2 的整组请求参数」展开
    assert "_raw_body_sink = needs_raw_body_payload(" in src
    assert "and not _raw_body_sink):" in src
    # `111 * 7` 追加身份段会变成编译失败的 `111 * 7s4st41…`（627 实测 500）
    assert "and not _raw_body_sink\n" in src
    # 名注入源 / 额外注入点补投对「读整个请求体」的控制器无意义
    assert "if _raw_body_sink:\n            _name_source = None" in src
    assert "_extra = [] if _raw_body_sink else _derive_extra(spec)" in src


# ── 2. 端点专用首发弹 ───────────────────────────────────────────────────


def test_endpoint_specific_payloads_are_selected_by_parser_class():
    from src.iast.payload_library import build_family_payloads

    cases = [
        ("deserialization", "Fastjson.java", "/fastjson/deserialize",
         "endpoint_fastjson_json", '{"name":'),
        ("deserialization", "XStreamRce.java", "/xstream",
         "endpoint_xstream_xml", "<java.lang.String>"),
        ("expression_injection", "QLExpress.java", "/vuln1",
         "endpoint_qlexpress_expr", "111 * 7"),
    ]
    for fam, sink, ep, provider, prefix in cases:
        lib = build_family_payloads(fam, _spec(fam, sink, ep))
        assert lib["provider"] == provider, (sink, lib)
        assert lib.get("sink_specific") is True, (sink, lib)
        assert lib["payloads"][0].startswith(prefix), (sink, lib["payloads"])


def test_endpoint_specific_payloads_leave_other_deser_sinks_alone():
    from src.iast.payload_library import build_family_payloads

    for sink, ep in (("Deserialize.java", "/deserialize"),
                     ("Shiro.java", "/shiro/deserialize")):
        lib = build_family_payloads(
            "deserialization", _spec("deserialization", sink, ep))
        assert lib["provider"] != "endpoint_fastjson_json"
        assert not lib.get("sink_specific"), (sink, lib)


def test_frontload_replaces_ysoserial_stream_at_first_position():
    from src.iast.payload_library import frontload_sink_specific

    stream = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
    for fam, sink, ep, prefix in (
        ("deserialization", "Fastjson.java", "/fastjson/deserialize", '{"name":'),
        ("deserialization", "XStreamRce.java", "/xstream", "<java.lang.String>"),
        ("expression_injection", "QLExpress.java", "/vuln1", "111 * 7"),
    ):
        out = frontload_sink_specific(fam, _spec(fam, sink, ep), [stream])
        assert out["changed"] is True, (sink, out)
        assert out["payloads"][0].startswith(prefix), (sink, out["payloads"])
        # endpoint_* 形态命中时旧弹整体丢弃：rO0AB 二进制流对这三个解析器都是废弹，
        # 留在观测臂里只会制造 500 与噪声。
        assert stream not in out["payloads"], (sink, out["payloads"])


def test_endpoint_frontload_drops_a2_destructive_expr_payloads():
    """627 的 QLExpress spec 238769 带 5 发 Runtime/ProcessBuilder 弹。"""
    from src.iast.payload_library import frontload_sink_specific

    sp = _spec("expression_injection", "QLExpress.java", "/vuln1",
               param_name="requestBody", spec_id="238769")
    a2 = [
        '1+1==2;System.out.println("Exploit");',
        '1+1==2;Runtime.getRuntime().exec("calc");',
        '1+1==2;new java.lang.ProcessBuilder("calc").start();',
    ]
    out = frontload_sink_specific("expression_injection", sp, a2)
    assert out["changed"] is True
    assert out["payloads"] == ["111 * 7", '"SASTAI_" + "238769"'], out["payloads"]
    assert not any("Runtime" in p or "ProcessBuilder" in p for p in out["payloads"])


def test_endpoint_frontload_also_works_when_current_is_empty():
    from src.iast.payload_library import frontload_sink_specific

    out = frontload_sink_specific(
        "deserialization", _spec("deserialization", "Fastjson.java",
                                 "/fastjson/deserialize"), [])
    # 旧实现 changed=False ⇒ D1 不采用库弹，spec 继续 degraded_no_synthesis
    assert out["changed"] is True, out
    assert out["payloads"][0].startswith('{"name":'), out["payloads"]


def test_multipart_rep_canary_cannot_override_the_main_slot():
    """content_type=multipart 时 query/form 登记漂移仍属同一字段。"""
    src = _read("src/application/d1_service.py")
    assert 'or "multipart" in str(content_type or "").lower()))' in src


def test_file_upload_provider_produces_nonempty_canary_payload():
    from src.iast.payload_library import build_family_payloads, frontload_sink_specific

    sp = _spec("file_upload", "FileUpload.java", "/file/upload",
               param_name="file", param_location="form")
    lib = build_family_payloads("file_upload", sp)
    assert lib["provider"] == "file_upload"
    assert lib["payloads"] and all(lib["payloads"])
    assert "s4st41abcdef0123456" in lib["payloads"][0]
    # 627 的 degraded_no_synthesis 空弹必须被换掉
    out = frontload_sink_specific("file_upload", sp, [])
    assert out["changed"] is True
    assert out["payloads"] == lib["payloads"]


def test_d1_multipart_filename_carries_canary_identity():
    src = _read("src/application/d1_service.py")
    assert '_fn_mark = re.sub(r"[^A-Za-z0-9_-]", ""' in src
    assert '"%s%s.txt" % (pname, _fn_suffix)' in src
    # 不能把路径穿越形态带进文件名
    assert "_fn_suffix" in src and "../" not in src.split("_fn_suffix")[1][:200]


# ── 3. 阴臂判据与红线门控 ───────────────────────────────────────────────


def test_deser_oracle_recognizes_text_parser_failure_at_status_200():
    from src.iast import response_oracle as orc

    arms = [
        orc.ArmResult(arm="deser_invalid", payload="SASTAI_NOT_AN_OBJECT_1",
                      status=200,
                      body="com.alibaba.fastjson.JSONException: syntax error, pos 6, "
                           "json : SASTAI_NOT_AN_OBJECT_1",
                      elapsed_ms=1, note="negative_control"),
        orc.ArmResult(arm="deser_valid", payload='{"name":"SASTAI_DESER_1"}',
                      status=200, body="SASTAI_DESER_1",
                      elapsed_ms=1, note="primary_payload"),
    ]
    verdict = orc.judge("deserialization", arms)
    assert verdict["verdict"] == "exploitable", verdict
    assert verdict["signal"] == "deser_object_accepted", verdict
    # 证据边界必须写清：不是 RCE
    assert "不等同于 RCE" in verdict["reason"]


def test_fastjson_gate_opens_without_widening_625_redlines():
    from src.cli.benchmark_cli import _oracle_gate_signal

    assert _oracle_gate_signal(
        "deserialization", "exploitable", "deser_object_accepted",
        sink_file="src/main/java/org/joychou/controller/Fastjson.java")
    assert _oracle_gate_signal(
        "deserialization", "exploitable", "deser_object_accepted",
        sink_file="src/main/java/org/joychou/controller/XStreamRce.java")
    # 625 三条红线误报必须继续被挡
    assert _oracle_gate_signal("xss", "exploitable", "reflection_raw",
                               sink_file="Log4j.java") == ""
    assert _oracle_gate_signal("cors", "exploitable", "acao_reflect",
                               sink_file="OriginFilter.java") == ""
    assert _oracle_gate_signal("url_redirect", "exploitable", "location_reflect",
                               sink_file="URLWhiteList.java") == ""


# ── 4. 627 真实数据 dry-run ─────────────────────────────────────────────


def test_627_open_points_are_covered_by_the_new_judgment():
    """用 627 落库的真实 spec 字段复核新判定，不依赖靶场在线。"""
    if not DB.is_file():
        pytest.skip("data/app.db 不存在")
    from src.application.d1_service import needs_raw_body_payload

    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT family, param_name, param_location, content_type, "
            "expected_sink_file, target_endpoint FROM trigger_specs "
            "WHERE task_id=627 AND lower(expected_sink_file) LIKE ?",
            ("%fastjson%",)).fetchall()
        rows += con.execute(
            "SELECT family, param_name, param_location, content_type, "
            "expected_sink_file, target_endpoint FROM trigger_specs "
            "WHERE task_id=627 AND lower(expected_sink_file) LIKE ?",
            ("%qlexpress%",)).fetchall()
    finally:
        con.close()
    if not rows:
        pytest.skip("627 结果已被清理，跳过 dry-run")
    covered = [r for r in rows if needs_raw_body_payload(
        r["family"], r["param_name"], r["param_location"], r["content_type"])]
    assert covered, "627 的 fastjson/qlexpress spec 一条都没被新判据命中"
    assert all("fastjson" in str(r["expected_sink_file"]).lower()
               or "qlexpress" in str(r["expected_sink_file"]).lower()
               for r in covered)


@pytest.mark.skipif(os.environ.get("SAST_AI_LIVE_PROBE") != "1",
                    reason="需显式打开活靶场探测（SAST_AI_LIVE_PROBE=1）")
def test_live_target_accepts_the_three_primary_payloads():
    """可选活靶场端到端：只在显式开关下跑，避免全量 pytest 依赖靶场在线。"""
    import requests
    from src.iast.payload_library import build_family_payloads

    base = "http://127.0.0.1:8080"
    s = requests.Session()
    s.trust_env = False
    login_page = s.get(base + "/login", timeout=8)
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', login_page.text)
    csrf = m.group(1) if m else ""
    s.post(base + "/login",
           data={"username": "joychou", "password": "joychou123", "_csrf": csrf},
           timeout=8, allow_redirects=False)
    cases = [
        ("deserialization", "Fastjson.java", "/fastjson/deserialize", "POST", "SASTAI_DESER_"),
        ("deserialization", "XStreamRce.java", "/xstream", "POST", "xstream"),
        ("expression_injection", "QLExpress.java", "/vuln1", "GET", "777"),
    ]
    for fam, sink, ep, method, expect in cases:
        primary = build_family_payloads(fam, _spec(fam, sink, ep))["payloads"][0]
        resp = s.request(method, base + ep, data=primary.encode(), timeout=10,
                         allow_redirects=False)
        assert resp.status_code == 200, (sink, resp.status_code, resp.text[:120])
        assert expect in resp.text, (sink, resp.text[:120])
