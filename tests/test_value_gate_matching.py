"""值级闸判据层单测（2026-10-18 双轨匹配落地）。

覆盖三项新行为，均有 r106 真实数据实证：
  1. 旧格式 marker（``s4st41<hex>"><svg<hex>``，xss spec 在用）payload 解析；
  2. 「payload 段 ∥ canary 身份段」双轨 at_sink 匹配（只比 source_value，
     不碰 evidence_json——实测它会把身份段匹配污染成 FP）；
  3. is_genuine_sink_identity 噪声约束：框架噪声 sink（Set-Cookie / addHeader 等）
     上的命中一律不算本族证据。
"""
import pytest

from src.core.sink_value_gate import (
    flatten_char_arrays,
    identity_of,
    judge_sink_value,
    payload_of,
)

IDENT = "s4st41d3c6c8df3965f3e0"
XSS_IDENT = "s4st413bb633990669c341"


class TestMarkerParsing:
    def test_new_format_payload_segment(self):
        assert payload_of(f"{IDENT}PAYLOAD663f6c06") == "663f6c06"

    def test_legacy_xss_marker_payload_is_injection_itself(self):
        # 旧格式没有 PAYLOAD 分隔符：payload = 身份段之后的注入串本身
        mk = f'{XSS_IDENT}"><svg5b7e19b5'
        assert payload_of(mk) == '"><svg5b7e19b5'
        assert identity_of(mk) == XSS_IDENT

    def test_identity_of_extracts_stable_prefix(self):
        assert identity_of(f"{IDENT}PAYLOAD663f6c06") == IDENT
        assert identity_of("") == ""

    def test_legacy_marker_no_longer_vacuously_no_event(self):
        # 修复前：payload_of 返回空 → judge 直接 no_event（xss 全族值级闸形同虚设）
        mk = f'{XSS_IDENT}"><svg5b7e19b5'
        evs = [{"sink_file": "org.apache.catalina.connector.CoyoteWriter.write",
                "source_value": '<html>abc"><svg5b7e19b5</html>',
                "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "xss")
        assert v["verdict"] == "at_sink"
        assert v["matched_on"] == "payload"


class TestDualTrackMatching:
    def test_identity_recovers_truncated_payload_trustbound_key_case(self):
        # r106 实证：session.putValue 把 canary 当 KEY 存、值段截尾
        # （实录 PAYLOAD56254c0，marker PAYLOAD56254c01）→ payload 段匹配失败，
        # 但身份段原样保留 → 双轨兜底判 at_sink（该用例是真 TP）。
        mk = "s4st41ba962e5319cb325fPAYLOAD56254c01"
        evs = [{"sink_file": "org.apache.catalina.session.StandardSessionFacade.putValue",
                "source_value": "[s4st41ba962e5319cb325fPAYLOAD56254c0, 10340]",
                "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "trust_boundary_violation")
        assert v["verdict"] == "at_sink"
        assert v["matched_on"] == "identity"

    def test_payload_segment_has_priority_over_identity(self):
        mk = f"{IDENT}PAYLOAD663f6c06"
        evs = [{"sink_file": "org.apache.ibatis.executor.CachingExecutor.query",
                "source_value": "SELECT * FROM t WHERE x='PAYLOAD663f6c06ident'",
                "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "sql_injection")
        assert v["verdict"] == "at_sink"
        assert v["matched_on"] == "payload"

    def test_evidence_json_identity_does_not_count(self):
        # 实测（r106 trustbound）：只把身份段放进 evidence_json 的 FP 被判 at_sink
        # （31 个 FP 全污染）。判据纪律：只比 source_value（sink 实际实参）。
        mk = f"{IDENT}PAYLOAD663f6c06"
        evs = [{"sink_file": "org.apache.ibatis.executor.CachingExecutor.query",
                "source_value": "SELECT * FROM t WHERE x='bar'",
                "evidence_json": f'{{"echo": "{IDENT}"}}'}]
        v = judge_sink_value(evs, mk, "sql_injection")
        assert v["verdict"] == "absent"

    def test_clean_sink_args_stay_absent(self):
        mk = f"{IDENT}PAYLOAD663f6c06"
        evs = [{"sink_file": "org.apache.ibatis.executor.CachingExecutor.query",
                "source_value": "SELECT * FROM t WHERE x='bar'",
                "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "sql_injection")
        assert v["verdict"] == "absent"

    def test_no_sink_events_no_event(self):
        mk = f"{IDENT}PAYLOAD663f6c06"
        v = judge_sink_value([], mk, "sql_injection")
        assert v["verdict"] == "no_event"


class TestNoiseSinkConstraint:
    def test_blacklisted_sink_hit_not_counted(self):
        # task-4 实证：7 条 confirmed 全是 Response Set-Cookie 噪声。框架噪声 sink
        # 上的 canary 命中（显式传 token 命中）也必须被剔除 → no_event。
        mk = f"{IDENT}PAYLOAD663f6c06"
        evs = [{"sink_file": "org.apache.catalina.connector.Response.addHeader",
                "source_value": "Set-Cookie: s4st41d3c6c8df3965f3e0PAYLOAD663f6c06",
                "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "sql_injection", sink_tokens=("addHeader",))
        assert v["verdict"] == "no_event"

    def test_trustbound_cookie_fake_sink_rejected(self):
        # 信任边界正向白名单：Cookie.<init> 是探针故意织的假 sink，即使命中 token
        # 也不算该族证据 → 无 session sink 事件 → no_event。
        mk = f"IDENT{IDENT}PAYLOAD663f6c06"
        evs = [{"sink_file": "javax.servlet.http.Cookie.<init>",
                "source_value": f"[{IDENT}PAYLOAD663f6c06, color]",
                "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "trust_boundary_violation",
                             sink_tokens=("Cookie",))
        assert v["verdict"] == "no_event"


class TestCharArrayFlatten:
    def test_flatten_single_char_list(self):
        # r106 xss 实录：CoyoteWriter.write 的 char[] 实参被逐字符记录
        raw = "[[s, 4, s, t, 4, 1, 3, b, b, 6, 5, 1, 6, 5, 5, c, a, d, f, 7, 3, d]]"
        assert flatten_char_arrays(raw) == "[s4st413bb651655cadf73d]"

    def test_param_list_not_flattened(self):
        # [userid, 10340] 是正常参数列表（含长元素），必须保持原样
        assert flatten_char_arrays("[userid, 10340]") == "[userid, 10340]"

    def test_short_char_list_kept(self):
        assert flatten_char_arrays("[a, b, c]") == "[a, b, c]"

    def test_judge_matches_char_array_sink_arg(self):
        # 逐字符记录的 writer 实参里含 canary → 重组后判 at_sink
        ident = "s4st413bb651655cadf73d"
        chars = ", ".join(ident)
        mk = f'{ident}"><svg0028a896'
        evs = [{"sink_file": "org.apache.catalina.connector.CoyoteWriter.write",
                "source_value": f"[[{chars}]]", "evidence_json": "{}"}]
        v = judge_sink_value(evs, mk, "xss")
        assert v["verdict"] == "at_sink"
