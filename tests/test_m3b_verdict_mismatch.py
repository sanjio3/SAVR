"""Part2 判据错配出清回归测试（2026-10-03）。

三件事：
  1. 路由键从「族名」换成「实际观测到的 sink 签名」（族名是上游主张，sink 是探针事实）；
  2. weak_random 单列 random_source 通道，终态只能是 confirmed_code_property，
     绝不能是 confirmed_exploitable（「用了 java.util.Random」不是可利用性主张）；
  3. 噪声 sink（Response.addHeader / Cookie.setHttpOnly / PrintWriter.write）不得
     触发任何族路由 —— 否则重演「借 sink 把别族判成自己」的误杀。

实测基线（run 46 真数据，勿改期望）：16 条 weak_random 原为 confirmed_exploitable，
按 Random sink 实证改判后 14 条 confirmed_code_property、2 条 unconfirmed（那 2 条
只有噪声 sink 事件，正是安全用例）。
"""
import unittest

from src.core.family_verdict import (
    CONFIRMED_CODE_PROPERTY,
    apply_family_route,
    judge_random_family,
    route_for,
)

_ALGO_EVENT = [{"sink_file": "java.security.MessageDigest.getInstance", "source_value": "[MD5]"}]
_RANDOM_EVENT = [{"sink_file": "java.util.Random.nextDouble", "source_value": "[]"}]
_NOISE_EVENTS = [
    {"sink_file": "org.apache.catalina.connector.Response.addHeader", "source_value": "[]"},
    {"sink_file": "javax.servlet.http.Cookie.setHttpOnly", "source_value": "[true]"},
    {"sink_file": "java.io.PrintWriter.write", "source_value": "[]"},
]


class RouteKeyTests(unittest.TestCase):
    def test_weak_random_routes_to_random_source(self):
        self.assertEqual(route_for("weak_random"), "random_source")

    def test_weak_hash_routes_to_algorithm(self):
        self.assertEqual(route_for("weak_hash"), "algorithm")

    def test_secure_cookie_routes_to_attribute(self):
        self.assertEqual(route_for("secure_cookie"), "attribute")

    def test_dataflow_family_untouched(self):
        """数据流族零回归：路由必须是 dataflow。"""
        for fam in ("sql_injection", "xss", "command_execution", "path_traversal", "ssrf"):
            self.assertEqual(route_for(fam), "dataflow")

    def test_observed_sink_drives_route_even_when_family_vague(self):
        """族名被上游带偏时，sink 实证仍能纠正路由（这是换键的全部意义）。"""
        self.assertEqual(route_for("weak_random", _RANDOM_EVENT), "random_source")

    def test_noise_sinks_contribute_nothing_to_route(self):
        """噪声 sink 不得改变任何族的路由 —— 借 sink 误判是最贵的错。

        判据：喂噪声事件的结果必须与「无任何事件」时完全一致（噪声既不能抬路由，
        也不能压路由）。族名路由是另一条独立的兜底路径，不受噪声影响。
        """
        for fam in ("weak_random", "weak_hash", "weak_crypto", "secure_cookie",
                    "sql_injection", "sensitive_data_exposure"):
            self.assertEqual(route_for(fam, _NOISE_EVENTS), route_for(fam),
                             f"{fam} 的路由被噪声 sink 改变了")

    def test_noise_only_events_leave_vague_family_on_dataflow(self):
        """泛化族（A2 自由命名重灾区）只有噪声实证时不得被抬到任何族通道。"""
        self.assertEqual(route_for("sensitive_data_exposure", _NOISE_EVENTS), "dataflow")
        self.assertEqual(route_for("weak_password_storage", _NOISE_EVENTS), "dataflow")


class WeakRandomVerdictTests(unittest.TestCase):
    def test_random_sink_observed_yields_code_property_not_exploitable(self):
        status, detail = judge_random_family(_RANDOM_EVENT)
        self.assertEqual(status, CONFIRMED_CODE_PROPERTY)
        self.assertNotEqual(status, "confirmed_exploitable")

    def test_secure_random_only_yields_unconfirmed(self):
        status, _ = judge_random_family(
            [{"sink_file": "java.security.SecureRandom.nextBytes", "source_value": "[]"}]
        )
        self.assertEqual(status, "unconfirmed")

    def test_no_events_yields_unconfirmed(self):
        self.assertEqual(judge_random_family([])[0], "unconfirmed")
        self.assertEqual(judge_random_family(_NOISE_EVENTS)[0], "unconfirmed")

    def test_misrouted_exploitable_is_corrected(self):
        """核心回归：原本错抬成 confirmed_exploitable 的 16 条，必须被改判掉。"""
        new, detail = apply_family_route("weak_random", "confirmed_exploitable", _RANDOM_EVENT)
        self.assertEqual(new, CONFIRMED_CODE_PROPERTY)
        self.assertTrue(detail.get("applied"))
        self.assertEqual(detail.get("old_status"), "confirmed_exploitable")

    def test_non_exploitable_status_is_not_touched(self):
        """低置信态不介入 —— 不能把「没验证」误升「确认」。"""
        new, detail = apply_family_route("weak_random", "no_evidence", _RANDOM_EVENT)
        self.assertEqual(new, "no_evidence")
        self.assertFalse(detail.get("applied"))

    def test_dataflow_family_passes_through(self):
        new, detail = apply_family_route("sql_injection", "confirmed_exploitable",
                                         [{"sink_file": ".executeQuery"}])
        self.assertEqual(new, "confirmed_exploitable")
        self.assertFalse(detail.get("applied"))


if __name__ == "__main__":
    unittest.main()
