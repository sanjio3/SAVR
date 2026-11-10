"""Part2 M1 度量地基回归测试（2026-10-03）。

覆盖三件事：
  1. env_premise 三态判定 + fail-open 语义（真值两层 L_code / L_exploit）；
  2. failure_attribution 四值判责的顺序（env→probe→pipeline→true_miss）；
  3. 稳定聚合键（family+file_tail+route）抗行漂移/抗措辞改写，且与 v2 精确键分工明确。

设计红线（勿改）：
  - 事实缺失必须 fail-open（unknown），绝不能返回 unsatisfied —— 那会让分母随采集
    能力波动，把「没采到事实」读成「漏洞打不通」。
  - 归因顺序不可颠倒：环境不支持时 probe/pipeline 信号不可信。
"""
import unittest

from src.core import env_premise as ep
from src.core import failure_attribution as fa
from src.core.vuln_hash import (
    aggregate_components,
    aggregate_stable_key,
    vulnerability_hash_v2,
)


class EnvPremiseTests(unittest.TestCase):
    def test_empty_premise_is_satisfied(self):
        self.assertEqual(ep.check_premise({}, {})[0], ep.SATISFIED)
        self.assertEqual(ep.check_premise(None, {})[0], ep.SATISFIED)

    def test_fact_missing_is_fail_open_not_unsatisfied(self):
        """事实缺失 → unknown（留在分母），绝不能是 unsatisfied。"""
        state, reason = ep.check_premise({"db_type": ["mysql"]}, {})
        self.assertEqual(state, ep.UNKNOWN)
        self.assertIn("fact_missing", reason)

    def test_mismatch_is_unsatisfied(self):
        state, _ = ep.check_premise({"db_type": ["mysql", "mariadb"]}, {"db_type": "postgresql"})
        self.assertEqual(state, ep.UNSATISFIED)

    def test_substring_match_is_case_insensitive(self):
        self.assertEqual(
            ep.check_premise({"db_type": ["mysql"]}, {"db_type": "MySQL 8.0.33"})[0],
            ep.SATISFIED,
        )

    def test_note_only_is_unknown_not_unsatisfied(self):
        """仅声明（阈值未实测）→ unknown，绝不静默缩小分母。"""
        state, reason = ep.check_premise({"_note": "Tomcat 版本阈值未实测"}, {"jdk_version": "11.0.1"})
        self.assertEqual(state, ep.UNKNOWN)
        self.assertIn("note_only", reason)

    def test_unknown_fact_key_does_not_kill_entry(self):
        """拼错/未登记的事实名：按 unknown 处理，不放行也不误杀（防御恒不满足）。"""
        state, reason = ep.check_premise({"os_version": [">=9"]}, {})
        self.assertEqual(state, ep.UNKNOWN)
        self.assertIn("unknown_fact_key", reason)

    def test_version_range_supports_java_semantics(self):
        """1.8 == 8、8u191 可解析；区间表达式走版本比较而非子串。"""
        self.assertEqual(
            ep.check_premise({"jdk_version": ["<8u191"]}, {"jdk_version": "1.8.0_65"})[0],
            ep.SATISFIED,
        )
        self.assertEqual(
            ep.check_premise({"jdk_version": ["<8u191"]}, {"jdk_version": "1.8.0_191"})[0],
            ep.UNSATISFIED,
        )

    def test_two_layer_counts(self):
        entries = [
            {"type": "a", "env_premise": {}},
            {"type": "b", "env_premise": {"db_type": ["mysql"]}},
            {"type": "c", "env_premise": {"_note": "未实测"}},
        ]
        out = ep.two_layer_counts(entries, {"db_type": "postgresql"})
        self.assertEqual(out["code_total"], 3)
        self.assertEqual(out["exploit_total"], 2)          # b 被剔除，c fail-open 留下
        self.assertEqual(out["env_unsupported"], 1)
        self.assertEqual(out["env_unverified"], 1)
        self.assertEqual(out["unsupported_types"], ["b"])


class FailureAttributionTests(unittest.TestCase):
    def _spec(self, **kw):
        base = {
            "id": 1, "family": "xss", "target_endpoint": "/x",
            "verification_status": "no_evidence", "iast_state": "no-arrival",
            "raw_json": "{}", "accounts_json": "[]", "victim_resource_id": "",
        }
        base.update(kw)
        return base

    def test_confirmed_spec_has_no_attribution(self):
        self.assertEqual(fa.classify(self._spec(verification_status="confirmed_exploitable")), ("", ""))

    def test_env_premise_unsatisfied_wins_over_probe_signal(self):
        """顺序铁律：环境不支持优先于探针信号（靶场都停服了，读什么都是 no-arrival）。"""
        cls, reason = fa.classify(
            self._spec(iast_state="probe_not_instrumented"),
            facts={"db_type": "postgresql"},
            env_premise={"db_type": ["mysql"]},
        )
        self.assertEqual(cls, fa.ENV_UNSUPPORTED)
        self.assertIn("env_premise", reason)

    def test_invalidated_is_env_unsupported(self):
        cls, _ = fa.classify(self._spec(verification_status="invalidated"))
        self.assertEqual(cls, fa.ENV_UNSUPPORTED)

    def test_probe_not_covered(self):
        cls, _ = fa.classify(self._spec(iast_state="probe_not_instrumented"))
        self.assertEqual(cls, fa.PROBE_NOT_COVERED)

    def test_pipeline_gap_never_replayed(self):
        cls, _ = fa.classify(self._spec(raw_json='{"unverified_kind":"never_replayed"}'))
        self.assertEqual(cls, fa.PIPELINE_GAP)

    def test_pipeline_gap_missing_victim_for_differential_family(self):
        cls, reason = fa.classify(
            self._spec(family="bola", iast_state="no-arrival", victim_resource_id="")
        )
        self.assertEqual(cls, fa.PIPELINE_GAP)
        self.assertIn("victim_resource_id", reason)

    def test_true_miss_is_the_fallback(self):
        """重放跑了、探针覆盖了、环境也支持，就是没打通 → 这才是要改判据的那一类。"""
        cls, _ = fa.classify(self._spec())
        self.assertEqual(cls, fa.TRUE_MISS)

    def test_golden_premise_map_is_fail_open(self):
        self.assertEqual(fa.golden_premise_map("一个不存在的靶场"), {})


class StableAggregateKeyTests(unittest.TestCase):
    def test_same_across_line_drift_and_wording_change(self):
        a = {"family": "xss", "file": "src/main/java/A.java", "target_endpoint": "/xss/reflect",
             "code_snippet": "out.print(x)"}
        b = dict(a, line=999, code_snippet="out.print( x )  // 措辞与行号都变了")
        self.assertEqual(aggregate_stable_key(a), aggregate_stable_key(b))

    def test_differs_by_route(self):
        a = {"family": "xss", "file": "src/main/java/A.java", "target_endpoint": "/xss/reflect"}
        c = dict(a, target_endpoint="/xss/stored")
        self.assertNotEqual(aggregate_stable_key(a), aggregate_stable_key(c))

    def test_spec_and_finding_views_agree(self):
        """spec 侧用 family 键、finding 侧用 finding_type 键，必须算出同一个聚合键。"""
        a = {"family": "xss", "file": "src/main/java/A.java", "target_endpoint": "/xss/reflect"}
        b = {"finding_type": "XSS", "file": "src/main/java/A.java", "entry_route": "/xss/reflect"}
        self.assertEqual(aggregate_stable_key(a), aggregate_stable_key(b))

    def test_unlocatable_item_yields_empty_key(self):
        """连文件/入口都没有的记录不给键 —— 否则会被并成一大坨。"""
        self.assertEqual(aggregate_stable_key({}), "")
        self.assertEqual(aggregate_stable_key({"family": "xss"}), "")

    def test_aggregate_key_is_not_the_precise_key(self):
        """双键分工：聚合键抗漂移，v2 精确键会因代码块变化而变。"""
        a = {"family": "xss", "file": "src/main/java/A.java", "target_endpoint": "/x",
             "code_snippet": "out.print(x)"}
        b = dict(a, code_snippet="totally different snippet body")
        self.assertEqual(aggregate_stable_key(a), aggregate_stable_key(b))
        self.assertNotEqual(vulnerability_hash_v2(a), vulnerability_hash_v2(b))

    def test_components_shape(self):
        c = aggregate_components({"family": "sql-injection", "file": "/a/b/C.java", "endpoint": "/q"})
        self.assertEqual(set(c), {"family", "file_tail", "route"})
        self.assertEqual(c["file_tail"], "a/b/c.java")


if __name__ == "__main__":
    unittest.main()
