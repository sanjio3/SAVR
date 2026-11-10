"""M1 证据阶梯唯一真相源：判据等价验收。

覆盖 classify 的四档映射（S4/S3/S2/S1）、族名 canonical 化，以及 decide_group
三套否决规则与 benchmark_cli 现有生产逻辑逐条等价。
"""
import unittest

from src.core.evidence_policy import (
    S1,
    S2,
    S3,
    S4,
    Evidence,
    Policy,
    best_kind,
    classify,
    decide_group,
)


def _judge(verdict):
    def j(evs, marker, family=""):
        return {"verdict": verdict}

    return j


class TestClassify(unittest.TestCase):
    def _spec(self, family="sql_injection", marker="s4st41abc"):
        return {"id": 1, "family": family, "taint_marker": marker}

    def test_at_sink_s4(self):
        self.assertEqual(classify(self._spec(), [{"x": 1}], judge=_judge("at_sink")).kind, S4)

    def test_absent_s3(self):
        self.assertEqual(classify(self._spec(), [{"x": 1}], judge=_judge("absent")).kind, S3)

    def test_no_event_with_events_s2(self):
        self.assertEqual(classify(self._spec(), [{"x": 1}], judge=_judge("no_event")).kind, S2)

    def test_no_event_without_events_s1(self):
        self.assertEqual(classify(self._spec(), [], judge=_judge("no_event")).kind, S1)

    def test_family_canonicalized(self):
        e = classify(self._spec(family="sqli"), [{"x": 1}], judge=_judge("at_sink"))
        self.assertEqual(e.family, "sql_injection")

    def test_capability_family_fallback(self):
        sp = {"id": 2, "capability_family": "trustbound", "taint_marker": "m"}
        e = classify(sp, [{"x": 1}], judge=_judge("absent"))
        self.assertEqual(e.family, "trust_boundary_violation")


class TestDecideGroup(unittest.TestCase):
    def _ev(self, kind, family="sql_injection", has_events=True, spec_id=1):
        return Evidence(kind=kind, family=family, has_events=has_events, spec_id=spec_id)

    def test_all_absent_veto(self):
        d, r = decide_group([self._ev(S3), self._ev(S3)], Policy())
        self.assertEqual((d, r), ("veto", "value-gate-absent"))

    def test_strict_c_veto(self):
        pol = Policy(strict_c_families=frozenset({"sql_injection"}))
        d, r = decide_group([self._ev(S3), self._ev(S2)], pol)
        self.assertEqual((d, r), ("veto", "value-gate-strict-c"))

    def test_strict_c_not_veto_when_at_sink(self):
        pol = Policy(strict_c_families=frozenset({"sql_injection"}))
        d, r = decide_group([self._ev(S3), self._ev(S4)], pol)
        self.assertEqual((d, r), ("confirm", "at-sink"))

    def test_strict_veto(self):
        pol = Policy(
            strict_enabled=True,
            strict_families=frozenset({"sql_injection"}),
            strict_covered_families=frozenset({"sql_injection"}),
        )
        # 不能全 S3（否则先命中 ①），故配一个无事件的 S1
        d, r = decide_group([self._ev(S3), self._ev(S1, has_events=False)], pol)
        self.assertEqual((d, r), ("veto", "value-gate-no-at-sink"))

    def test_strict_no_veto_without_absent(self):
        pol = Policy(
            strict_enabled=True,
            strict_families=frozenset({"sql_injection"}),
            strict_covered_families=frozenset({"sql_injection"}),
        )
        d, r = decide_group([self._ev(S2)], pol)  # 只有 S2，无 S3，默认不许否决
        self.assertEqual(d, "keep")

    def test_strict_allow_no_event(self):
        pol = Policy(
            strict_enabled=True,
            strict_families=frozenset({"sql_injection"}),
            strict_covered_families=frozenset({"sql_injection"}),
            strict_allow_no_event=True,
        )
        d, r = decide_group([self._ev(S2)], pol)
        self.assertEqual((d, r), ("veto", "value-gate-no-at-sink"))

    def test_keep_when_only_s1_s2(self):
        d, r = decide_group([self._ev(S1, has_events=False), self._ev(S2)], Policy())
        self.assertEqual(d, "keep")

    def test_confirm_on_s4(self):
        d, r = decide_group([self._ev(S4)], Policy())
        self.assertEqual((d, r), ("confirm", "at-sink"))

    def test_empty_group_keep(self):
        self.assertEqual(decide_group([], Policy())[0], "keep")


class TestBestKind(unittest.TestCase):
    def test_rank(self):
        self.assertEqual(best_kind([]), S1)
        self.assertEqual(best_kind([Evidence(S2), Evidence(S4), Evidence(S3)]), S4)
        self.assertEqual(best_kind([Evidence(S1), Evidence(S3)]), S3)


if __name__ == "__main__":
    unittest.main()
