import json
import unittest
from unittest.mock import patch

from src.cli import benchmark_cli
from src.core.vuln_hash import canonicalize_vuln_for_hash, vulnerability_hash_v2


class _FakeVuln:
    """最小可用假 vuln：仅实现 to_dict()。

    关键：identity vhash（vulnerability_hash_v2）**刻意不含 route**（见 src/core/vuln_hash.py
    任务③修复，route-漂移免疫），只认 family + file + code_snippet + sink 等「代码身份」字段。
    所以必须给每个 vuln 一个**相异的 file / code_snippet**，否则同族 vuln 会塌成同一个 vhash、
    只有最后一个 spec 被回放（这正是 execute_retryable_replay 的 vhash 过滤在真实数据上
    能区分不同端点的前提；OWASP 每个 BenchmarkTestNNNN.java 天然相异）。
    """

    def __init__(self, family, route, idx):
        self._d = {
            "type": family,
            "family": family,
            "route": route,
            "entry_route": route,
            "endpoint": route,
            "target_endpoint": route,
            "trigger_route": route,
            "file": "src/main/java/BenchmarkTest%05d.java" % idx,
            "file_path": "src/main/java/BenchmarkTest%05d.java" % idx,
            "code_snippet": "void doGet%d(HttpServletRequest req){}" % idx,
        }

    def to_dict(self):
        return dict(self._d)


def _vhash(v):
    return vulnerability_hash_v2(canonicalize_vuln_for_hash(v.to_dict()))


class _FakeDB:
    """内存假库：支撑 execute_retryable_replay 用到的三类 SQL。"""

    def __init__(self, status=None):
        self._status = dict(status or {})
        self._meta = {}
        self.update_calls = []
        self.select_calls = []

    def execute(self, sql, params=None, fetchone=False):
        sql_u = (sql or "").strip().upper()
        params = params or ()
        if sql_u.startswith("SELECT VERIFICATION_STATUS"):
            self.select_calls.append(params[0])
            return {"verification_status": self._status.get(int(params[0]), "no_evidence")}
        if sql_u.startswith("SELECT RAW_JSON"):
            self.select_calls.append(params[0])
            return {"raw_json": json.dumps(self._meta.get(int(params[0]), {}), ensure_ascii=False)}
        if sql_u.startswith("UPDATE TRIGGER_SPECS SET RAW_JSON"):
            sid = int(params[1])
            self._meta[sid] = json.loads(params[0])
            self.update_calls.append(sid)
            return None
        return None


def _build_scenario():
    """造 13 条 spec 跨 xss(7)/sqli(3)/ldap(3) 三族，返回 (db, retryable, spec_ids, vulns)。"""
    fams = ["xss"] * 7 + ["sqli"] * 3 + ["ldap"] * 3
    routes = ["/xss/%d" % i for i in range(7)] + \
             ["/sqli/%d" % i for i in range(3)] + \
             ["/ldap/%d" % i for i in range(3)]
    spec_ids, vulns, retryable = [], [], []
    for i, (fam, route) in enumerate(zip(fams, routes)):
        sid = i + 1
        v = _FakeVuln(fam, route, i)
        spec_ids.append(sid)
        vulns.append(v)
        retryable.append({
            "spec_id": sid,
            "vhash": _vhash(v),
            "family": fam,
            "endpoint": route,
            "round": 0,
        })
    return _FakeDB(), retryable, spec_ids, vulns, dict(zip([_vhash(v) for v in vulns], spec_ids))


class RetryableReplayTests(unittest.TestCase):
    def test_executes_and_clears_when_d2_confirms(self):
        db, retryable, spec_ids, vulns, spec_by_vh = _build_scenario()

        def _mock_d2(a1, a2, files, tp, et, task_id=None, code_root=None,
                     discovered_routes=None, output_dir=None):
            for res in (a2 or []):
                for v in getattr(res, "vulnerabilities", []) or []:
                    sid = spec_by_vh.get(_vhash(v))
                    if sid is not None:
                        db._status[sid] = "confirmed_exploitable"

        with patch.object(benchmark_cli, "run_d2_verify", side_effect=_mock_d2):
            res = benchmark_cli.execute_retryable_replay(
                db, 999, retryable, a1_results=[], a2_results=[_mk_a2(vulns)],
                files="F", target_path="T", external_target="E", code_root="C",
                discovered_routes=[], output_dir="O", inter_batch_sleep=0.0)
        self.assertEqual(res["executed"], 13)
        self.assertEqual(res["cleared"], 13)
        self.assertEqual(res["failed"], 0)
        # 每条 spec 的 replay_adjust.round 必须 +1（原无 replay_adjust → 1）
        for sid in spec_ids:
            self.assertEqual(db._meta[sid]["replay_adjust"]["round"], 1)

    def test_executes_but_not_cleared_when_d2_leaves_no_evidence(self):
        db, retryable, spec_ids, vulns, _ = _build_scenario()

        def _mock_d2_noop(a1, a2, files, tp, et, task_id=None, code_root=None,
                          discovered_routes=None, output_dir=None):
            return None

        with patch.object(benchmark_cli, "run_d2_verify", side_effect=_mock_d2_noop):
            res = benchmark_cli.execute_retryable_replay(
                db, 999, retryable, a1_results=[], a2_results=[_mk_a2(vulns)],
                files="F", target_path="T", external_target="E", code_root="C",
                discovered_routes=[], output_dir="O", inter_batch_sleep=0.0)
        self.assertEqual(res["executed"], 13)
        self.assertEqual(res["cleared"], 0)
        for sid in spec_ids:
            self.assertEqual(db._meta[sid]["replay_adjust"]["round"], 1)

    def test_empty_retryable_is_noop(self):
        db, _, _, vulns, _ = _build_scenario()
        calls = []

        def _mock_d2_count(*args, **kwargs):
            calls.append(1)

        with patch.object(benchmark_cli, "run_d2_verify", side_effect=_mock_d2_count):
            res = benchmark_cli.execute_retryable_replay(
                db, 999, [], a1_results=[], a2_results=[_mk_a2(vulns)],
                files="F", target_path="T", external_target="E", code_root="C",
                discovered_routes=[], output_dir="O")
        # 2026-10-08：返回值已扩展 batches/batch_size/elapsed_sec（重试环开销画像），
        # 空清单语义仍是「全零且绝不调 run_d2_verify」，故按关键字段断言而非整体 dict 相等。
        self.assertEqual(res["executed"], 0)
        self.assertEqual(res["cleared"], 0)
        self.assertEqual(res["failed"], 0)
        self.assertEqual(res["batches"], 0)
        self.assertEqual(calls, [])  # run_d2_verify 绝不应被调用


def _mk_a2(vulns):
    """构造一个带 .error/.agent/.vulnerabilities 的轻量 A2 结果对象。"""

    class _A2:
        def __init__(self, vs):
            self.error = None
            self.agent = "A2"
            self.vulnerabilities = vs

    return _A2(vulns)


if __name__ == "__main__":
    unittest.main()
