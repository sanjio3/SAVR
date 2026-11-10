"""vuln_hash 业务逻辑去重：category 维度 + 跨 stage 聚类（架构决议 去重落地）。

核心断言：
- category 显式进 hash：同 endpoint 不同 category（bola vs vertical_privesc）hash 不同，
  不被 _norm_family 统一掉进 idor 而含糊合并。
- business_logic_group_key：同 (app,file,route,method,param,category) → 同 key；category 不同 → 不同 key。
- cluster_business_logic_hypotheses：跨 analyzer / 跨 stage 同类目假说合并为一条
  pending_verification，保留 vuln_types/evidence；D1 source 或 status=confirmed 升级 confirmed。
"""
import unittest

from src.core.vuln_hash import (
    business_logic_group_key,
    cluster_business_logic_hypotheses,
    vulnerability_hash_v2,
)


class VulnHashCategoryTest(unittest.TestCase):
    def _item(self, category, route="/api/admin/users/{id}", file="app.py", param="id", method="GET"):
        return {
            "file": file,
            "target_endpoint": route,
            "http_method": method,
            "vulnerable_param": param,
            "category": category,
            "type": category.upper(),
            "sink": "repo.findById",
        }

    def test_category_differentiates_hash_same_endpoint(self):
        bola = self._item("bola")
        vertical = self._item("vertical_privesc")
        h1 = vulnerability_hash_v2(bola)
        h2 = vulnerability_hash_v2(vertical)
        self.assertNotEqual(h1, h2, "同 endpoint 不同 category 必须 hash 不同（防止含糊合并）")

    def test_same_category_same_hash(self):
        a = self._item("bola", route="/api/order/{id}")
        b = self._item("bola", route="/api/order/{id}")
        self.assertEqual(vulnerability_hash_v2(a), vulnerability_hash_v2(b))

    def test_injection_without_category_unchanged(self):
        # 注入类无 category（默认 ""）不影响既有 hash 行为
        item = {"file": "x.py", "type": "SQL Injection", "sink": "execute", "route": "/q"}
        out = vulnerability_hash_v2(item)
        self.assertTrue(out and len(out) == 24)


class BusinessLogicGroupKeyTest(unittest.TestCase):
    def test_same_key_for_same_tuple(self):
        base = dict(file="app.py", target_endpoint="/api/admin/users/{id}", http_method="GET",
                    vulnerable_param="id", category="bola")
        self.assertEqual(
            business_logic_group_key(base, app="mall"),
            business_logic_group_key(dict(base), app="mall"),
        )

    def test_category_changes_key(self):
        a = dict(file="app.py", target_endpoint="/api/admin/users/{id}", http_method="GET",
                 vulnerable_param="id", category="bola")
        b = dict(a, category="vertical_privesc")
        self.assertNotEqual(business_logic_group_key(a), business_logic_group_key(b))

    def test_app_changes_key(self):
        a = dict(file="app.py", target_endpoint="/x", http_method="GET", vulnerable_param="id", category="bola")
        self.assertNotEqual(business_logic_group_key(a, app="mall"), business_logic_group_key(a, app="other"))


class ClusterHypothesesTest(unittest.TestCase):
    def _hypo(self, source="a1-business-logic-ai", category="bola", evidence="missing ownership check", status=None):
        h = {
            "file": "app.py", "target_endpoint": "/api/order/{id}", "http_method": "GET",
            "vulnerable_param": "id", "category": category, "vuln_type": category.upper(),
            "source": source, "evidence": evidence,
        }
        if status is not None:
            h["status"] = status
        return h

    def test_merge_same_key_into_one_pending(self):
        hypos = [
            self._hypo(source="a1-business-logic-ai", evidence="no ownership check"),
            self._hypo(source="a1-offline-heuristic", evidence="findById without authz"),
        ]
        clusters = cluster_business_logic_hypotheses(hypos, app="mall")
        self.assertEqual(len(clusters), 1)
        c = clusters[0]
        self.assertEqual(c["status"], "pending_verification")
        self.assertEqual(sorted(c["sources"]), ["a1-business-logic-ai", "a1-offline-heuristic"])
        self.assertIn("no ownership check", c["evidence"])
        self.assertIn("findById without authz", c["evidence"])

    def test_distinct_category_not_merged(self):
        hypos = [
            self._hypo(category="bola", evidence="e1"),
            self._hypo(category="vertical_privesc", evidence="e2"),
        ]
        clusters = cluster_business_logic_hypotheses(hypos, app="mall")
        self.assertEqual(len(clusters), 2)
        cats = {c["category"] for c in clusters}
        self.assertEqual(cats, {"bola", "vertical_privesc"})

    def test_d1_source_upgrades_to_confirmed(self):
        hypos = [
            self._hypo(source="a1-business-logic-ai", evidence="e1"),
            self._hypo(source="d1-replay", evidence="replay confirmed"),
        ]
        clusters = cluster_business_logic_hypotheses(hypos, app="mall")
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["status"], "confirmed")

    def test_explicit_confirmed_status_upgrades(self):
        hypos = [self._hypo(source="a1-business-logic-ai", evidence="e1", **{"status": "confirmed"})]
        clusters = cluster_business_logic_hypotheses(hypos, app="mall")
        self.assertEqual(clusters[0]["status"], "confirmed")


if __name__ == "__main__":
    unittest.main()
