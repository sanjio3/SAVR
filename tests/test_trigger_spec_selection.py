"""回归测试：同一漏洞 hash 下多条 trigger_spec 的收敛选择。

背景（2026-08-31 定位的 bug）：A2 在 task-1/4/6/... 各次扫描里会对同一条反序列化漏洞登记多条
trigger_spec（family/endpoint/param 全同，仅 task_id/taint_marker 不同）。旧代码在 run_d2_verify 里
直接取 ``_matched_specs[0]``（最旧的 task-1 spec），若该 spec 预置了 ysoserial 文本 payload，
``spec_attack_payloads`` 即非空 → 绕过方案 1a 的 sca_forge 真 gadget 构造，导致正式流水线重放的是
假 payload、探针落不到真 rO0AB gadget。

修复后 ``_select_trigger_spec_for_task`` 优先选「本 task 登记的 spec」（attack_payloads 为空、自然走到
sca_forge 造真字节），无本 task spec 时回退 [0] 兼容旧行为。
"""

import unittest

from src.cli.benchmark_cli import _select_trigger_spec_for_task


def _spec(task_id, attack_payloads_json):
    return {
        "task_id": task_id,
        "vulnerability_hash_v2": "f49f56e3e7f3bccc4be55f68",
        "family": "deserialization",
        "attack_payloads_json": attack_payloads_json,
        "taint_marker": f"s4st41{task_id:012d}",
    }


class TriggerSpecSelectionTests(unittest.TestCase):
    def test_no_specs_returns_none(self):
        self.assertIsNone(_select_trigger_spec_for_task([], task_id=15))

    def test_single_foreign_spec_falls_back_to_zero(self):
        # 只有上一个 task 的 spec（无本 task spec）→ 取 [0]，兼容旧行为
        specs = [_spec(1, "[]"), _spec(4, "[]")]
        chosen = _select_trigger_spec_for_task(specs, task_id=15)
        self.assertEqual(chosen["task_id"], 1)

    def test_own_task_spec_preferred_over_older(self):
        # 本 task 的 spec 必须被优先选中，即便它排在后面
        specs = [_spec(1, "[]"), _spec(4, "[]"), _spec(15, "[]")]
        chosen = _select_trigger_spec_for_task(specs, task_id=15)
        self.assertEqual(chosen["task_id"], 15)

    def test_own_spec_selected_even_if_older_has_ysoserial_payload(self):
        # 关键回归点：旧 task-1 spec 预置了 ysoserial 文本 payload（会绕过 sca_forge），
        # 本 task spec 的 payload 为空 → 必须选本 task，才能触发方案 1a 真 gadget 构造。
        specs = [
            _spec(1, '["ysoserial CommonsCollections ... (text payload)"]'),
            _spec(15, "[]"),
        ]
        chosen = _select_trigger_spec_for_task(specs, task_id=15)
        self.assertEqual(chosen["task_id"], 15)
        self.assertEqual(chosen["attack_payloads_json"], "[]")


if __name__ == "__main__":
    unittest.main()
