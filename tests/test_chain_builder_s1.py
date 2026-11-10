"""S1 确定性回溯拼链：chain_builder 纯单元测试（不依赖 LLM / DB）。"""

import unittest

from src.core.chain_builder import (
    build_chain_from_index,
    format_chain_for_prompt,
    parse_http_entry,
    populate_entry_from_chain,
)


def _idx():
    """构造一个 Controller@Get → Service → Repo → Sink 的调用图（sink 在第 70 行）。

    调用图方向：callers 指「谁调用了本函数」，故越往入口方向 caller 越靠上层。
    """
    return {
        "functions": {
            "app/UserController.java:getAddress": {
                "name": "getAddress", "file": "app/UserController.java", "line": 10,
                "callers": [],
                "http_entry": "GET /api/address/{id}",
            },
            "app/UserService.java:loadAddress": {
                "name": "loadAddress", "file": "app/UserService.java", "line": 30,
                "callers": ["app/UserController.java:getAddress"], "http_entry": "",
            },
            "app/AddressRepo.java:find": {
                "name": "find", "file": "app/AddressRepo.java", "line": 50,
                "callers": ["app/UserService.java:loadAddress"], "http_entry": "",
            },
            "app/AddressRepo.java:vulnSink": {
                "name": "vulnSink", "file": "app/AddressRepo.java", "line": 70,
                "callers": ["app/AddressRepo.java:find"], "http_entry": "",
            },
        }
    }


class TestS1ChainBuilder(unittest.TestCase):
    def test_reaches_http_entry(self):
        chain = build_chain_from_index("app/AddressRepo.java", 70, _idx())
        self.assertIsNotNone(chain)
        self.assertTrue(chain["reached_entry"])
        # 链顺序必须是 [http_entry, ..., sink]
        self.assertEqual(chain["chain_detail"][0]["role"], "entry")
        self.assertEqual(chain["chain_detail"][-1]["role"], "sink")
        self.assertEqual(chain["chain_detail"][-1]["name"], "vulnSink")
        self.assertEqual(chain["entry_method"], "GET")
        self.assertEqual(chain["entry_route"], "/api/address/{id}")

    def test_no_entry_returns_none(self):
        idx = _idx()
        for f in idx["functions"].values():
            f["http_entry"] = ""
        self.assertIsNone(build_chain_from_index("app/AddressRepo.java", 70, idx))

    def test_basename_fallback(self):
        # SAST 报的 file 是绝对路径，code_index 用 rel_path：应靠 basename 命中。
        chain = build_chain_from_index("/abs/path/app/AddressRepo.java", 70, _idx())
        self.assertIsNotNone(chain)
        self.assertTrue(chain["reached_entry"])

    def test_parse_http_entry(self):
        self.assertEqual(parse_http_entry("POST /debug/import"), {"method": "POST", "route": "/debug/import"})
        self.assertEqual(parse_http_entry(""), {"method": "", "route": ""})

    def test_populate_entry_from_chain(self):
        chain = build_chain_from_index("app/AddressRepo.java", 70, _idx())
        ep = populate_entry_from_chain(chain)
        self.assertEqual(ep["method"], "GET")
        self.assertEqual(ep["route"], "/api/address/{id}")

    def test_format_chain_for_prompt(self):
        chain = build_chain_from_index("app/AddressRepo.java", 70, _idx())
        text = format_chain_for_prompt(chain)
        self.assertIn("确定性调用链", text)
        self.assertIn("vulnSink", text)
        self.assertIn("/api/address/{id}", text)

    def test_format_empty_chain_returns_blank(self):
        self.assertEqual(format_chain_for_prompt(None), "")
        self.assertEqual(format_chain_for_prompt({"reached_entry": False}), "")


if __name__ == "__main__":
    unittest.main()
