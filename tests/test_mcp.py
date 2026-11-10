"""MCP 二期/三期测试（§4.2，2026-09-20）。

覆盖：
  - protocol 层：消息构造/判定/序列化
  - server 层：initialize / tools/list / tools/call / 写门控 / 未知方法 / 通知静默 / stdio 解析错误
  - client 层：InProcessTransport 往返、McpToolBridge 发现与执行、工具级超时
  - StdioTransport：真实子进程 NDJSON 往返 + 超时
  - a2_tools 统一命名空间：外部工具注册 / all_tool_schemas / execute_tool 路由
"""
from __future__ import annotations

import io
import os
import sys
import unittest

from src.agents import a2_tools
from src.mcp import client as mc
from src.mcp import protocol as P
from src.mcp.server import McpServer, PlatformDataProvider


class FakeProvider(PlatformDataProvider):
    """只读返回固定行；写方法返回结构化成功（用于验证写门控放开后的路径）。"""

    def findings(self, *, workspace_id=None, task_id=None, limit=50):
        return [{"id": 1, "task_id": task_id or 1, "title": "demo", "severity": "HIGH"}][:limit]

    def blackboard(self, *, workspace_id=None, task_id=None, limit=200):
        return [{"id": 2, "family": "sql_injection", "sink_reached": 1}]

    def iast_events(self, *, workspace_id=None, task_id=None, limit=100):
        return [{"id": 3, "canary_state": "sink-reached", "sink_file": "A.java"}]

    def trigger_replay(self, *, task_id, finding_id=None):
        return {"ok": True, "replayed": True, "task_id": task_id, "finding_id": finding_id}

    def submit_rule_candidate(self, *, family, rule_expression, prompt_fragment="", workspace_id=None):
        return {"ok": True, "submitted": True, "family": family}


# ---------------------------------------------------------------- protocol
class TestProtocol(unittest.TestCase):
    def test_result_error_notification_shapes(self):
        self.assertEqual(P.make_result(1, {"a": 1})["result"], {"a": 1})
        err = P.make_error(2, P.METHOD_NOT_FOUND, "no such method")
        self.assertEqual(err["error"]["code"], P.METHOD_NOT_FOUND)
        self.assertIn("id", err)
        note = P.make_notification("notifications/initialized")
        self.assertNotIn("id", note)
        self.assertFalse(P.has_id(note))

    def test_is_request_vs_notification(self):
        self.assertTrue(P.is_request({"method": "x", "id": 1}))
        self.assertTrue(P.is_notification({"method": "x"}))
        self.assertFalse(P.is_notification({"method": "x", "id": 1}))

    def test_dumps_loads_roundtrip(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "get_findings", "arguments": {"task_id": 7}}}
        self.assertEqual(P.loads(P.dumps(msg)), msg)

    def test_tool_schema_camel_case(self):
        s = P.tool_schema_from_spec("t", "d", {"type": "object", "properties": {}})
        self.assertIn("inputSchema", s)
        self.assertNotIn("input_schema", s)

    def test_text_content_jsonifies_non_str(self):
        c = P.text_content({"ok": True})
        self.assertEqual(c["type"], "text")
        self.assertIn("ok", c["text"])


# ---------------------------------------------------------------- server
class TestServerDispatch(unittest.TestCase):
    def setUp(self):
        self.server = McpServer(provider=FakeProvider(), allow_write=False)

    def test_initialize(self):
        resp = self.server.handle_message(P.make_request(1, "initialize", {}))
        self.assertEqual(resp["result"]["protocolVersion"], P.MCP_PROTOCOL_VERSION)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "savr")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_tools_list_contains_platform_and_agentic_tools(self):
        resp = self.server.handle_message(P.make_request(1, "tools/list"))
        names = {t["name"] for t in resp["result"]["tools"]}
        platform = {"get_findings", "get_blackboard", "get_iast_events",
                    "trigger_replay", "submit_rule_candidate"}
        agentic = {"code_search", "read_file", "grep_symbol", "run_rule", "probe_readonly"}
        self.assertTrue(platform.issubset(names))
        self.assertTrue(agentic.issubset(names))
        # MCP 要求 camelCase inputSchema
        self.assertTrue(all("inputSchema" in t for t in resp["result"]["tools"]))

    def test_tools_call_readonly(self):
        resp = self.server.handle_message(P.make_request(1, "tools/call", {
            "name": "get_findings", "arguments": {"task_id": 9, "limit": 3}}))
        self.assertFalse(resp["result"]["isError"])
        self.assertIn("findings", resp["result"]["content"][0]["text"])

    def test_write_tools_denied_by_default(self):
        for tool in ("trigger_replay", "submit_rule_candidate"):
            args = {"task_id": 1} if tool == "trigger_replay" else {"family": "x", "rule_expression": "y"}
            resp = self.server.handle_message(P.make_request(1, "tools/call", {"name": tool, "arguments": args}))
            self.assertTrue(resp["result"]["isError"], tool)
            self.assertIn("禁用", resp["result"]["content"][0]["text"])

    def test_write_tools_allowed_when_enabled(self):
        srv = McpServer(provider=FakeProvider(), allow_write=True)
        resp = srv.handle_message(P.make_request(1, "tools/call", {
            "name": "trigger_replay", "arguments": {"task_id": 5}}))
        self.assertFalse(resp["result"]["isError"])
        self.assertIn("replayed", resp["result"]["content"][0]["text"])

    def test_agentic_tool_routed_via_a2_tools(self):
        # probe_readonly 只列清单不执行；经 a2_tools.execute_tool 路由，复用其白名单
        resp = self.server.handle_message(P.make_request(1, "tools/call", {
            "name": "probe_readonly", "arguments": {}}))
        self.assertFalse(resp["result"]["isError"])
        # 越界路径被 _safe_path 沙箱拒绝 → ok=False → isError
        resp2 = self.server.handle_message(P.make_request(2, "tools/call", {
            "name": "read_file", "arguments": {"path": "../../../../etc/passwd"}}))
        self.assertTrue(resp2["result"]["isError"])

    def test_unknown_tool_is_error_result(self):
        resp = self.server.handle_message(P.make_request(1, "tools/call", {"name": "nope", "arguments": {}}))
        self.assertTrue(resp["result"]["isError"])

    def test_unknown_method_returns_method_not_found(self):
        resp = self.server.handle_message(P.make_request(1, "weird/method"))
        self.assertEqual(resp["error"]["code"], P.METHOD_NOT_FOUND)

    def test_notification_returns_none(self):
        self.assertIsNone(self.server.handle_message(P.make_notification("notifications/initialized")))
        self.assertIsNone(self.server.handle_message(P.make_notification("unknown/note")))

    def test_default_provider_write_unimplemented(self):
        # 默认 SqlitePlatformDataProvider 未实现写：allow_write=True 时应返回结构化“未启用”
        srv = McpServer(allow_write=True)
        resp = srv.handle_message(P.make_request(1, "tools/call", {
            "name": "submit_rule_candidate", "arguments": {"family": "f", "rule_expression": "r"}}))
        self.assertTrue(resp["result"]["isError"])

    def test_serve_stdio_ndjson_and_parse_error(self):
        lines = [
            P.dumps(P.make_request(1, "tools/list")),
            "not-json",
            "",
            P.dumps(P.make_notification("notifications/initialized")),
        ]
        out = io.StringIO()
        self.server.serve_stdio(stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
        emitted = [l for l in out.getvalue().splitlines() if l.strip()]
        # tools/list 1 条响应 + 1 条解析错误响应；通知不回响应
        self.assertEqual(len(emitted), 2)
        first = P.loads(emitted[0])
        self.assertIn("tools", first["result"])
        second = P.loads(emitted[1])
        self.assertEqual(second["error"]["code"], P.PARSE_ERROR)


# ---------------------------------------------------------------- client
class TestClientInProcess(unittest.TestCase):
    def setUp(self):
        self.server = McpServer(provider=FakeProvider(), allow_write=True)
        self.client = mc.McpClient(mc.InProcessTransport(self.server))

    def test_initialize_and_list_and_call(self):
        info = self.client.initialize()
        self.assertEqual(self.client.server_info["name"], "savr")
        self.assertTrue(info)
        tools = self.client.list_tools()
        self.assertTrue(any(t["name"] == "get_findings" for t in tools))
        res = self.client.call_tool("get_findings", {"task_id": 1})
        self.assertFalse(res.get("isError"))

    def test_bridge_discover_and_execute(self):
        self.client.initialize()
        bridge = mc.McpToolBridge(self.client, server_name="ext")
        specs = bridge.discover()
        self.assertTrue(specs)
        names = [s["name"] for s in specs]
        self.assertIn("mcp__ext__get_findings", names)
        out = bridge.executor("mcp__ext__get_findings", {"task_id": 2})
        self.assertTrue(out["ok"])
        self.assertEqual(out["remote_tool"], "get_findings")
        # 未桥接的名字 → 结构化错误，不抛
        bad = bridge.executor("mcp__ext__nope", {})
        self.assertFalse(bad["ok"])

    def test_bridge_executor_reports_transport_error(self):
        class DeadTransport(mc.McpTransport):
            def request(self, method, params, timeout):
                raise mc.McpError("外部进程已退出")

            def notify(self, method, params=None):
                pass

        bridge = mc.McpToolBridge(mc.McpClient(DeadTransport()), server_name="dead")
        bridge._remote_names["mcp__dead__x"] = "x"  # 预置映射以走到调用
        out = bridge.executor("mcp__dead__x", {})
        self.assertFalse(out["ok"])
        self.assertIn("退出", out["error"])


# ---------------------------------------------------------------- stdio transport
class TestStdioTransport(unittest.TestCase):
    def test_custom_server_roundtrip_and_timeout(self):
        """用内联脚本自建 MCP server：验证真实子进程 NDJSON 往返 + id 匹配 + 工具级超时。"""
        script = (
            "import sys, json\n"
            "for line in sys.stdin:\n"
            "    line=line.strip()\n"
            "    if not line: continue\n"
            "    m=json.loads(line)\n"
            "    if m.get('method')=='tools/list':\n"
            "        r={'jsonrpc':'2.0','id':m['id'],'result':{'tools':[{'name':'echo','description':'','inputSchema':{'type':'object'}}]}}\n"
            "    elif m.get('method')=='tools/call' and m.get('params',{}).get('name')=='slow':\n"
            "        pass  # 故意不响应，触发超时\n"
            "    elif m.get('method')=='tools/call':\n"
            "        r={'jsonrpc':'2.0','id':m['id'],'result':{'content':[{'type':'text','text':'pong'}],'isError':False}}\n"
            "    else:\n"
            "        r={'jsonrpc':'2.0','id':m.get('id'),'result':{}}\n"
            "    sys.stdout.write(json.dumps(r)+'\\n'); sys.stdout.flush()\n"
        )
        tr = mc.StdioTransport([sys.executable, "-c", script])
        try:
            cli = mc.McpClient(tr)
            tools = cli.list_tools(timeout=10)
            self.assertEqual(tools[0]["name"], "echo")
            res = cli.call_tool("echo", {}, timeout=10)
            self.assertEqual(res["content"][0]["text"], "pong")
            with self.assertRaises(mc.McpError):
                cli.call_tool("slow", {}, timeout=0.5)  # 工具级超时
        finally:
            tr.close()


# ---------------------------------------------------------------- a2_tools 统一命名空间
class TestToolsNamespace(unittest.TestCase):
    def tearDown(self):
        a2_tools.clear_external_tools()

    def test_register_and_route_external_tool(self):
        schema = [{"name": "mcp__ext__remote_x", "description": "d",
                   "input_schema": {"type": "object", "properties": {}}}]
        calls = []

        def _exec(local_name, args):
            calls.append((local_name, args))
            return {"ok": True, "echo": args}

        n = a2_tools.register_external_tools(schema, _exec)
        self.assertEqual(n, 1)
        names = [s["name"] for s in a2_tools.all_tool_schemas()]
        self.assertIn("mcp__ext__remote_x", names)
        # execute_tool 路由到外部执行器
        res = a2_tools.execute_tool("mcp__ext__remote_x", {"a": 1})
        self.assertTrue(res["ok"])
        self.assertEqual(calls[0][0], "mcp__ext__remote_x")

    def test_unknown_tool_lists_external_names(self):
        a2_tools.register_external_tools(
            [{"name": "mcp__s__t", "description": "", "input_schema": {}}],
            lambda n, a: {"ok": True})
        res = a2_tools.execute_tool("definitely-not-a-tool")
        self.assertFalse(res["ok"])
        self.assertIn("mcp__s__t", res["available"])

    def test_local_tools_unaffected(self):
        # 无外部工具时 all_tool_schemas == TOOL_SCHEMAS（向后兼容）
        self.assertEqual([s["name"] for s in a2_tools.all_tool_schemas()],
                         [s["name"] for s in a2_tools.TOOL_SCHEMAS])


if __name__ == "__main__":
    unittest.main()


class TestMcpBootstrap(unittest.TestCase):
    """三期接线（bootstrap）：把外部 MCP server 接进扫描链路（2026-09-20）。

    此前 McpToolBridge 全仓零引用 —— 机制与测试都在，但没有调用方，外部 MCP 实际不可用。
    本组锁定接线本身：默认关闭零开销、幂等、fail-open、真实子进程可桥接、可关闭。
    """

    def setUp(self):
        from src.mcp import bootstrap as bs
        self.bs = bs
        bs.close_external_servers()
        bs.reset_state()

    def tearDown(self):
        self.bs.close_external_servers()
        self.bs.reset_state()

    def test_disabled_by_default_is_zero_cost(self):
        before = len(a2_tools.all_tool_schemas())
        st = self.bs.load_external_servers({"enabled": False})
        self.assertFalse(st["enabled"])
        self.assertEqual(st["tools"], [])
        self.assertEqual(len(a2_tools.all_tool_schemas()), before)

    def test_missing_config_is_disabled(self):
        st = self.bs.load_external_servers({})
        self.assertFalse(st["enabled"])
        self.assertEqual(st["servers"], [])

    def test_expand_env_treats_none_as_empty(self):
        # 回归护栏：str(None) == "None" 会被当成真实 cwd 传给 Popen，
        # 在 Windows 上报 NotADirectoryError [WinError 267]（本模块实测踩过）。
        self.assertEqual(self.bs._expand_env(None), "")
        self.assertEqual(self.bs._expand_env(""), "")
        os.environ["_MCP_TEST_VAR"] = "xyz"
        try:
            self.assertEqual(self.bs._expand_env("/a/${_MCP_TEST_VAR}/b"), "/a/xyz/b")
        finally:
            os.environ.pop("_MCP_TEST_VAR", None)

    def test_empty_command_is_reported_not_raised(self):
        cfg = {"enabled": True, "servers": [{"name": "broken", "command": []}]}
        st = self.bs.load_external_servers(cfg)
        self.assertEqual(st["tools"], [])
        self.assertTrue(any("command 为空" in e for e in st["errors"]))

    def test_bad_command_is_fail_open(self):
        cfg = {"enabled": True, "servers": [
            {"name": "nope", "command": ["definitely-not-a-real-binary-xyz"]}]}
        before = len(a2_tools.all_tool_schemas())
        st = self.bs.load_external_servers(cfg)   # 不得抛异常
        self.assertEqual(st["tools"], [])
        self.assertTrue(st["errors"], "起不来的 server 必须记入 errors")
        self.assertEqual(len(a2_tools.all_tool_schemas()), before)

    def test_load_is_idempotent_and_force_reloads(self):
        cfg = {"enabled": True, "servers": [{"name": "nope", "command": ["nope-xyz"]}]}
        first = self.bs.load_external_servers(cfg, force=True)
        second = self.bs.load_external_servers(cfg)          # 命中缓存
        self.assertEqual(first["servers"], second["servers"])
        third = self.bs.load_external_servers(cfg, force=True)
        self.assertEqual(len(third["servers"]), 1)

    def test_bridges_real_external_server_and_can_close(self):
        """端到端：把平台自己的 MCP server 当外部 server 拉起，走通 tools/call。"""
        cfg = {"enabled": True, "servers": [
            {"name": "platform", "command": [sys.executable, "-m", "src.mcp"]}]}
        local_before = len([s for s in a2_tools.all_tool_schemas()
                            if not str(s["name"]).startswith("mcp__")])
        st = self.bs.load_external_servers(cfg, force=True)
        if st["errors"]:
            self.skipTest(f"外部 server 未能拉起（环境相关）：{st['errors']}")
        self.assertTrue(st["tools"], "应发现远端工具")
        self.assertTrue(all(t.startswith("mcp__platform__") for t in st["tools"]))
        # 真调一次（读工具，不需要 allow_write）
        name = next(t for t in st["tools"] if t.endswith("get_findings"))
        res = a2_tools.execute_tool(name, {"task_id": 21, "limit": 1})
        self.assertTrue(res.get("ok"), res)
        self.assertTrue(res.get("mcp"))
        # 关闭后外部工具全部注销，本地工具数回到原值
        self.bs.close_external_servers()
        after = len([s for s in a2_tools.all_tool_schemas()
                     if not str(s["name"]).startswith("mcp__")])
        self.assertEqual(after, local_before)
        self.assertFalse(any(str(s["name"]).startswith("mcp__") for s in a2_tools.all_tool_schemas()))
