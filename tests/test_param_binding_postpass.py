"""Phase 0b/0c（param 补齐 + 请求形态纠正）的回归锁（2026-11-02）。

两起实测事故：

1. **补齐只写名字、把位置丢了**。`infer_for_spec` 是**按注解/字面量**判位置的
   （`request.getHeader("Origin")` ⇒ header、`@CookieValue` ⇒ cookie），比后面
   「按形参类型推编码」更确定。但补齐函数只 `UPDATE param_name`，位置留在默认 query
   ⇒ 从 header 推出来的参数被当 query 投出去，**请求形态错了等于白投**。

2. **形态纠正的跳过条件漏了一种情况**。原条件是 `if content_type and location != "query"`，
   于是「位置已定成 header 但 content_type 为空」会被后面的类型推断改回 form。
   但反过来的边界也要守住：`body` + 空 content_type **不算定死** ——
   `MultipartFile` 被 A2 猜成 body 时，必须让类型驱动升级成 multipart。
"""
from __future__ import annotations

import json
import os
import sqlite3

import pytest


class _DB:
    """最小 Database 兼容层：`execute(sql, params, fetchall=True)` 返回 dict 列表。

    平台 `Database` 返回的是 dict（生产代码用 `.get()` 取值），裸 sqlite3 返回 Row。
    这里必须对齐生产形态，否则测试测的是另一条代码路径。
    """

    def __init__(self, con):
        self.con = con

    def execute(self, sql, params=(), fetchall=False):
        cur = self.con.execute(sql, params)
        return [dict(r) for r in cur.fetchall()] if fetchall else cur


JAVA = """package d;
@RestController
public class Cors {
    @GetMapping("/cors/vuln/origin")
    public String vuls1(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("origin");
        response.setHeader("Access-Control-Allow-Origin", origin);
        return "";
    }
}
"""

JAVA_UPLOAD = """package d;
@RestController
public class Up {
    @PostMapping("/file/upload")
    public String up(@RequestParam("file") MultipartFile file) {
        return file.getOriginalFilename();
    }
}
"""


@pytest.fixture()
def env(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Cors.java").write_text(JAVA, encoding="utf-8")
    (tmp_path / "src" / "Up.java").write_text(JAVA_UPLOAD, encoding="utf-8")
    index = {"functions": {
        os.path.join("src", "Cors.java") + ":vuls1": {
            "file": os.path.join("src", "Cors.java"), "line": 4,
            "http_entry": "GET /cors/vuln/origin", "callers": [],
            "params_typed": [{"annotations": [], "type": "HttpServletRequest", "name": "request"}],
        },
        os.path.join("src", "Up.java") + ":up": {
            "file": os.path.join("src", "Up.java"), "line": 4,
            "http_entry": "POST /file/upload", "callers": [],
            "params_typed": [{"annotations": ['@RequestParam("file")'],
                              "type": "MultipartFile", "name": "file"}],
        },
    }}
    (tmp_path / "code_index.json").write_text(json.dumps(index), encoding="utf-8")

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute(
        "CREATE TABLE trigger_specs (id INTEGER PRIMARY KEY, task_id INT, family TEXT, "
        "expected_sink_file TEXT, expected_sink_line INT, target_endpoint TEXT, "
        "param_name TEXT, param_name_source TEXT, param_location TEXT, content_type TEXT)"
    )
    con.execute("CREATE TABLE scan_tasks (id INTEGER PRIMARY KEY, output_dir TEXT)")
    con.execute("INSERT INTO scan_tasks VALUES (1, ?)", (str(tmp_path),))
    yield con, str(tmp_path)  # code_root = 项目根（sink_file 是相对根的路径）
    con.close()


def _add(con, sid, sink_file, line, pname="", ploc="query", ct="", src=""):
    con.execute(
        "INSERT INTO trigger_specs VALUES (?,1,'cors',?,?,'/x',?,?,?,?)",
        (sid, sink_file, line, pname, src, ploc, ct))


def test_backfill_writes_location_for_header_channel(env):
    """从 `getHeader("origin")` 推出 header 时，位置必须一起写，不能留在 query。"""
    from src.cli.benchmark_cli import _apply_param_backfill_postpass

    con, src_root = env
    _add(con, 1, os.path.join("src", "Cors.java"), 6)
    n = _apply_param_backfill_postpass(1, _DB(con), src_root, src_root)
    assert n == 1
    row = dict(con.execute(
        "SELECT param_name, param_location, param_name_source FROM trigger_specs WHERE id=1").fetchone())
    assert row["param_name"].lower() == "origin", row
    assert row["param_location"] == "header", row
    assert row["param_name_source"].startswith("param_infer:"), row


def test_binding_does_not_override_annotation_derived_location(env):
    """位置来自注解/字面量通道时，类型推断不得把它改回 form/query。"""
    from src.cli.benchmark_cli import _apply_binding_postpass

    con, src_root = env
    _add(con, 1, os.path.join("src", "Cors.java"), 6, pname="origin", ploc="header",
         src="param_infer:get_header_literal:high")
    _apply_binding_postpass(1, _DB(con), src_root, src_root)
    loc = con.execute("SELECT param_location FROM trigger_specs WHERE id=1").fetchone()[0]
    assert loc == "header", loc


def test_binding_upgrades_body_without_content_type_to_multipart(env):
    """`body` + 空 content_type 不算定死：MultipartFile 必须升级成 multipart。"""
    from src.cli.benchmark_cli import _apply_binding_postpass

    con, src_root = env
    _add(con, 1, os.path.join("src", "Up.java"), 4, pname="file", ploc="body", ct="")
    _apply_binding_postpass(1, _DB(con), src_root, src_root)
    row = dict(con.execute(
        "SELECT param_location, content_type FROM trigger_specs WHERE id=1").fetchone())
    assert row["param_location"] == "form", row
    assert row["content_type"] == "multipart/form-data", row
