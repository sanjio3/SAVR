from pathlib import Path

import pytest

from src.application.entry_discovery_service import EntryDiscoveryService


def _write(proj: Path, name: str, body: str) -> None:
    (proj / name).write_text(body, encoding="utf-8")


def test_ast_discovers_blueprint_route_missed_by_regex(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    # `@bp.route` is NOT matched by the line-regex (which only knows app/router),
    # so only the AST branch can find it.
    _write(proj, "views.py", "\n".join([
        "from flask import Blueprint",
        "bp = Blueprint('bp', __name__)",
        "@bp.route('/reports')",
        "def reports():",
        "    return 'ok'",
    ]))
    result = EntryDiscoveryService().discover(str(proj))
    ast_entries = [e for e in result["entries"] if e["source"] == "ast-entry-discovery"]
    assert any("bp.route" in e["signature"] for e in ast_entries)
    assert all(e["confidence"] == "high" for e in ast_entries)


def test_ast_discovers_add_url_rule(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "legacy.py", "\n".join([
        "def register(app):",
        "    app.add_url_rule('/legacy', view_func=handler)",
    ]))
    result = EntryDiscoveryService().discover(str(proj))
    assert any(
        e["source"] == "ast-entry-discovery" and "add_url_rule" in e["signature"]
        for e in result["entries"]
    )


def test_regex_and_ast_do_not_double_count(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    # `@app.get` is matched by BOTH regex and AST at the same line: expect one entry.
    _write(proj, "api.py", "\n".join([
        "@app.get('/users')",
        "def get_users():",
        "    return []",
    ]))
    result = EntryDiscoveryService().discover(str(proj))
    line1 = [e for e in result["entries"] if e["line"] == 1 and e["entry_type"] == "web_route"]
    assert len(line1) == 1


def test_rules_loadable_from_custom_yaml(tmp_path: Path):
    # A company-specific annotation added purely via yaml, no code change.
    rules_file = tmp_path / "custom_rules.yaml"
    rules_file.write_text(
        "version: 1\nrules:\n"
        "  - entry_type: web_route\n"
        "    pattern: '@AcmeApi'\n"
        "    confidence: medium\n",
        encoding="utf-8",
    )
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "svc.java", "@AcmeApi\npublic void handle() {}\n")

    default_service = EntryDiscoveryService()
    assert not default_service.discover(str(proj))["entries"]

    custom_service = EntryDiscoveryService(rules_path=str(rules_file))
    entries = custom_service.discover(str(proj))["entries"]
    assert any("@AcmeApi" in e["signature"] for e in entries)


def test_request_params_flask_path_and_query(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "api.py", "\n".join([
        "from flask import request",
        "@app.route('/user/<int:uid>')",
        "def get_user(uid):",
        "    name = request.args.get('name')",
        "    return uid",
    ]))
    result = EntryDiscoveryService().discover(str(proj))
    entries = [e for e in result["entries"] if e["entry_type"] == "web_route"]
    assert entries, "应发现 web_route"
    params = entries[0]["request_params"]
    names = {p["param_name"]: p["param_location"] for p in params}
    assert names.get("uid") == "path"
    assert names.get("name") == "query"


def test_request_params_spring_path_and_body(tmp_path: Path):
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "Ctrl.java", "\n".join([
        "@RestController",
        "@RequestMapping('/api')",
        "public class Ctrl {",
        "  @PostMapping(value='/order/{oid}', consumes='application/json')",
        "  public void create(@PathVariable('oid') String oid, @RequestBody Order o) {}",
        "}",
    ]))
    result = EntryDiscoveryService().discover(str(proj))
    entries = [e for e in result["entries"] if e["entry_type"] == "web_route"]
    assert entries, "应发现 web_route"
    params = entries[0]["request_params"]
    by_name = {p["param_name"]: p for p in params}
    assert by_name["oid"]["param_location"] == "path"
    assert by_name["_body"]["param_location"] == "body"
    assert by_name["_body"]["content_type"] == "application/json"

