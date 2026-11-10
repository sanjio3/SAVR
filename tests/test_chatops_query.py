"""G11: SCA ChatOps query skill + bot adapters (第四版 §2.15). Offline fixtures."""

from pathlib import Path

import pytest

from src.application.advisory_service import AdvisoryService
from src.chatops.bots import format_answer_markdown, get_bot_adapter
from src.chatops.parser import parse_query
from src.chatops.skill import ScaChatOpsSkill
from src.infrastructure.db import Database


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(str(tmp_path / "app.db"))
    now = "2026-01-01T00:00:00"
    for eco, name, version, src in [
        ("pypi", "example-orm", "1.4.0", "requirements.txt"),
        ("pypi", "colourama", "0.1.6", "requirements.txt"),
    ]:
        database.execute(
            "INSERT INTO sca_components (workspace_id, ecosystem, name, version, source_file, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (1, eco, name, version, src, now, now),
        )
    return database


@pytest.fixture()
def skill(db: Database) -> ScaChatOpsSkill:
    advisory = AdvisoryService(db)
    advisory.ingest_local_dataset()
    return ScaChatOpsSkill(db, advisory_service=advisory)


def test_parse_text_component_and_version():
    parsed = parse_query("我们是否用了 example-orm@1.4.0？")
    assert parsed["name"] == "example-orm"
    assert parsed["version"] == "1.4.0"


def test_parse_cve_and_ghsa():
    parsed = parse_query("check CVE-2021-44228 and GHSA-jfh8-c2jp-5v3q")
    assert "CVE-2021-44228" in parsed["advisory_ids"]
    assert "GHSA-JFH8-C2JP-5V3Q" in parsed["advisory_ids"]


def test_parse_pypi_url():
    parsed = parse_query("https://pypi.org/project/example-orm/1.4.0/")
    assert parsed["is_url"] is True
    assert parsed["ecosystem"] == "pypi"
    assert parsed["name"] == "example-orm"
    assert parsed["version"] == "1.4.0"


def test_parse_npm_url_with_version():
    parsed = parse_query("https://www.npmjs.com/package/left-pad/v/1.3.0")
    assert parsed["name"] == "left-pad"
    assert parsed["version"] == "1.3.0"


def test_skill_reports_in_use_and_vulnerable(skill: ScaChatOpsSkill):
    answer = skill.query("example-orm 1.4.0 有没有漏洞", workspace_id=1)
    assert answer["in_use"] is True
    assert "requirements.txt" in answer["projects"]
    assert answer["vulnerable"] is True
    assert answer["vulnerability_hits"][0]["advisory_id"] == "PYSEC-2023-62"
    assert "升级" in answer["remediation"]


def test_skill_flags_malicious_component(skill: ScaChatOpsSkill):
    answer = skill.query("colourama", workspace_id=1)
    assert answer["exposure"]["malicious"] is True
    assert "恶意" in answer["remediation"] or "投毒" in answer["remediation"]


def test_skill_component_not_in_inventory(skill: ScaChatOpsSkill):
    answer = skill.query("totally-unused-lib", workspace_id=1)
    assert answer["in_use"] is False
    assert answer["vulnerable"] is False


def test_skill_advisory_id_lookup(skill: ScaChatOpsSkill):
    answer = skill.query("CVE-2023-0001", workspace_id=1)
    assert any(a["advisory_id"] == "PYSEC-2023-62" for a in answer["advisory_lookups"])


def test_bot_adapters_render_markdown(skill: ScaChatOpsSkill):
    answer = skill.query("example-orm 1.4.0", workspace_id=1)
    text = format_answer_markdown(answer)
    assert "example-orm" in text
    feishu = get_bot_adapter("feishu").build_payload(answer)
    assert feishu["platform"] == "feishu"
    dingtalk = get_bot_adapter("dingtalk").build_payload(answer)
    assert dingtalk["msgtype"] == "markdown"
    generic = get_bot_adapter("unknown-platform").build_payload(answer)
    assert generic["platform"] == "generic"
