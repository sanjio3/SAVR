"""发难清单批次5（机制表接线）单测：运行时事实 / OOB HTTP 接收端点 / fastjson 1.2.48+ 选弹。"""
import os

import pytest

from src.core.runtime_facts import check_depends, collect_facts, jdk_in_range, jdk_parts


# ---------------- runtime_facts ----------------

def test_jdk_parts_java_semantics():
    assert jdk_parts("1.8.0_191") == (8, 0, 191)
    assert jdk_parts("8u191") == (8, 0, 191)
    assert jdk_parts("11.0.1") == (11, 0, 1)
    assert jdk_parts("21") == (21,)
    assert jdk_parts("") is None


def test_jdk_in_range():
    assert jdk_in_range("1.8.0_65", "<8u191")
    assert not jdk_in_range("1.8.0_311", "<8u191")
    assert jdk_in_range("11.0.1", ">=8u191")
    assert jdk_in_range("17.0.2", ">=1.8")
    # 版本未知 fail-open 恒真
    assert jdk_in_range("", "<8u191")
    assert jdk_in_range("1.8.0_191", "*")


def test_check_depends_mismatch_blocks():
    mech = {"id": "jndi-trusturlcodebase", "depends": {"jdk_range": "<8u191", "classes": []}}
    ok, why = check_depends(mech, {"jdk_version": "1.8.0_311"})
    assert ok is False and any("jdk_version_mismatch" in w for w in why)


def test_check_depends_unknown_fails_open():
    mech = {"id": "jndi-trusturlcodebase", "depends": {"jdk_range": "<8u191", "classes": []}}
    ok, why = check_depends(mech, {})
    assert ok is True and "jdk_version_unknown" in why


def test_check_depends_classpath_missing_blocks():
    mech = {"id": "cb1", "depends": {"jdk_range": "*", "classes": ["org.apache.commons.beanutils.BeanComparator"]}}
    ok, why = check_depends(mech, {"jdk_version": "8", "classes": ["other.Class"]})
    assert ok is False and any("classpath_missing" in w for w in why)
    ok2, _ = check_depends(mech, {"jdk_version": "8", "classes": ["org.apache.commons.beanutils.BeanComparator"]})
    assert ok2 is True


def test_collect_facts_reads_env(monkeypatch):
    monkeypatch.setenv("SAST_AI_TARGET_JAVA_VERSION", "1.8.0_191")
    assert collect_facts()["jdk_version"] == "1.8.0_191"
    monkeypatch.delenv("SAST_AI_TARGET_JAVA_VERSION")
    monkeypatch.setenv("SAST_AI_TARGET_JAVA_MAJOR", "8")
    assert collect_facts()["jdk_version"] == "8.0"


# ---------------- fastjson 1.2.48+ 弹药链 ----------------

def test_fastjson_1268_chain_selected():
    from src.iast.payload_forge import PayloadForge
    forge = PayloadForge()
    hits = forge.select_chains(
        {"name": "com.alibaba:fastjson", "version": "1.2.68", "ecosystem": "maven"},
        family="deserialization",
    )
    ids = [h["id"] for h in hits]
    assert "fastjson-expectclass-1268" in ids
    # 1.2.25 也应命中旧链但不应命中 expectClass 链
    hits_old = forge.select_chains(
        {"name": "com.alibaba:fastjson", "version": "1.2.25", "ecosystem": "maven"},
        family="deserialization",
    )
    assert "fastjson-expectclass-1268" not in [h["id"] for h in hits_old]
    # 机制表口径：1.2.83+ 不再落在 expectClass 绕过面区间
    from src.core.mechanism_library import lookup as mlookup
    assert mlookup("com.alibaba:fastjson", "1.2.83") == []
    assert any(m["id"] == "fastjson-autotype-modern" for m in mlookup("com.alibaba:fastjson", "1.2.68"))


# ---------------- OOB HTTP 接收端点 ----------------

@pytest.fixture()
def oob_client(tmp_path, monkeypatch):
    db_path = str(tmp_path / "oob.db")
    monkeypatch.setenv("SAST_AI_DB_PATH", db_path)
    from fastapi.testclient import TestClient
    from src.api.app import create_app
    app = create_app()
    return TestClient(app), db_path


def test_oob_receive_and_status(oob_client):
    client, db_path = oob_client
    from src.iast import oob_monitor
    token = oob_monitor.new_token()
    assert oob_monitor.register(token, task_id=1, family="ssrf", db_path=db_path)
    # 目标出网打到收数端点
    r = client.get(f"/api/oob/{token}?canary=probe")
    assert r.status_code == 200
    assert oob_monitor.has_callback(token, db_path=db_path)
    st = client.get(f"/api/oob/status/{token}").json()
    assert st["has_callback"] is True
    recent = client.get("/api/oob/recent").json()
    assert any(c["token"] == token for c in recent["callbacks"])


def test_oob_unknown_token_is_harmless(oob_client):
    client, db_path = oob_client
    from src.iast import oob_monitor
    r = client.get("/api/oob/deadbeef00")
    assert r.status_code == 200
    assert oob_monitor.has_callback("deadbeef00", db_path=db_path)  # 收了但无登记行，仅回执


def test_oob_domain_form_token(oob_client):
    client, db_path = oob_client
    from src.iast import oob_monitor
    token = oob_monitor.new_token()
    oob_monitor.register(token, task_id=1, db_path=db_path)
    # 域名形态：token.base 被拆解
    client.get(f"/api/oob/{token}.oob.example.com")
    assert oob_monitor.has_callback(token, db_path=db_path)
