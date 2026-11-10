"""判定缓存单测（src/iast/decision_cache.py）。

纯模块，无 LLM 依赖。覆盖：建表、指纹归一化（注释/空白差异应同 hash）、命中/未命中、
覆盖写、空 verdict 不缓存、put_code 便捷路径。
"""
import sqlite3

from src.iast import decision_cache as DC


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = lambda cur, row: {col[0]: row[idx]
                                      for idx, col in enumerate(cur.description)}
    DC.ensure_decision_cache(c)
    return c


def test_ensure_idempotent():
    c = _conn()
    DC.ensure_decision_cache(c)
    assert c.execute("SELECT name FROM sqlite_master WHERE type='table' "
                     "AND name='decision_cache'").fetchone() is not None


def test_fingerprint_normalizes_comments_and_whitespace():
    a = "  // weak\n  Cipher.getInstance(\"DES\");   // todo\n"
    b = "Cipher.getInstance(\"DES\");"
    assert DC.fingerprint(a, "weak_crypto") == DC.fingerprint(b, "weak_crypto")


def test_fingerprint_keyed_by_family():
    code = "Cipher.getInstance(\"DES\");"
    assert DC.fingerprint(code, "weak_crypto") != DC.fingerprint(code, "weak_hash")


def test_put_then_lookup_hit():
    c = _conn()
    DC.put_code(c, code="SecureRandom sr = new SecureRandom();", family="weak_random",
                verdict="real", confidence=0.9, source="a2")
    hit = DC.lookup(c, "SecureRandom sr = new SecureRandom();", "weak_random")
    assert hit is not None
    assert hit["verdict"] == "real"
    assert hit["family"] == "weak_random"


def test_lookup_miss_on_different_family():
    c = _conn()
    DC.put_code(c, code="DES", family="weak_crypto", verdict="real")
    assert DC.lookup(c, "DES", "weak_hash") is None


def test_empty_verdict_not_cached():
    c = _conn()
    DC.put_code(c, code="foo", family="x", verdict="")
    assert DC.lookup(c, "foo", "x") is None


def test_put_overwrites_same_key():
    c = _conn()
    DC.put_code(c, code="bar", family="y", verdict="real", confidence=0.8, source="a2")
    DC.put_code(c, code="bar", family="y", verdict="false_positive", confidence=0.99,
                source="d2")
    hit = DC.lookup(c, "bar", "y")
    assert hit["verdict"] == "false_positive"
    assert hit["source"] == "d2"
    n = c.execute("SELECT COUNT(*) AS n FROM decision_cache").fetchone()["n"]
    assert n == 1  # 唯一索引生效，未产生重复行


def test_put_persists_spec_json():
    c = _conn()
    spec = {"route": "/x", "param_name": "p", "payload": "1"}
    DC.put_code(c, code="baz", family="z", verdict="real", spec_json=spec)
    hit = DC.lookup(c, "baz", "z")
    assert hit is not None
    import json
    assert json.loads(hit["spec_json"])["route"] == "/x"
