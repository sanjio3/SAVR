"""族⇄sink 白名单与族-证据一致性校验回归守卫。

实证背景（run 32 全量 205 用例）：
  - 平台族名与 OWASP 真值族名一致率 64.6%（124/192 用例），错不在归一层而在上游定族：
    21 条 hash/crypto/weakrand 被错叫成 sensitive_data_exposure，9 条被叫成
    weak_password_storage，15 条 xpathi/ldapi/trustbound 被套成 path_traversal。
  - 但 sink 不能无脑当判据：``Cookie.setHttpOnly`` 横跨 20+ 族、``Response.addHeader`` /
    ``FileOutputStream.<init>`` 亦如此。故本模块三条硬约束（见模块 docstring）：
    ① 只收专属 sink；② 本族已有专属 sink 实证则不动；③ 只有泛化族才允许被改判。

本测试锁定这三条不被后续改动破坏。
"""
import pytest

from src.core.family_sink_registry import (
    FAMILY_EXCLUSIVE_SINKS,
    VAGUE_FAMILIES,
    is_vague_family,
    reassign_family_by_sink_evidence,
    resolve_family_from_sinks,
    sink_hits_for,
)


def test_exclusive_sink_lookup():
    assert sink_hits_for("weak_hash", ["java.security.MessageDigest.getInstance"])
    assert not sink_hits_for("weak_hash", ["javax.crypto.Cipher.getInstance"])
    assert sink_hits_for("weak_crypto", ["javax.crypto.Cipher.getInstance"])
    assert sink_hits_for("weak_random", ["java.util.Random.nextDouble"])
    assert sink_hits_for("command_execution", ["java.lang.Runtime.exec"])
    assert sink_hits_for("sql_injection", ["org.hsqldb.jdbc.JDBCStatement.executeQuery"])


def test_noise_sinks_are_not_in_whitelist():
    """跨请求噪声 sink 绝不可进白名单（run 32 实测横跨 20+ 族）。"""
    noise = [
        "javax.servlet.http.Cookie.setHttpOnly",
        "javax.servlet.http.Cookie.setSecure",
        "org.apache.catalina.connector.Response.addHeader",
        "org.apache.catalina.connector.ResponseFacade.setHeader",
        "java.io.FileOutputStream.<init>",
        "java.io.FileInputStream.<init>",
        "java.io.RandomAccessFile.<init>",
    ]
    for fam in FAMILY_EXCLUSIVE_SINKS:
        for n in noise:
            assert not sink_hits_for(fam, [n]), "%s 不该被 %s 判为专属" % (fam, n)
    assert not resolve_family_from_sinks(noise)[0]


def test_resolve_picks_strongest_evidence():
    # 命中按「去重后的专属 sink 数」计：同一签名重复出现不重复计分。
    fam, hits, n = resolve_family_from_sinks([
        "java.security.MessageDigest.getInstance",
        "java.security.MessageDigest.getInstance",
        "javax.crypto.Cipher.getInstance",
    ])
    assert fam == "weak_hash" and n == 1
    # 并列时取表序在前（weak_hash 在 weak_crypto / weak_random 之前）
    fam2, hits2, n2 = resolve_family_from_sinks([
        "java.security.MessageDigest.getInstance",
        "javax.crypto.Cipher.getInstance",
        "java.util.Random.nextInt",
    ])
    assert fam2 == "weak_hash" and n2 == 1


def test_keep_family_when_own_exclusive_sink_present():
    """硬约束②：weak_random 用例里也用到 MessageDigest，但本族有 Random.next* 就不许改判。"""
    fam, detail = reassign_family_by_sink_evidence("weak_random", [
        "java.util.Random.nextDouble",
        "java.security.MessageDigest.getInstance",
        "javax.servlet.http.Cookie.setHttpOnly",
    ])
    assert fam == "weak_random"
    assert detail["consistent"] is True
    assert detail["reassigned"] is False
    assert "本族有专属 sink 实证" in detail["reason"]


def test_reassign_vague_family_to_hash():
    fam, detail = reassign_family_by_sink_evidence("sensitive_data_exposure", [
        "java.io.FileOutputStream.<init>",  # 噪声，应被忽略
        "java.security.MessageDigest.getInstance",
    ])
    assert fam == "weak_hash"
    assert detail["reassigned"] is True
    assert detail["prior_family"] == "sensitive_data_exposure"


def test_reassign_vague_family_to_crypto():
    fam, _ = reassign_family_by_sink_evidence("weak_password_storage", [
        "javax.crypto.Cipher.getInstance",
        "org.apache.catalina.connector.Response.addHeader",
    ])
    assert fam == "weak_crypto"


def test_reassign_vague_family_to_random():
    fam, _ = reassign_family_by_sink_evidence("weak_password_storage", [
        "java.util.Random.nextFloat",
    ])
    assert fam == "weak_random"


def test_dataflow_family_never_reassigned():
    """硬约束③：数据流族（path_traversal 等）凭噪声 sink 改判风险太高，一律不动。"""
    fam, detail = reassign_family_by_sink_evidence("path_traversal", [
        "java.security.MessageDigest.getInstance",
    ])
    assert fam == "path_traversal"
    assert detail["reassigned"] is False
    assert "数据流族" in detail["reason"]


def test_no_sink_evidence_keeps_family():
    fam, detail = reassign_family_by_sink_evidence(
        "sensitive_data_exposure", ["java.io.FileOutputStream.<init>"])
    assert fam == "sensitive_data_exposure"
    assert detail["reassigned"] is False
    assert "未观测到" in detail["reason"]


def test_empty_sinks_keeps_family():
    fam, detail = reassign_family_by_sink_evidence("sensitive_data_exposure", [])
    assert fam == "sensitive_data_exposure"
    assert detail["reassigned"] is False


def test_consistent_when_resolved_equals_current():
    fam, detail = reassign_family_by_sink_evidence(
        "weak_hash", ["java.security.MessageDigest.getInstance"])
    assert fam == "weak_hash" and detail["consistent"] is True


def test_vague_family_set_members():
    for f in ("sensitive_data_exposure", "weak_password_storage", "none", "generic", ""):
        assert is_vague_family(f), f
    for f in ("path_traversal", "sql_injection", "xss", "command_execution", "weak_hash"):
        assert not is_vague_family(f), f


def test_cookie_sinks_do_not_drive_reassign():
    """Cookie.setSecure/setHttpOnly 是 secure_cookie 真 sink，但横跨 20+ 族（run 32 实测），
    故刻意不进白名单：泛化族只观测到 Cookie sink 时不改判（宁可漏改，不可错改）。"""
    fam, detail = reassign_family_by_sink_evidence("cookie", [
        "javax.servlet.http.Cookie.setSecure",
        "org.apache.catalina.connector.Response.addHeader",
    ])
    assert fam == "cookie"
    assert detail["reassigned"] is False
    assert "未观测到" in detail["reason"]
