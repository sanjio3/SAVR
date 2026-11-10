#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CodeQL 构建 JDK 绑定单测（2026-10-31，T0.5）。

背景：java-sec-code 上 CodeQL 一直 `build_failed_or_empty`，根因不是查询包，
而是构建子进程继承了后端的 `JAVA_HOME=jdk-21`，项目却是 JDK8 + 老 Lombok：

    JAVA_HOME=jdk-21  → mvn -B compile 报 NoSuchFieldError: JCTree$JCImport.qualid
    JAVA_HOME=jdk65   → BUILD SUCCESS (4.7s)

所以「按项目声明钉 JDK」是 A1 主力能不能起来的前提。这组用例锁三件事：
1. 版本号解析（1.8.0_65 / 11.0.25 / 21.0.7）；
2. 从 pom.xml / build.gradle 读声明；
3. `SAST_AI_JAVA_HOME` 显式覆盖优先，且读不到声明时**不瞎猜**。
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents import a1_codeql_adapter as ad  # noqa: E402


def setup_function(_):
    ad._JDK_SCAN_CACHE = None


def test_major_of_variants():
    assert ad._major_of('"1.8.0_65"') == 8
    assert ad._major_of("11.0.25") == 11
    assert ad._major_of("21.0.7") == 21
    assert ad._major_of("1.7.0_80") == 7
    assert ad._major_of("") == 0


def test_project_java_major_from_pom(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><properties>"
        "<maven.compiler.source>1.8</maven.compiler.source>"
        "</properties></project>", encoding="utf-8")
    assert ad._project_java_major(str(tmp_path)) == 8


def test_project_java_major_java_version_wins(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project><properties><java.version>17</java.version>"
        "<maven.compiler.source>1.8</maven.compiler.source></properties></project>",
        encoding="utf-8")
    assert ad._project_java_major(str(tmp_path)) == 17


def test_project_java_major_from_gradle(tmp_path):
    (tmp_path / "build.gradle").write_text(
        "android { compileOptions { sourceCompatibility = JavaVersion.VERSION_11 } }",
        encoding="utf-8")
    assert ad._project_java_major(str(tmp_path)) == 11


def test_project_java_major_absent_returns_zero(tmp_path):
    assert ad._project_java_major(str(tmp_path)) == 0
    assert ad._project_java_major("") == 0


def test_resolve_honours_explicit_override(tmp_path, monkeypatch):
    """SAST_AI_JAVA_HOME 优先级最高（运维要能一键指定）。"""
    fake = tmp_path / "jdkX"
    (fake / "bin").mkdir(parents=True)
    monkeypatch.setenv("SAST_AI_JAVA_HOME", str(fake))
    assert ad.resolve_build_java_home(str(tmp_path)) == str(fake)


def test_resolve_returns_empty_without_declaration(tmp_path, monkeypatch):
    """项目没声明 JDK 时不瞎猜——保持继承，让调用方看到真实报错。"""
    monkeypatch.delenv("SAST_AI_JAVA_HOME", raising=False)
    assert ad.resolve_build_java_home(str(tmp_path)) == ""


def test_env_with_shim_pins_java_home_when_jdk_available(tmp_path, monkeypatch):
    """本机存在声明版本的 JDK 时，JAVA_HOME 与 PATH 都要指向它。"""
    monkeypatch.delenv("SAST_AI_JAVA_HOME", raising=False)
    jdks = ad._scan_jdks()
    if not jdks:
        pytest.skip("本机没有可用 JDK，跳过")
    major, path = jdks[0]
    (tmp_path / "pom.xml").write_text(
        f"<project><properties><maven.compiler.source>{major}</maven.compiler.source>"
        "</properties></project>", encoding="utf-8")
    env = ad._env_with_mvn_shim(str(tmp_path))
    assert os.path.normcase(env["JAVA_HOME"]) == os.path.normcase(path)
    assert os.path.normcase(os.path.join(path, "bin")) in os.path.normcase(env["PATH"])


def test_env_with_shim_does_not_touch_java_home_without_project(monkeypatch):
    """不传 project_path 时不改 JAVA_HOME（OWASP 那种无构建声明的路径保持原样）。"""
    monkeypatch.setenv("JAVA_HOME", r"D:/fake/jdk")
    env = ad._env_with_mvn_shim()
    assert env["JAVA_HOME"] == r"D:/fake/jdk"


# ── 库新鲜度（2026-11-01）：7 周前的旧库被复用是 A1 一直降级的真根因 ──────
def _write_db(path, *, finalized=True, created="2026-09-12T09:46:36.963177600Z",
              source=None):
    path.mkdir(parents=True, exist_ok=True)
    (path / "codeql-database.yml").write_text(
        "sourceLocationPrefix: %s\n"
        "creationMetadata:/n  creationTime: %s\n"
        "%s\n" % (source or "", created, "finalised: true" if finalized else "inProgress: true"),
        encoding="utf-8")
    return path


def test_db_usable_fresh(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "A.java").write_text("class A{}", encoding="utf-8")
    db = _write_db(tmp_path / "db", created="2099-01-01T00:00:00Z", source=str(proj))
    assert ad.CodeQLAdapter._db_is_usable(str(db), str(proj)) == (True, "ok")


def test_db_not_usable_when_stale(tmp_path):
    """库比源码旧 ⇒ 必须重建（这正是 java-sec-code 上 A1 一直降级的原因）。"""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "A.java").write_text("class A{}", encoding="utf-8")
    db = _write_db(tmp_path / "db", created="2020-01-01T00:00:00Z", source=str(proj))
    ok, why = ad.CodeQLAdapter._db_is_usable(str(db), str(proj))
    assert ok is False and why.startswith("stale_db")


def test_db_not_usable_when_source_mismatch(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    db = _write_db(tmp_path / "db", created="2099-01-01T00:00:00Z", source=str(tmp_path / "other"))
    ok, why = ad.CodeQLAdapter._db_is_usable(str(db), str(proj))
    assert ok is False and "source_root_mismatch" in why


def test_db_not_usable_when_not_finalized(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    db = _write_db(tmp_path / "db", finalized=False, created="2099-01-01T00:00:00Z", source=str(proj))
    ok, why = ad.CodeQLAdapter._db_is_usable(str(db), str(proj))
    assert ok is False and why == "db_not_finalized"


def test_db_not_usable_when_missing(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    ok, why = ad.CodeQLAdapter._db_is_usable(str(tmp_path / "nope"), str(proj))
    assert ok is False and why == "db_not_exists"


def test_pick_db_target_avoids_stale_dir(tmp_path):
    """base 库过期时不删不覆盖，改建到 .fresh-<ts> 兄弟目录。"""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "A.java").write_text("class A{}", encoding="utf-8")
    base = _write_db(tmp_path / ".codeql-db", created="2020-01-01T00:00:00Z", source=str(proj))
    target, reused, why = ad.CodeQLAdapter._pick_db_target(str(base), str(proj))
    assert reused is False
    assert ".codeql-db.fresh-" in target
    assert "stale_db" in why


# ── 库新鲜度（2026-11-01）：7 周前的旧库被复用是 A1 一直降级的真根因 ──────
def _write_db(path, *, finalized=True, created="2026-09-12T09:46:36.963177600Z",
              source=None):
    path.mkdir(parents=True, exist_ok=True)
    (path / "codeql-database.yml").write_text(
        "sourceLocationPrefix: %s\n"
        "creationMetadata:\n  creationTime: %s\n"
        "%s\n" % (source or "", created, "finalised: true" if finalized else "inProgress: true"),
        encoding="utf-8")
    return path


def test_db_usable_fresh(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "A.java").write_text("class A{}", encoding="utf-8")
    db = _write_db(tmp_path / "db", created="2099-01-01T00:00:00Z", source=str(proj))
    assert ad.CodeQLAdapter._db_is_usable(str(db), str(proj)) == (True, "ok")


def test_db_not_usable_when_stale(tmp_path):
    """库比源码旧 ⇒ 必须重建（这正是 java-sec-code 上 A1 一直降级的原因）。"""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "A.java").write_text("class A{}", encoding="utf-8")
    db = _write_db(tmp_path / "db", created="2020-01-01T00:00:00Z", source=str(proj))
    ok, why = ad.CodeQLAdapter._db_is_usable(str(db), str(proj))
    assert ok is False and why.startswith("stale_db")


def test_db_not_usable_when_source_mismatch(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    db = _write_db(tmp_path / "db", created="2099-01-01T00:00:00Z", source=str(tmp_path / "other"))
    ok, why = ad.CodeQLAdapter._db_is_usable(str(db), str(proj))
    assert ok is False and "source_root_mismatch" in why


def test_db_not_usable_when_not_finalized(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    db = _write_db(tmp_path / "db", finalized=False, created="2099-01-01T00:00:00Z", source=str(proj))
    ok, why = ad.CodeQLAdapter._db_is_usable(str(db), str(proj))
    assert ok is False and why == "db_not_finalized"


def test_db_not_usable_when_missing(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    ok, why = ad.CodeQLAdapter._db_is_usable(str(tmp_path / "nope"), str(proj))
    assert ok is False and why == "db_not_exists"


def test_pick_db_target_avoids_stale_dir(tmp_path):
    """base 库过期时不删不覆盖，改建到 .fresh-<ts> 兄弟目录。"""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "A.java").write_text("class A{}", encoding="utf-8")
    base = _write_db(tmp_path / ".codeql-db", created="2020-01-01T00:00:00Z", source=str(proj))
    target, reused, why = ad.CodeQLAdapter._pick_db_target(str(base), str(proj))
    assert reused is False
    assert ".codeql-db.fresh-" in target
    assert "stale_db" in why


# ── 强制重新编译（2026-11-01，本轮增量编译让 CodeQL 抓到 0 个 javac）──

def test_touch_sources_bumps_java_mtime(tmp_path):
    """touch 必须把 .java/.kt 的 mtime 抬到现在，否则 Maven 判「无需编译」。"""
    import os as _os
    import time as _time

    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    f = proj / "src" / "A.java"
    f.write_text("class A{}", encoding="utf-8")
    old = _time.time() - 86400
    _os.utime(f, (old, old))

    n = ad.CodeQLAdapter._touch_sources(str(proj))

    assert n == 1
    assert _os.path.getmtime(f) > old + 3600


def test_touch_sources_skips_build_dirs(tmp_path):
    """target/build 里的文件不能碰：靶场可能正跑在 target 下，且它们不是源码。"""
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "target").mkdir()
    (proj / "src" / "A.java").write_text("class A{}", encoding="utf-8")
    (proj / "target" / "Gen.java").write_text("class Gen{}", encoding="utf-8")

    assert ad.CodeQLAdapter._touch_sources(str(proj)) == 1


def test_touch_sources_ignores_non_source(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pom.xml").write_text("<project/>", encoding="utf-8")
    (proj / "readme.md").write_text("x", encoding="utf-8")
    assert ad.CodeQLAdapter._touch_sources(str(proj)) == 0


def test_mvn_shim_skips_source_mutating_plugins():
    """shim 必须带 -Dspotless.apply.skip 等开关。

    两条理由都是实测出来的：
    ① `spotless:apply` 会把格式化**写回被扫项目的 src/**（扫描器不该改证据）；
    ② 它需要 git 元数据，解压出来的项目没有 .git ⇒ BUILD FAILURE ⇒ 整个建库失败
       （本轮/584：OWASP 因此连续两轮 A1 降级成 heuristic）。
    """
    from pathlib import Path

    shim_dir = Path(ad.__file__).resolve().parent.parent.parent / "tools" / "mvn_shim"
    sh = (shim_dir / "mvn").read_text(encoding="utf-8", errors="replace")
    cmd = (shim_dir / "mvn.cmd").read_text(encoding="utf-8", errors="replace")
    for flag in ("-Dspotless.apply.skip=true", "-Dspotless.check.skip=true"):
        assert flag in sh, f"sh 版 shim 缺 {flag}"
        assert flag in cmd, f"cmd 版 shim 缺 {flag}"


# ── 强制重新编译（2026-11-01，本轮增量编译让 CodeQL 抓到 0 个 javac）──

def test_touch_sources_bumps_java_mtime(tmp_path):
    """touch 必须把 .java/.kt 的 mtime 抬到现在，否则 Maven 判「无需编译」。"""
    import os as _os
    import time as _time

    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    f = proj / "src" / "A.java"
    f.write_text("class A{}", encoding="utf-8")
    old = _time.time() - 86400
    _os.utime(f, (old, old))

    n = ad.CodeQLAdapter._touch_sources(str(proj))

    assert n == 1
    assert _os.path.getmtime(f) > old + 3600


def test_touch_sources_skips_build_dirs(tmp_path):
    """target/build 里的文件不能碰：靶场可能正跑在 target 下，且它们不是源码。"""
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "target").mkdir()
    (proj / "src" / "A.java").write_text("class A{}", encoding="utf-8")
    (proj / "target" / "Gen.java").write_text("class Gen{}", encoding="utf-8")

    assert ad.CodeQLAdapter._touch_sources(str(proj)) == 1


def test_touch_sources_ignores_non_source(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pom.xml").write_text("<project/>", encoding="utf-8")
    (proj / "readme.md").write_text("x", encoding="utf-8")
    assert ad.CodeQLAdapter._touch_sources(str(proj)) == 0


def test_mvn_shim_skips_source_mutating_plugins():
    """shim 必须带 -Dspotless.apply.skip 等开关。

    两条理由都是实测出来的：
    ① `spotless:apply` 会把格式化**写回被扫项目的 src/**（扫描器不该改证据）；
    ② 它需要 git 元数据，解压出来的项目没有 .git ⇒ BUILD FAILURE ⇒ 整个建库失败
       （本轮/584：OWASP 因此连续两轮 A1 降级成 heuristic）。
    """
    from pathlib import Path

    shim_dir = Path(ad.__file__).resolve().parent.parent.parent / "tools" / "mvn_shim"
    sh = (shim_dir / "mvn").read_text(encoding="utf-8", errors="replace")
    cmd = (shim_dir / "mvn.cmd").read_text(encoding="utf-8", errors="replace")
    for flag in ("-Dspotless.apply.skip=true", "-Dspotless.check.skip=true"):
        assert flag in sh, f"sh 版 shim 缺 {flag}"
        assert flag in cmd, f"cmd 版 shim 缺 {flag}"
