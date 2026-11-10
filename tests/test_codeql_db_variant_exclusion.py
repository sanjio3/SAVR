"""源码遍历必须排除所有 `.codeql-db*` 变体（2026-11-04，jsc 619 实测回归锁）。

根因：jsc 源码根下残留 5 个半成品库（`.codeql-db.partial2..5`，4.3 万文件 / 420MB），
CodeQL 建库时把它们**当源码复制**进库目录，路径变成
`.codeql-db.fresh-X/src/D_/.../java-sec-code/.codeql-db.partial3/src/D_/...`
⇒ 超过 Windows MAX_PATH(260) ⇒ AccessDeniedException ⇒
   ① 源文件复制失败；② finalize 清理 cache 时无限重试（死循环）；
   ③ 库不完整（finalised=false）⇒ analyze 得到 `java: empty`
   ⇒ 上层笼统记成 `build_failed_or_empty` ⇒ **静态侧整轮降级启发式**。

本文件锁住三条不变量：
  A. CodeQL 源码遍历跳过所有 `.codeql-db*` 前缀目录；
  B. entry discovery 跳过所有 `.codeql-db*` 前缀目录（否则同份源码登记 N 遍）；
  C. runtime_facts 跳过所有 `.codeql-db*` 前缀目录。
"""
from __future__ import annotations


def test_codeql_adapter_skips_all_codeql_db_variants():
    from src.agents.a1_codeql_adapter import CodeQLAdapter as A
    dirs = ["src", "main", "target", "build", "node_modules", ".git",
            ".codeql-db", ".codeql-db.partial3-123", ".codeql-db.fresh-99",
            ".codeql-db.broken-1", ".codeql-db.extra.sarif"]
    kept = A._filter_source_dirs(dirs)
    assert not any(d.startswith(".codeql-db") for d in kept), kept
    # 正常源码目录必须保留
    assert "src" in kept and "main" in kept
    # 构建产物仍然排除
    assert "target" not in kept and "node_modules" not in kept


def test_codeql_adapter_skip_dirs_keeps_codeql_prefix():
    """`.codeql` 开头的其它目录也应排除（与 file_inventory 的前缀口径一致）。"""
    from src.agents.a1_codeql_adapter import CodeQLAdapter as A
    kept = A._filter_source_dirs([".codeql-db", "codeql", "src"])
    assert "src" in kept
    assert ".codeql-db" not in kept


def test_entry_discovery_skips_codeql_db_variants():
    """entry discovery 也要跳过变体，否则同份源码被登记 N 遍。"""
    import inspect
    from src.application import entry_discovery_service as E
    src = inspect.getsource(E)
    assert ".codeql-db" in src
    # 必须是前缀匹配，而不是集合里的精确成员
    assert 'startswith(".codeql-db")' in src


def test_runtime_facts_skips_codeql_db_variants():
    import inspect
    from src.core import runtime_facts as R
    src = inspect.getsource(R)
    assert 'startswith(".codeql-db")' in src


def test_quarantine_moves_stale_db_dirs_out_of_source_root():
    """残留库必须被**移出**源码根，而不是在根内改名。

    根内改名无效：目录里的 .java/.properties 仍会被 --source-root 复制进去，
    路径照样爆 MAX_PATH(260)（jsc 619 实测）。
    """
    import os
    import shutil
    import tempfile

    from src.agents.a1_codeql_adapter import CodeQLAdapter as A
    tmp = tempfile.mkdtemp(prefix="_cq_quarantine_")
    try:
        for n in (".codeql-db", ".codeql-db.partial3-1", ".codeql-db.fresh-99",
                  ".codeql-db.broken-2", "src"):
            os.makedirs(os.path.join(tmp, n), exist_ok=True)
        with open(os.path.join(tmp, "A.java"), "w", encoding="utf-8") as fh:
            fh.write("class A{}")
        moved = A._quarantine_stale_db_dirs(tmp)
        assert len(moved) == 4, moved
        left = os.listdir(tmp)
        # 源码根里不该再有任何 .codeql-db* 目录
        assert not any(x.startswith(".codeql-db") for x in left), left
        # 真正的源码必须保留
        assert "src" in left and "A.java" in left
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_quarantine_keeps_named_target():
    """显式 keep 的目标库（如即将建库的目录）不该被移走。"""
    import os
    import shutil
    import tempfile

    from src.agents.a1_codeql_adapter import CodeQLAdapter as A
    tmp = tempfile.mkdtemp(prefix="_cq_keep_")
    try:
        keep = os.path.join(tmp, ".codeql-db.fresh-keep")
        os.makedirs(keep, exist_ok=True)
        moved = A._quarantine_stale_db_dirs(tmp, keep=keep)
        assert ".codeql-db.fresh-keep" not in moved, moved
        assert os.path.isdir(keep)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
