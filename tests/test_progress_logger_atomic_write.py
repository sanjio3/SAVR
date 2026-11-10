# -*- coding: utf-8 -*-
"""进度文件原子写的 Windows 文件锁回归锁。

2026-11-07：L3 run1 的 A1~reporting 全部 completed、报告与 DB 数据齐全，
却在最后一步 ``os.replace(scan_progress.md.tmp, scan_progress.md)`` 撞上
WinError 5 被判 failed。进度文件是可再生展示物，不该决定一轮扫描的成败。
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.core import progress_logger as pl  # noqa: E402


def test_replace_retries_then_succeeds(tmp_path, monkeypatch):
    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        if calls["n"] < 4:
            raise PermissionError(5, "拒绝访问")
        return real_replace(src, dst)

    monkeypatch.setattr(pl.os, "replace", flaky)
    monkeypatch.setattr(pl.time, "sleep", lambda *_: None)
    tmp, dst = tmp_path / "a.tmp", tmp_path / "a.md"
    tmp.write_text("x", encoding="utf-8")
    pl.ScanProgressLogger._replace_with_retry(str(tmp), str(dst))
    assert calls["n"] == 4
    assert dst.read_text(encoding="utf-8") == "x"
    assert not tmp.exists()


def test_replace_gives_up_after_six_attempts(tmp_path, monkeypatch):
    def always_fail(src, dst):
        raise PermissionError(5, "拒绝访问")

    monkeypatch.setattr(pl.os, "replace", always_fail)
    monkeypatch.setattr(pl.time, "sleep", lambda *_: None)
    tmp, dst = tmp_path / "a.tmp", tmp_path / "a.md"
    tmp.write_text("x", encoding="utf-8")
    with pytest.raises(PermissionError):
        pl.ScanProgressLogger._replace_with_retry(str(tmp), str(dst))


def test_md_write_falls_back_instead_of_failing_the_task(tmp_path, monkeypatch):
    def always_fail(src, dst):
        raise PermissionError(5, "拒绝访问")

    monkeypatch.setattr(pl.os, "replace", always_fail)
    monkeypatch.setattr(pl.time, "sleep", lambda *_: None)
    dst = tmp_path / "scan_progress.md"
    pl.ScanProgressLogger._atomic_write_text(str(dst), "pipeline done")
    assert dst.read_text(encoding="utf-8") == "pipeline done"
    assert not (tmp_path / "scan_progress.md.tmp").exists()


def test_md_normal_path_is_single_atomic_replace(tmp_path, monkeypatch):
    calls = {"n": 0}
    real_replace = os.replace

    def counted(src, dst):
        calls["n"] += 1
        return real_replace(src, dst)

    monkeypatch.setattr(pl.os, "replace", counted)
    dst = tmp_path / "scan_progress.md"
    pl.ScanProgressLogger._atomic_write_text(str(dst), "ok")
    assert calls["n"] == 1
    assert dst.read_text(encoding="utf-8") == "ok"


def test_json_keeps_fail_closed_semantics(tmp_path, monkeypatch):
    """进度 json 是权威中间产物，重试耗尽仍必须抛，不能静默降级。"""
    def always_fail(src, dst):
        raise PermissionError(5, "拒绝访问")

    monkeypatch.setattr(pl.os, "replace", always_fail)
    monkeypatch.setattr(pl.time, "sleep", lambda *_: None)
    obj = object.__new__(pl.ScanProgressLogger)
    obj.json_path = str(tmp_path / "scan_progress.json")
    with pytest.raises(PermissionError):
        obj._save_json({"phase": "d2"})
