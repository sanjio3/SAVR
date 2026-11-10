"""Phase 4.1 前置：应用日志落盘的回归锁。

背景：项目此前没有任何 logging 配置，`[D2]`/`[value-gate]` 日志只在 stdout，
进程重启即丢 —— r111 hash 任务「产物齐全却卡 running」因此无法归因。
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

import pytest


@pytest.fixture()
def clean_root():
    root = logging.getLogger()
    before = list(root.handlers)
    yield root
    for h in list(root.handlers):
        if h not in before:
            root.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass


def test_configure_file_logging_writes_and_is_idempotent(tmp_path, monkeypatch, clean_root):
    import os

    from src.api.app import configure_file_logging

    log_path = tmp_path / "app.log"
    monkeypatch.setenv("SAST_AI_LOG_FILE", str(log_path))
    configure_file_logging()
    configure_file_logging()  # 重复调用不得重复挂 handler

    # 注意：import src.api.app 会先按默认路径（logs/app.log）挂一个 handler，
    # 故只断言「本测试路径」的 handler 恰好一个。
    handlers = [h for h in clean_root.handlers
                if isinstance(h, RotatingFileHandler)
                and os.path.abspath(getattr(h, "baseFilename", "")) == os.path.abspath(str(log_path))]
    assert len(handlers) == 1, "重复调用应幂等（按绝对路径判重）"

    logging.getLogger("test.logging").info("hello-logging-落盘")
    for h in handlers:
        h.flush()
    assert "hello-logging-落盘" in log_path.read_text(encoding="utf-8")


def test_configure_file_logging_failure_is_non_fatal(tmp_path, monkeypatch, clean_root):
    """目录不可写时只告警，不抛异常（日志不可用不能阻断服务启动）。"""
    from src.api.app import configure_file_logging

    bad = tmp_path / "afile"
    bad.write_text("x", encoding="utf-8")
    monkeypatch.setenv("SAST_AI_LOG_FILE", str(bad / "sub" / "app.log"))  # 父路径是文件 ⇒ 必失败
    configure_file_logging()  # 不抛异常即通过
