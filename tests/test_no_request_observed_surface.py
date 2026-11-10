"""§8.4 第4点「运行时观测请求面」全链路移除的守卫测试（2026-09-01）。

背景：探针（sec-probe.jar）从不发送 eventType=request_observed —— 四个 jar 二进制里搜不到
该字符串，源码亦无发送方。故 iast_request_params 表恒无新增，1410 行存量全是扫描器字典盲打
噪声（/wp-admin/admin-ajax.php、XDEBUG_SESSION_START 等），且 param_resolver 早已把观测面
降权为 Tier0 未命中时的回退（恒不命中）。整条链路零产出，故全链路移除。

本测试锁死移除结果，防止将来有人"顺手加回"一个恒为空的观测面档：
1. IastService 不再具备 request_observed 落库 / 观测参数反查方法。
2. resolve_trigger_endpoint 不再接受 observed_params 入参。
3. A0Service 不再具备 merge_runtime_params，run 也不再接受 iast_observed_params。
4. 事件模型不再声明 route/method/params 三个 request_observed 专用字段。
5. 新建库不再创建 iast_request_params 表。

注意：本测试是"移除"的守护，不是"功能"的守护。若将来要让探针真正上报运行时请求面，
应先删掉本文件，并同步实现探针侧发送方（否则又是零产出死链路）。
"""
import inspect
import sqlite3
import tempfile
from pathlib import Path

from src.iast.schemas import IastEventItem
from src.iast.service import IastService
from src.application.a0_service import A0Service
from src.core.param_resolver import resolve_trigger_endpoint


def test_iast_service_has_no_request_observed_api():
    for name in (
        "_store_request_observed",
        "get_observed_request_params",
        "collect_observed_request_params_for_a0",
    ):
        assert not hasattr(IastService, name), f"IastService.{name} 应已随观测请求面一并移除"


def test_event_model_has_no_request_observed_fields():
    fields = IastEventItem.model_fields
    for name in ("route", "method", "params"):
        assert name not in fields, f"IastEventItem.{name} 应已随 request_observed 一并移除"


def test_resolver_has_no_observed_params_argument():
    params = inspect.signature(resolve_trigger_endpoint).parameters
    assert "observed_params" not in params, "解析器不应再接受观测面入参（该档恒为空）"


def test_a0_service_has_no_runtime_params_merge():
    assert not hasattr(A0Service, "merge_runtime_params"), "merge_runtime_params 应已移除"
    run_params = inspect.signature(A0Service.run).parameters
    assert "iast_observed_params" not in run_params, "A0Service.run 不应再接受 iast_observed_params"


def test_fresh_db_has_no_iast_request_params_table():
    from src.infrastructure.db import Database

    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "fresh.db")
        Database(db_path)  # 触发建表 + 迁移
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='iast_request_params'"
            ).fetchone()
        finally:
            conn.close()
        assert row is None, "新建库不应再创建 iast_request_params 表"
