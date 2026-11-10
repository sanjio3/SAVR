import logging
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.dependencies import container
from src.api.security import AuditMiddleware
from src.api.routers.reports import router as reports_router
from src.api.routers.results import router as results_router
from src.api.routers.system import router as system_router
from src.api.routers.tasks import router as tasks_router
from src.api.routers.workspaces import router as workspaces_router
from src.api.routers.finding_workflow import router as finding_workflow_router
from src.api.routers.idor import router as idor_router
from src.api.routers.entry_discovery import router as entry_discovery_router
from src.api.routers.a0 import router as a0_router
from src.api.routers.sca import router as sca_router
from src.api.routers.dast import router as dast_router
from src.api.routers.lifecycle import router as lifecycle_router
from src.api.routers.autonomy import router as autonomy_router
from src.api.routers.evaluation import router as evaluation_router
from src.api.routers.audit import router as audit_router
from src.api.routers.rule_feedback import router as rule_feedback_router
from src.api.routers.metrics import router as metrics_router
from src.api.routers.quota import router as quota_router
from src.api.routers.iast import router as iast_router
from src.api.routers.agent_bridge import router as agent_bridge_router
from src.api.routers.bola_race import router as bola_race_router
from src.api.routers.business_logic import router as business_logic_router
from src.api.routers.round_report import router as round_report_router
from src.api.routers.oob import router as oob_router


logger = logging.getLogger(__name__)


def configure_file_logging() -> None:
    """应用日志落盘（2026-10-19，Phase 4.1 前置）。

    背景：此前项目**没有任何 logging 配置**，`[D2]` / `[value-gate]` / `[retryable]` 这些
    关键判定日志全部只到 stdout，进程一重启就没了。直接后果：r111 的 hash 任务产物齐全
    却卡在 status=running，无法归因（finalize 明明有回读+重试，说明根本没走到）。
    没有落盘日志，所有性能/收尾问题的诊断都是盲的。

    实现约束：
      - 幂等：uvicorn reload / 重复 import 不重复挂 handler（按绝对路径判重）；
      - 失败不影响服务：目录不可写只告警，不抛异常；
      - 可配置：`SAST_AI_LOG_FILE`（默认 logs/app.log）、`SAST_AI_LOG_LEVEL`（默认 INFO）。
    """
    from logging.handlers import RotatingFileHandler

    path = os.path.abspath(os.environ.get("SAST_AI_LOG_FILE", os.path.join("logs", "app.log")))
    root = logging.getLogger()
    try:
        if any(isinstance(h, RotatingFileHandler) and os.path.abspath(getattr(h, "baseFilename", "")) == path
               for h in root.handlers):
            return
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fh = RotatingFileHandler(path, maxBytes=50 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        fh.setLevel(getattr(logging, str(os.environ.get("SAST_AI_LOG_LEVEL", "INFO")).upper(), logging.INFO))
        root.addHandler(fh)
        if root.level == logging.NOTSET or root.level > logging.INFO:
            root.setLevel(logging.INFO)
        logger.info("[logging] 应用日志落盘：%s", path)
    except Exception as exc:  # 日志不可用绝不能阻断服务启动
        logger.warning("[logging] 文件日志初始化失败（不影响扫描）：%s", exc)


def _cors_origins() -> list[str]:
    raw = os.environ.get("SAST_AI_CORS_ORIGINS", "").strip()
    if not raw:
        return ["*"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def create_app() -> FastAPI:
    configure_file_logging()
    app = FastAPI(title="SAST AI Service", version="2.1.0")
    origins = _cors_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=origins != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(AuditMiddleware, audit_repository_provider=lambda: container.audit_log_repository)
    app.include_router(workspaces_router)
    app.include_router(tasks_router)
    app.include_router(results_router)
    app.include_router(reports_router)
    app.include_router(system_router)
    app.include_router(finding_workflow_router)
    app.include_router(idor_router)
    app.include_router(entry_discovery_router)
    app.include_router(a0_router)
    app.include_router(sca_router)
    app.include_router(dast_router)
    app.include_router(lifecycle_router)
    app.include_router(autonomy_router)
    app.include_router(evaluation_router)
    app.include_router(audit_router)
    app.include_router(rule_feedback_router)
    app.include_router(metrics_router)
    app.include_router(quota_router)
    app.include_router(iast_router)
    app.include_router(agent_bridge_router)
    app.include_router(bola_race_router)
    app.include_router(business_logic_router)
    app.include_router(round_report_router)
    app.include_router(oob_router)

    @app.on_event("startup")
    def _startup_reconcile_orphans() -> None:
        # P0-1：后端启动即自检——回收「status 非终态但 task_result.json 已落盘」的孤儿扫描任务
        # （后端重启导致 watcher 线程丢失时产生）。失败不影响启动，仅告警。
        try:
            from src.infrastructure.orphan_recovery import reconcile_orphaned_tasks
            recovered = reconcile_orphaned_tasks(container.task_service, container.task_repository, dry_run=False)
            if recovered:
                logger.warning("[startup] 回收孤儿扫描任务 %d 个: %s", len(recovered), recovered)
        except Exception as exc:  # 启动自检绝不阻断服务拉起
            logger.warning("[startup] 孤儿任务回收异常（不影响启动）：%s", exc)

        # 半截状态根治（run 24 事故）：启动自检只在重启时跑一次，而 watcher 线程可能在后端
        # 活着的时候死掉（future 异常被线程池静默吞），此后没有任何机制再收口。这里补一个
        # 常驻的低频 reconcile 守护线程：运行期反复扫「非终态且本进程无 watcher」的任务。
        try:
            from src.infrastructure.orphan_recovery import start_periodic_reconciler
            start_periodic_reconciler(container.task_service, container.task_repository)
        except Exception as exc:
            logger.warning("[startup] 周期性 reconcile 启动失败（不影响服务）：%s", exc)

    return app


app = create_app()
