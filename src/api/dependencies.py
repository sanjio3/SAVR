import os
from pathlib import Path

from src.application.task_service import TaskService
from src.application.workspace_service import WorkspaceService
from src.application.a0_service import A0Service
from src.application.autonomy_service import AutonomyService
from src.application.advisory_service import AdvisoryService
from src.application.entry_discovery_service import EntryDiscoveryService
from src.application.evaluation_service import EvaluationService
from src.application.finding_workflow_service import FindingWorkflowService
from src.application.hash_migration_service import HashMigrationService
from src.application.d1_service import D1Service
from src.application.metrics_service import MetricsService
from src.application.retest_service import RetestService
from src.application.rule_feedback_service import RuleFeedbackService
from src.application.sca_asset_service import SCAAssetService
from src.iast.service import IastService
from src.iast.correlation import IastCorrelationService
from src.iast.adjudicator import I2Adjudicator
from src.chatops.skill import ScaChatOpsSkill
from src.infrastructure.db import Database
from src.infrastructure.event_bus import TaskEventBus
from src.infrastructure.repositories import (
    AuditLogRepository,
    EntryAssetRepository,
    FindingRepository,
    ModelRunRepository,
    ReportRepository,
    TaskEventRepository,
    TaskRepository,
    WorkspaceRepository,
)
from src.pipeline.a0.service import A0PreprocessService


class AppContainer:
    def __init__(self):
        self.data_dir = Path("data")
        db_path = os.environ.get("SAST_AI_DB_PATH", str(self.data_dir / "app.db"))
        self.db = Database(db_path)
        self.event_bus = TaskEventBus()
        self.preprocess = A0PreprocessService()
        self.workspace_repository = WorkspaceRepository(self.db)
        self.task_repository = TaskRepository(self.db)
        self.event_repository = TaskEventRepository(self.db)
        self.finding_repository = FindingRepository(self.db)
        self.report_repository = ReportRepository(self.db)
        self.model_run_repository = ModelRunRepository(self.db)
        self.entry_asset_repository = EntryAssetRepository(self.db)
        self.audit_log_repository = AuditLogRepository(self.db)
        self.finding_workflow_service = FindingWorkflowService(self.finding_repository)
        # 2026-09-19：按 agents.d1.enable_llm_overlay（默认关）注入 D1 的 LLM 网关。
        # 关时传 None，与接入前一致（D1 的 AI 复核与 LLM 造弹都不走）。
        self.d1_service = D1Service(self.db, gateway=D1Service.build_gateway_from_config(None))
        self.retest_service = RetestService(self.db, d1_service=self.d1_service)
        self.sca_asset_service = SCAAssetService(self.db)
        self.advisory_service = AdvisoryService(self.db)
        self.chatops_skill = ScaChatOpsSkill(self.db, advisory_service=self.advisory_service)
        self.entry_discovery_service = EntryDiscoveryService(self.entry_asset_repository)
        self.autonomy_service = AutonomyService(self.db)
        self.evaluation_service = EvaluationService(self.db)
        self.rule_feedback_service = RuleFeedbackService(self.db, evaluation_service=self.evaluation_service)
        self.hash_migration_service = HashMigrationService(self.db)
        self.metrics_service = MetricsService(self.db)
        self.iast_service = IastService(self.db)
        self.iast_correlation_service = IastCorrelationService(self.db)
        self.i2_adjudicator = I2Adjudicator(self.db, rule_feedback=self.rule_feedback_service)
        # §8.1 A0 编排：整合 Preprocess + R0 + EntryDiscovery + P0（依赖 iast_service，须在其后）
        self.a0_service = A0Service(
            preprocess=self.preprocess,
            entry_discovery=self.entry_discovery_service,
            iast_service=self.iast_service,
        )
        self.workspace_service = WorkspaceService(self.workspace_repository, self.preprocess)
        self.task_service = TaskService(
            self.task_repository,
            self.workspace_repository,
            self.event_repository,
            self.finding_repository,
            self.report_repository,
            self.event_bus,
            self.preprocess,
            db=self.db,
            d1_service=self.d1_service,
        )


container = AppContainer()
