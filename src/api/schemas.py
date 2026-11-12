from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class WorkspaceCreate(BaseModel):
    name: str
    target_path: str
    description: str = ""
    settings: Dict[str, Any] = Field(default_factory=dict)


class WorkspaceUpdate(BaseModel):
    name: Optional[str] = None
    target_path: Optional[str] = None
    description: Optional[str] = None
    slug: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)


class WorkspaceResponse(BaseModel):
    id: int
    name: str
    target_path: str
    description: str
    settings: Dict[str, Any]
    slug: str = ""
    archived: bool = False
    created_at: str
    updated_at: str


class ScanTaskCreate(BaseModel):
    workspace_id: int
    name: str
    enable_a1: bool = True
    enable_a2: bool = True
    enable_verification: bool = True
    output_format: str = "both"
    approval_mode: str = "off"
    tool_allowlist: list[str] = Field(default_factory=list)
    enable_sca: bool = True
    enable_ai_review: bool = True
    enable_idor: bool = False
    idor_app_id: str = ""
    enable_entry_discovery: bool = True
    scan_mode: str = "filter_first"
    model_profile: str = "default"
    prompt_version: str = "terminal-first-v1"
    # auto = 跑所有可用扫描器（osv-scanner/trivy/grype）并做跨工具交叉验证；
    # 单工具时 cross_validated 恒 False，交叉验证形同虚设。
    sca_tool: str = "auto"
    sca_severity_threshold: str = "LOW"
    sca_ignore_unfixed: bool = False
    # 作用域是「提交单个扫描任务时覆盖全局默认」，因为平台是多任务并发的，
    # 改全局配置会影响同时在跑的其它任务。留空 = 完全用服务端 config.yaml 的默认值。
    # 允许键见 src/cli/benchmark_cli.py::_apply_llm_overrides（未知键忽略并记日志）。
    llm_overrides: Dict[str, Any] = Field(default_factory=dict)
    # 必须在此显式声明：BaseModel 会把未声明的入参键静默丢弃（extra=ignore），
    # 结果就是 options.shard_file 恒空、扫描退化为全量，且**没有任何报错**。
    shard_file: str = ""
    # 未声明的键会在 model_dump 时被静默丢弃 —— REST 提交的 run_env 因此全部丢失
    # 后果是 D1 请求 dump
    # 不落盘、ysoserial / Shiro key 等按次能力开关整轮失效，而 628 走本地直提通道
    # 直接写库所以带着五项 run_env。同一个坑此前已在 shard_file 上踩过一次。
    run_env: Dict[str, Any] = Field(default_factory=dict)


class ScanTaskResponse(BaseModel):
    id: int
    workspace_id: int
    name: str
    status: str
    phase: str
    output_dir: str
    options: Dict[str, Any]
    summary: Dict[str, Any]
    error_message: str
    created_at: str
    started_at: str
    finished_at: str


class TaskEventResponse(BaseModel):
    id: int
    task_id: int
    event_type: str
    payload: Dict[str, Any]
    created_at: str


class FindingResponse(BaseModel):
    id: int
    task_id: int
    workspace_id: int
    finding_type: str
    severity: str
    file_path: str
    line: int
    title: str
    raw: Dict[str, Any]
    created_at: str
    # SCA 行可据此展示组件与编号（finding_type 仅留族名 "sca"）。非 SCA 行恒为空串。
    sca_component: str = ""
    sca_advisory_id: str = ""


class ReportResponse(BaseModel):
    id: int
    task_id: int
    workspace_id: int
    report_type: str
    file_path: str
    generated_at: str


class ReportContentResponse(BaseModel):
    id: int
    task_id: int
    workspace_id: int
    report_type: str
    file_path: str
    content: str
    content_type: str
    exists: bool


class SystemStatusResponse(BaseModel):
    status: str
    db_path: str
    active_tasks: int
    workspace_count: int


class HitlSettingsResponse(BaseModel):
    task_id: int
    approval_mode: str
    tool_allowlist: list[str] = Field(default_factory=list)
    pending_actions: list[dict[str, Any]] = Field(default_factory=list)


class HitlSettingsUpdate(BaseModel):
    approval_mode: Optional[str] = None
    tool_allowlist: Optional[list[str]] = None


class HitlPendingActionResponse(BaseModel):
    id: str
    task_id: int
    tool_id: str
    risk_level: str = ""
    reason: str = ""
    stage: str = ""
    status: str = "pending"
    created_at: str = ""
    resolved_at: str = ""
    proposed_action: Dict[str, Any] = Field(default_factory=dict)


class HitlActionResolveResponse(BaseModel):
    action: HitlPendingActionResponse
    settings: HitlSettingsResponse


class HitlAuditEntryResponse(BaseModel):
    id: int
    task_id: int
    action: str
    category: str = ""
    reason: str = ""
    route: str = ""
    method: str = ""
    tool_id: str = ""
    approval_mode: str = ""
    stage: str = ""
    detail: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = ""


class HitlBatchResolveItem(BaseModel):
    action_id: str
    decision: str


class HitlBatchResolveRequest(BaseModel):
    items: list[HitlBatchResolveItem]


class HitlBatchResolveResponse(BaseModel):
    resolved: list[HitlPendingActionResponse] = Field(default_factory=list)
    failed: list[Dict[str, Any]] = Field(default_factory=list)
    settings: HitlSettingsResponse


class HitlSuspendResponse(BaseModel):
    task_id: int
    status: str


class ToolSpecResponse(BaseModel):
    id: str
    name: str
    category: str
    risk_level: str
    language_scope: list[str] = Field(default_factory=list)
    vuln_families: list[str] = Field(default_factory=list)
    execution_modes: list[str] = Field(default_factory=list)
    requires_runtime: bool = False
    description: str = ""


class FixSuggestionResponse(BaseModel):
    summary: str
    patch_strategy: str
    validation_steps: list[str] = Field(default_factory=list)
    risk_notes: str = ""
    created_at: str = ""


class PatchDraftResponse(BaseModel):
    diff: str
    applies_cleanly: bool = False
    verified: bool = False
    reason: str = ""
    created_at: str = ""


class HumanDecisionRequest(BaseModel):
    decision: str
    reason_type: str = ""
    reason_detail: str = ""
    reviewer: str = "local"


class FixFeedbackRequest(BaseModel):
    adopted: bool = False
    misleading: bool = False
    led_to_retest_pass: Optional[bool] = None
    suggestion_id: str = ""
    comment: str = ""
    created_by: str = "local"


class RetestRequest(BaseModel):
    workspace_id: int
    strategy: str = "manual"
    result: str = ""
    app_id: str = ""
    base_ref: str = ""
    patch_ref: str = ""
    repo_path: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    created_by: str = "local"


class StatusUpdateRequest(BaseModel):
    workspace_id: int
    target_status: str
    created_by: str = "local"


class IdorAppRequest(BaseModel):
    app_id: Optional[str] = None
    app_name: str
    base_url: str = ""
    service_name: str = ""
    auth_type: str = "cookie"
    role_boundaries: list[dict[str, Any]] = Field(default_factory=list)
    accounts: list[dict[str, Any]] = Field(default_factory=list)


class IdorApiImportRequest(BaseModel):
    apis: list[dict[str, Any]] = Field(default_factory=list)


class IdorTrafficImportRequest(BaseModel):
    samples: list[dict[str, Any]] = Field(default_factory=list)


class EntryDiscoveryRequest(BaseModel):
    project_path: str
    workspace_id: Optional[int] = None
    task_id: Optional[int] = None
    persist: bool = False


class RuleCandidateDecisionRequest(BaseModel):
    status: str = "confirmed"
    confirmed_by: str = "local"


class TaintRuleCandidateRequest(BaseModel):
    kind: str
    pattern: str
    language: str = ""
    family: str = ""
    confidence: str = "medium"
    workspace_id: Optional[int] = None


class TaintRuleConfirmRequest(BaseModel):
    confirmed_by: str = "local"


class AutonomyPolicyRequest(BaseModel):
    name: str
    action: str = "auto_close"
    min_confidence: str = "high"
    verdict: str = "false_positive"
    max_impact: str = "medium"
    gray_percent: int = 0
    require_ai_agree: bool = True
    enabled: bool = True
    description: str = ""


class AutonomyEvaluateRequest(BaseModel):
    finding_id: int
    created_by: str = "system"


class EvaluationRunRequest(BaseModel):
    name: str = "adhoc"
    dataset_path: str = ""
    model: str = "local-heuristic-review"
    prompt_version: str = "terminal-first-v1"
    repeat: int = 1
    seed_jitter: bool = False
    scan_mode: str = ""
    agent_impl: str = ""


class EvaluationMatrixRequest(BaseModel):
    name: str = "matrix"
    dataset_path: str = ""
    repeat: int = 1
    seed_jitter: bool = False
    models: list[str] = Field(default_factory=list)
    prompt_versions: list[str] = Field(default_factory=list)
    scan_modes: list[str] = Field(default_factory=list)
    agent_impls: list[str] = Field(default_factory=list)



class SCAScanRequest(BaseModel):
    project_path: str
    workspace_id: Optional[int] = None
    task_id: Optional[int] = None
    output_dir: str = ""
    tool: str = "osv-scanner"
    severity_threshold: str = "LOW"
    ignore_unfixed: bool = False
    run_tool: bool = True
    persist: bool = True


class SCAImpactQueryRequest(BaseModel):
    advisory_id: str = ""
    cve: str = ""
    ghsa: str = ""
    component_name: str = ""
    package: str = ""
    ecosystem: str = ""
    workspace_id: Optional[int] = None


class AdvisoryIngestRequest(BaseModel):
    source: str = "osv"
    entries: list[dict[str, Any]] = Field(default_factory=list)


class AdvisoryMatchRequest(BaseModel):
    ecosystem: str = ""
    name: str
    version: str = ""


class ChatOpsQueryRequest(BaseModel):
    text: str
    workspace_id: Optional[int] = None
    platform: str = ""


class ScanCostRecordRequest(BaseModel):
    workspace_id: Optional[int] = None
    project: str = ""
    branch: str = ""
    commit_sha: str = ""
    scan_mode: str = ""
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: Optional[float] = None
    latency_ms: int = 0


class ScanTriggerPolicyRequest(BaseModel):
    workspace_id: Optional[int] = None
    name: str
    trigger: str = ""
    scan_mode: str = "filter_first"
    model: str = ""
    monthly_frequency: float = 0.0
    enabled: bool = True


class TicketExportRequest(BaseModel):
    finding_id: int
    platform: str = "offline"
    project: str = ""
    webhook_url: str = ""



class IdorAccountImportRequest(BaseModel):
    accounts: list[dict[str, Any]] = Field(default_factory=list)


class IdorScanRequest(BaseModel):
    mode: str = "imported_traffic"
    execute_http: bool = False
    allow_mutating: bool = False
