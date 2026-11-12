export interface Workspace {
  id: number;
  name: string;
  target_path: string;
  description: string;
  settings: Record<string, unknown>;
  slug?: string;
  archived?: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScanTask {
  id: number;
  workspace_id: number;
  name: string;
  status: string;
  phase: string;
  output_dir: string;
  options: Record<string, unknown>;
  summary: TaskSummary;
  error_message: string;
  created_at: string;
  started_at: string;
  finished_at: string;
}

export interface HitlSettings {
  task_id: number;
  approval_mode: string;
  tool_allowlist: string[];
  pending_actions: Record<string, unknown>[];
}

export interface HitlAuditEntry {
  id: number;
  task_id: number;
  action: string;
  category: string;
  reason: string;
  route: string;
  method: string;
  tool_id: string;
  approval_mode: string;
  stage: string;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface ToolSpec {
  id: string;
  name: string;
  category: string;
  risk_level: string;
  language_scope: string[];
  vuln_families: string[];
  execution_modes: string[];
  requires_runtime: boolean;
  description: string;
}

export interface WorkspaceUploadScanResponse {
  workspace: Workspace;
  task: ScanTask;
}

export interface TaskEvent {
  id?: number;
  task_id: number;
  event_type: string;
  payload: Record<string, unknown>;
  created_at?: string;
}

export interface PipelineStage {
  label: string;
  status: string;
  message: string;
  metrics: Record<string, unknown>;
  started_at?: string;
  finished_at?: string;
  // items 是后端裁剪后的代表性任务（每阶段至多 8 条，pipeline 每秒随进度事件推送，
  // 全量回传会把事件体积重新撑大），total 是该阶段真实任务总数。
  tasks?: {
    total?: number;
    items?: { name?: string; status?: string; detail?: string }[];
  };
}

export interface TaskSummary {
  pipeline?: Record<string, PipelineStage>;
  current_stage?: string;
  results?: Record<string, Record<string, unknown>>;
  reports?: ReportRecord[];
  finding_count?: number;
  final_report_summary?: Record<string, unknown>;
  hitl?: {
    approval_mode?: string;
    tool_allowlist?: string[];
    pending_actions?: Record<string, unknown>[];
  };
  [key: string]: unknown;
}

export interface TaintFlowHypothesis {
  source_present?: boolean; // 有攻击者可控 source 点
  sink_present?: boolean; // 识别到 sink（危险函数调用点，本身不等于危险）
  reachable?: boolean; // source→sink 可达
  barrier_free?: boolean; // 中间无有效净化器/barrier
  flow_complete?: boolean; // 四者全真才允许断言「危险」
  obligations?: Record<string, boolean>;
  proof_gaps?: string[];
  proof_confidence?: string;
}

export interface FindingRaw {
  priority_score?: number;
  supporting_node_count?: number;
  display_title?: string;
  display_family?: string;
  original_type?: string;
  chain_id?: string;
  proof_tier?: string;
  attack_chain_summary?: string;
  entry_route?: string;
  trigger_route?: string;
  is_primary_chain?: boolean;
  d2_status?: string;
  d2_candidate_ready?: boolean;
  vulnerability_hash_v2?: string;
  hash_confidence?: string;
  ai_review?: Record<string, unknown>;
  human_decision?: Record<string, unknown>;
  fix_suggestion?: Record<string, unknown>;
  patch_draft?: Record<string, unknown>;
  sca?: Record<string, unknown>;
  idor?: Record<string, unknown>;
  taint_flow_hypothesis?: TaintFlowHypothesis;
  confirmed?: boolean;
  is_dangerous?: boolean;
  severity_claimed?: string;
  detection_method?: string;
  rule_name?: string;
  verification_decision?: {
    verification_status?: string;
    judge_reason?: string;
    matched_outcomes?: string[];
    confidence?: string;
    confirmed?: boolean;
  };
  execution_evidence?: {
    requests_made?: string[];
    side_effects_observed?: string[];
    artifacts_created?: string[];
    cleanup_performed?: string[];
    raw_signals?: string[];
    step_errors?: string[];
  };
  [key: string]: unknown;
}

export interface Finding {
  id: number;
  task_id: number;
  workspace_id: number;
  finding_type: string;
  severity: string;
  file_path: string;
  line: number;
  title: string;
  raw: FindingRaw;
  created_at: string;
  // 迁移前的历史行这两列为空串，故设为可选，前端展示时回退 raw.sca.*。
  sca_component?: string;
  sca_advisory_id?: string;
}

export interface ReportRecord {
  id: number;
  task_id: number;
  workspace_id: number;
  report_type: string;
  file_path: string;
  generated_at: string;
}

export interface ReportContentRecord extends ReportRecord {
  content: string;
  content_type: string;
  exists: boolean;
}

/** 结构化可视化报告（GET /api/reports/{id}/structured）。 */
export interface StructuredReport {
  task_id: number;
  overview: {
    app_findings: number;
    sca_findings: number;
    total_findings: number;
    total_specs: number;
    confirmed_specs: number;
    spec_coverage: number;
  };
  distributions: {
    severity: Record<string, number>;
    by_source: Record<string, number>;
    by_verification: Record<string, number>;
    by_iast_state: Record<string, number>;
    by_family: Record<string, number>;
  };
  family_matrix: Record<string, Record<string, number>>;
  findings: StructuredFinding[];
  findings_truncated: boolean;
  findings_total: number;
}

export type EvidenceStrength = "strong" | "weak" | "dast_only" | "unverified" | "negative" | "detect_only";

export interface StructuredFinding {
  family: string;
  finding_type: string;
  severity: string;
  title: string;
  location: string;
  endpoint: string;
  http_method: string;
  source: string;
  verification_status: string;
  iast_state: string;
  expected_sink: string;
  evidence_strength: EvidenceStrength;
}

export interface SCASToolStatus {
  tool: string;
  available: boolean;
  version?: string;
  path?: string;
  install_hint?: string;
}

// ---- IAST（§3.10 ExternalTarget / §3.3 关联聚合 / §4.5 报告）----

export interface ExternalTarget {
  service_url: string;
  app_name: string;
  agent_id: string;
  probe_mode: string; // 固定 monitor
  code_path: string;
  auth_context?: Record<string, unknown>;
}

export interface IastSession {
  id: number;
  workspace_id: number;
  app_name: string;
  agent_id: string;
  target_url: string;
  code_path: string;
  probe_mode: string;
  probe_packages?: string;
  server_port?: number;
  status: string;
  agent_phase?: string;
  java_path?: string;
  probe_version?: string;
  version_status?: string;
  last_heartbeat_at?: string;
  registered_at: string;
  probe_token?: string;
}

export interface IastCorrelationFinding {
  vulnerability_hash_v2: string;
  finding_type: string;
  severity: string;
  file_path: string;
  line: number;
  title: string;
  source: string;
  iast: {
    state: string | null;
    confirmed_runtime: boolean;
    exploit_confirmed: boolean;
    event_count: number;
    last_seen: string;
    app_name: string;
    agent_id: string;
    sink_file: string;
    sink_line: number;
    trace_id?: string;
    event_types?: string[];
    canary_observed?: boolean;
  };
  sources: string[];
}

export interface IastCorrelationStats {
  total_hypotheses: number;
  iast_observed: number;
  confirmed_runtime: number;
  exploit_confirmed: number;
  coverage_ratio: number;
  confirmed_runtime_ratio: number;
  exploit_confirmed_ratio: number;
  per_asset: Array<{ asset: string; total: number; observed: number; confirmed_runtime: number; exploit_confirmed: number }>;
}

export interface IastCorrelationUnmatchedCanary {
  canary_identity: string;
  owner_task_id: number | null;
  event_type: string;
  canary_state: string;
  ingested_at: string;
}

export interface IastCorrelationDiagnostics {
  current_task_spec_count: number;
  unmatched_canary_events: IastCorrelationUnmatchedCanary[];
  unmatched_count: number;
}

export interface IastCorrelation {
  workspace_id: number | null;
  task_id: number | null;
  generated_at: string;
  stats: IastCorrelationStats;
  findings: IastCorrelationFinding[];
  diagnostics?: IastCorrelationDiagnostics;
}

// §D1 靶面明细（trigger-specs 端点）
export interface TriggerSpecInfo {
  id: number | null;
  task_id: number | null;
  vulnerability_hash_v2: string | null;
  endpoint: string;
  http_method: string;
  param_name: string;
  param_location: string;
  family: string;
  canary_identity: string;
  source: string;
}

// ---- I2 裁决器（§8.1 / §3.18 / §4.7.1）----
export interface I2EvidenceChainStep {
  stage: string; // SAST | DAST | IAST | D2
  id: string;
  [key: string]: unknown;
}

export interface I2PerHypothesis {
  vulnerability_hash_v2: string;
  taint_marker?: string;
  evidence_chain: I2EvidenceChainStep[];
  included_in_report: boolean;
  sast_hypothesis: { vulnerability_hash_v2: string };
  d2_verdict: string;
}

export interface I2HypothesisOnlyDetail {
  vulnerability_hash_v2: string;
  stability_count: number;
  status: string; // pending | likely-false-positive
}

export interface I2AuditCoverage {
  workspace_id: number | null;
  task_id: number | null;
  stats: {
    spec_count: number;
    total_hypotheses: number;
    excluded_no_trigger_spec: number;
    matched: number;
    hypothesis_only: number;
    observed_only: number;
    likely_false_positive?: number;
  };
  matched: string[];
  hypothesis_only: string[];
  hypothesis_only_detail: I2HypothesisOnlyDetail[];
  observed_only: Array<Record<string, unknown>>;
  per_hypothesis: I2PerHypothesis[];
  feedback?: Record<string, unknown>;
}
