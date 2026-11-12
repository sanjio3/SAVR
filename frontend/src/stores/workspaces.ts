import { defineStore } from "pinia";

import { http } from "@/services/http";
import type {
  Finding,
  HitlAuditEntry,
  HitlSettings,
  ReportContentRecord,
  ReportRecord,
  ScanTask,
  TaskEvent,
  ToolSpec,
  Workspace,
  SCASToolStatus,
} from "@/types";

export const useWorkspaceStore = defineStore("workspaces", {
  state: () => ({
    items: [] as Workspace[],
    tasks: [] as ScanTask[],
    workspaceFindings: [] as Finding[],
    workspaceReports: [] as ReportRecord[],
    selectedWorkspace: null as Workspace | null,
    selectedTask: null as ScanTask | null,
    events: [] as TaskEvent[],
    findings: [] as Finding[],
    reports: [] as ReportRecord[],
    selectedReport: null as ReportRecord | null,
    reportContent: null as ReportContentRecord | null,
    includeArchived: false,
    hitlSettings: null as HitlSettings | null,
    hitlAudit: [] as HitlAuditEntry[],
    toolRegistry: [] as ToolSpec[],
    scaTools: [] as SCASToolStatus[],
    reviewMetrics: {} as Record<string, unknown>,
    entryDiscovery: null as Record<string, unknown> | null,
  }),
  actions: {
    resetLists() {
      this.items = [];
      this.tasks = [];
      this.workspaceFindings = [];
      this.workspaceReports = [];
      this.events = [];
      this.findings = [];
      this.reports = [];
      this.selectedReport = null;
      this.reportContent = null;
    },
    async fetchWorkspaces(includeArchived?: boolean) {
      const effectiveIncludeArchived = includeArchived ?? this.includeArchived;
      this.includeArchived = effectiveIncludeArchived;
      const { data } = await http.get<Workspace[]>("/api/workspaces", {
        params: { include_archived: effectiveIncludeArchived },
      });
      this.items = data;
      return data;
    },
    async createWorkspace(payload: Partial<Workspace>) {
      const { data } = await http.post<Workspace>("/api/workspaces", payload);
      this.items.unshift(data);
      return data;
    },
    async fetchWorkspace(workspaceId: number) {
      const { data } = await http.get<Workspace>(`/api/workspaces/${workspaceId}`);
      this.selectedWorkspace = data;
      return data;
    },
    async archiveWorkspace(workspaceId: number) {
      const { data } = await http.post<Workspace>(`/api/workspaces/${workspaceId}/archive`);
      this._replaceWorkspace(data);
      if (this.selectedWorkspace?.id === workspaceId) {
        this.selectedWorkspace = data;
      }
      return data;
    },
    async unarchiveWorkspace(workspaceId: number) {
      const { data } = await http.post<Workspace>(`/api/workspaces/${workspaceId}/unarchive`);
      this._replaceWorkspace(data);
      if (this.selectedWorkspace?.id === workspaceId) {
        this.selectedWorkspace = data;
      }
      return data;
    },
    async deleteWorkspace(workspaceId: number) {
      await http.delete(`/api/workspaces/${workspaceId}`);
      this.items = this.items.filter((item) => item.id !== workspaceId);
      if (this.selectedWorkspace?.id === workspaceId) {
        this.selectedWorkspace = null;
        this.tasks = [];
        this.workspaceFindings = [];
        this.workspaceReports = [];
      }
    },
    async updateWorkspace(workspaceId: number, payload: Partial<Workspace>) {
      const { data } = await http.put<Workspace>(`/api/workspaces/${workspaceId}`, payload);
      const index = this.items.findIndex((item) => item.id === workspaceId);
      if (index >= 0) this.items.splice(index, 1, data);
      if (this.selectedWorkspace?.id === workspaceId) this.selectedWorkspace = data;
      return data;
    },
    async fetchTasks(workspaceId?: number) {
      const { data } = await http.get<ScanTask[]>("/api/scan-tasks", {
        params: workspaceId ? { workspace_id: workspaceId } : {},
      });
      this.tasks = data;
      return data;
    },
    async clearWorkspaceTasks(workspaceId: number) {
      await http.delete(`/api/workspaces/${workspaceId}/scan-tasks`);
      this.tasks = this.tasks.filter((task) => task.workspace_id !== workspaceId);
      if (this.selectedWorkspace?.id === workspaceId) {
        this.workspaceFindings = [];
        this.workspaceReports = [];
      }
    },
    async createTask(payload: Record<string, unknown>) {
      const { data } = await http.post<ScanTask>("/api/scan-tasks", payload);
      this.tasks.unshift(data);
      this.selectedTask = data;
      return data;
    },
    async fetchTask(taskId: number) {
      const { data } = await http.get<ScanTask>(`/api/scan-tasks/${taskId}`);
      this.selectedTask = data;
      this.hitlSettings = {
        task_id: taskId,
        approval_mode: String((data.summary?.hitl as any)?.approval_mode || (data.options?.approval_mode as string) || "off"),
        tool_allowlist: Array.isArray((data.summary?.hitl as any)?.tool_allowlist)
          ? (((data.summary?.hitl as any)?.tool_allowlist as string[]) || [])
          : Array.isArray(data.options?.tool_allowlist)
            ? ((data.options.tool_allowlist as string[]) || [])
            : [],
        pending_actions: Array.isArray((data.summary?.hitl as any)?.pending_actions)
          ? (((data.summary?.hitl as any)?.pending_actions as Record<string, unknown>[]) || [])
          : [],
      };
      return data;
    },
    async fetchTaskHitl(taskId: number) {
      const { data } = await http.get<HitlSettings>(`/api/scan-tasks/${taskId}/hitl`);
      this.hitlSettings = data;
      return data;
    },
    async fetchTaskHitlPending(taskId: number) {
      const { data } = await http.get<Record<string, unknown>[]>(`/api/scan-tasks/${taskId}/hitl/pending`);
      this.hitlSettings = {
        task_id: taskId,
        approval_mode: String(this.hitlSettings?.approval_mode || this.selectedTask?.options?.approval_mode || "off"),
        tool_allowlist: Array.isArray(this.hitlSettings?.tool_allowlist) ? [...this.hitlSettings!.tool_allowlist] : [],
        pending_actions: Array.isArray(data) ? data : [],
      };
      return data;
    },
    async updateTaskHitl(taskId: number, payload: Partial<HitlSettings>) {
      const { data } = await http.patch<HitlSettings>(`/api/scan-tasks/${taskId}/hitl`, payload);
      this.hitlSettings = data;
      if (this.selectedTask?.id === taskId) {
        this.selectedTask = {
          ...this.selectedTask,
          options: {
            ...this.selectedTask.options,
            approval_mode: data.approval_mode,
            tool_allowlist: data.tool_allowlist,
          },
          summary: {
            ...this.selectedTask.summary,
            hitl: {
              approval_mode: data.approval_mode,
              tool_allowlist: data.tool_allowlist,
              pending_actions: data.pending_actions,
            },
          },
        };
      }
      return data;
    },
    async resolveTaskHitlAction(taskId: number, actionId: string, decision: "approved" | "rejected") {
      const path = `/api/scan-tasks/${taskId}/hitl/actions/${actionId}/${decision === "approved" ? "approve" : "reject"}`;
      const { data } = await http.post<{ action: Record<string, unknown>; settings: HitlSettings }>(path);
      this.hitlSettings = data.settings;
      if (this.selectedTask?.id === taskId) {
        this.selectedTask = {
          ...this.selectedTask,
          options: {
            ...this.selectedTask.options,
            approval_mode: data.settings.approval_mode,
            tool_allowlist: data.settings.tool_allowlist,
          },
          summary: {
            ...this.selectedTask.summary,
            hitl: {
              approval_mode: data.settings.approval_mode,
              tool_allowlist: data.settings.tool_allowlist,
              pending_actions: data.settings.pending_actions,
            },
          },
        };
      }
      return data;
    },
    async fetchToolRegistry() {
      const { data } = await http.get<ToolSpec[]>("/api/system/tool-registry");
      this.toolRegistry = data;
      return data;
    },
    async fetchTaskHitlAudit(taskId: number) {
      const { data } = await http.get<HitlAuditEntry[]>(`/api/scan-tasks/${taskId}/hitl/audit`);
      this.hitlAudit = data;
      return data;
    },
    async batchResolveTaskHitl(
      taskId: number,
      items: { action_id: string; decision: "approved" | "rejected" }[],
    ) {
      const { data } = await http.post<{ resolved: Record<string, unknown>[]; failed: Record<string, unknown>[]; settings: HitlSettings }>(
        `/api/scan-tasks/${taskId}/hitl/actions/batch`,
        { items },
      );
      this.hitlSettings = data.settings;
      if (this.selectedTask?.id === taskId) {
        this.selectedTask = {
          ...this.selectedTask,
          options: {
            ...this.selectedTask.options,
            approval_mode: data.settings.approval_mode,
            tool_allowlist: data.settings.tool_allowlist,
          },
          summary: {
            ...this.selectedTask.summary,
            hitl: {
              approval_mode: data.settings.approval_mode,
              tool_allowlist: data.settings.tool_allowlist,
              pending_actions: data.settings.pending_actions,
            },
          },
        };
      }
      return data;
    },
    async suspendTask(taskId: number) {
      const { data } = await http.post<{ task_id: number; status: string }>(`/api/scan-tasks/${taskId}/suspend`);
      if (this.selectedTask?.id === taskId) {
        this.selectedTask = { ...this.selectedTask, status: data.status as ScanTask["status"] };
      }
      return data;
    },
    async resumeTask(taskId: number) {
      const { data } = await http.post<{ task_id: number; status: string }>(`/api/scan-tasks/${taskId}/resume`);
      if (this.selectedTask?.id === taskId) {
        this.selectedTask = { ...this.selectedTask, status: data.status as ScanTask["status"] };
      }
      return data;
    },
    async fetchScaTools() {
      const { data } = await http.get<SCASToolStatus[]>("/api/system/sca-tools");
      this.scaTools = data;
      return data;
    },
    async runAiReview(findingId: number) {
      const { data } = await http.post<Record<string, unknown>>(`/api/findings/${findingId}/ai-review`);
      await this.refreshSelectedTaskFindings();
      return data;
    },
    async submitHumanDecision(findingId: number, payload: Record<string, unknown>) {
      const { data } = await http.post<Record<string, unknown>>(`/api/findings/${findingId}/human-decision`, payload);
      await this.refreshSelectedTaskFindings();
      return data;
    },
    async generateFixSuggestion(findingId: number) {
      const { data } = await http.post<Record<string, unknown>>(`/api/findings/${findingId}/fix-suggestion`);
      await this.refreshSelectedTaskFindings();
      return data;
    },
    async generatePatchDraft(findingId: number) {
      const { data } = await http.post<Record<string, unknown>>(`/api/findings/${findingId}/patch-draft`);
      await this.refreshSelectedTaskFindings();
      return data;
    },
    async fetchReviewMetrics(taskId?: number) {
      const { data } = await http.get<Record<string, unknown>>("/api/metrics/review", { params: taskId ? { task_id: taskId } : {} });
      this.reviewMetrics = data;
      return data;
    },
    async discoverEntries(projectPath: string) {
      const { data } = await http.post<Record<string, unknown>>("/api/entry-discovery/tasks", { project_path: projectPath });
      this.entryDiscovery = data;
      return data;
    },
    async refreshSelectedTaskFindings() {
      if (!this.selectedTask) return [] as Finding[];
      const findings = await this.fetchTaskFindings(this.selectedTask.id);
      await this.fetchReviewMetrics(this.selectedTask.id);
      return findings;
    },
    async deleteTask(taskId: number) {
      await http.delete(`/api/scan-tasks/${taskId}`);
      this.tasks = this.tasks.filter((task) => task.id !== taskId);
      if (this.selectedTask?.id === taskId) {
        this.selectedTask = null;
        this.events = [];
        this.findings = [];
        this.reports = [];
        this.selectedReport = null;
        this.reportContent = null;
      }
    },
    async fetchTaskEvents(taskId: number) {
      const { data } = await http.get<TaskEvent[]>(`/api/scan-tasks/${taskId}/events`);
      this.events = data;
      return data;
    },
    async fetchTaskFindings(taskId: number) {
      const { data } = await http.get<Finding[]>("/api/results/findings", { params: { task_id: taskId } });
      this.findings = data;
      return data;
    },
    async fetchWorkspaceFindings(workspaceId: number) {
      const { data } = await http.get<Finding[]>("/api/results/findings", { params: { workspace_id: workspaceId } });
      this.workspaceFindings = data;
      return data;
    },
    async fetchTaskReports(taskId: number) {
      const { data } = await http.get<ReportRecord[]>("/api/reports", { params: { task_id: taskId } });
      this.reports = data;
      this.selectedReport = data[0] ?? null;
      this.reportContent = null;
      return data;
    },
    async fetchWorkspaceReports(workspaceId: number) {
      const { data } = await http.get<ReportRecord[]>("/api/reports", { params: { workspace_id: workspaceId } });
      this.workspaceReports = data;
      return data;
    },
    async fetchReportContent(reportId: number) {
      const { data } = await http.get<ReportContentRecord>(`/api/reports/${reportId}/content`);
      this.reportContent = data;
      return data;
    },
    selectReport(report: ReportRecord | null) {
      this.selectedReport = report;
      if (!report) {
        this.reportContent = null;
      }
    },
    pushEvent(event: TaskEvent) {
      this.events.push(event);
      if (
        event.event_type === "task_progress" ||
        event.event_type === "task_completed" ||
        event.event_type === "task_failed" ||
        event.event_type === "task_hitl_pending" ||
        event.event_type === "task_hitl_resolved"
      ) {
        const taskId = Number(event.task_id);
        if (this.selectedTask && this.selectedTask.id === taskId) {
          this.selectedTask = {
            ...this.selectedTask,
            phase: String((event.payload.current_stage as string) || (event.payload.phase as string) || this.selectedTask.phase),
            summary: {
              ...this.selectedTask.summary,
              ...(event.payload.pipeline ? { pipeline: event.payload.pipeline as any } : {}),
              ...(event.payload.stage_results
                ? { results: { ...(this.selectedTask.summary?.results || {}), ...(event.payload.stage_results as any) } }
                : {}),
              ...(event.payload.reports ? { reports: event.payload.reports as ReportRecord[] } : {}),
              ...(event.payload.finding_count ? { finding_count: Number(event.payload.finding_count) } : {}),
              ...(event.payload.summary ? { final_report_summary: event.payload.summary as any } : {}),
              ...(event.payload.hitl ? { hitl: event.payload.hitl as any } : {}),
              current_stage: String(
                (event.payload.current_stage as string) || (event.payload.phase as string) || this.selectedTask.summary?.current_stage || "",
              ),
            },
          };
          this.tasks = this.tasks.map((task) => (task.id === taskId ? this.selectedTask! : task));
        }
      }
    },
    _replaceWorkspace(workspace: Workspace) {
      const index = this.items.findIndex((item) => item.id === workspace.id);
      if (index >= 0) {
        this.items.splice(index, 1, workspace);
      } else {
        this.items.unshift(workspace);
      }
    },
  },
});
