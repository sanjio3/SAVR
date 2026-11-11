import { defineStore } from "pinia";

import { http } from "@/services/http";
import type { IastCorrelation, IastSession, I2AuditCoverage, TriggerSpecInfo } from "@/types";

export const useIastStore = defineStore("iast", {
  state: () => ({
    sessions: [] as IastSession[],
    correlation: null as IastCorrelation | null,
    adjudication: null as I2AuditCoverage | null,
    taskEventsSummary: null as Record<string, unknown> | null,
    triggerSpecs: [] as TriggerSpecInfo[],
  }),
  actions: {
    reset() {
      this.sessions = [];
      this.correlation = null;
      this.adjudication = null;
      this.taskEventsSummary = null;
    },
    async fetchSessions(workspaceId?: number) {
      const { data } = await http.get<IastSession[]>("/api/iast/sessions", {
        params: workspaceId ? { workspace_id: workspaceId } : {},
      });
      this.sessions = data;
      return data;
    },
    async registerSession(payload: {
      target_url: string;
      code_path: string;
      app_name: string;
      agent_id: string;
      workspace_id?: number;
      probe_mode?: string;
      probe_packages?: string;
      server_port?: number;
      java_path?: string;
    }) {
      const { data } = await http.post<IastSession>("/api/iast/sessions", payload);
      this.sessions.unshift(data);
      return data;
    },
    async fetchCorrelation(params: { workspace_id?: number; task_id?: number }) {
      const { data } = await http.get<IastCorrelation>("/api/iast/correlation", { params });
      this.correlation = data;
      return data;
    },
    async generateCorrelationReport(workspaceId: number, taskId?: number) {
      const { data } = await http.post<Record<string, unknown>>(
        "/api/iast/correlation/report",
        null,
        { params: { workspace_id: workspaceId, task_id: taskId } },
      );
      return data;
    },
    async replayDast(payload: {
      trigger_spec: Record<string, unknown>;
      target: Record<string, unknown>;
    }) {
      const { data } = await http.post<Record<string, unknown>>("/api/dast/replay", payload);
      return data;
    },
    async fetchAdjudication(params: { workspace_id?: number; task_id?: number }) {
      const { data } = await http.get<I2AuditCoverage>("/api/iast/adjudication", { params });
      this.adjudication = data;
      return data;
    },
    async fetchTaskEventsSummary(taskId: number) {
      const { data } = await http.get<Record<string, unknown>>("/api/iast/task-events-summary", {
        params: { task_id: taskId },
      });
      this.taskEventsSummary = data;
      return data;
    },
    async fetchTriggerSpecs(params: { workspace_id?: number; task_id?: number }) {
      const { data } = await http.get<TriggerSpecInfo[]>("/api/iast/trigger-specs", { params });
      this.triggerSpecs = data;
      return data;
    },
  },
});
