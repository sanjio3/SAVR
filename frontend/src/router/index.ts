import { createRouter, createWebHistory } from "vue-router";

import TaskDetailPage from "@/pages/TaskDetailPage.vue";
import RunMonitorPage from "@/pages/RunMonitorPage.vue";
import SCAAssetPage from "@/pages/SCAAssetPage.vue";
import DastIdorPage from "@/pages/DastIdorPage.vue";
import AutonomyReviewPage from "@/pages/AutonomyReviewPage.vue";
import EvaluationMetricsPage from "@/pages/EvaluationMetricsPage.vue";
import OpsDashboardPage from "@/pages/OpsDashboardPage.vue";
import UsagePage from "@/pages/UsagePage.vue";
import RuleFeedbackPage from "@/pages/RuleFeedbackPage.vue";
import SettingsPage from "@/pages/SettingsPage.vue";
import WorkspaceDetailPage from "@/pages/WorkspaceDetailPage.vue";
import WorkspaceListPage from "@/pages/WorkspaceListPage.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", component: WorkspaceListPage },
    { path: "/runs", component: RunMonitorPage },
    { path: "/workspaces/:id", component: WorkspaceDetailPage },
    // 任务页 tab 用**组件内本地 state**（selectedTab ref，默认 Overview），不与 URL 同步 ——
    // 2026-09-22 回退：早期 Q7 曾用路径分段（/tasks/:id/findings），但 HITL 分支与
    // 深链需求弱、且与 router 状态耦合带来维护负担，故改回纯本地 state。路由不再带 :tab? 段。
    { path: "/workspace/:slug/task/:taskId", component: TaskDetailPage },
    { path: "/tasks/:id", component: TaskDetailPage },
    { path: "/sca", component: SCAAssetPage },
    { path: "/dast-idor", component: DastIdorPage },
    { path: "/autonomy", component: AutonomyReviewPage },
    { path: "/metrics", component: EvaluationMetricsPage },
    { path: "/ops", component: OpsDashboardPage },
    { path: "/usage", component: UsagePage },
    { path: "/rule-feedback", component: RuleFeedbackPage },
    { path: "/settings", component: SettingsPage },
  ],
});

export default router;
