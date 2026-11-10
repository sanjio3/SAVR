<template>
  <AppModal
    :open="open"
    title="设置中心"
    :subtitle="current.desc"
    size="xl"
    align="top"
    @close="emit('close')"
  >
    <!--
      左侧二级分段切换 + 右侧内容区。
      七个分区直接复用既有的页面组件本身，不另抄一份 —— 路由（/autonomy 等）
      与这里渲染的是同一份代码，改一处两边同步，不存在两份实现漂移的问题。
    -->
    <div class="settings-shell">
      <nav class="settings-nav" aria-label="设置分区">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          type="button"
          class="settings-nav-item"
          :class="{ active: tab.key === active }"
          :aria-current="tab.key === active ? 'true' : undefined"
          @click="active = tab.key"
        >
          <span class="settings-nav-label">{{ tab.label }}</span>
          <span class="settings-nav-desc">{{ tab.short }}</span>
        </button>
      </nav>

      <div class="settings-content">
      <div class="settings-content-head">
        <span class="settings-section-title">{{ current.label }}</span>
      </div>
        <component :is="current.component" />
      </div>
    </div>

    <template #footer>
      <div class="settings-foot">
        <span class="muted">设置改动即时保存，关闭弹层不影响已保存内容。</span>
        <button type="button" class="ghost-button sm" @click="emit('close')">关闭</button>
      </div>
    </template>
  </AppModal>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";

import AppModal from "@/components/AppModal.vue";
import AutonomyReviewPage from "@/pages/AutonomyReviewPage.vue";
import RuleFeedbackPage from "@/pages/RuleFeedbackPage.vue";
import SettingsPage from "@/pages/SettingsPage.vue";
import SCAAssetPage from "@/pages/SCAAssetPage.vue";
import DastIdorPage from "@/pages/DastIdorPage.vue";
import OpsDashboardPage from "@/pages/OpsDashboardPage.vue";
import UsagePage from "@/pages/UsagePage.vue";

type TabKey =
  | "review"
  | "rules"
  | "general"
  | "sca"
  | "idor"
  | "ops"
  | "usage";

interface Tab {
  key: TabKey;
  label: string;
  /** 左侧按钮里的短说明 */
  short: string;
  /** 弹层副标题里的完整说明 */
  desc: string;
  component: unknown;
}

const props = defineProps<{ open: boolean; initial?: TabKey }>();
const emit = defineEmits<{ close: [] }>();

// 分区直接复用既有页面组件本身，不另抄一份（路由页与本弹层渲染同一份代码）。
// 2026-09-24 导航改造：删旧的「指标」重复入口（/metrics 已是一级导航），
// 新增资产/运维类分区，把原占一级导航的 SCA 资产、越权扫描、运维看板、用量统计收进此处。
const tabs: Tab[] = [
  { key: "review", label: "复核队列", short: "自治关闭策略与回滚", desc: "自治关闭策略、按 finding 试算与处置审计回滚。", component: AutonomyReviewPage },
  { key: "rules", label: "规则反哺", short: "污点规则候选与回归", desc: "污点规则候选队列、确认与回归结果。", component: RuleFeedbackPage },
  { key: "general", label: "常规", short: "扫描强度与存储", desc: "默认扫描配置、LLM 扫描强度分级、平台固定行为与存储位置。", component: SettingsPage },
  { key: "sca", label: "SCA 资产", short: "组件与依赖漏洞", desc: "组件/依赖 CVE 清单、影响查询与人工确认。", component: SCAAssetPage },
  { key: "idor", label: "越权扫描", short: "IDOR/越权流量回放", desc: "越权场景配置、流量回放与结果判定。", component: DastIdorPage },
  { key: "ops", label: "运维看板", short: "平台健康与吞吐", desc: "进程/看门狗/队列/IAST 摄取吞吐等平台健康度。", component: OpsDashboardPage },
  { key: "usage", label: "用量统计", short: "调用量与配额", desc: "LLM 调用量、成本、配额与冗余统计。", component: UsagePage },
];

const active = ref<TabKey>("general");

// 每次打开回到调用方指定的分区；不指定则停在上次位置（同一次会话里连着调两个分区很常见）
watch(
  () => props.open,
  (isOpen) => {
    if (isOpen && props.initial) active.value = props.initial;
  },
);

const current = computed<Tab>(() => tabs.find((tab) => tab.key === active.value) ?? tabs[tabs.length - 1]);
</script>

<style scoped>
.settings-shell {
  display: grid;
  grid-template-columns: 208px minmax(0, 1fr);
  gap: 20px;
  align-items: start;
}

@media (max-width: 900px) {
  .settings-shell {
    grid-template-columns: 1fr;
  }
}

.settings-nav {
  display: grid;
  gap: 4px;
  /* 右侧内容很长，左侧分段跟着滚，不然滚到下面就找不到切换入口了 */
  position: sticky;
  top: 0;
}

.settings-nav-item {
  display: grid;
  gap: 2px;
  padding: 10px 12px;
  text-align: left;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  background: transparent;
  cursor: pointer;
  transition: background 0.16s var(--ease-out), border-color 0.16s var(--ease-out);
}

.settings-nav-item:hover {
  background: var(--color-surface-2);
}

.settings-nav-item.active {
  background: var(--color-accent-soft);
  border-color: var(--color-accent);
}

.settings-nav-label {
  font-size: 14px;
  font-weight: 600;
  color: var(--color-ink);
}

.settings-nav-item.active .settings-nav-label {
  color: var(--color-accent);
}

.settings-nav-desc {
  font-size: 12px;
  color: var(--color-muted);
}

.settings-content {
  min-width: 0;
}

.settings-content-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.settings-section-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--color-ink);
}

.settings-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

/* 内嵌的是完整页面组件：去掉它自带的页级居中约束与外边距，
   卡片内边距也收一档，否则弹层里会出现「卡中卡」的重复留白。 */
.settings-content :deep(.page) {
  max-width: none;
  gap:14px;
}

.settings-content :deep(.hero) {
  display: none;
}

.settings-content :deep(.hero h1) {
  font-size: 19px;
}
</style>
