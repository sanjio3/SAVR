<template>
  <section class="card stack">
    <div class="row between wrap gap-sm">
      <div>
        <h3>报告预览</h3>
        <p class="muted">默认优先展示 B2 Markdown 报告，仍保留下载入口。</p>
      </div>
      <div class="row wrap gap-sm" v-if="reports.length">
        <button
          v-for="item in reports"
          :key="item.id"
          type="button"
          class="ghost-button"
          :class="{ active: selected?.id === item.id }"
          @click="$emit('select', item)"
        >
          {{ item.report_type }}
        </button>
        <a v-if="selected" class="button" :href="`/api/reports/${selected.id}/download`" target="_blank">下载</a>
      </div>
    </div>

    <div v-if="loading" class="report-shell muted">报告加载中…</div>
    <div v-else-if="!selected" class="report-shell muted">当前任务还没有生成报告。</div>
    <pre v-else-if="content && content.content_type === 'application/json'">{{ content.content }}</pre>
    <article
      v-else-if="renderedHtml"
      class="markdown-body report-shell"
      v-html="renderedHtml"
    />
    <pre v-else-if="content?.content">{{ content.content }}</pre>
    <div v-else class="report-shell muted">报告内容为空。</div>
  </section>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { marked } from "marked";

import type { ReportContentRecord, ReportRecord } from "@/types";

const props = defineProps<{
  reports: ReportRecord[];
  selected: ReportRecord | null;
  content: ReportContentRecord | null;
  loading?: boolean;
}>();

defineEmits<{
  (e: "select", report: ReportRecord): void;
}>();

function escapeUnsafeHtml(content: string): string {
  return String(content || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const renderedHtml = computed(() => {
  if (!props.content || props.content.content_type !== "text/markdown") {
    return "";
  }
  return marked.parse(escapeUnsafeHtml(props.content.content)) as string;
});
</script>
