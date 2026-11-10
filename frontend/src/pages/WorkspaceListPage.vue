<template>
  <section class="page">
    <div class="hero row between wrap gap-md">
      <div class="stack">
        <h1>工作区</h1>
        <p class="muted">每个工作区保存源码路径、历史运行、工作区内漏洞与报告。</p>
      </div>
      <div class="row wrap gap-sm">
        <button class="ghost-button" @click="showCreate = !showCreate">
          {{ showCreate ? "收起新建" : "新建工作区" }}
        </button>
        <button class="ghost-button" @click="toggleArchived">
          {{ showArchived ? "隐藏已归档" : "显示已归档" }}
        </button>
      </div>
    </div>

    <div v-if="showCreate" class="card">
      <h2>从本地路径创建工作区</h2>
      <WorkspacePathCreate :busy="createBusy" :error="createError" @submit="createWorkspace" />
    </div>

    <SkeletonBlock v-if="loading" variant="card" :rows="2" label="正在读取工作区…" />

    <div class="card stack">
      <h2>工作区列表</h2>
      <div v-if="loading" class="stack">
        <span class="skeleton skeleton-line" style="width: 40%" />
        <span class="skeleton skeleton-line" style="width: 72%" />
      </div>
      <div v-else-if="!store.items.length" class="empty-state">
        <strong>当前没有工作区记录</strong>
        <span>点右上角「新建工作区」，填一个本地源码路径即可开始；Java 项目建议指向含 pom.xml 的根目录。</span>
      </div>
      <div v-else class="project-list">
        <div v-for="item in store.items" :key="item.id" class="project-card">
          <div class="stack">
            <div class="row between wrap gap-sm">
              <strong>{{ item.name }}</strong>
              <span v-if="item.archived" class="status-badge status-queued">已归档</span>
            </div>
            <div class="muted small">{{ item.target_path }}</div>
          </div>
          <div class="row wrap gap-sm">
            <RouterLink class="ghost-button" :to="`/workspaces/${item.id}`">打开工作区</RouterLink>
            <button class="ghost-button" @click="toggleArchive(item)">
              {{ item.archived ? "取消归档" : "归档" }}
            </button>
            <button class="ghost-button danger-outline" @click="askRemove(item)">删除</button>
          </div>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :open="Boolean(pendingRemove)"
      title="删除工作区"
      :message="pendingRemove ? `将删除工作区「${pendingRemove.name}」及其全部运行记录与漏洞，操作不可撤销。` : ''"
      confirm-text="删除"
      @confirm="confirmRemove"
      @cancel="pendingRemove = null"
    />
  </section>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import ConfirmDialog from "@/components/ConfirmDialog.vue";
import SkeletonBlock from "@/components/SkeletonBlock.vue";
import WorkspacePathCreate from "@/components/WorkspacePathCreate.vue";
import { useWorkspaceStore } from "@/stores/workspaces";
import type { Workspace } from "@/types";

const store = useWorkspaceStore();
const router = useRouter();
const createBusy = ref(false);
const createError = ref("");
const showArchived = ref(false);
const showCreate = ref(false);
const pendingRemove = ref<Workspace | null>(null);
// App.vue 启动时可能已经拉过工作区列表，有数据就不再闪骨架
const loading = ref(!store.items.length);

onMounted(async () => {
  try {
    await store.fetchWorkspaces(showArchived.value);
  } finally {
    loading.value = false;
  }
});

async function createWorkspace(payload: { name: string; target_path: string; description: string; target_url: string }) {
  createBusy.value = true;
  createError.value = "";
  try {
    const workspace = await store.createWorkspace({
      name: payload.name,
      target_path: payload.target_path,
      description: payload.description,
      settings: payload.target_url ? { target_url: payload.target_url } : {},
    });
    router.push(`/workspaces/${workspace.id}`);
  } catch (error: any) {
    createError.value = error?.response?.data?.detail || error?.message || "创建失败";
  } finally {
    createBusy.value = false;
  }
}

async function toggleArchived() {
  showArchived.value = !showArchived.value;
  await store.fetchWorkspaces(showArchived.value);
}

async function toggleArchive(workspace: Workspace) {
  if (workspace.archived) {
    await store.unarchiveWorkspace(workspace.id);
  } else {
    await store.archiveWorkspace(workspace.id);
  }
  await store.fetchWorkspaces(showArchived.value);
}

function askRemove(workspace: Workspace) {
  pendingRemove.value = workspace;
}

async function confirmRemove() {
  const target = pendingRemove.value;
  pendingRemove.value = null;
  if (!target) return;
  await store.deleteWorkspace(target.id);
}
</script>
