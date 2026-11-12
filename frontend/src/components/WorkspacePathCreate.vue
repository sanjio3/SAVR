<template>
  <form class="stack" @submit.prevent="submit">
    <input v-model="form.name" type="text" placeholder="项目名称" />
    <input v-model="form.target_path" type="text" placeholder="代码路径（本地绝对路径），如 D:/path/to/project" />
    <input v-model="form.target_url" type="text" placeholder="测试环境地址（可选），如 http://127.0.0.1:8080" />
    <textarea v-model="form.description" rows="3" placeholder="描述（可选）"></textarea>
    <div class="muted" v-if="error">{{ error }}</div>
    <button :disabled="!canSubmit || busy" type="submit">{{ busy ? "创建中..." : "创建项目" }}</button>
  </form>
</template>

<script setup lang="ts">
import { computed, reactive } from "vue";

const props = defineProps<{
  busy?: boolean;
  error?: string;
}>();

const emit = defineEmits<{
  submit: [payload: { name: string; target_path: string; description: string; target_url: string }];
}>();

const form = reactive({
  name: "",
  target_path: "",
  target_url: "",
  description: "",
});

const canSubmit = computed(() => form.name.trim() !== "" && form.target_path.trim() !== "");
const busy = computed(() => props.busy ?? false);
const error = computed(() => props.error ?? "");

function submit() {
  if (!canSubmit.value) return;
  emit("submit", {
    name: form.name.trim(),
    target_path: form.target_path.trim(),
    target_url: form.target_url.trim(),
    description: form.description,
  });
  form.name = "";
  form.target_path = "";
  form.target_url = "";
  form.description = "";
}
</script>
