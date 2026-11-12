<template>
  <div v-if="open" class="confirm-overlay" @click.self="emit('cancel')">
    <div class="confirm-dialog" role="dialog" aria-modal="true" :aria-label="title">
      <h3>{{ title }}</h3>
      <p class="muted">{{ message }}</p>
      <div class="actions">
        <button type="button" class="ghost-button" @click="emit('cancel')">取消</button>
        <button type="button" class="danger-solid" @click="emit('confirm')">{{ confirmText }}</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{ open: boolean; title?: string; message?: string; confirmText?: string }>(),
  { title: "确认操作", message: "", confirmText: "确认" },
);
const emit = defineEmits<{ confirm: []; cancel: [] }>();
</script>
