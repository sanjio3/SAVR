<template>
  <!--
    通用模态基座。三点必须做对，否则弹层会在真实页面里露馅：
    1. Teleport 到 body：留在原地会被父级的 overflow / transform / z-index 裁掉或压住。
    2. 进出场动画分层：遮罩只做 opacity，面板做 opacity + 轻微位移缩放；
       进场（.24s，ease-out）比退场（.16s，ease-in）慢一点，关闭更跟手。
    3. 无障碍与焦点：role/aria-modal/aria-labelledby、打开时移入焦点、
       Tab 在面板内循环、关闭后把焦点还给触发它的元素。
  -->
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="open" class="modal-root" :class="{ 'align-top': align === 'top' }" @click.self="onBackdrop">
        <div
          ref="panel"
          class="modal-panel"
          :class="`size-${size}`"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="titleId"
          tabindex="-1"
          @keydown="onPanelKeydown"
        >
          <header class="modal-head">
            <div class="modal-heading">
              <h2 :id="titleId" class="modal-title">{{ title }}</h2>
              <p v-if="subtitle" class="modal-subtitle">{{ subtitle }}</p>
            </div>
            <button type="button" class="modal-close" aria-label="关闭" @click="requestClose">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" /></svg>
            </button>
          </header>

          <div class="modal-body">
            <slot />
          </div>

          <footer v-if="$slots.footer" class="modal-foot">
            <slot name="footer" />
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from "vue";

import { lockScroll, unlockScroll } from "@/domain/scroll-lock";

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    subtitle?: string;
    /** md 常规 / lg 宽（设置中心）/ xl 全屏级 */
    size?: "sm" | "md" | "lg" | "xl";
    align?: "center" | "top";
    closeOnBackdrop?: boolean;
    closeOnEsc?: boolean;
  }>(),
  { subtitle: "", size: "md", align: "center", closeOnBackdrop: true, closeOnEsc: true },
);

const emit = defineEmits<{ close: [] }>();

const panel = ref<HTMLElement | null>(null);
/** 每个实例一个 id，避免同页多个弹层 aria-labelledby 撞车 */
const titleId = `modal-title-${useId()}`;
let lastFocused: HTMLElement | null = null;

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      lastFocused = document.activeElement as HTMLElement | null;
      lockScroll();
      // 面板还没渲染出来，等这一帧结束再抢焦点
      void nextTick(() => focusFirst());
    } else {
      unlockScroll();
      const back = lastFocused;
      lastFocused = null;
      void nextTick(() => {
        if (back && document.contains(back)) back.focus();
      });
    }
  },
  // immediate：组件可能以 open=true 初始挂载（watch 默认不会为初值触发），
  // 那样就不会上锁也不会移入焦点。
  { immediate: true },
);

onMounted(() => window.addEventListener("keydown", onWindowKeydown));
onBeforeUnmount(() => {
  window.removeEventListener("keydown", onWindowKeydown);
  // 组件被卸载时若弹层还开着，必须把页面滚动还回去，否则整页锁死
  if (props.open) unlockScroll();
});

function requestClose() {
  emit("close");
}

function onBackdrop() {
  if (props.closeOnBackdrop) requestClose();
}

function onWindowKeydown(event: KeyboardEvent) {
  if (!props.open || !props.closeOnEsc) return;
  if (event.key === "Escape") {
    event.stopPropagation();
    requestClose();
  }
}

function focusables(): HTMLElement[] {
  const el = panel.value;
  if (!el) return [];
  // getClientRects 比 offsetParent 稳：offsetParent 对 fixed 定位元素会返回 null，
  // 弹层祖先正是 position:fixed，用它会把可聚焦元素误判成不可见。
  return Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (node) => node.getClientRects().length > 0,
  );
}

function focusFirst() {
  const el = panel.value;
  if (!el) return;
  const nodes = focusables();
  (nodes[0] || el).focus();
}

/** Tab / Shift+Tab 在面板内首尾相接，避免焦点跑到背后的页面上去 */
function onPanelKeydown(event: KeyboardEvent) {
  if (event.key !== "Tab") return;
  const el = panel.value;
  if (!el) return;
  const nodes = focusables();
  if (!nodes.length) {
    event.preventDefault();
    return;
  }
  const first = nodes[0];
  const last = nodes[nodes.length - 1];
  const active = document.activeElement;
  if (event.shiftKey && (active === first || active === el)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}
</script>
