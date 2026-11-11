import { nextTick, onBeforeUnmount, onMounted, watch, type Ref } from "vue";

/**
 * 宽表横向滚动同步。
 *
 * 只做一件事：给真正溢出的 .table-wrap 打上 is-scrollable，
 * 让「首列冻结」的右侧发丝影只在需要时出现，不至于在能放下的表上凭空多一道线。
 *
 * 数据是异步灌进来的，所以除了挂载时机，还要监听三件事：
 * 窗口尺寸、容器尺寸、容器内的 DOM 变化（切标签页、表格行是 v-for 渲染的）。
 *
 * 注意：根节点常带 v-if（数据到位前是 null），所以必须在 ref 变化时重新挂 observer。
 * 只在 onMounted 挂一次，会漏掉「挂载时根还不存在」的页面（任务详情页就是这么漏的：
 * 首屏根为 null，observer 没建起来，切到「发现」标签后 is-scrollable 一直不生效，
 * 只有手动触发一次 window resize 才恢复）。
 */
export function syncTableScroll(root: HTMLElement | null): void {
  if (!root) return;
  root.querySelectorAll<HTMLElement>(".table-wrap").forEach((wrap) => {
    const scrollable = wrap.scrollWidth > wrap.clientWidth + 1;
    wrap.classList.toggle("is-scrollable", scrollable);
  });
}

export function useTableScroll(root: Ref<HTMLElement | null>) {
  let observer: ResizeObserver | null = null;
  let mutation: MutationObserver | null = null;
  let frame = 0;

  const run = () => {
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      syncTableScroll(root.value);
    });
  };

  const runNow = () => {
    void nextTick(run);
  };

  const detach = () => {
    observer?.disconnect();
    observer = null;
    mutation?.disconnect();
    mutation = null;
  };

  const attach = (el: HTMLElement | null) => {
    detach();
    if (!el) return;

    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(run);
      observer.observe(el);
    }

    if (typeof MutationObserver !== "undefined") {
      mutation = new MutationObserver(run);
      mutation.observe(el, { childList: true, subtree: true });
    }

    runNow();
  };

  watch(root, (el) => attach(el), { immediate: true, flush: "post" });

  onMounted(() => {
    runNow();
    window.addEventListener("resize", run);
  });

  onBeforeUnmount(() => {
    if (frame) cancelAnimationFrame(frame);
    detach();
    window.removeEventListener("resize", run);
  });

  return runNow;
}
