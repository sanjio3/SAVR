/**
 * 页面滚动锁。
 *
 * 计数器必须活在**模块作用域**：<script setup> 的顶层声明会被编译进 setup() 内部，
 * 是每实例的，放那里两个弹层各记各的数，内层一关就会把外层的锁解掉。
 * 因此单独成文件，用模块级变量共享。
 */
let locks = 0;
let savedOverflow = "";

export function lockScroll(): void {
  if (locks === 0) {
    savedOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  locks += 1;
}

export function unlockScroll(): void {
  if (locks === 0) return;
  locks -= 1;
  if (locks === 0) {
    document.body.style.overflow = savedOverflow;
  }
}

/** 仅供测试与异常兜底：确认当前是否仍处于锁定状态 */
export function isScrollLocked(): boolean {
  return locks > 0;
}
