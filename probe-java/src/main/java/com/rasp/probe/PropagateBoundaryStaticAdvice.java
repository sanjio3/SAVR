package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * 类型边界传播 (F2 修复) —— 静态工厂形态（Paths.get）。
 *
 * <p>{@link PropagateBoundaryAdvice} 覆盖构造器形态，但 {@code java.nio.file.Paths} 没有公开
 * 构造器，所有路径创建必经静态工厂 {@code Paths.get(String, String...)}。若只 hook 构造器，
 * Paths 边界传播对 Paths 而言是个空操作 —— 经 {@code Paths.get} 落地的 {@code Path} 在 sink 处
 * 取不到源字符串，路径穿越族在 Paths 这条路径上永远 no-arrival。本项目此前就是漏了这条
 * （Paths.get），本次补登记。
 *
 * <p>与 PropagateBoundaryAdvice 拆成两个 advice 类的原因：同一个 advice 类里出现两个
 * {@code @OnMethodExit} 被同一个 matcher 绑定，会触发 ByteBuddy 1.15.11 的
 * "Duplicate advice" 整类插桩失败（见 PropagateBoundaryAdvice 注释）。本类只管静态工厂，
 * 复用 {@link PropagateBoundaryAdvice#propagate} 做实际边界登记；二者都已登记进
 * {@code ByteBuddyHookInstaller#injectBootstrapHelpers} 的 BOOTSTRAP 注入，故运行时
 * 内联进 java.base 后均可被 bootstrap 加载器解析到（不会 NoClassDefFoundError）。
 *
 * <p>本类只匹配 {@code get(String, ...)}（arg0 为路径首段字符串）；{@code get(URI)} 的 arg0
 * 是 {@code URI}，extractContent 取不到文本内容，无需传播，由 matcher 排除。
 */
public final class PropagateBoundaryStaticAdvice {
    private PropagateBoundaryStaticAdvice() {
    }

    /**
     * 静态工厂形态。捕获返回值（新 Path 载体）与参数 0（路径首段字符串），复用构造器形态的
     * propagate 完成边界登记。静态方法无 {@code @Advice.This}，返回值用 {@code @Advice.Return}。
     */
    @Advice.OnMethodExit
    public static void onStatic(@Advice.Origin("#t.#m") String origin,
                               @Advice.Return Object self, @Advice.Argument(0) Object src) {
        if (self == null || src == null) {
            return;
        }
        PropagateBoundaryAdvice.propagate(self, src, origin);
    }
}
