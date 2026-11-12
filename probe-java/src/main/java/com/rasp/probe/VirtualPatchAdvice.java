package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * 方法级虚拟补丁 advice。
 *
 * <p>由 {@link VirtualPatchEngine} 在收到 VIRTUAL_PATCH 规则后按目标方法运行时织入。
 * 不做任何判定逻辑，只把 Origin + 入参交给 {@link HookRuntime#onVirtualPatch}，
 * 判定与拦截统一走既有闸口。
 *
 * <p>刻意<b>不加</b> {@code suppress}：拦截依赖 {@code SecurityException} 向上抛出，
 * suppress 会把它吞掉导致补丁永不生效；内部所有非拦截异常已在 HookRuntime 内 fail-open。
 */
public final class VirtualPatchAdvice {
    private VirtualPatchAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.AllArguments Object[] args) {
        HookRuntime.onVirtualPatch(origin, args);
    }
}
