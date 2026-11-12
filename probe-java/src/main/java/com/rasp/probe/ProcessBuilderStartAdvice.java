package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class ProcessBuilderStartAdvice {
    private ProcessBuilderStartAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.This Object processBuilder) {
        HookRuntime.onProcessBuilderStart(origin, processBuilder);
    }
}
