package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class BootstrapProcessBuilderStartAdvice {
    private BootstrapProcessBuilderStartAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.This Object processBuilder) {
        BootstrapBridge.onProcessBuilderStart(origin, processBuilder);
    }
}
