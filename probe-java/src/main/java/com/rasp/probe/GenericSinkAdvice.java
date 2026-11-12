package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class GenericSinkAdvice {
    private GenericSinkAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.AllArguments Object[] args) {
        HookRuntime.onGenericSink(origin, args);
    }
}
