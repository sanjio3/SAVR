package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class ServletGetParameterAdvice {
    private ServletGetParameterAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onExit(@Advice.Argument(0) String name, @Advice.Return Object value) {
        HookRuntime.markHttpSource("http.parameter", name, value);
    }
}

