package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class ServletGetHeaderAdvice {
    private ServletGetHeaderAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onExit(@Advice.Argument(0) String name, @Advice.Return Object value) {
        HookRuntime.markHttpSource("http.header", name, value);
    }
}

