package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class ServletGetCookiesAdvice {
    private ServletGetCookiesAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onExit(@Advice.Return Object value) {
        HookRuntime.markCookieSources(value);
    }
}
