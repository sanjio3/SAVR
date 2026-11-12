package com.rasp.probe;

import net.bytebuddy.asm.Advice;

import java.util.concurrent.Callable;

public final class ExecutorCallableAdvice {
    private ExecutorCallableAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(value = 0, readOnly = false) Callable<?> command) {
        command = HookRuntime.wrapCallable(command);
    }
}
