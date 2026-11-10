package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class ExecutorRunnableAdvice {
    private ExecutorRunnableAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Argument(value = 0, readOnly = false) Runnable command) {
        command = HookRuntime.wrapRunnable(command);
    }
}
