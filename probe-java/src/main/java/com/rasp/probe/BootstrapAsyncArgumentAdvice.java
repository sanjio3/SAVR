package com.rasp.probe;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

public final class BootstrapAsyncArgumentAdvice {
    private BootstrapAsyncArgumentAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.AllArguments(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object[] args) {
        for (int index = 0; index < args.length; index++) {
            args[index] = BootstrapBridge.wrapAsyncArgument(args[index]);
        }
    }
}
