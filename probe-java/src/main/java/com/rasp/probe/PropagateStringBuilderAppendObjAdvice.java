package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringBuilder/StringBuffer.append(Object|boolean|char|float|double)
 * and appendCodePoint(int) (java.base, bootstrap-injected). The new content sits at
 * argument 0.
 */
public final class PropagateStringBuilderAppendObjAdvice {
    private PropagateStringBuilderAppendObjAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onAppend(@Advice.This Object builder, @Advice.Argument(0) Object arg,
            @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (TaintStore.isHigh(builder) || TaintStore.isHigh(arg)) {
            TaintStore.markHigh(builder);
        } else if (TaintStore.isLow(builder) || TaintStore.isLow(arg)) {
            TaintStore.markLow(builder);
        }
    }
}
