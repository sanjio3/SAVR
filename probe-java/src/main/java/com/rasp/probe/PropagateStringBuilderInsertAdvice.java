package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringBuilder/StringBuffer.insert(int, X) (java.base, bootstrap-injected).
 * The inserted content sits at argument 1; mark the builder from itself or the inserted value.
 */
public final class PropagateStringBuilderInsertAdvice {
    private PropagateStringBuilderInsertAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onInsert(@Advice.This Object builder, @Advice.Argument(1) Object arg,
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
