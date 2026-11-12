package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringBuilder/StringBuffer.replace(int, int, String) (java.base).
 * The new content sits at argument 2; mark the builder from itself or the replacement.
 */
public final class PropagateStringBuilderReplaceAdvice {
    private PropagateStringBuilderReplaceAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onReplace(@Advice.This Object builder, @Advice.Argument(2) Object replacement,
            @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (TaintStore.isHigh(builder) || TaintStore.isHigh(replacement)) {
            TaintStore.markHigh(builder);
        } else if (TaintStore.isLow(builder) || TaintStore.isLow(replacement)) {
            TaintStore.markLow(builder);
        }
    }
}
