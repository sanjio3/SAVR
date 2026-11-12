package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: mutable builder {@code toString} (java.base, bootstrap-injected).
 *
 * The String produced by {@code StringBuilder/StringBuffer/StringJoiner.toString}
 * inherits the builder's confidence. Split from the old
 * {@code PropagateStringBuilderAdvice} so each {@code @OnMethodExit} lives in its own
 * class (ByteBuddy rejects two {@code @OnMethodExit} methods in one class with
 * "Duplicate advice" and fail-opens the whole type transform).
 */
public final class PropagateStringBuilderToStringAdvice {
    private PropagateStringBuilderToStringAdvice() {
    }

    @Advice.OnMethodExit
    public static void onToString(@Advice.This Object builder, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        if (TaintStore.isHigh(builder)) {
            TaintStore.markHigh(result);
        } else if (TaintStore.isLow(builder)) {
            TaintStore.markLow(result);
        }
    }
}
