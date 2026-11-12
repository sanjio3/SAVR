package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringBuilder/StringBuffer.substring(...) (java.base, bootstrap-injected).
 * Returns a NEW String derived from this' content; mark it from this.
 */
public final class PropagateStringBuilderSubstringAdvice {
    private PropagateStringBuilderSubstringAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onSubstring(@Advice.This Object builder, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        TaintStore.markFrom(result, builder);
    }
}
