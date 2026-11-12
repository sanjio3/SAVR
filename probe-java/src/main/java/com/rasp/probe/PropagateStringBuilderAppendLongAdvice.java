package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringBuilder/StringBuffer.append(long) (java.base, bootstrap-injected).
 *
 * Numeric-low edge — see PropagateStringBuilderAppendIntAdvice. Own class
 * because the (This + Argument(0)) role set collides with the int variant and
 * PropagateStringBuilderAdvice.onAppend under ByteBuddy's single-binding-per-role-set rule.
 */
public final class PropagateStringBuilderAppendLongAdvice {
    private PropagateStringBuilderAppendLongAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onAppendLong(@Advice.This Object builder, @Advice.Argument(0) long v) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (TaintStore.isPrimitiveLow(v)) {
            TaintStore.markLow(builder);
        }
    }
}
