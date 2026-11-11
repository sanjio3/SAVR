package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringBuilder/StringBuffer.append(int) (java.base, bootstrap-injected).
 *
 * Numeric-low edge: a tainted numeric value (parsed from user input) recorded
 * in the request-scoped primitive-low table re-taints the builder LOW so a later
 * String rebuild still carries taint. Kept in its own class because the (This +
 * Argument(0)) role set collides with PropagateStringBuilderAdvice.onAppend and the
 * long variant under ByteBuddy's single-binding-per-role-set rule.
 */
public final class PropagateStringBuilderAppendIntAdvice {
    private PropagateStringBuilderAppendIntAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onAppendInt(@Advice.This Object builder, @Advice.Argument(0) int v) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (TaintStore.isPrimitiveLow(v)) {
            TaintStore.markLow(builder);
        }
    }
}
