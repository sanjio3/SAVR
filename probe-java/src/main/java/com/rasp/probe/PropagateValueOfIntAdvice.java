package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.valueOf(int) (java.base, bootstrap-injected).
 *
 * Numeric-low edge: if the int value was parsed from a tainted String the
 * primitive-low table flags it, so the valueOf result is re-marked LOW (observe-only,
 * never blocks). Own class because it shares the (Argument(0) + Return) role set with
 * the long variant and PropagateValueOfObjectAdvice under ByteBuddy's rule.
 */
public final class PropagateValueOfIntAdvice {
    private PropagateValueOfIntAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onValueOfInt(@Advice.Argument(0) int v, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        if (TaintStore.isPrimitiveLow(v)) {
            TaintStore.markLow(result);
        }
    }
}
