package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.valueOf(long) (java.base, bootstrap-injected).
 *
 * Numeric-low edge (11.1.7) — see PropagateValueOfIntAdvice. Own class because it
 * shares the (Argument(0) + Return) role set with the int variant and
 * PropagateValueOfObjectAdvice under ByteBuddy's rule.
 */
public final class PropagateValueOfLongAdvice {
    private PropagateValueOfLongAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onValueOfLong(@Advice.Argument(0) long v, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        if (TaintStore.isPrimitiveLow(v)) {
            TaintStore.markLow(result);
        }
    }
}
