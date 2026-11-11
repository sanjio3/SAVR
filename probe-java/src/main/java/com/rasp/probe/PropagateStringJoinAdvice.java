package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.join (java.base, bootstrap-injected).
 *
 * join(delim, a, b, c) / join(delim, iterable): the produced String is tainted if
 * the delimiter OR any joined element is tainted. Catches join-based SQL/command
 * construction bypass.
 */
public final class PropagateStringJoinAdvice {
    private PropagateStringJoinAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onJoin(@Advice.Argument(0) Object delim, @Advice.Argument(1) Object parts,
            @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        boolean high = TaintStore.isHigh(delim) || taintedAny(parts, true);
        boolean low = TaintStore.isLow(delim) || taintedAny(parts, false);
        if (high) {
            TaintStore.markHigh(result);
        } else if (low) {
            TaintStore.markLow(result);
        }
    }

    private static boolean taintedAny(Object parts, boolean high) {
        if (parts instanceof Object[]) {
            for (Object o : (Object[]) parts) {
                if (o != null && (high ? TaintStore.isHigh(o) : TaintStore.isLow(o))) {
                    return true;
                }
            }
            return false;
        }
        if (parts instanceof Iterable) {
            for (Object o : (Iterable<?>) parts) {
                if (o != null && (high ? TaintStore.isHigh(o) : TaintStore.isLow(o))) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }
}
