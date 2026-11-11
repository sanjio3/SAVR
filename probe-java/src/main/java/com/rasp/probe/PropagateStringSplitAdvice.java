package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.split (java.base, bootstrap-injected).
 *
 * split returns NEW Strings derived from this' content; if this is tainted the
 * fragments inherit its taint (e.g. id.split(" ")[0] still flows to a sink).
 */
public final class PropagateStringSplitAdvice {
    private PropagateStringSplitAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onSplit(@Advice.This Object self, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        if (!(result instanceof Object[])) {
            return;
        }
        Object[] frags = (Object[]) result;
        if (TaintStore.isHigh(self)) {
            for (Object frag : frags) {
                if (frag != null) {
                    TaintStore.markHigh(frag);
                }
            }
        } else if (TaintStore.isLow(self)) {
            for (Object frag : frags) {
                if (frag != null) {
                    TaintStore.markLow(frag);
                }
            }
        }
    }
}
