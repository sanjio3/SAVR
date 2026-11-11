package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.format (java.base, bootstrap-injected).
 *
 * format("... %s ...", taintedArg): the produced String is tainted if the format
 * string OR any argument is tainted. Catches the String.format SQL/command
 * construction bypass form.
 */
public final class PropagateStringFormatAdvice {
    private PropagateStringFormatAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onFormat(@Advice.Argument(0) Object fmt, @Advice.Argument(1) Object args,
            @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        boolean high = TaintStore.isHigh(fmt) || TaintStore.isHighAny(toArray(args));
        boolean low = TaintStore.isLow(fmt) || TaintStore.isLowAny(toArray(args));
        if (high) {
            TaintStore.markHigh(result);
        } else if (low) {
            TaintStore.markLow(result);
        }
    }

    private static Object[] toArray(Object args) {
        if (args instanceof Object[]) {
            return (Object[]) args;
        }
        return null;
    }
}
