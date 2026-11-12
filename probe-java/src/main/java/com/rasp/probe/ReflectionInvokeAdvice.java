package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 reflection sink — observe-only invoke/newInstance (java.base, bootstrap-injected).
 *
 * {@code Method.invoke} / {@code Constructor.newInstance} are OBSERVE-ONLY. Blocking on a
 * tainted argument would be catastrophic (the JDK/Spring invoke controller methods with
 * parsed request parameters as arguments), so we only report (telemetry) when the
 * receiver (invoke) or a String argument (newInstance) is tainted — a rare, higher-signal
 * signal — and never throw. The classic reflection-RCE is caught by the {@code Runtime.exec}
 * sink regardless of how it was dispatched.
 *
 * <p>Split from the old {@code ReflectionSinkAdvice}: one {@code @OnMethodEnter} per class.
 * A single {@code @Argument(0)} binding dispatches on the argument shape — an Object[] is
 * {@code Constructor.newInstance(args)}; a scalar is {@code Method.invoke(receiver)}.
 */
public final class ReflectionInvokeAdvice {
    private ReflectionInvokeAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object arg0) {
        if (!TaintStore.isRequestTainted() || arg0 == null) {
            return;
        }
        if (arg0 instanceof Object[]) {
            Object[] arr = (Object[]) arg0;
            // Constructor.newInstance(Object[] args): report any tainted String argument.
            for (Object a : arr) {
                if (a instanceof String && TaintStore.isHigh((String) a)) {
                    String s = (String) a;
                    BootstrapBridge.reportTaint("TAINT_FLOW", origin, s);
                    return;
                }
            }
        } else if (TaintStore.isHigh(arg0)) {
            // Method.invoke(Object receiver): report a tainted receiver (rare/high-signal).
            BootstrapBridge.reportTaint("TAINT_FLOW", origin, String.valueOf(arg0));
        }
    }
}
