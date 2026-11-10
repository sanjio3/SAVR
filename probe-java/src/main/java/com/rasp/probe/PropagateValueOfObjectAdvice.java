package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.valueOf(Object) and String.valueOf(char[]) (java.base,
 * bootstrap-injected). The produced String inherits the argument's taint. (The
 * numeric overloads valueOf(int)/valueOf(long) carry the 11.1.7 low-confidence
 * primitive edge and live in their own classes — ByteBuddy forbids two
 * @OnMethodExit methods sharing the (Argument(0) + Return) role set in one class.)
 */
public final class PropagateValueOfObjectAdvice {
    private PropagateValueOfObjectAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onValueOf(@Advice.Argument(0) Object arg, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        TaintStore.markFrom(result, arg);
    }
}
