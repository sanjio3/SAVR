package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: String.concat (java.base, bootstrap-injected).
 *
 * "a".concat(b): the result is tainted if either operand is tainted. Catches the
 * explicit-concatenation bypass form of command/SQL injection.
 */
public final class PropagateStringConcatAdvice {
    private PropagateStringConcatAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onConcat(@Advice.This Object self, @Advice.Argument(0) Object other,
            @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        TaintStore.markFrom(result, self);
        TaintStore.markFrom(result, other);
    }
}
