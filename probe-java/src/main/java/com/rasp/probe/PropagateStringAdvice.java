package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: derived String operations (java.base, bootstrap-injected).
 *
 * substring / replace / toUpperCase / toLowerCase: the produced String inherits
 * the taintedness of the receiver. Applied only to these named
 * methods so the matcher does not also catch concat/valueOf.
 */
public final class PropagateStringAdvice {
    private PropagateStringAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onDerived(@Advice.This Object self, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        TaintStore.markFrom(result, self);
    }
}
