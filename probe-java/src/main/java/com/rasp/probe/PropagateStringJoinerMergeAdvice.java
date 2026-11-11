package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: StringJoiner.merge(StringJoiner) (java.base, bootstrap-injected).
 * The merged joiner's content (argument 0) flows into this; mark this from itself or
 * the other joiner.
 */
public final class PropagateStringJoinerMergeAdvice {
    private PropagateStringJoinerMergeAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onMerge(@Advice.This Object self, @Advice.Argument(0) Object other,
            @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (TaintStore.isHigh(self) || TaintStore.isHigh(other)) {
            TaintStore.markHigh(self);
        } else if (TaintStore.isLow(self) || TaintStore.isLow(other)) {
            TaintStore.markLow(self);
        }
    }
}
