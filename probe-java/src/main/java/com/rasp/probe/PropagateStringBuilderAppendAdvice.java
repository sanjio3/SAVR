package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: mutable builder append / seeding (java.base, bootstrap-injected).
 *
 * Covers {@code append(CharSequence/String/Object/char[])} on StringBuilder/StringBuffer,
 * {@code add(CharSequence)} on StringJoiner, and the {@code (CharSequence)} constructors
 * (which seed a new builder from its argument). The builder inherits the taint of the
 * appended argument (or keeps an existing taint).
 *
 * <p>Split from the old {@code PropagateStringBuilderAdvice}: ByteBuddy rejects any
 * advice class carrying two {@code @OnMethodExit} methods with "Duplicate advice", which
 * fail-opened the whole StringBuilder/StringBuffer/StringJoiner transform. The
 * {@code toString} half lives in {@link PropagateStringBuilderToStringAdvice}.
 */
public final class PropagateStringBuilderAppendAdvice {
    private PropagateStringBuilderAppendAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onAppend(@Advice.This Object builder, @Advice.Argument(0) Object arg) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (TaintStore.isHigh(builder) || TaintStore.isHigh(arg)) {
            TaintStore.markHigh(builder);
        } else if (TaintStore.isLow(builder) || TaintStore.isLow(arg)) {
            TaintStore.markLow(builder);
        }
    }
}
