package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: builder seeding constructor (java.base, bootstrap-injected).
 *
 * {@code StringBuilder(CharSequence)} / {@code StringBuffer(CharSequence)} /
 * {@code StringJoiner(CharSequence)}: the new builder inherits the taint of its backing
 * CharSequence. This is what keeps {@code new StringBuilder(tainted)} tainted so that a
 * later {@code toString()} (see {@link PropagateStringBuilderToStringAdvice}) propagates
 * the taint through a hand-written builder.
 *
 * <p>Deliberately a plain {@code @OnMethodExit} (no {@code onThrowable}/{@code suppress}):
 * ByteBuddy cannot wrap a constructor's super() call in a try/catch, so advice with
 * {@code onThrowable} on a constructor throws "Cannot catch exception during constructor
 * call" and fail-opens the whole StringBuilder/StringBuffer/StringJoiner transform.
 */
public final class PropagateStringBuilderCtorAdvice {
    private PropagateStringBuilderCtorAdvice() {
    }

    @Advice.OnMethodExit
    public static void onCtor(@Advice.This Object builder, @Advice.Argument(0) Object arg) {
        if (!TaintStore.isRequestTainted() || builder == null || arg == null) {
            return;
        }
        if (TaintStore.isHigh(arg)) {
            TaintStore.markHigh(builder);
        } else if (TaintStore.isLow(arg)) {
            TaintStore.markLow(builder);
        }
    }
}
