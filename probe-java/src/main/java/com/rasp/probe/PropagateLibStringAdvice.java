package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation for third-party library string transformations.
 *
 * Covers the common shape of a static/instance utility transform whose primary
 * subject is {@code argument 0} (a String / CharSequence), e.g.
 * {@code StringUtils.replace(text, ...)}, {@code Joiner.join(elements)},
 * {@code CharMatcher.retainFrom(input)}, {@code FilenameUtils.normalize(path)}.
 *
 * The produced value inherits the taint of its subject. When the subject is a
 * container (array / Iterable / Map) — as in {@code join} / {@code
 * collectionToDelimitedString} — the taint is read from its elements, so a List
 * of tainted Strings yields a tainted joined result.
 *
 * <p>Installed via {@code baseBuilder} (UsingUnsafe injection) on application-
 * classloader types, so the advice is loaded into the target class loader and
 * shares the bootstrap {@link TaintStore} with every other hook.
 */
public final class PropagateLibStringAdvice {
    private PropagateLibStringAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onArg0(@Advice.Argument(0) Object subject, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || result == null) {
            return;
        }
        boolean high = isTaintedDeep(subject, true);
        boolean low = !high && isTaintedDeep(subject, false);
        if (high) {
            TaintStore.markHigh(result);
        } else if (low) {
            TaintStore.markLow(result);
        }
    }

    private static boolean isTaintedDeep(Object o, boolean high) {
        if (o == null) {
            return false;
        }
        if (high ? TaintStore.isHigh(o) : TaintStore.isLow(o)) {
            return true;
        }
        if (o instanceof Object[]) {
            for (Object e : (Object[]) o) {
                if (isTaintedDeep(e, high)) {
                    return true;
                }
            }
        } else if (o instanceof Iterable) {
            for (Object e : (Iterable<?>) o) {
                if (isTaintedDeep(e, high)) {
                    return true;
                }
            }
        } else if (o instanceof java.util.Map) {
            for (Object e : ((java.util.Map<?, ?>) o).values()) {
                if (isTaintedDeep(e, high)) {
                    return true;
                }
            }
        }
        return false;
    }
}
