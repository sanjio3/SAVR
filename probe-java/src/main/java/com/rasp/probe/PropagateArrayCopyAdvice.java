package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 数组重组传播 (手册 11.1.3 十.5).
 *
 * <p>{@code Arrays.copyOf / Arrays.copyOfRange}: the fresh array must inherit the source
 * taint — both the array-level mark and the per-element marks — otherwise a tainted
 * {@code byte[]} / {@code char[]} / {@code Object[]} that is resized or sliced (the normal
 * shape of "read the request body into a buffer, then trim it") arrives at the sink
 * completely clean.
 *
 * <p>Scope note: {@code System.arraycopy} and {@code array.clone} are native/intrinsic and
 * therefore NOT instrumentable — ByteBuddy cannot weave a native method. The
 * {@code Arrays.*} helpers are ordinary Java code and cover the overwhelming majority of
 * real reorganisations, because the JDK's own copy helpers funnel through them. Values that
 * escape through the native path are still recovered by the content shadow
 * ({@link TaintStore#markHighCarrier}).
 *
 * <p>Bootstrap-injected; references only the bootstrap {@link TaintStore}.
 */
public final class PropagateArrayCopyAdvice {
    private PropagateArrayCopyAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onArrayCopy(@Advice.Argument(0) Object source, @Advice.Return Object copy) {
        if (!TaintStore.isRequestTainted() || source == null || copy == null) {
            return;
        }
        TaintStore.markArrayFrom(copy, source);
    }
}
