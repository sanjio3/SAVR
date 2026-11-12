package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 反射字段级污点 — 写边.
 *
 * <p>{@code Field.set(owner, value)}: a tainted value stashed into a field makes the whole
 * container tainted, and the field name is kept as evidence. This is the edge that carries
 * user input across the "framework binds request body into a DTO" boundary — the DTO itself
 * becomes a tainted carrier, so the sink deep scan trips even when the sink receives the
 * object rather than the raw String.
 *
 * <p>Bootstrap-injected; references only the bootstrap {@link TaintStore}. Guarded by the
 * request-scoped short-circuit flag so an untainted request pays one ThreadLocal read.
 */
public final class ReflectFieldSetAdvice {
    private ReflectFieldSetAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onFieldSet(@Advice.This Object field,
                                  @Advice.Argument(0) Object owner,
                                  @Advice.Argument(1) Object value) {
        if (!TaintStore.isRequestTainted() || owner == null || value == null) {
            return;
        }
        TaintStore.propagateFieldWrite(owner, field, value);
    }
}
