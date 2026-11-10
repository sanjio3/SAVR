package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 反射字段级污点 — 读边 (手册 11.1.3 十.1).
 *
 * <p>{@code Field.get(owner)}: pulling a value back out of a tainted container yields a
 * tainted value. Without this edge the taint chain breaks at every POJO / DTO that
 * framework code (Jackson databind, Spring data binding, BeanUtils) populates and then
 * reads back reflectively — user input goes in, comes out "clean", and reaches the sink
 * unmarked.
 *
 * <p>Bootstrap-injected ({@code java.lang.reflect.Field} lives in java.base) and references
 * only the bootstrap {@link TaintStore}. Hot path: {@code Field.get} is called constantly by
 * frameworks, so the very first check is the request-scoped short-circuit flag — on an
 * untainted request this advice costs a single ThreadLocal read.
 *
 * <p>ByteBuddy 硬约束: exactly one @OnMethodExit per advice class (a second one aborts the
 * whole type transform), hence the read/write edges are two separate classes.
 */
public final class ReflectFieldGetAdvice {
    private ReflectFieldGetAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onFieldGet(@Advice.This Object field,
                                  @Advice.Argument(0) Object owner,
                                  @Advice.Return Object value) {
        if (!TaintStore.isRequestTainted() || owner == null || value == null) {
            return;
        }
        TaintStore.propagateFieldRead(owner, field, value);
    }
}
