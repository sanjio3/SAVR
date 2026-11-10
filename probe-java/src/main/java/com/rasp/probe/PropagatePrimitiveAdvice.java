package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: primitive parsing (java.base, bootstrap-injected).
 *
 * Integer/Long/Double.parseXxx with a tainted String source records the resulting
 * primitive value into the request-scoped numeric low-confidence edge table
 * (手册 11.1.7). Later String.valueOf(primitive) / builder.append(primitive) checks
 * that table so "WHERE id=" + Integer.parseInt(param) still carries taint.
 *
 * A single @OnMethodExit method serves all three parses: ByteBuddy boxes the
 * primitive return into the Object advice parameter, and we branch on its type.
 * (Splitting into three typed methods would re-trigger ByteBuddy's
 * "Duplicate advice" rule because they share the (Argument(0) + Return) role set.)
 *
 * Numeric taint is LOW confidence: it records only (never blocks) to avoid
 * false-blocking normal numeric parameters.
 */
public final class PropagatePrimitiveAdvice {
    private PropagatePrimitiveAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onParse(@Advice.Argument(0) Object input, @Advice.Return Object result) {
        if (!TaintStore.isRequestTainted() || input == null) {
            return;
        }
        if (!TaintStore.isTainted(input)) {
            return;
        }
        if (result instanceof Integer) {
            Integer i = (Integer) result;
            TaintStore.markPrimitiveLow(i.intValue());
        } else if (result instanceof Long) {
            Long l = (Long) result;
            TaintStore.markPrimitiveLow(l.longValue());
        } else if (result instanceof Double) {
            Double d = (Double) result;
            TaintStore.markPrimitiveLow((long) d.doubleValue());
        }
    }
}
