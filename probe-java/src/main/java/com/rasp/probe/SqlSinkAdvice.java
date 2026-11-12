package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class SqlSinkAdvice {
    private SqlSinkAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object sql) {
        // Route through the L2 taint gate: a non-parameterized SQL string built from
        // tainted (user) input must be intercepted on the data-flow, not just by the L1
        // signature. Taint-free SQL (e.g. a constant template) falls through to the
        // signature layer via onSink, so parameterized queries are unaffected.
        HookRuntime.onGenericSink(origin, new Object[]{sql});
    }
}

