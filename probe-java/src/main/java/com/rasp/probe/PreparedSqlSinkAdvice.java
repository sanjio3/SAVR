package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class PreparedSqlSinkAdvice {
    private PreparedSqlSinkAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.This Object statement) {
        HookRuntime.onPreparedSink(origin, statement);
    }
}
