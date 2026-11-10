package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * 参数化查询感知 — 参数绑定边 (手册 11.1.5 一).
 *
 * <p>{@code PreparedStatement.setString/setNString/setObject/setBytes(index, value)}: records
 * the bound value at its parameter position, and whether that value is tainted. The taint flag
 * is evidence only — a tainted parameter on a clean template is reported as
 * {@code SQL_PARAMETERIZED_SAFE} and never blocks (see {@link HookRuntime#onPreparedSink}).
 *
 * <p>Only the reference-typed setters are hooked: the numeric setters carry no injectable
 * content and hooking them would add cost on every ORM write for no detection value.
 */
public final class PreparedParameterAdvice {
    private PreparedParameterAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.This Object statement,
                               @Advice.Argument(0) int index,
                               @Advice.Argument(1) Object value) {
        HookRuntime.rememberPreparedParameter(statement, index, value);
    }
}
