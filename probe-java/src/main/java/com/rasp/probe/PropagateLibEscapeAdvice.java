package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 净化器感知 (手册 11.1.5 二 / 11.1.8 ③).
 *
 * <p>A sanitizer does NOT make a value universally safe: {@code escapeHtml4("1 or 1=1")}
 * is harmless in a response body yet still lethal inside a SQL statement. The previous
 * implementation blanket-cleared the taint ({@code TaintStore.unmark}), which silently
 * created a bypass — escape-then-concat-into-SQL became invisible to L2. Worse, a
 * commons-text escaper returns the SAME instance when there is nothing to escape, so the
 * blanket clear stripped the taint off the original source value.
 *
 * <p>Now the taint is KEPT and the sanitizer decision is recorded with (a) the sanitizer
 * identity for 溯源 and (b) the sink families it actually neutralizes, so
 * {@link TaintGate} can decide per sink family (分治). An unrecognized sanitizer maps to
 * the empty family set — it defuses nothing, the safe default.
 *
 * <p>Installed via {@code baseBuilder()} (UsingUnsafe injection) on application-classloader
 * types (commons-text / commons-lang3 / Spring HtmlUtils); references the bootstrap
 * {@link TaintStore}. The paired {@code unescape*} methods stay in
 * {@link PropagateLibStringAdvice} — they re-introduce raw dangerous content and must
 * inherit taint normally.
 */
public final class PropagateLibEscapeAdvice {
    private PropagateLibEscapeAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onEscaped(@Advice.Origin("#t.#m") String origin,
                                 @Advice.Argument(0) Object input,
                                 @Advice.Return Object result) {
        if (result == null) {
            return;
        }
        TaintStore.markFrom(result, input);
        TaintStore.markSanitized(result, origin, TaintStore.familiesForSanitizer(origin));
    }
}
