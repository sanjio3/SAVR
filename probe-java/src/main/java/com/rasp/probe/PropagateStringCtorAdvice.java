package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: data-bearing String constructors (java.base, bootstrap-injected).
 *
 * String(String)/String(char[])/String(byte[]): the produced String inherits the taint of
 * its backing argument. This is what keeps a tainted byte[] (e.g. from Base64.decode)
 * tainted after `new String(decoded)`.
 *
 * <p>NOTE: {@code @OnMethodExit} here deliberately has NO {@code onThrowable}/{@code
 * suppress} — ByteBuddy cannot wrap a constructor's super call in a try/catch, so
 * suppress-based advice on a constructor throws "Cannot catch exception during
 * constructor call" and fail-opens the whole String transform.
 */
public final class PropagateStringCtorAdvice {
    private PropagateStringCtorAdvice() {
    }

    @Advice.OnMethodExit
    public static void onCtor(@Advice.Origin("#t.#m") String origin, @Advice.This Object self, @Advice.Argument(0) Object arg) {
        if (self == null || arg == null) {
            return;
        }
        if (TaintStore.isRequestTainted()) {
            TaintStore.markFrom(self, arg);
        }
        // 记录 transform 跳点，供 sink 时刻序列化 taint_path 数据流证据链。
        TaintStore.recordTaintHop("transform", origin);
    }
}
