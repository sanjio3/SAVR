package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: decoding sinks (java.base, bootstrap-injected).
 *
 * URLDecoder.decode is the canonical encoding-bypass path (手册 11.1.3 七 / 11.1.8).
 * If the input string is tainted, the decoded result is tainted too, defeating
 * double-URL / percent / etc. obfuscation at the data level.
 */
public final class PropagateDecodeAdvice {
    private PropagateDecodeAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onDecode(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object input, @Advice.Return Object result) {
        if (input == null || result == null) {
            return;
        }
        if (TaintStore.isRequestTainted()) {
            TaintStore.markFrom(result, input);
        }
        // 记录 transform 跳点，供 sink 时刻序列化 taint_path 数据流证据链。
        TaintStore.recordTaintHop("transform", origin);
    }
}
