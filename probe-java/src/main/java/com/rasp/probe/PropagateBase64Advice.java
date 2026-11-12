package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 propagation: java.util.Base64 decoder/encoder (java.base, bootstrap-injected).
 *
 * decode(String|byte[]) and encode(byte[]|String) carry the tainted input through to
 * the output (byte[] or String). Catches Base64-obfuscated injection payloads that
 * survive a round-trip through Base64 before reaching the sink.
 */
public final class PropagateBase64Advice {
    private PropagateBase64Advice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onCodec(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object input, @Advice.Return Object result) {
        if (result == null || input == null) {
            return;
        }
        // 真实污点传播：被标记的请求继续传播污点（RASP 数据流核心）。
        if (TaintStore.isRequestTainted()) {
            TaintStore.markFrom(result, input);
        }
        // 记录 transform 跳点，供 sink 时刻序列化 taint_path 数据流证据链。
        TaintStore.recordTaintHop("transform", origin);
    }
}
