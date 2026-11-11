package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class BootstrapGenericSinkAdvice {
    private BootstrapGenericSinkAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.AllArguments Object[] args) {
        // 方案 B：反序列化 resolveClass / readObject 等作为「桥接 transform 跳点」记录，
        // 供 sink 时刻还原完整数据流证据链。它是传播/桥接语义点，不是危险 sink，故只记
        // transform 跳点、不进 onGenericSink——否则会被 onGenericSink 再标成 sink，导致 chain_conformance
        // 的 transform 匹配分支找不到该节点。
        TaintStore.recordTaintHop("transform", origin);
        if (!"java.io.ObjectInputStream.resolveClass".equals(origin)
                && !"java.io.ObjectInputStream.readObject".equals(origin)
                && !"java.io.ObjectInputStream.readUnshared".equals(origin)) {
            BootstrapBridge.onGenericSink(origin, args);
        }
    }
}
