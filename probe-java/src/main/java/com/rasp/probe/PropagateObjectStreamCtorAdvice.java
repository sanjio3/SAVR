package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 *
 * 背景：Java 原生反序列化 RCE 在平台上是「能报不能证」。其中一个断点是——攻击者可控的
 * 字节流（通常经 {@code Base64.decode} 得到 byte[]，再包成 ByteArrayInputStream）进入
 * {@code new ObjectInputStream(stream)} 之后，污点没有继续往里传：后续的
 * {@code resolveClass} 虽然被钩住（readObject 是 final 织不进去），但那条 advice 只做
 * {@code recordTaintHop}，不判断污点归属，于是 I1 无法证明「流入反序列化的是攻击者数据」。
 *
 * 本 advice 在构造器出口把流的污点标记传给 ObjectInputStream 实例本身，使
 * 「source(HTTP 参数) → Base64.decode → ObjectInputStream → 命令执行 sink」形成完整闭环。
 *
 * 关键约束（与 BootstrapGenericSinkAdvice 的分工）：
 * - 这里**绝不能**调 {@code onGenericSink}。ObjectInputStream 在链路里的角色是 transform
 *   （污点流经的桥接点），不是危险 sink；一旦被标成 sink，chain_conformance 的 transform
 *   匹配分支就找不到该节点，只剩 {@code sink|resolveClass}，丢失 transform 语义。
 * - 构造器 origin 是 {@code java.io.ObjectInputStream.<init>}，不在
 *   BootstrapGenericSinkAdvice 的反序列化白名单里，若误用该 advice 会直接落进 sink 分支。
 */
public final class PropagateObjectStreamCtorAdvice {
    private PropagateObjectStreamCtorAdvice() {
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onCtor(@Advice.Origin("#t.#m") String origin,
                              @Advice.Argument(0) Object input,
                              @Advice.This Object self) {
        if (self == null) {
            return;
        }
        // 记录 transform 跳点：供 I1 逐节点核对「反序列化确实发生」。
        TaintStore.recordTaintHop("transform", origin);
        if (input == null) {
            return;
        }
        // 真实污点传播：被标记的请求继续传播污点（RASP 数据流核心）。
        if (TaintStore.isRequestTainted()) {
            TaintStore.markFrom(self, input);
        }
    }
}
