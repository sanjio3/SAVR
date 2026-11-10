package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * 弱随机源 sink 专用 advice（取代 BootstrapGenericSinkAdvice）。
 *
 * <p>根因（OWASP BenchmarkTest00418 实证）：{@code java.security.SecureRandom extends
 * java.util.Random} 且未覆写 nextDouble/nextFloat/nextLong/nextInt/nextBoolean，ByteBuddy
 * 的 {@code named("java.util.Random")} 是**精确类型匹配**，挡不住继承调用 ——
 * {@code SecureRandom.getInstance("SHA1PRNG").nextDouble()} 会被错误地当成弱随机源上报，
 * 产生 weak_random 误报。
 *
 * <p>修复必须在 advice 内看 receiver 的**真实类型**：CSPRNG 子类一律跳过，不发射任何 sink
 * 事件。这是「sink 身份由运行时事实决定，而非静态声明」原则的落地（通用化 P2）。
 *
 * <p>注意：本 advice 不能复用 BootstrapGenericSinkAdvice，因为后者还被 Cipher.getInstance /
 * MessageDigest.getInstance 等**静态方法**复用，而 {@code @Advice.This} 在静态方法上不可用。
 */
public final class BootstrapRandomSourceAdvice {

    private BootstrapRandomSourceAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin,
                               @Advice.This Object self,
                               @Advice.AllArguments Object[] args) {
        // receiver 是密码学安全随机源（SecureRandom 及其任意子类，如 SHA1PRNG / NativePRNG /
        // DRBG）→ 不是弱随机源，直接跳过，不发射事件。
        if (self instanceof java.security.SecureRandom) {
            return;
        }
        BootstrapBridge.onGenericSink(origin, args);
    }
}
