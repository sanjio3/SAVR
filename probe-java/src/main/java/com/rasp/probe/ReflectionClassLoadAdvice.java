package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * L2 reflection sink — dynamic class loading (java.base, bootstrap-injected).
 *
 * {@code Class.forName(name)} / {@code ClassLoader.loadClass(name)} are blocked when the
 * class NAME itself is HIGH-tainted (手册 11.1.2 决策④ + 11.1.3 十·⑦). A tainted class
 * name only arises from attacker-controlled dynamic class loading, which is itself the
 * vulnerability; normal code uses constant class names that are never tainted, so this
 * is high-signal / low-false-positive.
 *
 * <p>Split from the old {@code ReflectionSinkAdvice}: ByteBuddy rejects a single advice
 * class with multiple {@code @OnMethodEnter} methods ("Duplicate advice"), which
 * fail-opened Class/ClassLoader/Method/Constructor transforms entirely. The observe-only
 * invoke/newInstance half lives in {@link ReflectionInvokeAdvice}.
 */
public final class ReflectionClassLoadAdvice {
    private ReflectionClassLoadAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object name) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        if (name instanceof String && TaintStore.isHigh((String) name)) {
            String s = (String) name;
            BootstrapBridge.reportTaint("RASP_BLOCKED_TAINT", origin, s);
            throw new SecurityException("Blocked by sec-agent RASP (taint-reflection): " + origin);
        }
    }
}
