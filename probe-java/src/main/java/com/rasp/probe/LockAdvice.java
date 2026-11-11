package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Marks the acquire/release of a {@code ReentrantLock} so the race detector can
 * note whether a read-modify-write was guarded by an explicit lock.
 */
public final class LockAdvice {

    private LockAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onLock(@Advice.This Object lock) {
        ConcurrencyContext.enter("lock@" + System.identityHashCode(lock));
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onUnlock(@Advice.This Object lock) {
        ConcurrencyContext.exit("lock@" + System.identityHashCode(lock));
    }
}
