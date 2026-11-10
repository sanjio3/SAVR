package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Marks the open/close of a Spring {@code @Transactional} boundary so the race
 * detector can note whether a read-modify-write happened inside a transaction.
 */
public final class TransactionAdvice {

    private TransactionAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter() {
        ConcurrencyContext.enter("txn@" + Thread.currentThread().getId());
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onExit() {
        ConcurrencyContext.exit("txn@" + Thread.currentThread().getId());
    }
}
