package com.rasp.probe;

import com.alibaba.ttl.TtlCallable;
import com.alibaba.ttl.TtlRunnable;

import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Async task wrapping for RASP (手册 11.1.3 二 / 十.9).
 *
 * <p>Two orthogonal scopes must survive a thread-pool handoff:
 * <ol>
 *   <li><b>Semantic scope</b> (principal, authz/race correlation) — carried by
 *       TransmittableThreadLocal via {@link TtlRunnable}/{@link TtlCallable}, which replays
 *       the captured scope inside the pool thread and restores it afterwards.</li>
 *   <li><b>Data-flow scope</b> — the taint marks themselves ride on object identity in a
 *       global table and therefore need NO snapshot; what does NOT cross the boundary is the
 *       per-thread short-circuit flag {@code REQUEST_TAINTED} and the requestId binding that
 *       gives access to the request's content shadow. Without re-raising them on the pool
 *       thread, {@link TaintGate} returns immediately ("clean request") and every sink reached
 *       asynchronously is a blind spot.</li>
 * </ol>
 *
 * <p>The functional-interface variants (Supplier/Function/Consumer/BiFunction/BiConsumer) are
 * the CompletableFuture chain (thenApply / thenAccept / thenCombine) and the parallelStream
 * ForkJoinPool path. They were previously no-ops, so the whole reactive/async surface lost L2
 * entirely; they now carry the data-flow scope.
 *
 * <p>Restore discipline: a pooled thread is returned to exactly the state it had before the
 * task ran ({@link TaintStore#detachThread()} when it was unbound), so a tainted request can
 * never bleed into the next task that reuses the thread. The originating request's归集 shadow
 * is deliberately NOT dropped here — that request is still running on its own thread.
 */
public final class AsyncContext {
    private AsyncContext() {
    }

    public static Runnable wrap(Runnable runnable) {
        if (runnable == null) {
            return null;
        }
        // idempotent=true so nested async hooks that re-wrap the same task return the
        // existing decorator instead of throwing.
        Runnable taintAware = new TaintAwareRunnable(runnable, Scope.capture());
        TtlRunnable wrapped = TtlRunnable.get(taintAware, false, true);
        return wrapped == null ? taintAware : wrapped;
    }

    public static <T> Callable<T> wrap(Callable<T> callable) {
        if (callable == null) {
            return null;
        }
        Callable<T> taintAware = new TaintAwareCallable<>(callable, Scope.capture());
        TtlCallable<T> wrapped = TtlCallable.get(taintAware, false, true);
        return wrapped == null ? taintAware : wrapped;
    }

    public static <T> Supplier<T> wrap(Supplier<T> supplier) {
        if (supplier == null) {
            return null;
        }
        Scope scope = Scope.capture();
        if (scope == null) {
            return supplier;
        }
        return () -> {
            Scope previous = scope.enter();
            try {
                return supplier.get();
            } finally {
                Scope.leave(previous);
            }
        };
    }

    public static <T, R> Function<T, R> wrap(Function<T, R> function) {
        if (function == null) {
            return null;
        }
        Scope scope = Scope.capture();
        if (scope == null) {
            return function;
        }
        return t -> {
            Scope previous = scope.enter();
            try {
                return function.apply(t);
            } finally {
                Scope.leave(previous);
            }
        };
    }

    public static <T> Consumer<T> wrap(Consumer<T> consumer) {
        if (consumer == null) {
            return null;
        }
        Scope scope = Scope.capture();
        if (scope == null) {
            return consumer;
        }
        return t -> {
            Scope previous = scope.enter();
            try {
                consumer.accept(t);
            } finally {
                Scope.leave(previous);
            }
        };
    }

    public static <T, U, R> BiFunction<T, U, R> wrap(BiFunction<T, U, R> function) {
        if (function == null) {
            return null;
        }
        Scope scope = Scope.capture();
        if (scope == null) {
            return function;
        }
        return (t, u) -> {
            Scope previous = scope.enter();
            try {
                return function.apply(t, u);
            } finally {
                Scope.leave(previous);
            }
        };
    }

    public static <T, U> BiConsumer<T, U> wrap(BiConsumer<T, U> consumer) {
        if (consumer == null) {
            return null;
        }
        Scope scope = Scope.capture();
        if (scope == null) {
            return consumer;
        }
        return (t, u) -> {
            Scope previous = scope.enter();
            try {
                consumer.accept(t, u);
            } finally {
                Scope.leave(previous);
            }
        };
    }

    /**
     * Immutable capture of the data-flow scope of the submitting thread. {@code capture()}
     * returns null on an untainted thread so a clean request pays no wrapper at all.
     */
    private static final class Scope {
        private final String requestId;
        private final boolean tainted;

        private Scope(String requestId, boolean tainted) {
            this.requestId = requestId;
            this.tainted = tainted;
        }

        static Scope capture() {
            try {
                String requestId = TaintStore.currentRequestId();
                boolean tainted = TaintStore.isRequestTainted();
                if (requestId == null && !tainted) {
                    return null;
                }
                return new Scope(requestId, tainted);
            } catch (Throwable ignored) {
                return null;
            }
        }

        /** Install this scope on the current thread, returning the scope it replaced. */
        Scope enter() {
            Scope previous;
            try {
                previous = new Scope(TaintStore.currentRequestId(), TaintStore.isRequestTainted());
                if (requestId != null) {
                    TaintStore.bindRequest(requestId);
                }
                TaintStore.setRequestTainted(tainted);
            } catch (Throwable ignored) {
                return null;
            }
            return previous;
        }

        static void leave(Scope previous) {
            try {
                if (previous == null || (previous.requestId == null && !previous.tainted)) {
                    TaintStore.detachThread();
                    return;
                }
                TaintStore.detachThread();
                if (previous.requestId != null) {
                    TaintStore.bindRequest(previous.requestId);
                }
                TaintStore.setRequestTainted(previous.tainted);
            } catch (Throwable ignored) {
            }
        }
    }

    private static final class TaintAwareRunnable implements Runnable {
        private final Runnable delegate;
        private final Scope scope;

        private TaintAwareRunnable(Runnable delegate, Scope scope) {
            this.delegate = delegate;
            this.scope = scope;
        }

        @Override
        public void run() {
            if (scope == null) {
                delegate.run();
                return;
            }
            Scope previous = scope.enter();
            try {
                delegate.run();
            } finally {
                Scope.leave(previous);
            }
        }
    }

    private static final class TaintAwareCallable<T> implements Callable<T> {
        private final Callable<T> delegate;
        private final Scope scope;

        private TaintAwareCallable(Callable<T> delegate, Scope scope) {
            this.delegate = delegate;
            this.scope = scope;
        }

        @Override
        public T call() throws Exception {
            if (scope == null) {
                return delegate.call();
            }
            Scope previous = scope.enter();
            try {
                return delegate.call();
            } finally {
                Scope.leave(previous);
            }
        }
    }
}
