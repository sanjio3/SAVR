package com.rasp.probe;

import java.util.ArrayList;
import java.util.List;

/**
 * Tracks the concurrency scopes currently active on the executing thread
 * (an open {@code @Transactional} boundary and/or a held {@code ReentrantLock}).
 * Used only to enrich {@code RACE_SUSPECT} events with context — a read-modify-write
 * that is correctly guarded by a transaction or lock is far less likely to be a
 * real race, so the scope list helps triage.
 */
public final class ConcurrencyContext {

    private static final ThreadLocal<List<String>> SCOPES = ThreadLocal.withInitial(ArrayList::new);

    private ConcurrencyContext() {
    }

    public static void enter(String scope) {
        SCOPES.get().add(scope);
    }

    public static void exit(String scope) {
        SCOPES.get().remove(scope);
    }

    static List<String> snapshot() {
        return new ArrayList<>(SCOPES.get());
    }

    static void clear() {
        SCOPES.remove();
    }
}
