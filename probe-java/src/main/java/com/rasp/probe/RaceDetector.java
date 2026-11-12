package com.rasp.probe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cross-thread Time-Of-Check-Time-Of-Use (TOCTOU) detector for the semantic RASP layer.
 *
 * <p>Business-logic race conditions (e.g. concurrent read-modify-write on the same
 * entity without a lock / atomic update) are invisible to taint tracking. This
 * detector watches repository access on a <b>resource key</b> (entityType:id):
 *
 * <ul>
 *   <li>{@link #recordRead} — a thread opened a read on the resource (e.g. findById).</li>
 *   <li>{@link #recordWrite} — a thread is about to write the resource (e.g. save/delete).
 *       If another, <i>different</i> thread still holds an open read on the same
 *       resource, that is a classic check-then-act window shared across threads
 *       and we raise {@code RACE_SUSPECT}.</li>
 * </ul>
 *
 * <p>The "open read" is held until the owning thread performs its own write (which
 * closes it) or a TTL expires, so a single thread's own read-modify-write is never
 * flagged — only genuinely concurrent access across threads.
 *
 * <p>State is bounded: entries are pruned by a short TTL on every write, so memory
 * stays flat under steady traffic. This is a heuristic prototype, not a formal
 * happens-before analysis.
 */
public final class RaceDetector {

    private static final long TTL_MILLIS = 1500;

    // resourceKey -> (threadId -> read timestamp)
    private static final Map<String, Map<Long, Long>> OPEN_READERS = new ConcurrentHashMap<>();

    private RaceDetector() {
    }

    static void recordRead(String resourceKey) {
        if (resourceKey == null || resourceKey.isBlank()) {
            return;
        }
        long now = System.currentTimeMillis();
        OPEN_READERS
                .computeIfAbsent(resourceKey, k -> new ConcurrentHashMap<>())
                .put(Thread.currentThread().getId(), now);
    }

    static void recordWrite(String resourceKey) {
        if (resourceKey == null || resourceKey.isBlank()) {
            return;
        }
        long now = System.currentTimeMillis();
        long self = Thread.currentThread().getId();
        Map<Long, Long> readers = OPEN_READERS.get(resourceKey);
        if (readers == null) {
            return;
        }
        // Drop stale readers first.
        readers.entrySet().removeIf(entry -> now - entry.getValue() > TTL_MILLIS);
        Set<String> concurrent = new HashSet<>();
        for (Long threadId : readers.keySet()) {
            if (!threadId.equals(self)) {
                concurrent.add("thread-" + threadId);
            }
        }
        if (!concurrent.isEmpty()) {
            SecurityAgent.reportRaceSuspect(resourceKey, new ArrayList<>(concurrent));
        }
        // This thread finished its read-modify-write: close its own open read.
        readers.remove(self);
        if (readers.isEmpty()) {
            OPEN_READERS.remove(resourceKey);
        }
    }
}
