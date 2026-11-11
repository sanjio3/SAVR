package com.rasp.probe;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Per-hook governance and self-metrics (手册十.3 "安全边界").
 *
 * <p>Every hook family gets:
 * <ul>
 *   <li>a hit counter and an exception counter (observability),</li>
 *   <li>a single-point on/off toggle that can be flipped at runtime from the
 *       control plane without redeploying the agent,</li>
 *   <li>optional sampling and per-second rate limiting so a hot observation
 *       hook can never dominate the host's CPU budget.</li>
 * </ul>
 *
 * <p>Enforcement paths (RASP sinks) use {@link #shouldEnforce(String)} which
 * respects the toggle but never samples away a potential block. Observation
 * paths (RASP observation sources/propagators/unknown methods) use
 * {@link #shouldObserve(String)} which additionally honours sampling and rate
 * limiting. All state is lock-free so the hot path stays cheap; a tripped
 * circuit breaker still short-circuits earlier in {@link HookRuntime}.
 */
public final class HookMetrics {
    private static final Map<String, HookCounters> COUNTERS = new ConcurrentHashMap<>();
    private static final AtomicLong droppedEvents = new AtomicLong(0);
    // SINK_HIT）。与 droppedEvents 分开计数，避免把「主动抑制」误报成「队列满丢弃」。
    private static final AtomicLong suppressedStartupNoise = new AtomicLong(0);
    // 含 "sec-agent.log" 标记，覆盖 TAINT_FLOW 主通道）。与 droppedEvents / suppressedStartupNoise
    // 分开计数，便于在运维视图区分「主动抑制的自噪声」与「队列满丢弃」「JVM 自举噪声」。
    private static final AtomicLong suppressedSelfLogNoise = new AtomicLong(0);
    // droppedEvents / suppressedStartupNoise / suppressedSelfLogNoise 分开计数，便于在运维视图
    // 区分「主动去重的重放洪峰重复」与「队列满丢弃」「JVM 自举噪声」「探针自噪声」。
    private static final AtomicLong suppressedDedup = new AtomicLong(0);
    // 计数，不进全局熔断错误预算——它只影响单条 hook 调用（该条 fail-open），不代表基础设施
    // 过载，把它计入错误预算曾导致 D2 并发重放期 CME 风暴直接触发全局降级 passthrough、
    // 静默丢失整段证据窗口。
    private static final AtomicLong concurrentModErrors = new AtomicLong(0);

    // 100 = process everything. Lower values deterministically sample observation hooks.
    private static volatile int sampleRatePercent = 100;
    // 0 = unlimited. Otherwise the max number of observation invocations processed per hook per second.
    private static volatile int rateLimitPerSecond = 0;

    private HookMetrics() {
    }

    public static void configure(ProbeConfig config) {
        if (config == null) {
            return;
        }
        sampleRatePercent = clampPercent(config.hookSampleRatePercent());
        rateLimitPerSecond = Math.max(0, config.hookRateLimitPerSecond());
    }

    /** Observation gate: counts the hit, then applies toggle + sampling + rate limit. */
    public static boolean shouldObserve(String hook) {
        HookCounters counters = counters(hook);
        long hits = counters.hits.incrementAndGet();
        if (!counters.enabled) {
            return false;
        }
        if (!passesSampling(hits)) {
            return false;
        }
        return passesRateLimit(counters);
    }

    /** Enforcement gate: counts the hit and respects the toggle, but never samples. */
    public static boolean shouldEnforce(String hook) {
        HookCounters counters = counters(hook);
        counters.hits.incrementAndGet();
        return counters.enabled;
    }

    /** Record a swallowed hook exception for the fail-open error-rate signal. */
    public static void error(String hook) {
        counters(hook).errors.increment();
    }

    /** Record an event dropped because the async event buffer was full. */
    public static void recordDroppedEvent() {
        droppedEvents.incrementAndGet();
    }

    public static long droppedEvents() {
        return droppedEvents.get();
    }

    /** Record a JVM-bootstrap-noise event suppressed before entering the ring (待请示 6 项 #2). */
    public static void recordSuppressedStartupNoise() {
        suppressedStartupNoise.incrementAndGet();
    }

    public static long suppressedStartupNoise() {
        return suppressedStartupNoise.get();
    }

    public static void recordSuppressedSelfLogNoise() {
        suppressedSelfLogNoise.incrementAndGet();
    }

    public static long suppressedSelfLogNoise() {
        return suppressedSelfLogNoise.get();
    }

    public static void recordSuppressedDedup() {
        suppressedDedup.incrementAndGet();
    }

    public static long suppressedDedup() {
        return suppressedDedup.get();
    }

    public static void recordConcurrentModError() {
        concurrentModErrors.incrementAndGet();
    }

    public static long concurrentModErrors() {
        return concurrentModErrors.get();
    }

    /** Runtime single-point toggle for a hook family. */
    public static void setHookEnabled(String hook, boolean enabled) {
        counters(hook).enabled = enabled;
    }

    public static boolean isHookEnabled(String hook) {
        return counters(hook).enabled;
    }

    /**
     * Apply per-hook enable/disable directives pushed from the control plane.
     * Keys are hook family names, values are booleans.
     */
    public static void applyToggles(Map<String, Object> toggles) {
        if (toggles == null) {
            return;
        }
        for (Map.Entry<String, Object> entry : toggles.entrySet()) {
            Object value = entry.getValue();
            boolean enabled = value instanceof Boolean ? ((Boolean) value).booleanValue()
                    : "true".equalsIgnoreCase(String.valueOf(value));
            setHookEnabled(entry.getKey(), enabled);
        }
    }

    /** Snapshot of per-hook hit/error/enabled state for heartbeat reporting. */
    public static Map<String, Object> snapshot() {
        Map<String, Object> hooks = new LinkedHashMap<>();
        long totalHits = 0;
        long totalErrors = 0;
        for (Map.Entry<String, HookCounters> entry : COUNTERS.entrySet()) {
            HookCounters counters = entry.getValue();
            long hits = counters.hits.get();
            long errors = counters.errors.sum();
            totalHits += hits;
            totalErrors += errors;
            Map<String, Object> perHook = new LinkedHashMap<>();
            perHook.put("hits", hits);
            perHook.put("errors", errors);
            perHook.put("enabled", counters.enabled);
            hooks.put(entry.getKey(), perHook);
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalHits", totalHits);
        summary.put("totalErrors", totalErrors);
        summary.put("droppedEvents", droppedEvents.get());
        summary.put("suppressedStartupNoise", suppressedStartupNoise.get());
        summary.put("suppressedDedup", suppressedDedup.get());
        summary.put("concurrentModErrors", concurrentModErrors.get());
        summary.put("sampleRatePercent", sampleRatePercent);
        summary.put("rateLimitPerSecond", rateLimitPerSecond);
        summary.put("hooks", hooks);
        return summary;
    }

    static void resetForTesting() {
        COUNTERS.clear();
        droppedEvents.set(0);
        suppressedStartupNoise.set(0);
        suppressedDedup.set(0);
        concurrentModErrors.set(0);
        sampleRatePercent = 100;
        rateLimitPerSecond = 0;
    }

    private static boolean passesSampling(long hits) {
        int rate = sampleRatePercent;
        if (rate >= 100) {
            return true;
        }
        // Deterministic 1-in-N sampling window keyed on the running hit count.
        return (hits % 100) < rate;
    }

    private static boolean passesRateLimit(HookCounters counters) {
        int limit = rateLimitPerSecond;
        if (limit <= 0) {
            return true;
        }
        long nowSecond = System.currentTimeMillis() / 1000L;
        synchronized (counters) {
            if (counters.windowSecond != nowSecond) {
                counters.windowSecond = nowSecond;
                counters.windowCount = 0;
            }
            if (counters.windowCount >= limit) {
                return false;
            }
            counters.windowCount++;
            return true;
        }
    }

    private static HookCounters counters(String hook) {
        return COUNTERS.computeIfAbsent(hook == null ? "unknown" : hook, key -> new HookCounters());
    }

    private static int clampPercent(int value) {
        if (value < 1) {
            return 1;
        }
        return Math.min(value, 100);
    }

    private static final class HookCounters {
        private final AtomicLong hits = new AtomicLong();
        private final LongAdder errors = new LongAdder();
        private volatile boolean enabled = true;
        private long windowSecond = 0L;
        private int windowCount = 0;
    }
}
