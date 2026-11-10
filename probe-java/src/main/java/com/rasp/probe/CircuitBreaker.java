package com.rasp.probe;

import com.sun.management.OperatingSystemMXBean;

import java.lang.management.ManagementFactory;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Stability circuit breaker. When process CPU, event-queue backlog, or hook error rate
 * exceed configured thresholds, the probe degrades to pure passthrough so the host
 * application keeps serving traffic unimpeded. After metrics stay healthy for the
 * cooldown window, instrumentation is re-enabled automatically. The trip flag is a
 * cheap static volatile read so gating hot paths costs almost nothing.
 */
public final class CircuitBreaker {
    private static final long SAMPLE_INTERVAL_MS = 1000L;

    // 2026-09-14 熔断振荡修复（第二、三项）：滞回水线 + 半开探测。
    // 旧实现：触发水线与恢复水线同为「不超阈」，恢复靠「连续 5s 不超阈」的定时恢复，无半开探测。
    // 由于排空速率远低于生产速率（见 EventBuffer 的修复），队列一出阈值就恢复、恢复 1s 又触顶，
    // 形成约 10s 的 tripped/recovered 弛张振荡。
    // 现改为：①恢复水线（resume）显著低于触发水线，形成滞回带，避免擦边反复；
    //          ②最短跳闸时长，避免抖动式跳合；
    //          ③半开探测：冷却与最短跳闸都满足后，仍需连续 N 次健康采样才真正恢复。
    // 全部可经系统属性覆盖，默认值面向本地回环上报场景。
    private static final int RESUME_CPU_PERCENT = intProp("sec.circuit.cpu.resume.percent", 70);
    private static final int RESUME_QUEUE_PERCENT = intProp("sec.circuit.queue.resume.percent", 60);
    private static final int RECOVER_SAMPLES = intProp("sec.circuit.recover.samples", 3);
    private static final long MIN_TRIP_MS = longProp("sec.circuit.min.trip.ms", 10000L);

    // false = full protection, true = passthrough (degraded).
    private static volatile boolean tripped = false;
    // Sticky passthrough set by auto-rollback when the agent falls back to observation-only.
    private static volatile boolean rollbackDegraded = false;
    private static final AtomicLong hookErrors = new AtomicLong(0);

    private final ProbeConfig config;
    private final EventBuffer eventBuffer;
    private final AutoRollbackController rollbackController;
    private final OperatingSystemMXBean osBean;
    private volatile long lastOverloadedAtMillis = 0L;
    private volatile long lastTrippedAtMillis = 0L;
    private int healthySamples = 0;
    private ScheduledExecutorService sampler;

    public CircuitBreaker(ProbeConfig config, EventBuffer eventBuffer) {
        this(config, eventBuffer, null);
    }

    public CircuitBreaker(ProbeConfig config, EventBuffer eventBuffer, AutoRollbackController rollbackController) {
        this.config = config;
        this.eventBuffer = eventBuffer;
        this.rollbackController = rollbackController;
        this.osBean = resolveOsBean();
    }

    /** Cheap gate for hot paths. Returns false while degraded to passthrough. */
    public static boolean instrumentationEnabled() {
        return !tripped && !rollbackDegraded;
    }

    /** Called from hook fail-open handlers to feed the error-rate signal. */
    public static void recordHookError() {
        hookErrors.incrementAndGet();
    }

    /**
     * 2026-09-29（P1 熔断语义改造）：按异常类型分流的入口。
     * 并发类异常（ConcurrentModificationException 及其 cause 链）只影响单条 hook 调用
     * （该条 fail-open、该条事件丢失），不代表基础设施过载——把它计入全局错误预算曾导致
     * D2 并发重放期 CME 风暴直接触发全局降级 passthrough，静默丢失整段证据窗口。
     * 因此并发类异常只进 HookMetrics 独立计数（可观测），不进熔断错误预算；
     * 全局熔断保留基础设施信号（CPU/队列/非并发 hook 异常）。
     */
    public static void recordHookError(Throwable throwable) {
        if (isConcurrencyFault(throwable)) {
            HookMetrics.recordConcurrentModError();
            return;
        }
        hookErrors.incrementAndGet();
    }

    private static boolean isConcurrencyFault(Throwable throwable) {
        Throwable current = throwable;
        int depth = 0;
        while (current != null && depth < 8) {
            if (current instanceof java.util.ConcurrentModificationException) {
                return true;
            }
            current = current.getCause();
            depth++;
        }
        return false;
    }

    /** Auto-rollback sets this when the agent has no known-good version to fall back to. */
    public static void setRollbackDegraded(boolean degraded) {
        rollbackDegraded = degraded;
    }

    /** Test hook to reset global state between cases. */
    static void resetForTesting() {
        tripped = false;
        rollbackDegraded = false;
        hookErrors.set(0);
    }
    public void start() {
        if (!config.circuitBreakerEnabled()) {
            return;
        }
        sampler = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "sec-agent-circuit-breaker");
            thread.setDaemon(true);
            return thread;
        });
        sampler.scheduleWithFixedDelay(() -> FailOpen.run("circuit-sample", this::sampleOnce),
                SAMPLE_INTERVAL_MS, SAMPLE_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    void sampleOnce() {
        long errors = hookErrors.getAndSet(0);
        int cpuPercent = sampleCpuPercent();
        int queuePercent = sampleQueuePercent();
        evaluateSignals(cpuPercent, queuePercent, errors, System.currentTimeMillis());
    }

    /**
     * 带滞回与半开探测的判定核心。
     *
     * @param cpuPercent   进程 CPU 占用，负值表示不可采样
     * @param queuePercent 事件队列占用率
     * @param errors       本采样周期内的 hook 异常数
     * @param nowMillis    当前时间
     */
    void evaluateSignals(int cpuPercent, int queuePercent, long errors, long nowMillis) {
        boolean overloaded = (cpuPercent >= 0 && cpuPercent >= config.cbCpuThresholdPercent())
                || queuePercent >= config.cbQueueThresholdPercent()
                || errors >= config.cbErrorThreshold();
        // 恢复用的是更严的「健康」口径（滞回带）：必须低于 resume 水线且无异常。
        boolean healthy = (cpuPercent < 0 || cpuPercent < RESUME_CPU_PERCENT)
                && queuePercent < RESUME_QUEUE_PERCENT
                && errors == 0;

        if (overloaded) {
            lastOverloadedAtMillis = nowMillis;
            healthySamples = 0;
            if (!tripped) {
                tripped = true;
                lastTrippedAtMillis = nowMillis;
                AgentLogger.warn("circuit", "tripped: degrading probe to passthrough (cpu="
                        + cpuPercent + "% queue=" + queuePercent + "% errors=" + errors + ")");
            }
        } else if (tripped) {
            healthySamples = healthy ? healthySamples + 1 : 0;
            long sinceTrip = nowMillis - lastTrippedAtMillis;
            long quietFor = nowMillis - lastOverloadedAtMillis;
            if (sinceTrip >= MIN_TRIP_MS
                    && quietFor >= config.cbCooldownMillis()
                    && healthySamples >= RECOVER_SAMPLES) {
                tripped = false;
                healthySamples = 0;
                AgentLogger.info("circuit", "recovered: instrumentation re-enabled (cpu="
                        + cpuPercent + "% queue=" + queuePercent + "%)");
            }
        }
        if (rollbackController != null) {
            rollbackController.observeCircuit(tripped);
        }
    }

    // 兼容入口：等价于只看「过载与否」的旧口径（cpu/queue/errors 由布尔映射而来）。
    void evaluate(boolean overloaded, long nowMillis) {
        evaluateSignals(overloaded ? 100 : 0, overloaded ? 100 : 0, overloaded ? 1L : 0L, nowMillis);
    }

    private static int intProp(String key, int fallback) {
        try {
            String raw = System.getProperty(key);
            return raw == null || raw.isBlank() ? fallback : Integer.parseInt(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private static long longProp(String key, long fallback) {
        try {
            String raw = System.getProperty(key);
            return raw == null || raw.isBlank() ? fallback : Long.parseLong(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    int sampleCpuPercent() {
        if (osBean == null) {
            return -1;
        }
        double load = osBean.getProcessCpuLoad();
        if (load < 0) {
            return -1;
        }
        return (int) Math.round(load * 100);
    }

    int sampleQueuePercent() {
        int capacity = eventBuffer.queueCapacity();
        if (capacity <= 0) {
            return 0;
        }
        return (int) Math.round((eventBuffer.pendingEvents() * 100.0) / capacity);
    }

    private static OperatingSystemMXBean resolveOsBean() {
        try {
            java.lang.management.OperatingSystemMXBean bean = ManagementFactory.getOperatingSystemMXBean();
            if (bean instanceof OperatingSystemMXBean) {
                return (OperatingSystemMXBean) bean;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
