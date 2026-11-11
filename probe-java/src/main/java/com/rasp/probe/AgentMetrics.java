package com.rasp.probe;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Assembles the agent self-metrics reported on each heartbeat:
 * hook hit counts, swallowed hook exceptions, dropped events, event-queue length,
 * known rule version, and the current circuit-breaker/degradation state.
 *
 * <p>The event buffer is registered once at startup so the metrics can be collected
 * from the heartbeat thread without threading the buffer through every caller.
 */
public final class AgentMetrics {
    private static volatile EventBuffer eventBuffer;

    private AgentMetrics() {
    }

    public static void register(EventBuffer buffer) {
        eventBuffer = buffer;
    }

    static void resetForTesting() {
        eventBuffer = null;
    }

    public static Map<String, Object> snapshot(ProbeMode mode, long ruleVersion) {
        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("mode", mode == null ? "UNKNOWN" : mode.name());
        metrics.put("ruleVersion", ruleVersion);
        EventBuffer buffer = eventBuffer;
        if (buffer != null) {
            metrics.put("queueLength", buffer.pendingEvents());
            metrics.put("queueCapacity", buffer.queueCapacity());
            metrics.put("queueRemaining", buffer.remainingCapacity());
        }
        metrics.put("instrumentationEnabled", CircuitBreaker.instrumentationEnabled());
        metrics.putAll(HookMetrics.snapshot());
        return metrics;
    }
}
