package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HookMetricsTest {
    @BeforeEach
    @AfterEach
    void reset() {
        HookMetrics.resetForTesting();
    }

    @Test
    void countsHitsAndErrorsPerHook() {
        HookMetrics.shouldObserve("source.http");
        HookMetrics.shouldObserve("source.http");
        HookMetrics.error("source.http");

        Map<String, Object> snapshot = HookMetrics.snapshot();
        @SuppressWarnings("unchecked")
        Map<String, Object> hooks = (Map<String, Object>) snapshot.get("hooks");
        @SuppressWarnings("unchecked")
        Map<String, Object> source = (Map<String, Object>) hooks.get("source.http");

        assertEquals(2L, ((Number) source.get("hits")).longValue());
        assertEquals(1L, ((Number) source.get("errors")).longValue());
        assertEquals(2L, ((Number) snapshot.get("totalHits")).longValue());
        assertEquals(1L, ((Number) snapshot.get("totalErrors")).longValue());
    }

    @Test
    void toggleDisablesObservationAndEnforcement() {
        HookMetrics.setHookEnabled("sink.jdbc", false);

        assertFalse(HookMetrics.shouldEnforce("sink.jdbc"));
        assertFalse(HookMetrics.shouldObserve("sink.jdbc"));

        HookMetrics.setHookEnabled("sink.jdbc", true);
        assertTrue(HookMetrics.shouldEnforce("sink.jdbc"));
    }

    @Test
    void applyTogglesFromControlPlane() {
        HookMetrics.applyToggles(Map.of("source.cookie", false, "sink.command", true));

        assertFalse(HookMetrics.isHookEnabled("source.cookie"));
        assertTrue(HookMetrics.isHookEnabled("sink.command"));
    }

    @Test
    void samplingDropsAFractionOfObservations() {
        HookMetrics.configure(withSampleRate(25));

        int processed = 0;
        for (int i = 0; i < 100; i++) {
            if (HookMetrics.shouldObserve("propagator.return")) {
                processed++;
            }
        }
        // Deterministic 1-in-100 window: exactly 25 of every 100 pass.
        assertEquals(25, processed);
    }

    @Test
    void rateLimitCapsObservationsPerSecond() {
        HookMetrics.configure(withRateLimit(5));

        int processed = 0;
        for (int i = 0; i < 50; i++) {
            if (HookMetrics.shouldObserve("source.http")) {
                processed++;
            }
        }
        assertTrue(processed <= 5, "rate limit should cap processed observations, was " + processed);
    }

    @Test
    void enforcementIsNeverSampledAway() {
        HookMetrics.configure(withSampleRate(1));

        int enforced = 0;
        for (int i = 0; i < 100; i++) {
            if (HookMetrics.shouldEnforce("sink.jdbc")) {
                enforced++;
            }
        }
        assertEquals(100, enforced);
    }

    @Test
    void droppedEventsAreTracked() {
        HookMetrics.recordDroppedEvent();
        HookMetrics.recordDroppedEvent();
        assertEquals(2L, HookMetrics.droppedEvents());
        assertEquals(2L, ((Number) HookMetrics.snapshot().get("droppedEvents")).longValue());
    }

    private static ProbeConfig withSampleRate(int percent) {
        return baseConfig(percent, 0);
    }

    private static ProbeConfig withRateLimit(int perSecond) {
        return baseConfig(100, perSecond);
    }

    private static ProbeConfig baseConfig(int samplePercent, int rateLimit) {
        return new ProbeConfig("http://127.0.0.1:1", "agent", "app", "dev", "", 1, 16, false, true, true, true, true,
                true, false, true, true, false, false, false, true, "", 256, false, ".sec-agent", "0.1.0", "1", 300,
                true, 90, 90, 50, 5000, samplePercent, rateLimit);
    }
}
