package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 *
 * 旧实现：触发与恢复同用一个水线、恢复靠定时、无半开探测，导致队列一出阈值就恢复、
 * 恢复 1s 又被生产速率顶回，形成约 10s 的 tripped/recovered 弛张振荡。
 * 新实现：滞回带（恢复水线低于触发水线）+ 最短跳闸时长 + 半开探测（连续健康采样才恢复）。
 */
class CircuitBreakerHysteresisTest {

    private CircuitBreaker newBreaker() {
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1000, 1024);
        return new CircuitBreaker(config, (EventBuffer) null);
    }

    @AfterEach
    void tearDown() {
        CircuitBreaker.resetForTesting();
    }

    @Test
    void doesNotChatterInsideTheHysteresisBand() {
        CircuitBreaker.resetForTesting();
        CircuitBreaker breaker = newBreaker();
        long t = 1_000_000L;

        // 队列 95% 超过触发水线 90% → 跳闸
        breaker.evaluateSignals(0, 95, 0, t);
        assertFalse(CircuitBreaker.instrumentationEnabled(), "队列超触发水线应跳闸");

        // 之后长期停在滞回带内（70%：低于触发 90%，但高于恢复 60%）——不应恢复，这是旧实现的振荡点
        for (int i = 1; i <= 20; i++) {
            breaker.evaluateSignals(0, 70, 0, t + i * 1000L);
        }
        assertFalse(CircuitBreaker.instrumentationEnabled(), "滞回带内不应恢复");
    }

    @Test
    void recoversOnlyAfterSustainedHealthySamples() {
        CircuitBreaker.resetForTesting();
        CircuitBreaker breaker = newBreaker();
        long t = 2_000_000L;

        breaker.evaluateSignals(0, 95, 0, t);
        assertFalse(CircuitBreaker.instrumentationEnabled());

        // 第一次健康采样：时间够（>最短跳闸 10s、>冷却 5s），但连续健康次数不足 → 仍不应恢复
        breaker.evaluateSignals(0, 10, 0, t + 11_000L);
        assertFalse(CircuitBreaker.instrumentationEnabled(), "半开探测：单次健康不足以恢复");

        breaker.evaluateSignals(0, 10, 0, t + 22_000L);
        assertFalse(CircuitBreaker.instrumentationEnabled(), "半开探测：两次健康仍不足");

        breaker.evaluateSignals(0, 10, 0, t + 33_000L);
        assertTrue(CircuitBreaker.instrumentationEnabled(), "达到连续健康采样数后应恢复");
    }

    @Test
    void respectsMinimumTripDuration() {
        CircuitBreaker.resetForTesting();
        CircuitBreaker breaker = newBreaker();
        long t = 3_000_000L;

        breaker.evaluateSignals(0, 95, 0, t);
        // 健康采样但远早于最短跳闸时长 → 不应恢复（避免抖动式跳合）
        for (int i = 1; i <= 5; i++) {
            breaker.evaluateSignals(0, 5, 0, t + i * 100L);
        }
        assertFalse(CircuitBreaker.instrumentationEnabled(), "早于最短跳闸时长不应恢复");
    }
}
