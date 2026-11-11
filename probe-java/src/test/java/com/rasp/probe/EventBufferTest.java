package com.rasp.probe;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EventBufferTest {

    @BeforeEach
    void resetDedupTable() {
        // DEDUP 是 static 表（按 canary+sink 跨请求去重）；测试用同一个固定 canary/sink，
        // 不隔离会互相污染（前一个测试写入的键会把后一个测试的首条判成窗口内重复）。
        EventBuffer.resetDedupForTesting();
    }

    @Test
    void dropsEventsWhenQueueIsFullWithoutBlocking() {
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 1);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));

        assertTrue(buffer.offer(event("one")));
        assertFalse(buffer.offer(event("two")));
        assertEquals(1, buffer.pendingEvents());
    }

    @Test
    void sendFailureDropsDrainedBatch() {
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 10);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        buffer.offer(event("one"));

        buffer.flush();

        assertEquals(0, buffer.pendingEvents());
    }

    @Test
    void ringBufferExposesBackpressureCapacity() {
        // Requested size 3 rounds up to the next power of two (4) for the ring buffer.
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 3);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));

        assertEquals(4, buffer.queueCapacity());
        assertEquals(4, buffer.remainingCapacity());

        // 用两个不同 sink（键不同）确保都被接收。同键去重语义由
        // dedupKeepsFirstReplayEventAndDropsRepeatWithinWindow 专测。
        buffer.offer(new SecurityEvent("SINK_HIT", "HIGH", "trace", "session-1", "jdbc-a", "a",
                Map.of("canary", "s4st41deadbeef0000"), "", ""));
        buffer.offer(new SecurityEvent("SINK_HIT", "HIGH", "trace", "session-1", "jdbc-b", "b",
                Map.of("canary", "s4st41deadbeef0000"), "", ""));

        assertEquals(2, buffer.pendingEvents());
        assertEquals(2, buffer.remainingCapacity());
    }

    @Test
    void suppressesNoCanarySinkHitOutsideRequest() {
        // 待请示 6 项 #2：无 canary 且不在请求上下文的 SINK_HIT 是 JVM 自举噪声，入环前丢弃。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 4);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        long before = HookMetrics.suppressedStartupNoise();

        assertFalse(buffer.offer(new SecurityEvent(
                "SINK_HIT", "HIGH", "trace", "s", "jdbc", "p", Map.of(), "", "")));
        assertEquals(0, buffer.pendingEvents());
        assertEquals(before + 1, HookMetrics.suppressedStartupNoise());
    }

    @Test
    void keepsSinkHitWithCanaryOutsideRequest() {
        // 带 canary 的 sink 命中是真信号，任何上下文都不得抑制。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 4);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));

        assertTrue(buffer.offer(new SecurityEvent(
                "SINK_HIT", "HIGH", "trace", "s", "jdbc", "p",
                Map.of("canary", "s4st41deadbeef0000"), "", "")));
        assertEquals(1, buffer.pendingEvents());
    }

    @Test
    void dropsProbeSelfSinkNoiseAtSource() {
        // 且调用栈含 com.rasp.probe，是探针自插桩噪声，须从源头丢弃（offer 返回 false），不进环。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 4);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        // droppedEvents 分开（同 suppressedStartupNoise 的设计），避免「主动抑制」被误报成「丢弃」。
        long before = HookMetrics.suppressedSelfLogNoise();
        SecurityEvent selfNoise = new SecurityEvent(
                "SINK_HIT", "HIGH", "trace", "s",
                "java.nio.file.Files.newOutputStream", "sec-agent.log",
                Map.of("canary", "s4st41deadbeef0000"), "",
                "com.rasp.probe.LocalEventLogger.write(LocalEventLogger.java:42)");
        assertFalse(buffer.offer(selfNoise));
        assertEquals(0, buffer.pendingEvents());
        assertEquals(before + 1, HookMetrics.suppressedSelfLogNoise());
    }

    @Test
    void keepsApplicationFileWriteSinkWithCanary() {
        // 应用真实文件写入 sink（调用栈不含探针包）带 canary 是真信号，不得丢弃（即便 sink 同为文件写入）。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 4);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        SecurityEvent appSink = new SecurityEvent(
                "SINK_HIT", "HIGH", "trace", "s",
                "java.nio.file.Files.newOutputStream", "/upload/evil.txt",
                Map.of("canary", "s4st41deadbeef0000"), "",
                "com.target.app.UploadController.save(UploadController.java:88)");
        assertTrue(buffer.offer(appSink));
        assertEquals(1, buffer.pendingEvents());
    }

    @Test
    void dropsTaintFlowSelfLogNoise() {
        // 日志标记 "sec-agent.log"，调用栈常为空。旧判定（仅 SINK_HIT+栈含探针包）对该通道失效，
        // 须从源头丢弃（offer 返回 false），不进环、不污染关联层 confirmed_runtime。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 4);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        long before = HookMetrics.suppressedSelfLogNoise();
        SecurityEvent selfNoise = new SecurityEvent(
                "TAINT_FLOW", "HIGH", "trace", "s",
                "java.nio.file.Files.newOutputStream",
                "[logs\\sec-agent.log,[CREATE,APPEND]]",
                Map.of("canary", "s4st41deadbeef0000"), "", "");
        assertFalse(buffer.offer(selfNoise));
        assertEquals(0, buffer.pendingEvents());
        assertEquals(before + 1, HookMetrics.suppressedSelfLogNoise());
    }

    @Test
    void keepsTaintFlowWithCanaryAndAppPayload() {
        // 带 canary 且 payload 不涉及探针自写日志标记的应用 TAINT_FLOW 是真信号，不得丢弃。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 4);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        SecurityEvent appTaint = new SecurityEvent(
                "TAINT_FLOW", "HIGH", "trace", "s", "java.sql.Statement.executeQuery",
                "id=1 OR 1=1", Map.of("canary", "s4st41deadbeef0000"), "", "");
        assertTrue(buffer.offer(appTaint));
        assertEquals(1, buffer.pendingEvents());
    }

    @Test
    void dedupKeepsFirstReplayEventAndDropsRepeatWithinWindow() {
        // 连首条都被判重复 → 带 canary 的 SINK_HIT 被系统性全丢（实测四任务带 canary 的
        // SINK_HIT = 0）。正确语义：窗口内同键放行首条、丢弃后续。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 8);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));

        assertTrue(buffer.offer(event("first")), "首条带 canary 的 SINK_HIT 必须放行");
        assertFalse(buffer.offer(event("second")), "窗口内同键重复必须被去重");
        assertEquals(1, buffer.pendingEvents());
    }

    @Test
    void dedupDoesNotSuppressDifferentSinkKeys() {
        // 去重键是 (canary, sink)：同 canary 不同 sink 是不同事实，必须都放行。
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 8);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));

        assertTrue(buffer.offer(new SecurityEvent("SINK_HIT", "HIGH", "t", "s",
                "java.sql.Statement.execute", "p", Map.of("canary", "s4st41deadbeef0000"), "", "")));
        assertTrue(buffer.offer(new SecurityEvent("SINK_HIT", "HIGH", "t", "s",
                "java.lang.Runtime.exec", "p", Map.of("canary", "s4st41deadbeef0000"), "", "")));
        assertEquals(2, buffer.pendingEvents());
    }

    /** 真实扫描期 sink 事件带 canary，故测试用带 canary 的事件验证队列语义。 */
    private SecurityEvent event(String payload) {
        return new SecurityEvent("SINK_HIT", "HIGH", "trace", "session-1", "jdbc", payload,
                Map.of("canary", "s4st41deadbeef0000"), "", "");
    }
}

