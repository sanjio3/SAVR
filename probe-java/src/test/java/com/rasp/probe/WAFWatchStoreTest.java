package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ModSecurity 双向激活闭环（探针侧）— 验证心跳下发的"关注会话"会使该会话进入
 * 全量采样(跳过 SEC_MAX_SAMPLE_LENGTH 截断),非关注会话保持截断。
 */
class WAFWatchStoreTest {

    @AfterEach
    void tearDown() {
        WAFWatchStore.reset();
        TaintStore.clearCurrentRequest();
        HookRuntime.configure(configWithMaxSample(512));
    }

    @Test
    void watchedSessionGetsFullSample() {
        WAFWatchStore.setWatched(List.of("req-1"));
        assertTrue(WAFWatchStore.isWatched("req-1"));
        assertFalse(WAFWatchStore.isWatched("req-other"));

        TaintStore.bindRequest("req-1");
        String longPayload = "x".repeat(2000);
        assertEquals(longPayload, HookRuntime.sample(longPayload),
                "watched session must bypass truncation for full taint-path sampling");
    }

    @Test
    void unwatchedSessionStillTruncated() {
        WAFWatchStore.setWatched(List.of("req-watched"));
        TaintStore.bindRequest("req-plain");
        int maxLen = 16;
        HookRuntime.configure(configWithMaxSample(maxLen));
        String longPayload = "y".repeat(2000);
        assertEquals(maxLen, HookRuntime.sample(longPayload).length(),
                "unwatched session keeps truncated sampling");
    }

    @Test
    void consumeWatchSessionsFromApplyConfig() {
        ProbeState state = new ProbeState();
        state.applyConfig(java.util.Map.of("watchSessions", List.of("req-9")));
        assertTrue(WAFWatchStore.isWatched("req-9"));
    }

    private static ProbeConfig configWithMaxSample(int max) {
        return new ProbeConfig(
                "http://localhost:8080", "agent-watch", "demo",
                50, 1024,
                true, true, true, true, true, true, true,
                "", max);
    }
}