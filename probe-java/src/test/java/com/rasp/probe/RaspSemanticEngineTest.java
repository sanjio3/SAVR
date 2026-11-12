package com.rasp.probe;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RaspSemanticEngineTest {
    @Test
    void blockingRuleBlocksPayloadInBlockMode() {
        ProbeState state = new ProbeState();
        state.applyConfig(Map.of(
                "mode", "BLOCK",
                "ruleVersion", 9,
                "rules", java.util.List.of(new AgentRule(1, "PAYLOAD_BLACKLIST", "BLOCKING", "(?i)jndi",
                        "", "", 0.9, "demo"))));
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 10);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        RaspSemanticEngine engine = new RaspSemanticEngine(buffer, state);

        RaspDecision decision = engine.inspect("lookup", "${jndi:ldap://x}");

        assertTrue(decision.blocked());
    }

    @Test
    void semanticReviewAllowsWhileReportingForAi() {
        ProbeState state = new ProbeState();
        state.applyConfig(Map.of("mode", "BLOCK", "ruleVersion", 1));
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 10);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        RaspSemanticEngine engine = new RaspSemanticEngine(buffer, state);

        // 待请示 6 项 #2：无 canary 的 SINK_HIT 仅在请求上下文内才上报（上下文外被视为启动噪声抑制）。
        // 本用例验证语义引擎的「上报供 AI 复核」路径，故显式进入请求上下文。
        HookRuntime.enterRequest();
        RaspDecision decision;
        try {
            decision = engine.inspect("spel", "VChqYXZhLmxhbmcuUnVudGltZSkuZ2V0UnVudGltZSgpLmV4ZWMoJ2NhbGMnKQ==");
        } finally {
            HookRuntime.exitRequest();
        }

        assertFalse(decision.blocked());
        assertTrue(buffer.pendingEvents() > 0);
    }
}
