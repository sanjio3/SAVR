package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the auto-rollback trigger closure (manual section 10.2): heartbeat anomaly,
 * persistent circuit trip, rollback-to-previous success, and rollback-without-previous
 * falling back to observation-only passthrough.
 */
class AutoRollbackControllerTest {
    @TempDir
    Path tempDir;

    @BeforeEach
    @AfterEach
    void reset() {
        CircuitBreaker.resetForTesting();
    }

    @Test
    void consecutiveHeartbeatFailuresTriggerRollbackToPrevious() throws Exception {
        Files.writeString(tempDir.resolve("previous"), "0.9.0");
        AutoRollbackController controller = controller("1.0.0", true);

        for (int i = 0; i < 4; i++) {
            controller.recordHeartbeat(false);
        }
        assertFalse(controller.hasRolledBack());

        controller.recordHeartbeat(false); // fifth failure crosses default threshold

        assertTrue(controller.hasRolledBack());
        assertEquals("heartbeat-anomaly", controller.lastReason());
        assertEquals(RollbackOutcome.ROLLED_BACK, controller.lastOutcome());
        assertEquals("0.9.0", Files.readString(tempDir.resolve("candidate")).trim());
    }

    @Test
    void successfulHeartbeatResetsFailureStreak() {
        AutoRollbackController controller = controller("1.0.0", true);

        for (int i = 0; i < 4; i++) {
            controller.recordHeartbeat(false);
        }
        controller.recordHeartbeat(true); // resets
        for (int i = 0; i < 4; i++) {
            controller.recordHeartbeat(false);
        }

        assertFalse(controller.hasRolledBack());
    }

    @Test
    void persistentCircuitTripTriggersRollback() throws Exception {
        Files.writeString(tempDir.resolve("previous"), "0.9.0");
        AutoRollbackController controller = controller("1.0.0", true);

        for (int i = 0; i < 10; i++) {
            controller.observeCircuit(true);
        }

        assertTrue(controller.hasRolledBack());
        assertEquals("circuit-persistent-trip", controller.lastReason());
    }

    @Test
    void recoveredCircuitResetsTripStreak() {
        AutoRollbackController controller = controller("1.0.0", true);

        for (int i = 0; i < 9; i++) {
            controller.observeCircuit(true);
        }
        controller.observeCircuit(false); // recovery resets streak
        for (int i = 0; i < 9; i++) {
            controller.observeCircuit(true);
        }

        assertFalse(controller.hasRolledBack());
    }

    @Test
    void rollbackWithoutPreviousEntersObservationOnlyPassthrough() {
        AutoRollbackController controller = controller("1.0.0", true);
        assertTrue(CircuitBreaker.instrumentationEnabled());

        for (int i = 0; i < 5; i++) {
            controller.recordHeartbeat(false);
        }

        assertTrue(controller.hasRolledBack());
        assertEquals(RollbackOutcome.OBSERVATION_ONLY, controller.lastOutcome());
        assertFalse(CircuitBreaker.instrumentationEnabled(), "observation-only must degrade to passthrough");
    }

    @Test
    void disabledUpdatesMakeControllerInert() {
        AutoRollbackController controller = controller("1.0.0", false);

        for (int i = 0; i < 20; i++) {
            controller.recordHeartbeat(false);
            controller.observeCircuit(true);
        }

        assertFalse(controller.hasRolledBack());
        assertTrue(CircuitBreaker.instrumentationEnabled());
    }

    private AutoRollbackController controller(String version, boolean updatesEnabled) {
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent-1", "app", "prod", "", 1_000, 128,
                false, true, true, true, true, true, false, true, true, true, true, true, true,
                "", 256, updatesEnabled, tempDir.toString(), version, "1", 300);
        ProbeHttpClient platformClient = new ProbeHttpClient(config);
        AgentUpdateManager manager = new AgentUpdateManager(config, platformClient);
        return new AutoRollbackController(config, manager);
    }
}
