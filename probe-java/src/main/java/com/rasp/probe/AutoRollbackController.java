package com.rasp.probe;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Closes the auto-rollback loop (manual section 10.2). It watches three runtime health
 * signals and, when any crosses its threshold, asks {@link AgentUpdateManager} to fall
 * back to the previous known-good agent:
 *
 * <ul>
 *   <li>startup reconcile: a staged candidate that failed to load;</li>
 *   <li>heartbeat anomaly: N consecutive control-plane heartbeat failures;</li>
 *   <li>persistent circuit trip: the breaker stays tripped for N consecutive samples
 *       (which itself folds in CPU, queue backlog, and hook error-rate overload).</li>
 * </ul>
 *
 * A rollback fires at most once per process; if there is no previous version to return to
 * the agent stays up in observation-only mode (passthrough) rather than crashing the host.
 * Thresholds are read locally from properties/env to avoid growing the ProbeConfig record.
 */
public final class AutoRollbackController {
    private final ProbeConfig config;
    private final AgentUpdateManager updateManager;
    private final int heartbeatFailureThreshold;
    private final int circuitTripStreakThreshold;

    private final AtomicInteger heartbeatFailures = new AtomicInteger(0);
    private final AtomicInteger circuitTripStreak = new AtomicInteger(0);
    private volatile boolean rolledBack = false;
    private volatile String lastReason = "";
    private volatile RollbackOutcome lastOutcome;

    public AutoRollbackController(ProbeConfig config, AgentUpdateManager updateManager) {
        this.config = config;
        this.updateManager = updateManager;
        this.heartbeatFailureThreshold = Math.max(1,
                intConfig("sec.agent.rollback.heartbeat.failures", "SEC_AGENT_ROLLBACK_HEARTBEAT_FAILURES", 5));
        this.circuitTripStreakThreshold = Math.max(1,
                intConfig("sec.agent.rollback.circuit.trip.streak", "SEC_AGENT_ROLLBACK_CIRCUIT_TRIP_STREAK", 10));
    }

    /** Detect and react to a candidate that was staged but failed to load on this restart. */
    public void verifyStartup(String loadedVersion) {
        FailOpen.run("rollback-startup", () -> {
            StartupOutcome outcome = updateManager.reconcileOnStartup(loadedVersion);
            if (outcome == StartupOutcome.LOAD_FAILED) {
                triggerRollback("startup-load-failed");
            }
        });
    }

    /** Feed the outcome of each control-plane heartbeat. */
    public void recordHeartbeat(boolean success) {
        if (!config.agentUpdateEnabled()) {
            return;
        }
        if (success) {
            heartbeatFailures.set(0);
            return;
        }
        if (heartbeatFailures.incrementAndGet() >= heartbeatFailureThreshold) {
            triggerRollback("heartbeat-anomaly");
        }
    }

    /** Feed the breaker state on every sample; a sustained trip escalates to rollback. */
    public void observeCircuit(boolean tripped) {
        if (!config.agentUpdateEnabled()) {
            return;
        }
        if (!tripped) {
            circuitTripStreak.set(0);
            return;
        }
        if (circuitTripStreak.incrementAndGet() >= circuitTripStreakThreshold) {
            triggerRollback("circuit-persistent-trip");
        }
    }

    private void triggerRollback(String reason) {
        if (rolledBack) {
            return;
        }
        synchronized (this) {
            if (rolledBack) {
                return;
            }
            rolledBack = true;
        }
        lastReason = reason;
        RollbackOutcome outcome = updateManager.rollback(reason);
        lastOutcome = outcome;
        if (outcome == RollbackOutcome.OBSERVATION_ONLY) {
            // No known-good version to return to: keep serving but stop instrumenting.
            CircuitBreaker.setRollbackDegraded(true);
            AgentLogger.warn("rollback", "no previous version; entering observation-only passthrough (" + reason + ")");
        } else {
            AgentLogger.warn("rollback", "previous version staged for restart (" + reason + ")");
        }
    }

    public boolean hasRolledBack() {
        return rolledBack;
    }

    public String lastReason() {
        return lastReason;
    }

    public RollbackOutcome lastOutcome() {
        return lastOutcome;
    }

    private static int intConfig(String property, String env, int defaultValue) {
        String raw = System.getProperty(property);
        if (raw == null || raw.isBlank()) {
            raw = System.getenv(env);
        }
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(raw.trim().toLowerCase(Locale.ROOT));
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }
}
