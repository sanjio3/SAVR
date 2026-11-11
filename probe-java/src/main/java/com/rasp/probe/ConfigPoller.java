package com.rasp.probe;

import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class ConfigPoller {
    private final ProbeState state;
    private final ProbeHttpClient httpClient;
    private final AutoRollbackController rollbackController;
    private final ScheduledExecutorService executor;

    public ConfigPoller(ProbeState state, ProbeHttpClient httpClient) {
        this(state, httpClient, null);
    }

    public ConfigPoller(ProbeState state, ProbeHttpClient httpClient, AutoRollbackController rollbackController) {
        this.state = state;
        this.httpClient = httpClient;
        this.rollbackController = rollbackController;
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "sec-agent-config-poller");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void start() {
        executor.scheduleWithFixedDelay(() -> FailOpen.run("poll-config", this::pollOnce), 0, 30, TimeUnit.SECONDS);
    }

    public void pollOnce() {
        Map<String, Object> metrics = AgentMetrics.snapshot(state.mode(), state.ruleVersion());
        java.util.Optional<java.util.Map<String, Object>> config = httpClient.heartbeat(state.mode(), state.ruleVersion(), metrics, state.agentPhase());
        if (rollbackController != null) {
            rollbackController.recordHeartbeat(config.isPresent());
        }
        config.ifPresent(state::applyConfig);
    }
}

