package com.rasp.probe;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AgentUpdatePoller {
    private final ProbeConfig config;
    private final AgentUpdateManager updateManager;
    private final ScheduledExecutorService executor;

    public AgentUpdatePoller(ProbeConfig config, AgentUpdateManager updateManager) {
        this.config = config;
        this.updateManager = updateManager;
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "sec-agent-update-poller");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void start() {
        if (!config.agentUpdateEnabled()) {
            return;
        }
        long intervalSeconds = Math.max(30, config.updateCheckIntervalSeconds());
        executor.scheduleWithFixedDelay(() -> FailOpen.run("poll-agent-update", updateManager::checkOnce),
                intervalSeconds, intervalSeconds, TimeUnit.SECONDS);
        AgentLogger.info("update", "scheduled agent artifact polling every " + intervalSeconds + " seconds");
    }
}
