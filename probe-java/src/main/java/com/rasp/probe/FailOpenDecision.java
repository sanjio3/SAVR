package com.rasp.probe;

import java.util.function.Supplier;

public final class FailOpenDecision {
    private FailOpenDecision() {
    }

    public static RaspDecision run(Supplier<RaspDecision> action, RaspDecision fallback) {
        try {
            return action.get();
        } catch (Throwable throwable) {
            AgentLogger.warn("core", "decision failed-open: " + throwable.getClass().getSimpleName());
            return fallback;
        }
    }
}

