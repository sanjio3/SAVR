package com.rasp.probe;

import java.time.Instant;

public final class AgentLogger {
    private AgentLogger() {
    }

    public static void info(String module, String message) {
        log("INFO", module, message);
    }

    public static void warn(String module, String message) {
        log("WARN", module, message);
    }

    public static void error(String module, String message) {
        log("ERROR", module, message);
    }

    private static void log(String level, String module, String message) {
        System.err.printf("%s [-] [%s] [%s] %s%n", Instant.now(), level, module, message);
        LocalEventLogger.instance().log(level, module, message);
    }
}

