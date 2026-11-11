package com.rasp.probe;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class FailOpen {
    private FailOpen() {
    }

    /** 已打印过完整堆栈的异常签名（operation:异常类名），防止并发重放期同签名刷屏。 */
    private static final Set<String> LOGGED_SIGNATURES =
            ConcurrentHashMap.newKeySet();

    public static void run(String operation, Runnable action) {
        try {
            action.run();
        } catch (Throwable throwable) {
            String signature = operation + ":" + throwable.getClass().getName();
            if (LOGGED_SIGNATURES.add(signature)) {
                // 首次出现：打完整堆栈，用于定位并发缺陷（如 CME）的精确行号
                StringWriter sw = new StringWriter(1024);
                throwable.printStackTrace(new PrintWriter(sw));
                AgentLogger.warn("core", operation + " failed-open (first occurrence, signature="
                        + signature + ") stack:\n" + sw);
            } else {
                AgentLogger.warn("core", operation + " failed-open: "
                        + throwable.getClass().getSimpleName()
                        + " (signature seen " + "before, full stack printed once)");
            }
        }
    }
}

