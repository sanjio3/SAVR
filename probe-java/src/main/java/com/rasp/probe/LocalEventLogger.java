package com.rasp.probe;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fail-open local audit log. Persists agent logs and security events to
 * {@code <log-dir>/sec-agent.log} (default {@code logs/} under the working
 * directory) with a structured {@code [TraceID][Level][Module]} line so the
 * probe remains observable even when the Server/control-plane is unreachable
 * (manual §七.2: events must be inspectable locally, not only by the Server).
 *
 * <p>Observability controls (address the §七.2 review: events had no
 * dedup/aggregation and could flood at high traffic):
 * <ul>
 *   <li><b>Aggregation</b> — within a single flush window, events sharing the
 *       same {@code (eventType + sink + taint-signature)} are collapsed into one
 *       {@code [EVT-AGG]} line carrying a hit count, so 1 000 identical SINK_HIT
 *       in 2 s become a single line instead of 1 000.</li>
 *   <li><b>Critical-event guarantee</b> — semantic suspects ({@code BOLA_SUSPECT},
 *       {@code RACE_SUSPECT}) and unknown methods are ALWAYS written individually at
 *       a forced {@code [ERROR]} level, independent of the minimum severity filter,
 *       because they are the highest-value ops signals when the Server is unreachable.</li>
 *   <li><b>Minimum severity</b> — {@code sec.local.log.minSeverity}
 *       (LOW|MEDIUM|HIGH|ERROR, default LOW) drops below-threshold non-critical
 *       events from the local log to cap volume.</li>
 *   <li><b>Critical-only mode</b> — {@code sec.local.log.onlyBrokenChain=true}
 *       keeps ONLY critical semantic-suspect events (BOLA/RACE), the
 *       "运维全盲时只留关键信号" posture the manual calls for.</li>
 * </ul>
 *
 * <p>All I/O is best-effort: a write failure is swallowed and disables further
 * writes for the process rather than ever throwing into an instrumented thread.
 */
final class LocalEventLogger {

    // severity ranking: LOW < MEDIUM < HIGH < ERROR
    private static final int RANK_LOW = 1;
    private static final int RANK_MEDIUM = 2;
    private static final int RANK_HIGH = 3;
    private static final int RANK_ERROR = 4;

    // 2026-09-16（待请示 6 项 #4）：本地日志按大小轮转，避免 sec-agent.log 无限增长撑爆磁盘。
    // 单文件上限 64MB，保留 3 份备份（sec-agent.log.1/.2/.3）。超出即在写入前轮转。
    private static final long MAX_FILE_BYTES = 64L * 1024 * 1024;
    private static final int MAX_BACKUPS = 3;

    private static final LocalEventLogger INSTANCE = new LocalEventLogger();

    private final boolean enabled;
    private final int minSeverityRank;
    private final boolean onlyBrokenChain;
    private volatile Path file;
    private final Object lock = new Object();

    private LocalEventLogger() {
        String dir = System.getProperty("sec.local.log.dir", "logs");
        this.enabled = !"false".equalsIgnoreCase(
                System.getProperty("sec.local.log.enabled",
                        System.getenv("SEC_LOCAL_LOG_ENABLED") == null ? "true"
                                : System.getenv("SEC_LOCAL_LOG_ENABLED")));
        this.minSeverityRank = parseSeverity(System.getProperty("sec.local.log.minSeverity",
                System.getenv("SEC_LOCAL_LOG_MIN_SEVERITY") == null ? "LOW"
                        : System.getenv("SEC_LOCAL_LOG_MIN_SEVERITY")));
        this.onlyBrokenChain = "true".equalsIgnoreCase(
                System.getProperty("sec.local.log.onlyBrokenChain",
                        System.getenv("SEC_LOCAL_LOG_ONLY_BROKEN_CHAIN") == null ? "false"
                                : System.getenv("SEC_LOCAL_LOG_ONLY_BROKEN_CHAIN")));
        try {
            Path logDir = Paths.get(dir);
            Files.createDirectories(logDir);
            this.file = logDir.resolve("sec-agent.log");
        } catch (IOException | RuntimeException ignored) {
            this.file = null;
        }
    }

    static LocalEventLogger instance() {
        return INSTANCE;
    }

    boolean enabled() {
        return enabled && file != null;
    }

    void logEvent(SecurityEvent event) {
        logEvents(List.of(event));
    }

    void logEvents(List<SecurityEvent> events) {
        if (!enabled() || events.isEmpty()) {
            return;
        }
        StringBuilder critical = new StringBuilder();
        Map<String, Agg> aggregated = new LinkedHashMap<>();
        for (SecurityEvent event : events) {
            // Critical events (broken taint chain, business-logic suspects) are always
            // written individually at forced ERROR level, independent of the severity
            // filter or critical-only mode — they are the highest-value ops signals.
            if (isCritical(event.eventType())) {
                critical.append(formatCritical(event));
                continue;
            }
            if (onlyBrokenChain) {
                // Critical-only mode: drop everything except broken-chain.
                continue;
            }
            int rank = severityRank(event.severity());
            if (rank < minSeverityRank) {
                continue;
            }
            String signature = signatureOf(event);
            Agg bucket = aggregated.get(signature);
            if (bucket == null) {
                bucket = new Agg(event);
                aggregated.put(signature, bucket);
            } else {
                bucket.count++;
            }
            bucket.lastPayload = truncate(event.payload());
        }
        if (critical.length() > 0) {
            append(critical.toString());
        }
        if (!aggregated.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Agg bucket : aggregated.values()) {
                sb.append(formatAggregate(bucket));
            }
            append(sb.toString());
        }
    }

    void log(String level, String module, String message) {
        if (!enabled()) {
            return;
        }
        append(String.format("%s [%s] [%s] %s%n", Instant.now(), level, module, message));
    }

    // ---- formatting helpers ----

    private static boolean isCritical(String eventType) {
        return "BOLA_SUSPECT".equals(eventType)
                || "RACE_SUSPECT".equals(eventType);
    }

    private String formatCritical(SecurityEvent event) {
        String label = "CRITICAL";
        if ("BOLA_SUSPECT".equals(event.eventType())) {
            label = "BOLA";
        } else if ("RACE_SUSPECT".equals(event.eventType())) {
            label = "RACE";
        }
        String trace = dashIfBlank(event.traceId());
        String ctx = event.context() == null ? "-" : event.context().toString();
        return String.format("%s [%s] [ERROR] trace=%s sink=%s payload=%s ctx=%s%n",
                Instant.now(), label, trace, nullToDash(event.sink()),
                truncate(event.payload()), truncate(ctx, 360));
    }

    private String formatAggregate(Agg bucket) {
        SecurityEvent event = bucket.sample;
        String trace = dashIfBlank(event.traceId());
        if (bucket.count <= 1) {
            return String.format("%s [EVT] [%s] [%s] trace=%s sink=%s payload=%s%n",
                    Instant.now(), event.severity(), event.eventType(), trace,
                    nullToDash(event.sink()), truncate(event.payload()));
        }
        return String.format("%s [EVT-AGG] [%s] [%s] count=%d sink=%s first=%s last=%s%n",
                Instant.now(), event.severity(), event.eventType(), bucket.count,
                nullToDash(event.sink()), truncate(bucket.firstPayload),
                truncate(bucket.lastPayload));
    }

    private String signatureOf(SecurityEvent event) {
        Object ctx = event.context();
        String taints = "-";
        if (ctx instanceof Map<?, ?>) {
            Map<?, ?> map = (Map<?, ?>) ctx;
            Object t = map.get("taints");
            if (t != null) {
                taints = t.toString();
            }
        }
        // (eventType, sink, taint-signature) — collapses repeated identical flows.
        return event.eventType() + "|" + nullToDash(event.sink()) + "|" + truncate(taints, 160);
    }

    private static final class Agg {
        final SecurityEvent sample;
        final String firstPayload;
        String lastPayload;
        int count = 1;

        Agg(SecurityEvent sample) {
            this.sample = sample;
            this.firstPayload = truncate(sample.payload());
            this.lastPayload = this.firstPayload;
        }
    }

    private void append(String text) {
        Path target = this.file;
        if (target == null) {
            return;
        }
        synchronized (lock) {
            // 2026-09-16（待请示 6 项 #4）：写入前若即将超限则先轮转，避免单文件无限膨胀。
            try {
                if (Files.exists(target) && Files.size(target) + text.length() > MAX_FILE_BYTES) {
                    rotate();
                }
            } catch (IOException ignored) {
                // 轮转失败不阻断写入，继续追加到当前文件
            }
            try (BufferedWriter writer = Files.newBufferedWriter(target, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write(text);
            } catch (IOException ignored) {
                // disable further writes rather than risk throwing into a hot path
                this.file = null;
            }
        }
    }

    // 2026-09-16（待请示 6 项 #4）：大小轮转。sec-agent.log → .1 → .2 → .3（覆盖最旧），
    // 全程 best-effort，失败绝不抛入热路径。
    private void rotate() {
        Path current = this.file;
        if (current == null) {
            return;
        }
        Path dir = current.getParent();
        if (dir == null) {
            return;
        }
        try {
            // 2026-09-16 修正（轮转回归测试抓出的 off-by-one）：起点必须是 MAX_BACKUPS 而不是
            // MAX_BACKUPS-1。否则 .2→.3 这一步永不执行，实际只留 2 份备份，且第 2 代内容被
            // 第 1 代直接覆盖（静默丢一代历史）。i=MAX_BACKUPS 时 src=.2 → dst=.3，
            // REPLACE_EXISTING 天然覆盖最旧一份，无需额外 delete。
            for (int i = MAX_BACKUPS; i >= 1; i--) {
                Path src = (i == 1) ? current : dir.resolve("sec-agent.log." + (i - 1));
                Path dst = dir.resolve("sec-agent.log." + i);
                if (Files.exists(src)) {
                    Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING);
                }
            }
        } catch (IOException ignored) {
            // 轮转失败保持原文件，下一轮再试
        }
    }

    private static int severityRank(String severity) {
        if (severity == null) {
            return RANK_LOW;
        }
        if ("MEDIUM".equals(severity)) {
            return RANK_MEDIUM;
        }
        if ("HIGH".equals(severity)) {
            return RANK_HIGH;
        }
        if ("ERROR".equals(severity)) {
            return RANK_ERROR;
        }
        return RANK_LOW;
    }

    private static int parseSeverity(String value) {
        if (value == null) {
            return RANK_LOW;
        }
        String upper = value.toUpperCase();
        if ("MEDIUM".equals(upper)) {
            return RANK_MEDIUM;
        }
        if ("HIGH".equals(upper)) {
            return RANK_HIGH;
        }
        if ("ERROR".equals(upper)) {
            return RANK_ERROR;
        }
        return RANK_LOW;
    }

    private static String dashIfBlank(String s) {
        return s == null || s.isBlank() ? "-" : s;
    }

    private static String nullToDash(String s) {
        return s == null ? "-" : s;
    }

    private static String truncate(String s) {
        return truncate(s, 480);
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "-";
        }
        return s.length() > max ? s.substring(0, max) + "...(+" + (s.length() - max) + ")" : s;
    }
}
