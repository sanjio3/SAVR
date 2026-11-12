package com.rasp.probe;

import com.lmax.disruptor.EventPoller;
import com.lmax.disruptor.InsufficientCapacityException;
import com.lmax.disruptor.RingBuffer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Lock-free asynchronous event pipeline backed by an LMAX Disruptor ring buffer
 * (manual technology stack: "Disruptor 内存队列"). Business threads publish sink/source
 * events with a non-blocking {@code tryNext} and, when the ring is full, the event is
 * dropped rather than blocking the host — preserving the Fail-Open constitution. A
 * single daemon consumer polls batches off the ring and flushes them to the Server.
 *
 * <p>Poll (pull) mode is used instead of Disruptor's push {@code BatchEventProcessor} so
 * the existing scheduled-flush cadence and the test-visible {@link #flush} entry point
 * keep working unchanged, while backpressure is now observable via {@link #pendingEvents}
 * (ring occupancy) and {@link #remainingCapacity}.
 */
public class EventBuffer {
    // 旧值 MAX_BATCH=50 且每 2s flush 一次 → 排空上限仅 25 条/s，远低于扫描高峰的生产速率，
    // 队列持续贴近容量 → 触发熔断 → 停产后 4s 排空 + 5s 冷却 → 恢复 1s 又满，形成约 10s 的
    // 4 倍），仅改默认值一行；仍可用系统属性覆盖（sec.event.flush.batch / .interval.ms）。
    private static final int MAX_BATCH = intProp("sec.event.flush.batch", 512);
    private static final long FLUSH_INTERVAL_MS = longProp("sec.event.flush.interval.ms", 250L);
    // 发送失败重试（第四项）：旧实现单次发送失败即丢整批，是数据损失放大器。
    // 现改为在有界重试后才计丢弃，重试不把事件退回环（保持背压语义与既有测试不变）。
    private static final int SEND_RETRIES = intProp("sec.event.send.retries", 3);
    private static final long SEND_BACKOFF_MS = longProp("sec.event.send.backoff.ms", 200L);
    private static final boolean DROP_NO_CANARY_SINKS = boolProp("sec.event.dropNoCanarySinks", true);
    // 旧 isSelfSinkNoise 仅覆盖 SINK_HIT+栈含 com.rasp.probe 对主通道完全失效。可用
    // -Dsec.event.dropSelfLogNoise=false 关闭（纵深防御对后端 correlation.py 的同名过滤）。
    private static final boolean DROP_SELF_LOG_NOISE = boolProp("sec.event.dropSelfLogNoise", true);
    private static final String SELF_LOG_MARKER = "sec-agent.log";
    // sink 会高频重复上报（同一请求被多跳命中），但 D2 只需要「到达」事实，不需要每条事件。洪峰期丢弃
    // 重复不丢证据，且不需改消费端。仅对「带 canary 的重放流量」生效——普通监控流量 canary 为空，
    // 完全不走此分支，绝不误吞真实业务事件。窗口内同键只放行首条，窗口外（下一轮重放/不同 sink）仍记录。
    private static final long DEDUP_WINDOW_MS = longProp("sec.event.dedup.window.ms", 250L);
    private static final int DEDUP_MAX_ENTRIES = intProp("sec.event.dedup.maxEntries", 20000);
    private static final java.util.concurrent.ConcurrentHashMap<String, Long> DEDUP =
            new java.util.concurrent.ConcurrentHashMap<>();

    private final ProbeConfig config;
    private final ProbeHttpClient httpClient;
    private final RingBuffer<EventHolder> ringBuffer;
    private final EventPoller<EventHolder> poller;
    private final ScheduledExecutorService executor;

    public EventBuffer(ProbeConfig config, ProbeHttpClient httpClient) {
        this.config = config;
        this.httpClient = httpClient;
        int size = nextPowerOfTwo(Math.max(1, config.eventQueueSize()));
        // Multi-producer: many instrumented business threads publish concurrently.
        this.ringBuffer = RingBuffer.createMultiProducer(EventHolder::new, size);
        this.poller = ringBuffer.newPoller();
        // Gate producers on the poller's progress so remainingCapacity reflects consumption.
        ringBuffer.addGatingSequences(poller.getSequence());
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "sec-agent-event-flusher");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Non-blocking publish. Returns false (and counts a drop) when the ring is full. */
    public boolean offer(SecurityEvent event) {
        // 请求上下文（REQUEST_DEPTH==0），是 JVM 启动期自身读 fat jar / 建连接 / 渲染模板触发的
        // 框架 sink，与任何扫描假说无关——实测重启后 4 分钟涌入 12770 条、99.2% 被去重丢弃。
        // 入环前丢弃即省下解析/去重/落库预算。可用 -Dsec.event.dropNoCanarySinks=false 关闭。
        if (DROP_NO_CANARY_SINKS && isBootstrapNoise(event)) {
            HookMetrics.recordSuppressedStartupNoise();
            return false;
        }
        if (isSelfSinkNoise(event)) {
            HookMetrics.recordSuppressedSelfLogNoise();
            return false;
        }
        // 生效——普通监控流量 canary 为空，完全不走此分支，绝不误吞真实业务事件。D2 重放洪峰期内，
        // 同一 canary 同一 sink 会被多跳命中高频重复上报，但 D2 只需要「到达」事实，窗口内同键只放行
        // 首条、丢弃重复，洪峰期不丢证据且不需改消费端。fail-open：判不出（无 ctx/解析异常）不丢。
        if (isDuplicateReplay(event)) {
            HookMetrics.recordSuppressedDedup();
            return false;
        }
        try {
            long sequence = ringBuffer.tryNext();
            try {
                ringBuffer.get(sequence).event = event;
            } finally {
                ringBuffer.publish(sequence);
            }
            return true;
        } catch (InsufficientCapacityException full) {
            HookMetrics.recordDroppedEvent();
            return false;
        } catch (RuntimeException ignored) {
            HookMetrics.recordDroppedEvent();
            return false;
        }
    }

    public void start() {
        executor.scheduleWithFixedDelay(() -> FailOpen.run("flush-events", this::flush),
                FLUSH_INTERVAL_MS, FLUSH_INTERVAL_MS, TimeUnit.MILLISECONDS);
        // 而日志零告警，无法定位是环满丢弃 / 去重 / 抑制。此处仅在计数变化时打印，避免刷屏。
        executor.scheduleWithFixedDelay(() -> FailOpen.run("metrics-log", this::logMetricsIfChanged),
                METRICS_LOG_INTERVAL_MS, METRICS_LOG_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    private static final long METRICS_LOG_INTERVAL_MS = longProp("sec.event.metrics.log.ms", 30000L);
    private long lastDroppedEvents = -1L;
    private long lastSuppressedDedup = -1L;

    /** 周期打印事件管道健康度（仅在有变化时）：环满丢弃 / 去重抑制 / 自举与自噪声抑制。 */
    private void logMetricsIfChanged() {
        long dropped = HookMetrics.droppedEvents();
        long dedup = HookMetrics.suppressedDedup();
        if (dropped == lastDroppedEvents && dedup == lastSuppressedDedup) {
            return;
        }
        lastDroppedEvents = dropped;
        lastSuppressedDedup = dedup;
        AgentLogger.info("metrics", "event-pipeline droppedEvents=" + dropped
                + " suppressedDedup=" + dedup
                + " suppressedStartupNoise=" + HookMetrics.suppressedStartupNoise()
                + " suppressedSelfLogNoise=" + HookMetrics.suppressedSelfLogNoise()
                + " pending=" + pendingEvents() + " remaining=" + remainingCapacity());
    }

    public void flush() {
        List<SecurityEvent> events = drainBatch();
        if (events.isEmpty()) {
            return;
        }
        LocalEventLogger.instance().logEvents(events);
        String body = JsonCodec.stringify(Map.of(
                "agentId", config.agentId(),
                "appName", config.appName(),
                "environment", config.environment(),
                "events", events.stream().map(this::eventBody).collect(java.util.stream.Collectors.toList())));
        boolean sent = sendWithRetry(body);
        if (!sent) {
            for (int i = 0; i < events.size(); i++) {
                HookMetrics.recordDroppedEvent();
            }
            AgentLogger.warn("transport", "dropped " + events.size() + " events after "
                    + SEND_RETRIES + " send attempts failed");
        }
    }

    /** 有界重试发送：成功即返回；全部失败才返回 false（由上层计丢弃）。 */
    private boolean sendWithRetry(String body) {
        for (int attempt = 1; attempt <= Math.max(1, SEND_RETRIES); attempt++) {
            if (httpClient.sendEvents(body)) {
                return true;
            }
            if (attempt < SEND_RETRIES) {
                try {
                    Thread.sleep(SEND_BACKOFF_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
        }
        return false;
    }

    /**
     * 不在请求上下文。仅作用于 SINK_HIT（TAINT/BOLA/RACE 语义事件不受影响，避免丢早期污点跳点）。
     * fail-open：判不出即返回 false（不丢），绝不因抑制逻辑丢真实信号。
     */
    private static boolean isBootstrapNoise(SecurityEvent event) {
        try {
            if (event == null || !"SINK_HIT".equals(event.eventType())) {
                return false;
            }
            if (HookRuntime.inRequestContext()) {
                return false;
            }
            Object ctx = event.context();
            if (ctx instanceof Map<?, ?>) {
                Object canary = ((Map<?, ?>) ctx).get("canary");
                return canary == null || canary.toString().isEmpty();
            }
            return true; // 无 context 的 SINK_HIT 必然是框架裸 sink
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * 探针自身写日志（LocalEventLogger 走 java.nio.file.Files.newBufferedWriter）会命中文件写入
     * sink，产生 sink=java.nio.file.Files.newOutputStream 的 SINK_HIT，但其调用栈含 com.rasp.probe
     * （探针自身包），与应用真实漏洞无关——只刷屏日志、污染排查。
     *
     * （payload/sink 含 "sec-agent.log" 标记），调用栈常为空，旧判定（仅 SINK_HIT+栈含探针包）对
     * 主通道完全失效。现以「tainted source value / sink 含探针自写日志标记」为通用判据，覆盖所有
     * 事件类型；原 SINK_HIT+栈含探针包判定保留为纵深防御。标记 "sec-agent.log" 是探针内部日志名，
     * 真实应用漏洞不会涉及，误杀风险极低。可用 -Dsec.event.dropSelfLogNoise=false 整体关闭。
     * fail-open：缺字段/解析异常不丢，绝不因抑制逻辑丢真实信号。
     */
    private static boolean isSelfSinkNoise(SecurityEvent event) {
        if (!DROP_SELF_LOG_NOISE) {
            return false;
        }
        try {
            if (event == null) {
                return false;
            }
            // 会触发 sun.security.provider 内部的哈希/文件 sink，此刻请求上下文未建立、探针内部状态为
            // null → reportSink 路径 NPE（被 FailOpen 捕获打首栈，P1 可观测性让我们看到了它）。此类事件
            // 绝不在请求上下文内且栈含 sun.security.provider，与任何扫描假说无关，直接丢弃。
            // 独立于 DROP_SELF_LOG_NOISE 开关（这是健壮性相关的自噪声，默认始终抑制）；
            // fail-open：判不出（无栈/解析异常）不丢，绝不因抑制逻辑丢真实信号。
            if (!HookRuntime.inRequestContext()) {
                Object st = event.stackTrace();
                String stStr = st == null ? "" : String.valueOf(st);
                if (stStr.contains("sun.security.provider")) {
                    return true;
                }
            }
            // 旧通道（纵深防御）：SINK_HIT 且 sink 为文件写、调用栈含探针自身包。
            if ("SINK_HIT".equals(event.eventType())) {
                String sink = event.sink() == null ? "" : event.sink();
                if (sink.contains("java.nio.file.Files")) {
                    Object st = event.stackTrace();
                    String stStr = st == null ? "" : String.valueOf(st);
                    if (stStr.contains("com.rasp.probe")) {
                        return true;
                    }
                }
            }
            // 主通道（含 TAINT_FLOW）：tainted source value / sink 含探针自写日志标记。
            String payload = event.payload() == null ? "" : event.payload();
            String sink = event.sink() == null ? "" : event.sink();
            return payload.contains(SELF_LOG_MARKER) || sink.contains(SELF_LOG_MARKER);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * 只对「带 canary 的 SINK_HIT」生效——canary 来自重放请求头 X-SASTAI-Trace，普通业务
     * 流量该字段为空，直接返回 false（不走此分支）。窗口内同键只放行首条、丢弃后续重复。
     * 用 ConcurrentHashMap.compute 原子地「查+放」，避免多生产者在同毫秒各放一条。
     * fail-open：缺 ctx / 解析异常一律返回 false（不丢），绝不因去重逻辑吞真实信号。
     */
    private static boolean isDuplicateReplay(SecurityEvent event) {
        try {
            if (event == null || !"SINK_HIT".equals(event.eventType())) {
                return false;
            }
            Object ctx = event.context();
            if (!(ctx instanceof Map<?, ?>)) {
                return false;
            }
            Object canary = ((Map<?, ?>) ctx).get("canary");
            if (canary == null || canary.toString().isEmpty()) {
                return false; // 普通监控流量不走此分支
            }
            String sink = event.sink() == null ? "" : event.sink();
            final String key = canary.toString() + "\u0000" + sink;
            final long now = System.currentTimeMillis();
            // (now - prev) 恒 < 窗口 → **首条也判重复**，带 canary 的 SINK_HIT 被系统性全丢
            // 现语义与注释一致：窗口内同键**放行首条、丢弃后续**；窗口过期刷新起点再放行。
            final Long prev = DEDUP.putIfAbsent(key, now);
            if (prev == null) {
                return false; // 首条：放行
            }
            if ((now - prev) < DEDUP_WINDOW_MS) {
                return true; // 窗口内重复：丢弃
            }
            DEDUP.put(key, now); // 窗口过期：刷新起点，放行本条
            // 防 DEDUP 无限增长：超过上限时清理窗口外的陈旧键（canary 每事务刷新，旧键不再被触碰）。
            if (DEDUP.size() > DEDUP_MAX_ENTRIES) {
                final long cutoff = now - DEDUP_WINDOW_MS;
                DEDUP.entrySet().removeIf(e -> e.getValue() < cutoff);
            }
            return false;
        } catch (Throwable ignored) {
            return false; // fail-open：判不出不丢
        }
    }

    /** 测试隔离用：清空 static 去重表（同 HookMetrics.resetForTesting 的既有先例）。 */
    static void resetDedupForTesting() {
        DEDUP.clear();
    }

    private static boolean boolProp(String key, boolean fallback) {        try {
            String raw = System.getProperty(key);
            return raw == null || raw.isBlank() ? fallback : Boolean.parseBoolean(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private static int intProp(String key, int fallback) {
        try {
            String raw = System.getProperty(key);
            return raw == null || raw.isBlank() ? fallback : Integer.parseInt(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private static long longProp(String key, long fallback) {
        try {
            String raw = System.getProperty(key);
            return raw == null || raw.isBlank() ? fallback : Long.parseLong(raw.trim());
        } catch (RuntimeException ignored) {
            return fallback;
        }
    }

    private List<SecurityEvent> drainBatch() {
        List<SecurityEvent> events = new ArrayList<>(MAX_BATCH);
        try {
            poller.poll((holder, sequence, endOfBatch) -> {
                SecurityEvent event = holder.event;
                holder.event = null; // release reference so the slot can be GC'd
                if (event != null) {
                    events.add(event);
                }
                return events.size() < MAX_BATCH; // stop once the batch is full
            });
        } catch (Exception exception) {
            AgentLogger.warn("transport", "event poll failed-open: " + exception.getClass().getSimpleName());
        }
        return events;
    }

    public int pendingEvents() {
        return (int) (ringBuffer.getBufferSize() - ringBuffer.remainingCapacity());
    }

    public int queueCapacity() {
        return ringBuffer.getBufferSize();
    }

    /** Free ring slots — exposed for backpressure metrics/observability. */
    public long remainingCapacity() {
        return ringBuffer.remainingCapacity();
    }

    private Map<String, Object> eventBody(SecurityEvent event) {
        // context 可能含设计一① 的 canary / canaryState（sink 现场断言），展平为顶层字段，
        // 供后端 agent_bridge._translate_probe_event 直接读取并归一到 sink-reached-probe 态。
        Map<String, Object> ctx = event.context() != null ? event.context() : java.util.Collections.emptyMap();
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("eventType", event.eventType());
        body.put("severity", event.severity());
        body.put("traceId", event.traceId());
        body.put("sessionId", event.sessionId());
        body.put("sink", event.sink());
        body.put("payload", event.payload());
        body.put("sinkMethod", event.sinkMethod());
        body.put("stackTrace", event.stackTrace());
        body.put("context", ctx);
        body.put("canary", ctx.getOrDefault("canary", ""));
        body.put("canaryState", ctx.getOrDefault("canaryState", ""));
        return body;
    }

    private static int nextPowerOfTwo(int value) {
        int result = Integer.highestOneBit(value);
        return result == value ? result : result << 1;
    }

    /** Mutable, pre-allocated ring slot holding one event. */
    private static final class EventHolder {
        private SecurityEvent event;
    }
}
