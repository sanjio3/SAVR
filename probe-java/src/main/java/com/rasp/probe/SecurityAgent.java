package com.rasp.probe;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class SecurityAgent {
    private static volatile EventBuffer eventBuffer;
    private static volatile ProbeState state;
    private static volatile RaspSemanticEngine raspSemanticEngine;

    private SecurityAgent() {
    }

    public static void premain(String agentArgs, Instrumentation instrumentation) {
        start("premain", instrumentation);
    }

    public static void agentmain(String agentArgs, Instrumentation instrumentation) {
        start("agentmain", instrumentation);
    }

    public static void start(String source) {
        start(source, null);
    }

    public static void start(String source, Instrumentation instrumentation) {
        FailOpen.run("agent-start", () -> {
            ProbeConfig config = ProbeConfig.load();
            ProbeHttpClient httpClient = new ProbeHttpClient(config);
            state = new ProbeState();
            eventBuffer = new EventBuffer(config, httpClient);
            raspSemanticEngine = new RaspSemanticEngine(eventBuffer, state);
            HookRuntime.configure(config);
            HookMetrics.configure(config);
            state.applyInitialMode();
            AgentMetrics.register(eventBuffer);
            AgentUpdateManager updateManager = new AgentUpdateManager(config, httpClient);
            AutoRollbackController rollbackController = new AutoRollbackController(config, updateManager);
            rollbackController.verifyStartup(config.probeVersion());
            new CircuitBreaker(config, eventBuffer, rollbackController).start();
            updateManager.markCurrentHealthy();
            updateManager.checkOnce();
            new AgentUpdatePoller(config, updateManager).start();
            if (instrumentation != null && config.byteBuddyEnabled()) {
                // 方案 B 收尾：把仅含「共享状态载体 TaintHub」的 bootstrap jar 挂到 bootstrap 类加载器
                // 搜索路径。TaintHub 只存在于此 bootstrap jar（绝不进 sec-probe.jar），因此无论
                // AppClassLoader 侧的 agent 代码，还是 bootstrap 侧的反序列化 transform advice，经
                // 各自的 TaintStore 委托最终都落到唯一一份 bootstrap TaintHub 静态实例——彻底消除
                // 此前「TaintStore 双类加载器实例」导致的 taint_path 跨类加载器分裂（反序列化中间
                // 节点丢失）。
                appendBootstrapJar(instrumentation);
                ByteBuddyHookInstaller.install(instrumentation, config);
                // 方法级虚拟补丁引擎 (手册 11.2.5)：拿住 Instrumentation 句柄，后续心跳
                // 下发 VIRTUAL_PATCH 规则时按目标方法做运行时 retransform。
                VirtualPatchEngine.install(instrumentation, config);
                // 方案 1：探针内部透明暖机——retransform 完成后，同步热循环已插桩核心类，
                // 逼 JVM 把重编译尾在 boot 期结清，用户首请求即快、无需任何外部合成请求。
                // 方案 3：暖机算力同步跑完（快，~1s）后再放行业务；此后进入 WARMING_UP 宽限窗口，
                // 后台线程周期上报 WARMING_UP，窗口结束才置 READY，让前端能看到「预热中」而非「已挂」。
                if (config.warmupEnabled()) {
                    try {
                        httpClient.heartbeat(state.mode(), state.ruleVersion(), null, "WARMING_UP");
                    } catch (Throwable ignored) {
                    }
                    WarmupRoutine.run(config);
                    final int settle = config.warmupSettleSeconds();
                    if (settle > 0) {
                        Thread settleThread = new Thread(() -> {
                            try {
                                long deadline = System.currentTimeMillis() + (long) settle * 1000L;
                                while (System.currentTimeMillis() < deadline) {
                                    long remaining = deadline - System.currentTimeMillis();
                                    Thread.sleep(Math.min(5000L, Math.max(0L, remaining)));
                                    try {
                                        httpClient.heartbeat(state.mode(), state.ruleVersion(), null, "WARMING_UP");
                                    } catch (Throwable ignored) {
                                    }
                                }
                            } catch (InterruptedException ignored) {
                                Thread.currentThread().interrupt();
                            }
                            state.setAgentPhase("READY");
                            try {
                                httpClient.heartbeat(state.mode(), state.ruleVersion(), null, "READY");
                            } catch (Throwable ignored) {
                            }
                        }, "sec-agent-warmup-settle");
                        settleThread.setDaemon(true);
                        settleThread.start();
                    } else {
                        state.setAgentPhase("READY");
                        try {
                            httpClient.heartbeat(state.mode(), state.ruleVersion(), null, "READY");
                        } catch (Throwable ignored) {
                        }
                    }
                } else {
                    state.setAgentPhase("READY");
                }
            }
            new ConfigPoller(state, httpClient, rollbackController).start();
            eventBuffer.start();
            AgentLogger.info("core", "started via " + source + " for app " + config.appName());
            // A2 插桩覆盖台账：把本次已安装的 hook 清单发一条 HOOK_INVENTORY 事件。
            // 后端据此把 no-iast-evidence 二分为「探针没插到」（观测缺失，不得判无漏洞）
            // 与「插到了但没触发」（真漏报）。此前全平台无任何此类记录，导致该归因只能靠猜。
            reportHookInventory();
        });
    }

    /**
     * 发射已安装 hook 清单（A2 覆盖台账的交付路径）。
     *
     * <p>发一条汇总事件而非每个 hook 一条：hook 数量可达数百，逐条发会淹没事件表。
     * {@code payload} 放 {@code count} 可读摘要，{@code context.hook_inventory} 放
     * {@code "type|name|origin;..."} 紧凑串（EventBuffer 走 JSON，控制体积）。
     *
     * <p>失败清单（{@code failed|} 前缀）单独计数字段，便于后端区分「压根没尝试插」与
     * 「尝试插了但失败」——二者都是观测缺失但根因不同。
     */
    private static void reportHookInventory() {
        try {
            java.util.Map<String, String> hooks = HookRuntime.installedHooks();
            if (hooks.isEmpty()) {
                AgentLogger.warn("core", "hook inventory empty — 覆盖台账为空，"
                        + "no-iast-evidence 归因不可用");
                return;
            }
            int failed = 0;
            StringBuilder sb = new StringBuilder();
            for (java.util.Map.Entry<String, String> e : hooks.entrySet()) {
                if (e.getKey().startsWith("failed|")) {
                    failed++;
                }
                if (sb.length() > 0) {
                    sb.append(';');
                }
                sb.append(e.getKey()).append('|').append(e.getValue() == null ? "" : e.getValue());
            }
            java.util.Map<String, Object> ctx = new java.util.HashMap<>();
            ctx.put("mode", state.mode().name());
            ctx.put("reason", "hook-inventory");
            ctx.put("hook_inventory", sb.toString());
            ctx.put("hook_count", hooks.size());
            ctx.put("hook_failed_count", failed);
            final java.util.Map<String, String> hooksFinal = hooks;
            final int failedFinal = failed;
            final String inventoryFinal = sb.toString();
            FailOpen.run("report-hook-inventory", () -> eventBuffer.offer(new SecurityEvent(
                    "HOOK_INVENTORY",
                    "MEDIUM",
                    java.util.UUID.randomUUID().toString(),
                    "",
                    "probe-hook-inventory",
                    "installed hooks: " + hooksFinal.size() + " (failed: " + failedFinal + ")",
                    ctx,
                    "", "")));
            AgentLogger.info("core", "hook inventory reported: " + hooks.size() + " (failed: " + failed + ")");
        } catch (Throwable throwable) {
            AgentLogger.warn("core", "hook inventory report failed-open: "
                    + throwable.getClass().getSimpleName());
        }
    }

    public static void reportSink(String sink, String payload) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        // 探针/框架后台 IO）此刻探针内部状态可能未就绪，走完整断言会 NPE。真实命中必在请求上下文内，
        // 故上下文外的 sink 直接返回，不进 TaintStore/inspectRasp/captureStackTrace 重路径。fail-open。
        if (!HookRuntime.inRequestContext()) {
            return;
        }
        // 记录 sink 跳点（origin=sink），随 taint_path 回带形成数据流证据链。
        TaintStore.recordTaintHop("sink", sink);
        RaspDecision decision = inspectRasp(sink, payload);
        if (decision.blocked()) {
            throw new SecurityException("Blocked by sec-agent RASP: " + decision.reason());
        }
        EventBuffer buffer = eventBuffer;
        ProbeState currentState = state;
        if (buffer == null || currentState == null) {
            return;
        }
        java.util.Map<String, Object> ctx = new java.util.HashMap<>();
        ctx.put("mode", currentState.mode().name());
        // 把本请求累积的污点传播路径回带进事件，供上报层还原数据流证据链。
        String taintPath = TaintStore.taintPathJson();
        if (!taintPath.isEmpty()) {
            ctx.put("taint_path", taintPath);
        }
        // 设计一①：sink 现场显式断言平台 canary 抵达危险函数实参 → 透传 canary + canaryState=sink-reached，
        // 后端将其归一到独立态 sink-reached-probe，即便 D1 仅投 canary 探针也判有害、不降级。
        //
        //   值级（canary 身份段真实出现在本 sink 实参文本里）→ 断言 canaryState=sink-reached（强证据）；
        //   trace 级（canary 仅由请求携带、并不在本 sink 实参里）→ 只回带 canary 做关联，不设 canaryState。
        //   实测近 6 万事件：89% 的 sink-reached 是 trace 级噪声 sink（Cookie.setSecure /
        //   FileOutputStream.<init> / Cipher.getInstance），把它们抬成 sink-reached-probe 正是误报根。
        String valueCanary = HookRuntime.currentSinkValueCanary();
        if (!valueCanary.isEmpty()) {
            ctx.put("canary", valueCanary);
            ctx.put("canaryState", "sink-reached");
        } else {
            String reqCanary = HookRuntime.currentSinkCanary();
            if (!reqCanary.isEmpty()) {
                ctx.put("canary", reqCanary);
            }
        }
        // L3 语义层：透传消毒器记录（与 reportTaintEvent 同款，见该处说明）。
        String sinkSanitizer = HookRuntime.currentSinkSanitizer();
        ctx.put("sink_sanitizer", sinkSanitizer == null ? "" : sinkSanitizer);
        FailOpen.run("report-sink", () -> buffer.offer(new SecurityEvent(
                "SINK_HIT",
                currentState.mode() == ProbeMode.BLOCK ? "HIGH" : "MEDIUM",
                UUID.randomUUID().toString(),
                TaintStore.currentRequestId(),
                sink,
                payload,
                ctx,
                captureSinkMethod(),
                captureStackTrace())));
    }

    // 跳过探针自身/基础设施帧（com.rasp.probe、net.bytebuddy、反射/Thread 等），
    // 取第一个应用帧作为 sink 方法身份。
    private static boolean isInfraFrame(String cn) {
        return cn.startsWith("com.rasp.probe")
                || "java.lang.Thread".equals(cn)
                || cn.startsWith("net.bytebuddy")
                || cn.startsWith("java.lang.reflect")
                || cn.startsWith("jdk.internal.reflect")
                || cn.startsWith("sun.reflect");
    }

    private static String captureSinkMethod() {
        for (StackTraceElement f : Thread.currentThread().getStackTrace()) {
            String cn = f.getClassName();
            if (!isInfraFrame(cn)) {
                return cn + "." + f.getMethodName()
                        + "(" + (f.getFileName() == null ? "?" : f.getFileName())
                        + ":" + f.getLineNumber() + ")";
            }
        }
        return "";
    }

    private static String captureStackTrace() {
        StringBuilder sb = new StringBuilder();
        boolean started = false;
        int count = 0;
        for (StackTraceElement f : Thread.currentThread().getStackTrace()) {
            String cn = f.getClassName();
            if (!started) {
                if (isInfraFrame(cn)) {
                    continue;
                }
                started = true;
            } else if (isInfraFrame(cn)) {
                break; // 回到探针/基础设施帧，停止（避免把更深的 advice 帧当噪声）
            }
            sb.append("at ").append(cn).append(".").append(f.getMethodName())
                    .append("(").append(f.getFileName() == null ? "?" : f.getFileName())
                    .append(":").append(f.getLineNumber()).append(")\n");
            if (++count >= 40) {
                break;
            }
        }
        return sb.toString();
    }

    public static void onTaintGate(String sink, String payload, boolean block) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        ProbeState currentState = state;
        if (currentState == null) {
            return;
        }
        if (block && currentState.mode() == ProbeMode.BLOCK) {
            reportTaintEvent("RASP_BLOCKED_TAINT", sink, payload);
            throw new SecurityException("Blocked by sec-agent RASP (taint): " + sink);
        }
        reportTaintEvent("TAINT_FLOW", sink, payload);
    }

    /**
     * 方法级虚拟补丁命中 (手册 11.2.5 三)。
     *
     * <p>拦截条件是「规则已转 BLOCKING」且「探针处于 BLOCK 模式」——两者缺一只观测。
     * 这样 AI 产出的规则 (最高 OBSERVING) 天然不会拦流量，必须经人工审核转 BLOCKING
     * 才具备拦截力，且拦截仍是既有的 SecurityException 语义，不新增第二套拦截机制。
     */
    public static void onVirtualPatchHit(VirtualPatchTarget target, String origin, String payload) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        ProbeState currentState = state;
        if (currentState == null || target == null) {
            return;
        }
        boolean block = target.blocking() && currentState.mode() == ProbeMode.BLOCK;
        reportPatchEvent(block ? "RASP_BLOCKED_PATCH" : "VIRTUAL_PATCH_HIT",
                block ? "HIGH" : "MEDIUM", target, payload, origin);
        if (block) {
            throw new SecurityException("Blocked by sec-agent virtual patch rule-" + target.ruleId()
                    + ": " + target.coordinate());
        }
    }

    /** 虚拟补丁生命周期与命中事件的统一落盘出口 (applied / revoked / rejected / hit / blocked)。 */
    public static void reportPatchEvent(String type, String severity, VirtualPatchTarget target,
            String payload, String reason) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        EventBuffer buffer = eventBuffer;
        ProbeState currentState = state;
        if (buffer == null || currentState == null || target == null) {
            return;
        }
        java.util.Map<String, Object> ctx = new java.util.HashMap<>();
        ctx.put("ruleId", Long.toString(target.ruleId()));
        ctx.put("ruleState", target.blocking() ? "BLOCKING" : "OBSERVING");
        ctx.put("level", target.callLevel() ? "call" : "parameter");
        ctx.put("reason", reason == null ? "" : reason);
        ctx.put("mode", currentState.mode().name());
        FailOpen.run("report-virtual-patch", () -> buffer.offer(new SecurityEvent(
                type,
                severity,
                UUID.randomUUID().toString(),
                TaintStore.currentRequestId(),
                "virtual-patch:" + target.coordinate(),
                payload == null ? "" : payload,
                ctx,
                "", "")));
    }

    public static void reportTaintEvent(String type, String sink, String payload) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        // 记录 sink 跳点（origin=sink），随 taint_path 回带形成数据流证据链。
        TaintStore.recordTaintHop("sink", sink);
        EventBuffer buffer = eventBuffer;
        ProbeState currentState = state;
        if (buffer == null || currentState == null) {
            return;
        }
        String severity = "RASP_BLOCKED_TAINT".equals(type) ? "HIGH" : "MEDIUM";
        java.util.Map<String, Object> ctx = new java.util.HashMap<>();
        ctx.put("mode", currentState.mode().name());
        ctx.put("reason", "taint-flow");
        String taintPath = TaintStore.taintPathJson();
        if (!taintPath.isEmpty()) {
            ctx.put("taint_path", taintPath);
        }
        // 设计一①：sink 现场显式断言平台 canary 抵达危险函数实参 → 透传 canary + canaryState=sink-reached。
        //
        //   值级（canary 真实出现在本 sink 实参里）才断言 sink-reached；trace 级只关联、不断言。
        String valueCanary = HookRuntime.currentSinkValueCanary();
        if (!valueCanary.isEmpty()) {
            ctx.put("canary", valueCanary);
            ctx.put("canaryState", "sink-reached");
        } else {
            String reqCanary = HookRuntime.currentSinkCanary();
            if (!reqCanary.isEmpty()) {
                ctx.put("canary", reqCanary);
            }
        }
        // L3 语义层：透传本 sink 实参上的消毒器记录（"sanitizerId|family1,family2"）。
        // 后端据此把「到达但已消毒」从「到达即漏洞」里择出来（OWASP ldapi/sqli 安全用例）。
        // 空串表示「本 sink 实参无消毒记录」，与「未采集到」同义，后端按证据缺失处理。
        String sinkSanitizer = HookRuntime.currentSinkSanitizer();
        ctx.put("sink_sanitizer", sinkSanitizer == null ? "" : sinkSanitizer);
        FailOpen.run("report-taint", () -> buffer.offer(new SecurityEvent(
                type,
                severity,
                UUID.randomUUID().toString(),
                TaintStore.currentRequestId(),
                sink,
                payload,
                ctx,
                "", "")));
    }

    /**
     * 发射 L3 语义层证据：本次请求内各 sink 的调用结果（{@code no_throw} / {@code threw}）。
     *
     * <p>每条 sink 结果发一个独立事件，{@code sink} 字段放被调用类名，
     * {@code payload} 放人类可读摘要，{@code context} 携带机器可读字段：
     * <ul>
     *   <li>{@code sink_outcome} = {@code no_throw} | {@code threw}</li>
     *   <li>{@code sink_exception_class} = 异常全限定类名（仅 threw 时有）</li>
     *   <li>{@code sink_exception_msg} = 异常消息截断 256 字符（仅 threw 时有）</li>
     *   <li>{@code canary} = 该次 sink 命中时的平台 canary（冻结值）</li>
     *   <li>{@code canaryState} = {@code sink-outcome}（与 TAINT_FLOW 的 {@code sink-reached} 区分，
     *       后端据此分流到 L3 通道，不混入 L2 值级判据）</li>
     * </ul>
     *
     * <p>异常类型本身即族判据：SQLException→sqli、NamingException→ldapi、
     * NumberFormatException→类型混淆。后端按此映射，<b>但不</b>由探针裁决有害性。
     *
     * <p>fail-open：整体包在 {@link FailOpen} 里；空列表直接返回不发事件。
     */
    public static void reportSinkOutcome(java.util.List<HookRuntime.SinkOutcome> outcomes) {
        if (outcomes == null || outcomes.isEmpty()) {
            return;
        }
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        EventBuffer buffer = eventBuffer;
        ProbeState currentState = state;
        if (buffer == null || currentState == null) {
            return;
        }
        for (HookRuntime.SinkOutcome outcome : outcomes) {
            try {
                java.util.Map<String, Object> ctx = new java.util.HashMap<>();
                ctx.put("mode", currentState.mode().name());
                ctx.put("reason", "sink-outcome");
                ctx.put("canaryState", "sink-outcome");
                ctx.put("sink_outcome", outcome.threw ? "threw" : "no_throw");
                if (outcome.threw) {
                    ctx.put("sink_exception_class", outcome.exceptionClass);
                    ctx.put("sink_exception_msg", outcome.exceptionMessage);
                }
                if (!outcome.canary.isEmpty()) {
                    ctx.put("canary", outcome.canary);
                }
                String summary = outcome.target
                        + (outcome.threw
                                ? " threw " + outcome.exceptionClass + ": " + outcome.exceptionMessage
                                : " completed without exception");
                final java.util.Map<String, Object> finalCtx = ctx;
                final String finalSummary = summary;
                FailOpen.run("report-sink-outcome", () -> buffer.offer(new SecurityEvent(
                        "SINK_OUTCOME",
                        "MEDIUM",
                        UUID.randomUUID().toString(),
                        TaintStore.currentRequestId(),
                        outcome.target,
                        finalSummary,
                        finalCtx,
                        "", "")));
            } catch (Throwable throwable) {
                // 单条失败不影响其余条目
                AgentLogger.warn("core", "sink outcome emit failed-open: "
                        + throwable.getClass().getSimpleName());
            }
        }
    }

    /**
     * 把只含 {@link TaintHub}（共享状态载体）的 bootstrap jar 挂到 bootstrap 类加载器搜索路径。
     *
     * <p>关键约束：{@code TaintHub} 仅存在于此 bootstrap jar，<b>绝不</b>进入 {@code sec-probe.jar}
     * （AppClassLoader）。这样 AppClassLoader 侧代码（agent / servlet 源标记 advice）与 bootstrap 侧
     * 的反序列化 transform advice，经各自的 {@link TaintStore} 委托最终都落到唯一一份 bootstrap
     * {@code TaintHub} 静态实例，消除「双类加载器 TaintStore 实例」导致的 taint_path 跨加载器分裂。
     * 若 bootstrap jar 缺失则降级跳过（fail-open，仅影响方案 B 的反序列化节点精确核对）。
     */
    private static void appendBootstrapJar(Instrumentation instrumentation) {
        try {
            java.net.URL loc = SecurityAgent.class.getProtectionDomain().getCodeSource().getLocation();
            if (loc == null) {
                AgentLogger.warn("core", "appendBootstrapJar: code source location unavailable");
                return;
            }
            java.io.File agentJar = new java.io.File(loc.toURI());
            java.io.File dir = agentJar.getParentFile();
            java.io.File bootstrapJar = new java.io.File(dir, "sec-probe-bootstrap.jar");
            if (bootstrapJar.exists() && bootstrapJar.isFile()) {
                instrumentation.appendToBootstrapClassLoaderSearch(new java.util.jar.JarFile(bootstrapJar));
                AgentLogger.info("core", "appended bootstrap jar: " + bootstrapJar.getAbsolutePath());
            } else {
                AgentLogger.warn("core", "appendBootstrapJar: bootstrap jar not found at " + bootstrapJar.getAbsolutePath());
            }
        } catch (Throwable t) {
            AgentLogger.warn("core", "appendBootstrapJar failed: " + t);
        }
    }

    public static void reportBolaSuspect(String principal, List<String> objectAccesses) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        // 仅当平台 canary 身份段（s4st41<16hex>）存在时才发射 BOLA_SUSPECT。canary 来自平台经
        // X-SASTAI-Trace 头注入的重放请求，是后端按 canary 关联回本次重放、做「授权 hook 语义确认」
        // 的唯一凭据。无 canary（普通用户流量）不发射，避免向 iast_events 灌入无法关联的噪声事件。
        String canary = HookRuntime.currentCanary();
        if (canary.isEmpty()) {
            // 诊断：无 canary 跳过发射（普通流量，符合预期）。若这里 objects 非空却无 canary，
            // 说明请求未带 X-SASTAI-Trace 头（非重放流量），不是缺陷。
            AgentLogger.info("bola", "skip(empty-canary) objects=" + objectAccesses.size());
            return;
        }
        AgentLogger.info("bola", "EMIT canary=" + canary + " principal=" + principal
                + " objects=" + objectAccesses.size());
        EventBuffer buffer = eventBuffer;
        ProbeState currentState = state;
        if (buffer == null || currentState == null) {
            return;
        }
        String joined = String.join(",", objectAccesses);
        // 授权盲点（BOLA）事件：payload 描述缺失的对象级授权访问，context 携带主体、访问对象清单与
        // 平台 canary，供上报层还原为「授权 hook 语义确认」的运行时证据并按 canary 关联回重放。
        // traceId / payload / canary 三处都写入身份段，兼容后端在任意字段扫描 s4st41<16hex>。
        final String bolaPayload = "missing object-level authorization: " + joined + " |canary:" + canary;
        java.util.Map<String, Object> ctx = new java.util.HashMap<>();
        ctx.put("principal", principal);
        ctx.put("objects", joined);
        ctx.put("mode", currentState.mode().name());
        ctx.put("canary", canary);
        FailOpen.run("report-bola", () -> buffer.offer(new SecurityEvent(
                "BOLA_SUSPECT",
                "HIGH",
                canary,
                TaintStore.currentRequestId(),
                "bola",
                bolaPayload,
                ctx,
                "", "")));
    }

    public static void reportRaceSuspect(String resourceKey, List<String> concurrentReaders) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        EventBuffer buffer = eventBuffer;
        ProbeState currentState = state;
        if (buffer == null || currentState == null) {
            return;
        }
        String joined = String.join(",", concurrentReaders);
        java.util.Map<String, Object> ctx = new java.util.HashMap<>();
        ctx.put("resource", resourceKey);
        ctx.put("concurrentReaders", joined);
        ctx.put("scopes", String.join(",", ConcurrencyContext.snapshot()));
        ctx.put("mode", currentState.mode().name());
        FailOpen.run("report-race", () -> buffer.offer(new SecurityEvent(
                "RACE_SUSPECT",
                "HIGH",
                UUID.randomUUID().toString(),
                TaintStore.currentRequestId(),
                "race",
                "concurrent read-write on " + resourceKey + " by " + joined,
                ctx,
                "", "")));
    }

    public static RaspDecision inspectRasp(String sink, String payload) {
        RaspSemanticEngine engine = raspSemanticEngine;
        if (engine == null) {
            return RaspDecision.allow("agent-not-started");
        }
        return engine.inspect(sink, payload);
    }

    /**
     * Pure content-danger predicate for the L2 taint gate (no event, no throw). Lets the
     * taint path block only tainted values whose content is actually an attack, avoiding
     * over-blocking benign tainted values (e.g. {@code id=1}) at dangerous sinks.
     */
    public static boolean isDangerousContent(String payload) {
        RaspSemanticEngine engine = raspSemanticEngine;
        return engine != null && engine.isDangerousContent(payload);
    }

    public static void reportCve(String cveId, String description, String poc) {
        RaspSemanticEngine engine = raspSemanticEngine;
        if (engine != null) {
            engine.reportCve(cveId, description, poc);
        }
    }
}
