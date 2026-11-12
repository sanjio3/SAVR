package com.rasp.probe;

import java.util.Locale;
import java.util.Map;

public final class ProbeConfig {
    private final String serverUrl;
    private final String agentId;
    private final String appName;
    private final String environment;
    private final String agentToken;
    private final int networkTimeoutMs;
    private final int eventQueueSize;
    private final boolean byteBuddyEnabled;
    private final boolean servletHooksEnabled;
    private final boolean jdbcHooksEnabled;
    private final boolean commandHooksEnabled;
    private final boolean expressionHooksEnabled;
    private final boolean deserializationHooksEnabled;
    private final boolean unknownMethodHooksEnabled;
    private final boolean propagatorHooksEnabled;
    private final boolean fileHooksEnabled;
    private final boolean httpClientHooksEnabled;
    private final boolean jndiHooksEnabled;
    private final boolean asyncContextEnabled;
    private final boolean frameworkHooksEnabled;
    private final String appPackages;
    private final int maxSampleLength;
    private final boolean agentUpdateEnabled;
    private final String agentHome;
    private final String probeVersion;
    private final String protocolVersion;
    private final int updateCheckIntervalSeconds;
    private final boolean circuitBreakerEnabled;
    private final int cbCpuThresholdPercent;
    private final int cbQueueThresholdPercent;
    private final int cbErrorThreshold;
    private final int cbCooldownMillis;
    private final int hookSampleRatePercent;
    private final int hookRateLimitPerSecond;
    private final boolean authzHooksEnabled;
    private final boolean raceHooksEnabled;
    // ---- M2 盲点 / 字段级 / 数组重组 ----
    // blindSpotHooksEnabled: Jackson 多态反序列化 / NoSQL(Mongo) / SSTI 模板引擎 / GraphQL sink。
    // fieldTaintHooksEnabled: java.lang.reflect.Field get/set 字段级污点边。
    // arrayTaintHooksEnabled: java.util.Arrays copyOf/copyOfRange 数组重组继承。
    private final boolean blindSpotHooksEnabled;
    private final boolean fieldTaintHooksEnabled;
    private final boolean arrayTaintHooksEnabled;
    // virtualPatchEnabled: 方法级虚拟补丁运行时 retransform 引擎。
    private final boolean virtualPatchEnabled;

    public ProbeConfig(String serverUrl, String agentId, String appName, String environment, String agentToken, int networkTimeoutMs, int eventQueueSize, boolean byteBuddyEnabled, boolean servletHooksEnabled, boolean jdbcHooksEnabled, boolean commandHooksEnabled, boolean expressionHooksEnabled, boolean deserializationHooksEnabled, boolean unknownMethodHooksEnabled, boolean propagatorHooksEnabled, boolean fileHooksEnabled, boolean httpClientHooksEnabled, boolean jndiHooksEnabled, boolean asyncContextEnabled, boolean frameworkHooksEnabled, String appPackages, int maxSampleLength, boolean agentUpdateEnabled, String agentHome, String probeVersion, String protocolVersion, int updateCheckIntervalSeconds, boolean circuitBreakerEnabled, int cbCpuThresholdPercent, int cbQueueThresholdPercent, int cbErrorThreshold, int cbCooldownMillis, int hookSampleRatePercent, int hookRateLimitPerSecond, boolean authzHooksEnabled, boolean raceHooksEnabled, boolean blindSpotHooksEnabled, boolean fieldTaintHooksEnabled, boolean arrayTaintHooksEnabled, boolean virtualPatchEnabled) {
        this.serverUrl = serverUrl;
        this.agentId = agentId;
        this.appName = appName;
        this.environment = environment;
        this.agentToken = agentToken;
        this.networkTimeoutMs = networkTimeoutMs;
        this.eventQueueSize = eventQueueSize;
        this.byteBuddyEnabled = byteBuddyEnabled;
        this.servletHooksEnabled = servletHooksEnabled;
        this.jdbcHooksEnabled = jdbcHooksEnabled;
        this.commandHooksEnabled = commandHooksEnabled;
        this.expressionHooksEnabled = expressionHooksEnabled;
        this.deserializationHooksEnabled = deserializationHooksEnabled;
        this.unknownMethodHooksEnabled = unknownMethodHooksEnabled;
        this.propagatorHooksEnabled = propagatorHooksEnabled;
        this.fileHooksEnabled = fileHooksEnabled;
        this.httpClientHooksEnabled = httpClientHooksEnabled;
        this.jndiHooksEnabled = jndiHooksEnabled;
        this.asyncContextEnabled = asyncContextEnabled;
        this.frameworkHooksEnabled = frameworkHooksEnabled;
        this.appPackages = appPackages;
        this.maxSampleLength = maxSampleLength;
        this.agentUpdateEnabled = agentUpdateEnabled;
        this.agentHome = agentHome;
        this.probeVersion = probeVersion;
        this.protocolVersion = protocolVersion;
        this.updateCheckIntervalSeconds = updateCheckIntervalSeconds;
        this.circuitBreakerEnabled = circuitBreakerEnabled;
        this.cbCpuThresholdPercent = cbCpuThresholdPercent;
        this.cbQueueThresholdPercent = cbQueueThresholdPercent;
        this.cbErrorThreshold = cbErrorThreshold;
        this.cbCooldownMillis = cbCooldownMillis;
        this.hookSampleRatePercent = hookSampleRatePercent;
        this.hookRateLimitPerSecond = hookRateLimitPerSecond;
        this.authzHooksEnabled = authzHooksEnabled;
        this.raceHooksEnabled = raceHooksEnabled;
        this.blindSpotHooksEnabled = blindSpotHooksEnabled;
        this.fieldTaintHooksEnabled = fieldTaintHooksEnabled;
        this.arrayTaintHooksEnabled = arrayTaintHooksEnabled;
        this.virtualPatchEnabled = virtualPatchEnabled;
    }

    public String serverUrl() {
        return serverUrl;
    }

    public String agentId() {
        return agentId;
    }

    public String appName() {
        return appName;
    }

    public String environment() {
        return environment;
    }

    public String agentToken() {
        return agentToken;
    }

    public int networkTimeoutMs() {
        return networkTimeoutMs;
    }

    public int eventQueueSize() {
        return eventQueueSize;
    }

    public boolean byteBuddyEnabled() {
        return byteBuddyEnabled;
    }

    public boolean servletHooksEnabled() {
        return servletHooksEnabled;
    }

    public boolean jdbcHooksEnabled() {
        return jdbcHooksEnabled;
    }

    public boolean commandHooksEnabled() {
        return commandHooksEnabled;
    }

    public boolean expressionHooksEnabled() {
        return expressionHooksEnabled;
    }

    public boolean deserializationHooksEnabled() {
        return deserializationHooksEnabled;
    }

    public boolean unknownMethodHooksEnabled() {
        return unknownMethodHooksEnabled;
    }

    public boolean propagatorHooksEnabled() {
        return propagatorHooksEnabled;
    }

    public boolean fileHooksEnabled() {
        return fileHooksEnabled;
    }

    public boolean httpClientHooksEnabled() {
        return httpClientHooksEnabled;
    }

    public boolean jndiHooksEnabled() {
        return jndiHooksEnabled;
    }

    public boolean asyncContextEnabled() {
        return asyncContextEnabled;
    }

    public boolean frameworkHooksEnabled() {
        return frameworkHooksEnabled;
    }

    public String appPackages() {
        return appPackages;
    }

    public int maxSampleLength() {
        return maxSampleLength;
    }

    public boolean agentUpdateEnabled() {
        return agentUpdateEnabled;
    }

    public String agentHome() {
        return agentHome;
    }

    public String probeVersion() {
        return probeVersion;
    }

    public String protocolVersion() {
        return protocolVersion;
    }

    public int updateCheckIntervalSeconds() {
        return updateCheckIntervalSeconds;
    }

    public boolean circuitBreakerEnabled() {
        return circuitBreakerEnabled;
    }

    public int cbCpuThresholdPercent() {
        return cbCpuThresholdPercent;
    }

    public int cbQueueThresholdPercent() {
        return cbQueueThresholdPercent;
    }

    public int cbErrorThreshold() {
        return cbErrorThreshold;
    }

    public int cbCooldownMillis() {
        return cbCooldownMillis;
    }

    public int hookSampleRatePercent() {
        return hookSampleRatePercent;
    }

    public int hookRateLimitPerSecond() {
        return hookRateLimitPerSecond;
    }

    public boolean authzHooksEnabled() {
        return authzHooksEnabled;
    }

    public boolean raceHooksEnabled() {
        return raceHooksEnabled;
    }

    public boolean blindSpotHooksEnabled() {
        return blindSpotHooksEnabled;
    }

    public boolean fieldTaintHooksEnabled() {
        return fieldTaintHooksEnabled;
    }

    public boolean arrayTaintHooksEnabled() {
        return arrayTaintHooksEnabled;
    }

    public boolean virtualPatchEnabled() {
        return virtualPatchEnabled;
    }


    public ProbeConfig(String serverUrl, String agentId, String appName, int networkTimeoutMs, int eventQueueSize) {
        this(serverUrl, agentId, appName, "dev", "", networkTimeoutMs, eventQueueSize, false, true, true, true, true,
                true, false, true, true, false, false, false, true, "", 256, false, ".sec-agent", "0.1.0", "1", 300,
                true, 90, 90, 50, 5000, 100, 0, false, false, true, true, true, true);
    }

    public ProbeConfig(String serverUrl, String agentId, String appName, int networkTimeoutMs, int eventQueueSize,
            boolean byteBuddyEnabled, boolean servletHooksEnabled, boolean jdbcHooksEnabled, boolean commandHooksEnabled,
            boolean expressionHooksEnabled, boolean deserializationHooksEnabled, boolean unknownMethodHooksEnabled,
            String appPackages, int maxSampleLength) {
        this(serverUrl, agentId, appName, "dev", "", networkTimeoutMs, eventQueueSize, byteBuddyEnabled,
                servletHooksEnabled, jdbcHooksEnabled, commandHooksEnabled, expressionHooksEnabled,
                deserializationHooksEnabled, unknownMethodHooksEnabled, true, true, true, true, true, true, appPackages, maxSampleLength,
                false, ".sec-agent", "0.1.0", "1", 300,
                true, 90, 90, 50, 5000, 100, 0, false, false, true, true, true, true);
    }

    // Full field list minus the circuit-breaker settings, kept so existing callers and
    // tests written before the circuit breaker keep compiling with sensible defaults.
    public ProbeConfig(String serverUrl, String agentId, String appName, String environment, String agentToken,
            int networkTimeoutMs, int eventQueueSize, boolean byteBuddyEnabled, boolean servletHooksEnabled,
            boolean jdbcHooksEnabled, boolean commandHooksEnabled, boolean expressionHooksEnabled,
            boolean deserializationHooksEnabled, boolean unknownMethodHooksEnabled, boolean propagatorHooksEnabled,
            boolean fileHooksEnabled,             boolean httpClientHooksEnabled, boolean jndiHooksEnabled,
            boolean asyncContextEnabled, boolean frameworkHooksEnabled, String appPackages, int maxSampleLength,
            boolean agentUpdateEnabled,
            String agentHome, String probeVersion, String protocolVersion, int updateCheckIntervalSeconds) {
        this(serverUrl, agentId, appName, environment, agentToken, networkTimeoutMs, eventQueueSize, byteBuddyEnabled,
                servletHooksEnabled, jdbcHooksEnabled, commandHooksEnabled, expressionHooksEnabled,
                deserializationHooksEnabled, unknownMethodHooksEnabled, propagatorHooksEnabled, fileHooksEnabled,
                httpClientHooksEnabled, jndiHooksEnabled, asyncContextEnabled, frameworkHooksEnabled, appPackages,
                maxSampleLength,
                agentUpdateEnabled, agentHome, probeVersion, protocolVersion, updateCheckIntervalSeconds,
                true, 90, 90, 50, 5000, 100, 0, false, false, true, true, true, true);
    }

    // Full settings except the two semantic categories (authz/race). Kept for the integration
    // and metrics tests that must toggle the circuit-breaker and hook sample/rate settings
    // explicitly. authz/race default to disabled here so these tests do not exercise the
    // semantic hooks unless they opt in.
    public ProbeConfig(String serverUrl, String agentId, String appName, String environment, String agentToken,
            int networkTimeoutMs, int eventQueueSize, boolean byteBuddyEnabled, boolean servletHooksEnabled,
            boolean jdbcHooksEnabled, boolean commandHooksEnabled, boolean expressionHooksEnabled,
            boolean deserializationHooksEnabled, boolean unknownMethodHooksEnabled, boolean propagatorHooksEnabled,
            boolean fileHooksEnabled, boolean httpClientHooksEnabled, boolean jndiHooksEnabled,
            boolean asyncContextEnabled, boolean frameworkHooksEnabled, String appPackages, int maxSampleLength,
            boolean agentUpdateEnabled,
            String agentHome, String probeVersion, String protocolVersion, int updateCheckIntervalSeconds,
            boolean circuitBreakerEnabled, int cbCpuThresholdPercent, int cbQueueThresholdPercent, int cbErrorThreshold,
            int cbCooldownMillis, int hookSampleRatePercent, int hookRateLimitPerSecond) {
        this(serverUrl, agentId, appName, environment, agentToken, networkTimeoutMs, eventQueueSize, byteBuddyEnabled,
                servletHooksEnabled, jdbcHooksEnabled, commandHooksEnabled, expressionHooksEnabled,
                deserializationHooksEnabled, unknownMethodHooksEnabled, propagatorHooksEnabled, fileHooksEnabled,
                httpClientHooksEnabled, jndiHooksEnabled, asyncContextEnabled, frameworkHooksEnabled, appPackages,
                maxSampleLength, agentUpdateEnabled, agentHome, probeVersion, protocolVersion, updateCheckIntervalSeconds,
                circuitBreakerEnabled, cbCpuThresholdPercent, cbQueueThresholdPercent, cbErrorThreshold, cbCooldownMillis,
                hookSampleRatePercent, hookRateLimitPerSecond, false, false, true, true, true, true);
    }

    public static ProbeConfig load() {
        return new ProbeConfig(
                value("sec.server.url", "SEC_SERVER_URL", "http://localhost:8080"),
                value("sec.agent.id", "SEC_AGENT_ID", "local-agent"),
                value("sec.app.name", "SEC_APP_NAME", "demo-app"),
                value("sec.environment", "SEC_ENVIRONMENT", "dev"),
                value("sec.agent.token", "SEC_AGENT_TOKEN", ""),
                intValue("sec.network.timeout.ms", "SEC_NETWORK_TIMEOUT_MS", 50),
                intValue("sec.event.queue.size", "SEC_EVENT_QUEUE_SIZE", 1024),
                booleanValue("sec.bytebuddy.enabled", "SEC_BYTEBUDDY_ENABLED", true),
                booleanValue("sec.hook.servlet.enabled", "SEC_HOOK_SERVLET_ENABLED", true),
                booleanValue("sec.hook.jdbc.enabled", "SEC_HOOK_JDBC_ENABLED", true),
                booleanValue("sec.hook.command.enabled", "SEC_HOOK_COMMAND_ENABLED", true),
                booleanValue("sec.hook.expression.enabled", "SEC_HOOK_EXPRESSION_ENABLED", true),
                booleanValue("sec.hook.deserialization.enabled", "SEC_HOOK_DESERIALIZATION_ENABLED", true),
                booleanValue("sec.hook.unknown.enabled", "SEC_HOOK_UNKNOWN_ENABLED", false),
                booleanValue("sec.hook.propagator.enabled", "SEC_HOOK_PROPAGATOR_ENABLED", true),
                booleanValue("sec.hook.file.enabled", "SEC_HOOK_FILE_ENABLED", true),
                booleanValue("sec.hook.http-client.enabled", "SEC_HOOK_HTTP_CLIENT_ENABLED", true),
                booleanValue("sec.hook.jndi.enabled", "SEC_HOOK_JNDI_ENABLED", true),
                booleanValue("sec.async.context.enabled", "SEC_ASYNC_CONTEXT_ENABLED", true),
                booleanValue("sec.hook.framework.enabled", "SEC_HOOK_FRAMEWORK_ENABLED", true),
                value("sec.app.packages", "SEC_APP_PACKAGES", ""),
                intValue("sec.max.sample.length", "SEC_MAX_SAMPLE_LENGTH", 256),
                booleanValue("sec.agent.update.enabled", "SEC_AGENT_UPDATE_ENABLED", false),
                value("sec.agent.home", "SEC_AGENT_HOME", ".sec-agent"),
                value("sec.agent.version", "SEC_AGENT_VERSION", "0.1.0"),
                value("sec.agent.protocol.version", "SEC_AGENT_PROTOCOL_VERSION", "1"),
                intValue("sec.update.check.interval.seconds", "SEC_UPDATE_CHECK_INTERVAL_SECONDS", 300),
                booleanValue("sec.circuit.enabled", "SEC_CIRCUIT_ENABLED", true),
                intValue("sec.circuit.cpu.threshold.percent", "SEC_CIRCUIT_CPU_THRESHOLD_PERCENT", 90),
                intValue("sec.circuit.queue.threshold.percent", "SEC_CIRCUIT_QUEUE_THRESHOLD_PERCENT", 90),
                intValue("sec.circuit.error.threshold", "SEC_CIRCUIT_ERROR_THRESHOLD", 50),
                intValue("sec.circuit.cooldown.ms", "SEC_CIRCUIT_COOLDOWN_MS", 5000),
                intValue("sec.hook.sample.rate.percent", "SEC_HOOK_SAMPLE_RATE_PERCENT", 100),
                intValueAllowingZero("sec.hook.rate.limit.per.second", "SEC_HOOK_RATE_LIMIT_PER_SECOND", 0),
                booleanValue("sec.hook.authz.enabled", "SEC_HOOK_AUTHZ_ENABLED", true),
                booleanValue("sec.hook.race.enabled", "SEC_HOOK_RACE_ENABLED", true),
                booleanValue("sec.hook.blindspot.enabled", "SEC_HOOK_BLINDSPOT_ENABLED", true),
                booleanValue("sec.hook.field.taint.enabled", "SEC_HOOK_FIELD_TAINT_ENABLED", true),
                booleanValue("sec.hook.array.taint.enabled", "SEC_HOOK_ARRAY_TAINT_ENABLED", true),
                booleanValue("sec.patch.virtual.enabled", "SEC_PATCH_VIRTUAL_ENABLED", true));
    }

    private static String value(String property, String env, String defaultValue) {
        String propertyValue = System.getProperty(property);
        if (propertyValue != null && !propertyValue.isBlank()) {
            return propertyValue;
        }
        String envValue = System.getenv(env);
        return envValue == null || envValue.isBlank() ? defaultValue : envValue;
    }

    private static int intValue(String property, String env, int defaultValue) {
        String raw = value(property, env, Integer.toString(defaultValue));
        try {
            return Math.max(1, Integer.parseInt(raw));
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private static int intValueAllowingZero(String property, String env, int defaultValue) {
        String raw = value(property, env, Integer.toString(defaultValue));
        try {
            return Math.max(0, Integer.parseInt(raw));
        } catch (NumberFormatException ignored) {
            return defaultValue;
        }
    }

    private static boolean booleanValue(String property, String env, boolean defaultValue) {
        String raw = value(property, env, Boolean.toString(defaultValue));
        return "true".equalsIgnoreCase(raw) || "1".equals(raw) || "yes".equalsIgnoreCase(raw);
    }

    public Map<String, Object> heartbeatPayload(ProbeMode mode, long knownRuleVersion) {
        return heartbeatPayload(mode, knownRuleVersion, null);
    }

    public Map<String, Object> heartbeatPayload(ProbeMode mode, long knownRuleVersion, Map<String, Object> metrics) {
        return heartbeatPayload(mode, knownRuleVersion, metrics, null);
    }

    /**
     * 心跳负载（方案 3：WARMING_UP 状态可见）。agentPhase 非空时随心跳上报探针阶段：
     * WARMING_UP = 挂载后 retransform 重编译尾尚未收敛，首请求较慢；READY = 已透明暖机完成。
     */
    public Map<String, Object> heartbeatPayload(ProbeMode mode, long knownRuleVersion, Map<String, Object> metrics, String agentPhase) {
        java.util.Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("agentId", agentId);
        payload.put("appName", appName);
        payload.put("environment", environment);
        payload.put("probeVersion", probeVersion);
        payload.put("currentMode", mode.name().toUpperCase(Locale.ROOT));
        payload.put("knownRuleVersion", knownRuleVersion);
        if (metrics != null && !metrics.isEmpty()) {
            payload.put("metrics", metrics);
        }
        if (agentPhase != null && !agentPhase.isBlank()) {
            payload.put("agentPhase", agentPhase);
        }
        return payload;
    }

    /** 方案 1：挂载后是否执行探针内部透明暖机（默认开，可用 -Dsec.warmup.enabled=false 关闭）。 */
    public boolean warmupEnabled() {
        return booleanValue("sec.warmup.enabled", "SEC_WARMUP_ENABLED", true);
    }

    /** 方案 1：暖机热循环每类方法的迭代次数（默认 20000）。 */
    public int warmupIterations() {
        return Math.max(1, intValue("sec.warmup.iterations", "SEC_WARMUP_ITERATIONS", 20000));
    }

    /** 方案 3：暖机后保持 WARMING_UP 的宽限窗口秒数（默认 30），让前端能看到「预热中」。0 表示暖机完即 READY。 */
    public int warmupSettleSeconds() {
        return Math.max(0, intValue("sec.warmup.settle.seconds", "SEC_WARMUP_SETTLE_SECONDS", 30));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ProbeConfig)) {
            return false;
        }
        ProbeConfig that = (ProbeConfig) o;
        return java.util.Objects.equals(serverUrl, that.serverUrl)
            && java.util.Objects.equals(agentId, that.agentId)
            && java.util.Objects.equals(appName, that.appName)
            && java.util.Objects.equals(environment, that.environment)
            && java.util.Objects.equals(agentToken, that.agentToken)
            && java.util.Objects.equals(networkTimeoutMs, that.networkTimeoutMs)
            && java.util.Objects.equals(eventQueueSize, that.eventQueueSize)
            && java.util.Objects.equals(byteBuddyEnabled, that.byteBuddyEnabled)
            && java.util.Objects.equals(servletHooksEnabled, that.servletHooksEnabled)
            && java.util.Objects.equals(jdbcHooksEnabled, that.jdbcHooksEnabled)
            && java.util.Objects.equals(commandHooksEnabled, that.commandHooksEnabled)
            && java.util.Objects.equals(expressionHooksEnabled, that.expressionHooksEnabled)
            && java.util.Objects.equals(deserializationHooksEnabled, that.deserializationHooksEnabled)
            && java.util.Objects.equals(unknownMethodHooksEnabled, that.unknownMethodHooksEnabled)
            && java.util.Objects.equals(propagatorHooksEnabled, that.propagatorHooksEnabled)
            && java.util.Objects.equals(fileHooksEnabled, that.fileHooksEnabled)
            && java.util.Objects.equals(httpClientHooksEnabled, that.httpClientHooksEnabled)
            && java.util.Objects.equals(jndiHooksEnabled, that.jndiHooksEnabled)
            && java.util.Objects.equals(asyncContextEnabled, that.asyncContextEnabled)
            && java.util.Objects.equals(frameworkHooksEnabled, that.frameworkHooksEnabled)
            && java.util.Objects.equals(appPackages, that.appPackages)
            && java.util.Objects.equals(maxSampleLength, that.maxSampleLength)
            && java.util.Objects.equals(agentUpdateEnabled, that.agentUpdateEnabled)
            && java.util.Objects.equals(agentHome, that.agentHome)
            && java.util.Objects.equals(probeVersion, that.probeVersion)
            && java.util.Objects.equals(protocolVersion, that.protocolVersion)
            && java.util.Objects.equals(updateCheckIntervalSeconds, that.updateCheckIntervalSeconds)
            && java.util.Objects.equals(circuitBreakerEnabled, that.circuitBreakerEnabled)
            && java.util.Objects.equals(cbCpuThresholdPercent, that.cbCpuThresholdPercent)
            && java.util.Objects.equals(cbQueueThresholdPercent, that.cbQueueThresholdPercent)
            && java.util.Objects.equals(cbErrorThreshold, that.cbErrorThreshold)
            && java.util.Objects.equals(cbCooldownMillis, that.cbCooldownMillis)
            && java.util.Objects.equals(hookSampleRatePercent, that.hookSampleRatePercent)
            && java.util.Objects.equals(hookRateLimitPerSecond, that.hookRateLimitPerSecond)
            && java.util.Objects.equals(authzHooksEnabled, that.authzHooksEnabled)
            && java.util.Objects.equals(raceHooksEnabled, that.raceHooksEnabled)
            && java.util.Objects.equals(blindSpotHooksEnabled, that.blindSpotHooksEnabled)
            && java.util.Objects.equals(fieldTaintHooksEnabled, that.fieldTaintHooksEnabled)
            && java.util.Objects.equals(arrayTaintHooksEnabled, that.arrayTaintHooksEnabled)
            && java.util.Objects.equals(virtualPatchEnabled, that.virtualPatchEnabled);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(serverUrl, agentId, appName, environment, agentToken, networkTimeoutMs, eventQueueSize, byteBuddyEnabled, servletHooksEnabled, jdbcHooksEnabled, commandHooksEnabled, expressionHooksEnabled, deserializationHooksEnabled, unknownMethodHooksEnabled, propagatorHooksEnabled, fileHooksEnabled, httpClientHooksEnabled, jndiHooksEnabled, asyncContextEnabled, frameworkHooksEnabled, appPackages, maxSampleLength, agentUpdateEnabled, agentHome, probeVersion, protocolVersion, updateCheckIntervalSeconds, circuitBreakerEnabled, cbCpuThresholdPercent, cbQueueThresholdPercent, cbErrorThreshold, cbCooldownMillis, hookSampleRatePercent, hookRateLimitPerSecond, authzHooksEnabled, raceHooksEnabled, blindSpotHooksEnabled, fieldTaintHooksEnabled, arrayTaintHooksEnabled, virtualPatchEnabled);
    }

    @Override
    public String toString() {
        return "ProbeConfig[" + "serverUrl=" + serverUrl + ", " + "agentId=" + agentId + ", " + "appName=" + appName + ", " + "environment=" + environment + ", " + "agentToken=" + agentToken + ", " + "networkTimeoutMs=" + networkTimeoutMs + ", " + "eventQueueSize=" + eventQueueSize + ", " + "byteBuddyEnabled=" + byteBuddyEnabled + ", " + "servletHooksEnabled=" + servletHooksEnabled + ", " + "jdbcHooksEnabled=" + jdbcHooksEnabled + ", " + "commandHooksEnabled=" + commandHooksEnabled + ", " + "expressionHooksEnabled=" + expressionHooksEnabled + ", " + "deserializationHooksEnabled=" + deserializationHooksEnabled + ", " + "unknownMethodHooksEnabled=" + unknownMethodHooksEnabled + ", " + "propagatorHooksEnabled=" + propagatorHooksEnabled + ", " + "fileHooksEnabled=" + fileHooksEnabled + ", " + "httpClientHooksEnabled=" + httpClientHooksEnabled + ", " + "jndiHooksEnabled=" + jndiHooksEnabled + ", " + "asyncContextEnabled=" + asyncContextEnabled + ", " + "frameworkHooksEnabled=" + frameworkHooksEnabled + ", " + "appPackages=" + appPackages + ", " + "maxSampleLength=" + maxSampleLength + ", " + "agentUpdateEnabled=" + agentUpdateEnabled + ", " + "agentHome=" + agentHome + ", " + "probeVersion=" + probeVersion + ", " + "protocolVersion=" + protocolVersion + ", " + "updateCheckIntervalSeconds=" + updateCheckIntervalSeconds + ", " + "circuitBreakerEnabled=" + circuitBreakerEnabled + ", " + "cbCpuThresholdPercent=" + cbCpuThresholdPercent + ", " + "cbQueueThresholdPercent=" + cbQueueThresholdPercent + ", " + "cbErrorThreshold=" + cbErrorThreshold + ", " + "cbCooldownMillis=" + cbCooldownMillis + ", " + "hookSampleRatePercent=" + hookSampleRatePercent + ", " + "hookRateLimitPerSecond=" + hookRateLimitPerSecond + ", " + "authzHooksEnabled=" + authzHooksEnabled + ", " + "raceHooksEnabled=" + raceHooksEnabled + ", " + "blindSpotHooksEnabled=" + blindSpotHooksEnabled + ", " + "fieldTaintHooksEnabled=" + fieldTaintHooksEnabled + ", " + "arrayTaintHooksEnabled=" + arrayTaintHooksEnabled + ", " + "virtualPatchEnabled=" + virtualPatchEnabled + "]";
    }
}
