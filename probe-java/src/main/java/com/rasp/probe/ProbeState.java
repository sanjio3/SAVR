package com.rasp.probe;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

public class ProbeState {
    private final AtomicReference<ProbeMode> mode = new AtomicReference<>(ProbeMode.MONITOR);
    private final AtomicLong ruleVersion = new AtomicLong(0);
    private final AtomicReference<List<AgentRule>> rules = new AtomicReference<>(List.of());
    // 方案 3：探针阶段。premain 暖机前为 WARMING_UP，暖机完成（或禁用暖机）置 READY。
    private final AtomicReference<String> agentPhase = new AtomicReference<>("WARMING_UP");

    public ProbeMode mode() {
        return mode.get();
    }

    public String agentPhase() {
        return agentPhase.get();
    }

    public void setAgentPhase(String phase) {
        agentPhase.set(phase);
    }

    /**
     * Pin the initial mode before the first Server contact. Lets operators start the
     * agent in BLOCK mode for air-gapped / local verification, or force MONITOR.
     * Reads {@code sec.mode} system property then {@code SEC_MODE} env, accepting
     * MONITOR / BLOCK (case-insensitive). Invalid values are ignored (stays MONITOR).
     */
    public void applyInitialMode() {
        String raw = System.getProperty("sec.mode");
        if (raw == null || raw.isBlank()) {
            raw = System.getenv("SEC_MODE");
        }
        if (raw == null || raw.isBlank()) {
            return;
        }
        try {
            mode.set(ProbeMode.valueOf(raw.trim().toUpperCase(java.util.Locale.ROOT)));
        } catch (IllegalArgumentException ignored) {
            // Unknown value: keep default MONITOR.
        }
    }

    public long ruleVersion() {
        return ruleVersion.get();
    }

    public List<AgentRule> rules() {
        return rules.get();
    }

    public void applyConfig(Map<String, Object> data) {
        Object nextMode = data.get("mode");
        if (nextMode != null) {
            ProbeMode parsedMode = ProbeMode.valueOf(nextMode.toString());
            mode.set(parsedMode);
        }
        Object nextVersion = data.get("ruleVersion");
        if (nextVersion instanceof Number) {
            ruleVersion.set(((Number) nextVersion).longValue());
        }
        Object nextRules = data.get("rules");
        if (nextRules instanceof List<?>) {
            List<?> list = (List<?>) nextRules;
            List<AgentRule> parsedRules = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof AgentRule) {
                    AgentRule rule = (AgentRule) item;
                    parsedRules.add(rule);
                }
            }
            rules.set(List.copyOf(parsedRules));
            // 方法级虚拟补丁热下发 (手册 11.2.5 一)：规则变更即做一次织入/卸载差分。
            // 引擎未安装时是无副作用空操作，故单测直接调 applyConfig 也安全。
            VirtualPatchEngine.onRulesUpdated(rules.get());
        }
        Object toggles = data.get("hookToggles");
        if (toggles instanceof Map<?, ?>) {
            Map<?, ?> map = (Map<?, ?>) toggles;
            @SuppressWarnings("unchecked")
            Map<String, Object> typed = (Map<String, Object>) map;
            HookMetrics.applyToggles(typed);
        }
        // ModSecurity 双向激活闭环(下行方向)— 读取服务端下发的"关注会话"列表,
        // 对这些会话进入全量采样。watchSessions 由 /api/agent/heartbeat 的
        // AgentConfigResponse.watchSessions 承载,经 heartbeat 的 data 解析至此。
        consumeWatchSessions(data.get("watchSessions"));
    }

    private static void consumeWatchSessions(Object raw) {
        if (raw instanceof List<?>) {
            List<?> list = (List<?>) raw;
            List<String> sessions = list.stream()
                    .filter(java.util.Objects::nonNull)
                    .map(String::valueOf)
                    .collect(java.util.stream.Collectors.toList());
            WAFWatchStore.setWatched(sessions);
        }
    }

    public List<AgentRule> raspRules() {
        return rules.get().stream().filter(rule -> rule.active()
                && ("PAYLOAD_BLACKLIST".equals(rule.type()) || "VIRTUAL_PATCH".equals(rule.type()))).collect(java.util.stream.Collectors.toList());
    }
}
