package com.rasp.probe;

import java.util.Map;

public final class SecurityEvent {
    private final String eventType;
    private final String severity;
    private final String traceId;
    private final String sessionId;
    private final String sink;
    private final String payload;
    private final Map<String, Object> context;
    // 2026-09-15 item 5：sink 现场补充方法级身份与完整调用栈，
    // 后端据此回填 iast_events.sink_method / stack_trace（此前恒空，归因精度不足）。
    private final String sinkMethod;
    private final String stackTrace;

    public SecurityEvent(String eventType, String severity, String traceId, String sessionId, String sink, String payload, Map<String, Object> context, String sinkMethod, String stackTrace) {
        this.eventType = eventType;
        this.severity = severity;
        this.traceId = traceId;
        this.sessionId = sessionId;
        this.sink = sink;
        this.payload = payload;
        this.context = context;
        this.sinkMethod = sinkMethod;
        this.stackTrace = stackTrace;
    }

    public String eventType() {
        return eventType;
    }

    public String severity() {
        return severity;
    }

    public String traceId() {
        return traceId;
    }

    public String sessionId() {
        return sessionId;
    }

    public String sink() {
        return sink;
    }

    public String payload() {
        return payload;
    }

    public Map<String, Object> context() {
        return context;
    }

    public String sinkMethod() {
        return sinkMethod;
    }

    public String stackTrace() {
        return stackTrace;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof SecurityEvent)) {
            return false;
        }
        SecurityEvent that = (SecurityEvent) o;
        return java.util.Objects.equals(eventType, that.eventType)
            && java.util.Objects.equals(severity, that.severity)
            && java.util.Objects.equals(traceId, that.traceId)
            && java.util.Objects.equals(sessionId, that.sessionId)
            && java.util.Objects.equals(sink, that.sink)
            && java.util.Objects.equals(payload, that.payload)
            && java.util.Objects.equals(context, that.context)
            && java.util.Objects.equals(sinkMethod, that.sinkMethod)
            && java.util.Objects.equals(stackTrace, that.stackTrace);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(eventType, severity, traceId, sessionId, sink, payload, context, sinkMethod, stackTrace);
    }

    @Override
    public String toString() {
        return "SecurityEvent[" + "eventType=" + eventType + ", " + "severity=" + severity + ", " + "traceId=" + traceId + ", " + "sessionId=" + sessionId + ", " + "sink=" + sink + ", " + "payload=" + payload + ", " + "context=" + context + ", " + "sinkMethod=" + sinkMethod + ", " + "stackTrace=" + stackTrace + "]";
    }
}

