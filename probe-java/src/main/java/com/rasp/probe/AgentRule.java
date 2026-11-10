package com.rasp.probe;

public final class AgentRule {
    private final long id;
    private final String type;
    private final String state;
    private final String pattern;
    private final String targetClass;
    private final String targetMethod;
    private final double confidence;
    private final String description;

    public AgentRule(long id, String type, String state, String pattern, String targetClass, String targetMethod, double confidence, String description) {
        this.id = id;
        this.type = type;
        this.state = state;
        this.pattern = pattern;
        this.targetClass = targetClass;
        this.targetMethod = targetMethod;
        this.confidence = confidence;
        this.description = description;
    }

    public long id() {
        return id;
    }

    public String type() {
        return type;
    }

    public String state() {
        return state;
    }

    public String pattern() {
        return pattern;
    }

    public String targetClass() {
        return targetClass;
    }

    public String targetMethod() {
        return targetMethod;
    }

    public double confidence() {
        return confidence;
    }

    public String description() {
        return description;
    }


    public boolean active() {
        return "OBSERVING".equals(state) || "BLOCKING".equals(state);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AgentRule)) {
            return false;
        }
        AgentRule that = (AgentRule) o;
        return java.util.Objects.equals(id, that.id)
            && java.util.Objects.equals(type, that.type)
            && java.util.Objects.equals(state, that.state)
            && java.util.Objects.equals(pattern, that.pattern)
            && java.util.Objects.equals(targetClass, that.targetClass)
            && java.util.Objects.equals(targetMethod, that.targetMethod)
            && java.util.Objects.equals(confidence, that.confidence)
            && java.util.Objects.equals(description, that.description);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(id, type, state, pattern, targetClass, targetMethod, confidence, description);
    }

    @Override
    public String toString() {
        return "AgentRule[" + "id=" + id + ", " + "type=" + type + ", " + "state=" + state + ", " + "pattern=" + pattern + ", " + "targetClass=" + targetClass + ", " + "targetMethod=" + targetMethod + ", " + "confidence=" + confidence + ", " + "description=" + description + "]";
    }
}

