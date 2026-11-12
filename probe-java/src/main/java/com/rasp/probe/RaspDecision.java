package com.rasp.probe;

public final class RaspDecision {
    private final boolean blocked;
    private final String reason;

    public RaspDecision(boolean blocked, String reason) {
        this.blocked = blocked;
        this.reason = reason;
    }

    public boolean blocked() {
        return blocked;
    }

    public String reason() {
        return reason;
    }


    public static RaspDecision allow(String reason) {
        return new RaspDecision(false, reason);
    }

    public static RaspDecision block(String reason) {
        return new RaspDecision(true, reason);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RaspDecision)) {
            return false;
        }
        RaspDecision that = (RaspDecision) o;
        return java.util.Objects.equals(blocked, that.blocked)
            && java.util.Objects.equals(reason, that.reason);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(blocked, reason);
    }

    @Override
    public String toString() {
        return "RaspDecision[" + "blocked=" + blocked + ", " + "reason=" + reason + "]";
    }
}

