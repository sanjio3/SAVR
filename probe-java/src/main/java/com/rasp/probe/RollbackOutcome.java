package com.rasp.probe;

/** Result of an auto-rollback attempt. */
public enum RollbackOutcome {
    /** A known-good previous version was found and staged for the next restart. */
    ROLLED_BACK,
    /** No previous version to fall back to; agent stays up in observation-only (passthrough) mode. */
    OBSERVATION_ONLY
}
