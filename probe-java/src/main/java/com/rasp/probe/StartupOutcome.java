package com.rasp.probe;

/** Result of reconciling agent version pointers on startup after a (possible) update. */
public enum StartupOutcome {
    /** A pending candidate matched the loaded version: the update took effect. */
    CANDIDATE_APPLIED,
    /** A candidate was pending but the loaded version differs: the candidate failed to load. */
    LOAD_FAILED,
    /** Nothing to reconcile (no pending candidate). */
    NONE
}
