package com.rasp.probe;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;

class AgentUpdatePollerTest {
    @TempDir
    Path tempDir;

    @Test
    void disabledUpdatePollerDoesNotWritePointers() {
        ProbeConfig config = new ProbeConfig("http://127.0.0.1:1", "agent-1", "app", "prod", "", 1_000, 128,
                false, true, true, true, true, true, false, true, true, true, true, true, true,
                "", 256, false, tempDir.toString(), "1.0.0", "1", 30);
        ProbeHttpClient platformClient = new ProbeHttpClient(config) {
            @Override
            public Optional<AgentArtifactManifest> latestArtifact() {
                throw new AssertionError("disabled poller must not call platform");
            }
        };

        new AgentUpdatePoller(config, new AgentUpdateManager(config, platformClient)).start();

        assertFalse(Files.exists(tempDir.resolve("candidate.status")));
    }
}
