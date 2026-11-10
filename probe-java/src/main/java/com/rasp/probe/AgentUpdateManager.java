package com.rasp.probe;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AgentUpdateManager {
    // Property/env used to enable manifest signature enforcement. Read locally (not
    // through ProbeConfig) to avoid threading a 32nd record component through every
    // convenience constructor and test; signature verification is a self-contained
    // concern of the update subsystem.
    private static final String SIGNATURE_KEY_PROPERTY = "sec.agent.update.signature.key";
    private static final String SIGNATURE_KEY_ENV = "SEC_AGENT_UPDATE_SIGNATURE_KEY";

    private final ProbeConfig config;
    private final ProbeHttpClient platformClient;
    private final Path home;

    public AgentUpdateManager(ProbeConfig config, ProbeHttpClient platformClient) {
        this.config = config;
        this.platformClient = platformClient;
        this.home = Path.of(config.agentHome());
    }

    public void checkOnce() {
        if (!config.agentUpdateEnabled()) {
            return;
        }
        FailOpen.run("agent-update-check", () -> platformClient.latestArtifact()
                .filter(manifest -> manifest.validFor(config))
                .filter(this::inRollout)
                .filter(manifest -> !manifest.version().equals(config.probeVersion()))
                .ifPresent(this::downloadCandidate));
    }

    private boolean inRollout(AgentArtifactManifest manifest) {
        int rollout = Math.max(0, Math.min(100, manifest.rolloutPercent()));
        if (rollout >= 100) {
            return true;
        }
        if (rollout <= 0) {
            return false;
        }
        return Math.floorMod(config.agentId().hashCode(), 100) < rollout;
    }

    private void downloadCandidate(AgentArtifactManifest manifest) {
        try {
            Files.createDirectories(home.resolve("versions").resolve(manifest.version()));
            Path candidateJar = home.resolve("versions").resolve(manifest.version()).resolve("sec-probe.jar");
            int downloadTimeout = Math.max(2000, config.networkTimeoutMs());
            HttpURLConnection connection = (HttpURLConnection) new URL(manifest.downloadUrl())
                    .openConnection(Proxy.NO_PROXY);
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(downloadTimeout);
            connection.setReadTimeout(downloadTimeout);
            connection.setInstanceFollowRedirects(true);
            int status = connection.getResponseCode();
            if (status < 200 || status >= 300) {
                markFailure("download-failed-" + status);
                return;
            }
            try (InputStream body = connection.getInputStream()) {
                Files.copy(body, candidateJar, StandardCopyOption.REPLACE_EXISTING);
            }
            String sha256 = sha256(candidateJar);
            if (!manifest.sha256().equalsIgnoreCase(sha256)) {
                Files.deleteIfExists(candidateJar);
                markFailure("checksum-failed");
                return;
            }
            if (!verifySignature(manifest, sha256)) {
                Files.deleteIfExists(candidateJar);
                return;
            }
            writePointer("candidate", manifest.version());
            writePointer("candidate.sha256", sha256);
            writePointer("candidate.status", "PENDING_RESTART");
            AgentLogger.info("update", "downloaded candidate agent " + manifest.version() + "; restart required");
        } catch (Exception exception) {
            markFailure(exception.getClass().getSimpleName());
        }
    }

    public void markCurrentHealthy() {
        if (!config.agentUpdateEnabled()) {
            return;
        }
        FailOpen.run("agent-update-healthy", () -> {
            safeWritePointer("current", config.probeVersion());
            String candidate = readPointer("candidate");
            if (config.probeVersion().equals(candidate)) {
                safeWritePointer("candidate.status", "PROMOTED");
            }
        });
    }

    /**
     * Reconcile version pointers on startup so a failed-to-load candidate is detected.
     * If a candidate was staged (PENDING_RESTART / ROLLBACK_PENDING_RESTART) and the JVM
     * came up running that exact version, the update took effect and we record the prior
     * version as the rollback target. If instead we came up on a different version, the
     * candidate failed to load and we mark it FAILED so the next update cycle will not
     * re-promote the same broken jar. Fail-open throughout.
     */
    public StartupOutcome reconcileOnStartup(String loadedVersion) {
        if (!config.agentUpdateEnabled()) {
            return StartupOutcome.NONE;
        }
        String status = readPointer("candidate.status");
        boolean pending = status.startsWith("PENDING_RESTART") || status.startsWith("ROLLBACK_PENDING_RESTART");
        if (!pending) {
            return StartupOutcome.NONE;
        }
        String candidate = readPointer("candidate");
        if (candidate.equals(loadedVersion)) {
            String previousCurrent = readPointer("current");
            if (!previousCurrent.isBlank() && !previousCurrent.equals(loadedVersion)) {
                safeWritePointer("previous", previousCurrent);
            }
            safeWritePointer("current", loadedVersion);
            safeWritePointer("candidate.status",
                    status.startsWith("ROLLBACK") ? "ROLLBACK_APPLIED" : "APPLIED");
            AgentLogger.info("update", "candidate " + loadedVersion + " loaded successfully");
            return StartupOutcome.CANDIDATE_APPLIED;
        }
        safeWritePointer("candidate.status", "FAILED:load-failed-expected-" + candidate);
        safeWritePointer("current", loadedVersion);
        AgentLogger.warn("update", "candidate " + candidate + " failed to load; running " + loadedVersion);
        return StartupOutcome.LOAD_FAILED;
    }

    public RollbackOutcome rollback(String reason) {
        RollbackOutcome[] outcome = {RollbackOutcome.OBSERVATION_ONLY};
        FailOpen.run("agent-update-rollback", () -> {
            String previous = readPointer("previous");
            if (previous.isBlank()) {
                safeWritePointer("rollback.status", "OBSERVATION_ONLY:" + reason);
                outcome[0] = RollbackOutcome.OBSERVATION_ONLY;
                return;
            }
            safeWritePointer("candidate", previous);
            safeWritePointer("candidate.status", "ROLLBACK_PENDING_RESTART:" + reason);
            outcome[0] = RollbackOutcome.ROLLED_BACK;
            AgentLogger.warn("update", "rollback to previous agent requested: " + previous + " reason=" + reason);
        });
        return outcome[0];
    }

    private void markFailure(String reason) {
        FailOpen.run("agent-update-failure", () -> safeWritePointer("candidate.status", "FAILED:" + reason));
    }

    private void safeWritePointer(String name, String value) {
        try {
            writePointer(name, value);
        } catch (Exception ignored) {
        }
    }

    private void writePointer(String name, String value) throws java.io.IOException {
        Files.createDirectories(home);
        Files.writeString(home.resolve(name), value == null ? "" : value);
    }

    private String readPointer(String name) {
        try {
            Path file = home.resolve(name);
            return Files.exists(file) ? Files.readString(file).trim() : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private String sha256(Path file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                digest.update(buffer, 0, read);
            }
        }
        return hex(digest.digest());
    }

    /**
     * Enforce a detached HMAC-SHA256 signature over {@code version + "\n" + sha256} when a
     * shared key is configured. When no key is set, enforcement is skipped (opt-in until a
     * real key-distribution path exists) and a note is logged. A configured key with a
     * missing or mismatched signature fails the candidate closed (checksum already passed).
     */
    private boolean verifySignature(AgentArtifactManifest manifest, String sha256) {
        String key = signatureKey();
        if (key.isBlank()) {
            AgentLogger.info("update", "signature enforcement disabled: no " + SIGNATURE_KEY_ENV);
            return true;
        }
        String provided = manifest.signature();
        if (provided == null || provided.isBlank()) {
            markFailure("signature-missing");
            return false;
        }
        String expected;
        try {
            expected = hmacSha256Hex(key, manifest.version() + "\n" + sha256);
        } catch (Exception exception) {
            markFailure("signature-error-" + exception.getClass().getSimpleName());
            return false;
        }
        if (!constantTimeEquals(expected, provided.trim().toLowerCase(java.util.Locale.ROOT))) {
            markFailure("signature-failed");
            return false;
        }
        return true;
    }

    private String signatureKey() {
        String property = System.getProperty(SIGNATURE_KEY_PROPERTY);
        if (property != null && !property.isBlank()) {
            return property;
        }
        String env = System.getenv(SIGNATURE_KEY_ENV);
        return env == null ? "" : env.trim();
    }

    private static String hmacSha256Hex(String key, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return hex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte item : bytes) {
            builder.append(String.format("%02x", item));
        }
        return builder.toString();
    }
}

