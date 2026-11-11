package com.rasp.probe;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AgentUpdateManagerTest {
    @TempDir
    Path tempDir;

    @Test
    void validManifestDownloadsCandidateAndWritesRestartPointer() throws Exception {
        byte[] jarBytes = "candidate-agent".getBytes(StandardCharsets.UTF_8);
        HttpServer server = serve(jarBytes);
        try {
            AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"),
                    platformClient(manifest(server, "2.0.0", sha256(jarBytes))));

            manager.checkOnce();

            assertEquals("2.0.0", Files.readString(tempDir.resolve("candidate")).trim());
            assertEquals(sha256(jarBytes), Files.readString(tempDir.resolve("candidate.sha256")).trim());
            assertEquals("PENDING_RESTART", Files.readString(tempDir.resolve("candidate.status")).trim());
            assertTrue(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void checksumMismatchFailsClosedForCandidateButFailOpensProbe() throws Exception {
        HttpServer server = serve("tampered".getBytes(StandardCharsets.UTF_8));
        try {
            AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"),
                    platformClient(manifest(server, "2.0.0", "bad-sha")));

            manager.checkOnce();

            assertEquals("FAILED:checksum-failed", Files.readString(tempDir.resolve("candidate.status")).trim());
            assertFalse(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rollbackWithoutPreviousStaysObservationOnly() throws Exception {
        AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"), platformClient(null));

        manager.rollback("startup-error");

        assertEquals("OBSERVATION_ONLY:startup-error", Files.readString(tempDir.resolve("rollback.status")).trim());
    }

    @Test
    void rollbackWithPreviousMarksCandidateForRestart() throws Exception {
        Files.writeString(tempDir.resolve("previous"), "0.9.0");
        AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"), platformClient(null));

        RollbackOutcome outcome = manager.rollback("healthcheck-failed");

        assertEquals(RollbackOutcome.ROLLED_BACK, outcome);
        assertEquals("0.9.0", Files.readString(tempDir.resolve("candidate")).trim());
        assertEquals("ROLLBACK_PENDING_RESTART:healthcheck-failed", Files.readString(tempDir.resolve("candidate.status")).trim());
    }

    @Test
    void downloadNon2xxMarksFailureAndKeepsNoJar() throws Exception {
        HttpServer server = serveStatus(503);
        try {
            AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"),
                    platformClient(manifest(server, "2.0.0", "any-sha")));

            manager.checkOnce();

            assertEquals("FAILED:download-failed-503", Files.readString(tempDir.resolve("candidate.status")).trim());
            assertFalse(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void configuredKeyWithMissingSignatureFailsClosed() throws Exception {
        byte[] jarBytes = "candidate-agent".getBytes(StandardCharsets.UTF_8);
        HttpServer server = serve(jarBytes);
        System.setProperty("sec.agent.update.signature.key", "top-secret");
        try {
            AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"),
                    platformClient(manifest(server, "2.0.0", sha256(jarBytes))));

            manager.checkOnce();

            assertEquals("FAILED:signature-missing", Files.readString(tempDir.resolve("candidate.status")).trim());
            assertFalse(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")));
        } finally {
            System.clearProperty("sec.agent.update.signature.key");
            server.stop(0);
        }
    }

    @Test
    void configuredKeyWithWrongSignatureFailsClosed() throws Exception {
        byte[] jarBytes = "candidate-agent".getBytes(StandardCharsets.UTF_8);
        HttpServer server = serve(jarBytes);
        System.setProperty("sec.agent.update.signature.key", "top-secret");
        try {
            AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"),
                    platformClient(signedManifest(server, "2.0.0", sha256(jarBytes), "deadbeef")));

            manager.checkOnce();

            assertEquals("FAILED:signature-failed", Files.readString(tempDir.resolve("candidate.status")).trim());
            assertFalse(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")));
        } finally {
            System.clearProperty("sec.agent.update.signature.key");
            server.stop(0);
        }
    }

    @Test
    void configuredKeyWithValidSignaturePromotesCandidate() throws Exception {
        byte[] jarBytes = "candidate-agent".getBytes(StandardCharsets.UTF_8);
        String sha = sha256(jarBytes);
        HttpServer server = serve(jarBytes);
        System.setProperty("sec.agent.update.signature.key", "top-secret");
        try {
            String signature = hmac("top-secret", "2.0.0\n" + sha);
            AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"),
                    platformClient(signedManifest(server, "2.0.0", sha, signature)));

            manager.checkOnce();

            assertEquals("PENDING_RESTART", Files.readString(tempDir.resolve("candidate.status")).trim());
            assertTrue(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")));
        } finally {
            System.clearProperty("sec.agent.update.signature.key");
            server.stop(0);
        }
    }

    @Test
    void reconcileMarksCandidateAppliedWhenLoadedMatches() throws Exception {
        Files.writeString(tempDir.resolve("candidate"), "2.0.0");
        Files.writeString(tempDir.resolve("candidate.status"), "PENDING_RESTART");
        Files.writeString(tempDir.resolve("current"), "1.0.0");
        AgentUpdateManager manager = new AgentUpdateManager(config("2.0.0"), platformClient(null));

        StartupOutcome outcome = manager.reconcileOnStartup("2.0.0");

        assertEquals(StartupOutcome.CANDIDATE_APPLIED, outcome);
        assertEquals("APPLIED", Files.readString(tempDir.resolve("candidate.status")).trim());
        assertEquals("1.0.0", Files.readString(tempDir.resolve("previous")).trim());
        assertEquals("2.0.0", Files.readString(tempDir.resolve("current")).trim());
    }

    @Test
    void reconcileDetectsLoadFailureWhenLoadedDiffersFromCandidate() throws Exception {
        Files.writeString(tempDir.resolve("candidate"), "2.0.0");
        Files.writeString(tempDir.resolve("candidate.status"), "PENDING_RESTART");
        Files.writeString(tempDir.resolve("current"), "1.0.0");
        AgentUpdateManager manager = new AgentUpdateManager(config("1.0.0"), platformClient(null));

        StartupOutcome outcome = manager.reconcileOnStartup("1.0.0");

        assertEquals(StartupOutcome.LOAD_FAILED, outcome);
        assertEquals("FAILED:load-failed-expected-2.0.0", Files.readString(tempDir.resolve("candidate.status")).trim());
        assertEquals("1.0.0", Files.readString(tempDir.resolve("current")).trim());
    }

    private ProbeConfig config(String version) {
        return new ProbeConfig("http://127.0.0.1:1", "agent-1", "app", "prod", "", 1_000, 128,
                false, true, true, true, true, true, false, true, true, true, true, true, true,
                "", 256, true, tempDir.toString(), version, "1", 300);
    }

    private ProbeHttpClient platformClient(AgentArtifactManifest manifest) {
        return new ProbeHttpClient(config("1.0.0")) {
            @Override
            public Optional<AgentArtifactManifest> latestArtifact() {
                return Optional.ofNullable(manifest);
            }
        };
    }

    private AgentArtifactManifest manifest(HttpServer server, String version, String sha256) {
        return new AgentArtifactManifest(version, "1", "http://127.0.0.1:" + server.getAddress().getPort() + "/sec-probe.jar",
                sha256, "", "STABLE", 100);
    }

    private AgentArtifactManifest signedManifest(HttpServer server, String version, String sha256, String signature) {
        return new AgentArtifactManifest(version, "1", "http://127.0.0.1:" + server.getAddress().getPort() + "/sec-probe.jar",
                sha256, signature, "STABLE", 100);
    }

    private HttpServer serve(byte[] body) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/sec-probe.jar", exchange -> {
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }

    private HttpServer serveStatus(int status) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/sec-probe.jar", exchange -> {
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.start();
        return server;
    }

    private String hmac(String key, String message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder();
        for (byte value : hash) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    private String sha256(byte[] bytes) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(bytes);
        StringBuilder builder = new StringBuilder();
        for (byte value : hash) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}
