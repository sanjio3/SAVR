package com.rasp.probe;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 六类场景演练台（manual 10.2 验收标准）：把「探针热更新 + 自动回滚」整条产品链路
 * （下载 → 校验 → 加载 → 熔断 → 回滚 → 观察降级）在一个统一套件里一次性跑通，
 * 每个用例对应一类验收场景，以 agent home 指针文件的最终状态作为通过判据：
 *
 * <pre>
 *  场景① 下载失败           -> candidate.status = FAILED:download-failed-*, 无 jar 落地
 *  场景② 校验失败           -> candidate.status = FAILED:checksum-failed, 无 jar 落地
 *  场景③ 加载失败           -> reconcileOnStartup=LOAD_FAILED -> 触发 startup-load-failed 回滚
 *  场景④ 熔断触发           -> 连续 N 次 trip -> circuit-persistent-trip 回滚
 *  场景⑤ 回滚成功           -> ROLLED_BACK，previous 置为 next candidate，PENDING_RESTART
 *  场景⑥ 回滚失败(无 previous) -> OBSERVATION_ONLY，探针降级为 passthrough（不宕机）
 * </pre>
 */
class RollbackScenarioDrillTest {

    @TempDir
    Path tempDir;

    @BeforeEach
    @AfterEach
    void reset() {
        CircuitBreaker.resetForTesting();
    }

    @Test
    @DisplayName("场景① 下载失败：非 2xx 即 FAILED，候选 jar 不落地")
    void scenario1_downloadFailure() throws Exception {
        HttpServer server = serveStatus(503);
        try {
            AgentUpdateManager manager = manager(config("1.0.0", true),
                    platformClient(manifest(server, "2.0.0", "any-sha")));
            manager.checkOnce();

            assertEquals("FAILED:download-failed-503", readPointer("candidate.status"));
            assertFalse(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")),
                    "下载失败不得残留候选 jar");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("场景② 校验失败：sha256 不匹配即 FAILED，候选 jar 不落地")
    void scenario2_verificationFailure() throws Exception {
        HttpServer server = serve("tampered".getBytes(StandardCharsets.UTF_8));
        try {
            AgentUpdateManager manager = manager(config("1.0.0", true),
                    platformClient(manifest(server, "2.0.0", "bad-sha")));
            manager.checkOnce();

            assertEquals("FAILED:checksum-failed", readPointer("candidate.status"));
            assertFalse(Files.exists(tempDir.resolve("versions").resolve("2.0.0").resolve("sec-probe.jar")),
                    "校验失败不得残留候选 jar");
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("场景③ 加载失败：staged 候选未生效即 LOAD_FAILED，触发 startup 回滚")
    void scenario3_loadFailureTriggersRollback() throws Exception {
        // 已 staged 2.0.0，但本次以 1.0.0 起来 -> 说明 2.0.0 加载失败
        writePointer("candidate", "2.0.0");
        writePointer("candidate.status", "PENDING_RESTART");
        writePointer("current", "1.0.0");
        writePointer("previous", "0.9.0");
        AutoRollbackController controller = controller(config("1.0.0", true));

        controller.verifyStartup("1.0.0");

        assertTrue(controller.hasRolledBack(), "加载失败必须触发自动回滚");
        assertEquals("startup-load-failed", controller.lastReason());
        assertEquals(RollbackOutcome.ROLLED_BACK, controller.lastOutcome());
        // reconcileOnStartup 先标 FAILED:load-failed-expected-2.0.0，随后 triggerRollback
        // 用 ROLLBACK_PENDING_RESTART:startup-load-failed 覆盖，故终态是指向回滚待重启。
        assertEquals("ROLLBACK_PENDING_RESTART:startup-load-failed", readPointer("candidate.status"));
        assertEquals("0.9.0", readPointer("candidate"), "回滚目标应写入 candidate 供下次重启加载");
    }

    @Test
    @DisplayName("场景④ 熔断触发：熔断持续 trip 越过阈值即自动回滚")
    void scenario4_circuitTripTriggersRollback() throws Exception {
        writePointer("previous", "0.9.0");
        AutoRollbackController controller = controller(config("1.0.0", true));

        for (int i = 0; i < 10; i++) {
            controller.observeCircuit(true);
        }

        assertTrue(controller.hasRolledBack());
        assertEquals("circuit-persistent-trip", controller.lastReason());
        assertEquals(RollbackOutcome.ROLLED_BACK, controller.lastOutcome());
        assertEquals("0.9.0", readPointer("candidate"));
        assertTrue(readPointer("candidate.status").startsWith("ROLLBACK_PENDING_RESTART"));
    }

    @Test
    @DisplayName("场景⑤ 回滚成功：previous 置为 next candidate，标记 ROLLBACK_PENDING_RESTART")
    void scenario5_rollbackSuccessStagesPrevious() throws Exception {
        writePointer("previous", "0.9.0");
        AgentUpdateManager manager = manager(config("1.0.0", true), platformClient(null));

        RollbackOutcome outcome = manager.rollback("drill-reason");

        assertEquals(RollbackOutcome.ROLLED_BACK, outcome);
        assertEquals("0.9.0", readPointer("candidate"));
        assertEquals("ROLLBACK_PENDING_RESTART:drill-reason", readPointer("candidate.status"));
    }

    @Test
    @DisplayName("场景⑥ 回滚失败（无 previous）：进入观察模式，探针降级 passthrough 不宕机")
    void scenario6_rollbackFailureEntersObservation() throws Exception {
        assertTrue(CircuitBreaker.instrumentationEnabled(), "前置：插桩应处于启用态");
        AutoRollbackController controller = controller(config("1.0.0", true));

        // 无 previous 指针 -> 回滚无路可退
        for (int i = 0; i < 5; i++) {
            controller.recordHeartbeat(false);
        }

        assertTrue(controller.hasRolledBack());
        assertEquals(RollbackOutcome.OBSERVATION_ONLY, controller.lastOutcome());
        assertFalse(CircuitBreaker.instrumentationEnabled(), "观察模式必须降级为 passthrough，避免带病插桩");
        assertTrue(readPointer("rollback.status").startsWith("OBSERVATION_ONLY"));
    }

    // ---- 演练台装配 ----

    private ProbeConfig config(String version, boolean updatesEnabled) {
        // 与前序 AgentUpdateManagerTest / AutoRollbackControllerTest 保持同一构造签名。
        return new ProbeConfig("http://127.0.0.1:1", "agent-drill", "app", "prod", "", 1_000, 128,
                false, true, true, true, true, true, false, true, true, true, true, true, true,
                "", 256, updatesEnabled, tempDir.toString(), version, "1", 300);
    }

    private AgentUpdateManager manager(ProbeConfig config, ProbeHttpClient platformClient) {
        return new AgentUpdateManager(config, platformClient);
    }

    private AutoRollbackController controller(ProbeConfig config) {
        AgentUpdateManager manager = manager(config, new ProbeHttpClient(config));
        return new AutoRollbackController(config, manager);
    }

    private ProbeHttpClient platformClient(AgentArtifactManifest manifest) {
        return new ProbeHttpClient(config("1.0.0", true)) {
            @Override
            public Optional<AgentArtifactManifest> latestArtifact() {
                return Optional.ofNullable(manifest);
            }
        };
    }

    private AgentArtifactManifest manifest(HttpServer server, String version, String sha256) {
        return new AgentArtifactManifest(version, "1",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/sec-probe.jar",
                sha256, "", "STABLE", 100);
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

    private void writePointer(String name, String value) throws Exception {
        Files.createDirectories(tempDir);
        Files.writeString(tempDir.resolve(name), value);
    }

    private String readPointer(String name) throws Exception {
        Path file = tempDir.resolve(name);
        return Files.exists(file) ? Files.readString(file).trim() : "";
    }

    @SuppressWarnings("unused")
    private String sha256(byte[] bytes) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder builder = new StringBuilder();
        for (byte value : hash) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }
}