package com.rasp.probe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * 平台通信客户端（根因修复）。
 *
 * 本探针 jar 经启动器 -Xbootclasspath/a 挂到 bootstrap 类加载器。引导层只委派 java.base
 * 与该参数追加的 jar，不委派平台类加载器，因此平台模块类 java.net.http.HttpClient 在链接期
 * 解析不到 → NoClassDefFoundError → 被 FailOpen 吞掉 → 零插桩（java-sec-code 即此症状：
 * 8080 正常监听但 iast_events.sink_reached 恒为 0）。
 *
 * 改用 java.base 的 HttpURLConnection：① 引导层可见，彻底消除链接期崩溃；② 天然 HTTP/1.1，
 * 规避 JDK HttpClient 对 http:// 默认升级 h2c 致 uvicorn 返回 422 丢事件的隐患；③ 用
 * Proxy.NO_PROXY 直连 127.0.0.1:8000，绕过沙箱 / 企业代理的 HTTP 拦截。
 *
 * <p>2026-09-13 二次修正：HttpURLConnection 底层走 java.net.Socket，会被宿主应用注册的全局
 * {@code Socket.setSocketImplFactory} 拦截。java-sec-code 的 SSRF 演示端点（/ssrf/**）一旦被调用
 * 就注册该 factory，且其 {@code stopHook} 因 SocketHookImpl 不检查开关而失效，导致此后
 * <b>所有</b> 到内网地址的 socket 被拒 —— 探针上报 127.0.0.1:8000 全废，表现为
 * dropped N events after send failure、心跳停摆、D2 全部 no-iast-evidence。
 *
 * <p>故上报通道改为 <b>NIO（java.nio.channels.SocketChannel）</b>：
 * ① SocketChannel 属 java.base，bootstrap 可见（不像 java.net.http 需额外模块）；
 * ② 不经过 java.net.Socket / SocketImplFactory，天然免疫宿主注册的 socket hook；
 * ③ 仍用 HTTP/1.1 明文，规避 h2c 升级问题。
 */
public class ProbeHttpClient {
    private final ProbeConfig config;

    public ProbeHttpClient(ProbeConfig config) {
        this.config = config;
    }

    public Optional<Map<String, Object>> heartbeat(ProbeMode mode, long knownRuleVersion) {
        return heartbeat(mode, knownRuleVersion, null);
    }

    public Optional<Map<String, Object>> heartbeat(ProbeMode mode, long knownRuleVersion, Map<String, Object> metrics) {
        return heartbeat(mode, knownRuleVersion, metrics, null);
    }

    public Optional<Map<String, Object>> heartbeat(ProbeMode mode, long knownRuleVersion, Map<String, Object> metrics, String agentPhase) {
        try {
            String body = JsonCodec.stringify(config.heartbeatPayload(mode, knownRuleVersion, metrics, agentPhase));
            String response = post("/api/agent/heartbeat", body);
            Map<String, Object> envelope = JsonCodec.parseFlatEnvelope(response);
            Object data = envelope.get("data");
            if (data instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked")
                Map<String, Object> typed = (Map<String, Object>) data;
                return Optional.of(typed);
            }
        } catch (RuntimeException ignored) {
        }
        return Optional.empty();
    }

    public Optional<AgentArtifactManifest> latestArtifact() {
        try {
            String response = get("/api/agent/artifacts/latest");
            Map<String, Object> envelope = JsonCodec.parseFlatEnvelope(response);
            Object data = envelope.get("data");
            if (data instanceof Map<?, ?>) {
                Map<?, ?> map = (Map<?, ?>) data;
                return Optional.of(new AgentArtifactManifest(
                        string(map.get("version")),
                        string(map.get("protocolVersion")),
                        string(map.get("downloadUrl")),
                        string(map.get("sha256")),
                        string(map.get("signature")),
                        string(map.get("status")),
                        intValue(map.get("rolloutPercent"), 100)));
            }
        } catch (RuntimeException ignored) {
        }
        return Optional.empty();
    }

    public boolean sendEvents(String body) {
        try {
            post("/api/agent/events", body);
            return true;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private String get(String path) {
        try {
            return request("GET", path, null);
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private String post(String path, String body) {
        try {
            return request("POST", path, body);
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private String request(String method, String path, String body) throws IOException {
        URL url = new URL(config.serverUrl() + path);
        String host = url.getHost();
        int port = url.getPort() > 0 ? url.getPort() : 80;
        String target = url.getFile().isEmpty() ? "/" : url.getFile();
        byte[] payload = body == null ? null : body.getBytes(StandardCharsets.UTF_8);

        StringBuilder head = new StringBuilder();
        head.append(method).append(' ').append(target).append(" HTTP/1.1\r\n");
        head.append("Host: ").append(host).append(':').append(port).append("\r\n");
        head.append("Content-Type: application/json\r\n");
        head.append("Accept: application/json\r\n");
        head.append("Connection: close\r\n");
        if (config.agentToken() != null && !config.agentToken().isBlank()) {
            head.append("X-Agent-Token: ").append(config.agentToken()).append("\r\n");
        }
        if (payload != null) {
            head.append("Content-Length: ").append(payload.length).append("\r\n");
        }
        head.append("\r\n");

        int timeout = Math.max(1000, config.networkTimeoutMs());
        try (SocketChannel channel = SocketChannel.open()) {
            channel.socket().setTcpNoDelay(true);
            channel.socket().setSoTimeout(timeout);
            channel.connect(new InetSocketAddress(host, port));
            writeFully(channel, ByteBuffer.wrap(head.toString().getBytes(StandardCharsets.UTF_8)));
            if (payload != null) {
                writeFully(channel, ByteBuffer.wrap(payload));
            }
            byte[] raw = readToEnd(channel);
            int status = parseStatus(raw);
            String response = parseBody(raw);
            if (status >= 500) {
                throw new IllegalStateException("server error " + status);
            }
            return response;
        }
    }

    private static void writeFully(SocketChannel channel, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            if (channel.write(buffer) < 0) {
                throw new IOException("connection closed while writing");
            }
        }
    }

    private static byte[] readToEnd(SocketChannel channel) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        ByteBuffer chunk = ByteBuffer.allocate(8192);
        while (channel.read(chunk) >= 0) {
            chunk.flip();
            buffer.write(chunk.array(), chunk.arrayOffset() + chunk.position(), chunk.remaining());
            chunk.clear();
        }
        return buffer.toByteArray();
    }

    private static int parseStatus(byte[] raw) {
        String head = new String(raw, StandardCharsets.UTF_8);
        int eol = head.indexOf("\r\n");
        String line = eol > 0 ? head.substring(0, eol) : head;
        // HTTP/1.1 200 OK -> 取中间那段状态码
        String[] parts = line.split(" ");
        if (parts.length >= 2) {
            try {
                return Integer.parseInt(parts[1]);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private static String parseBody(byte[] raw) {
        String text = new String(raw, StandardCharsets.UTF_8);
        int split = text.indexOf("\r\n\r\n");
        if (split < 0) {
            return "";
        }
        String header = text.substring(0, split).toLowerCase(Locale.ROOT);
        String rest = text.substring(split + 4);
        if (header.contains("transfer-encoding: chunked")) {
            return dechunk(rest);
        }
        return rest;
    }

    /** 解 HTTP chunked 编码：每块前一行十六进制长度，0 长度块结束。 */
    private static String dechunk(String body) {
        StringBuilder out = new StringBuilder();
        int pos = 0;
        while (pos < body.length()) {
            int eol = body.indexOf("\r\n", pos);
            if (eol < 0) {
                break;
            }
            String sizeLine = body.substring(pos, eol).trim();
            int size;
            try {
                size = Integer.parseInt(sizeLine, 16);
            } catch (NumberFormatException ignored) {
                break;
            }
            pos = eol + 2;
            if (size == 0) {
                break;
            }
            if (pos + size > body.length()) {
                out.append(body, pos, body.length());
                break;
            }
            out.append(body, pos, pos + size);
            pos += size + 2;
        }
        return out.toString();
    }

    private String string(Object value) {
        return value == null ? "" : String.valueOf(value);
    }

    private int intValue(Object value, int fallback) {
        if (value instanceof Number) {
            Number number = (Number) value;
            return number.intValue();
        }
        try {
            return value == null ? fallback : Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }
}
