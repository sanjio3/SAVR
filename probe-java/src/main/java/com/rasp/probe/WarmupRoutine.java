package com.rasp.probe;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;

/**
 * 方案 1：探针挂载透明暖机。
 *
 * <p>根因：{@code ByteBuddyHookInstaller} 使用 {@code RETRANSFORMATION}，挂载瞬间会把已加载的核心
 * JDK 类（{@code java.lang.String} / {@code Integer} / {@code Base64} / {@code Arrays} /
 * {@code Thread} / {@code CompletableFuture} / 文件流等）全部重织为插桩版。HotSpot 必须令所有内联或
 * 依赖它们的已编译方法失效，再从头重编译整个 JVM；这笔重编译尾此前在「首个真实请求」上一次性结清，
 * 实测体现为 240~299s 的首请求悬崖。
 *
 * <p>本例程在 agent 内部、上报 READY 之前热循环调用上述已插桩核心类，逼 JVM 把重编译提前到 boot 期
 * 完成，用户拿到的就是「启动完即用」，无需任何外部合成请求（这是 agent 的职责，不是用户或运维的负担）。
 *
 * <p>全部 fail-open：任一步抛错即跳过，绝不中断 agent 启动；迭代次数由 {@code sec.warmup.iterations}
 * （默认 20000）控制。结果经 {@code ACCUM} 的 volatile 写保留活性，防止 JIT 把整段热循环当成死代码消除。
 */
final class WarmupRoutine {
    private WarmupRoutine() {
    }

    // 防止 JIT 死代码消除：所有热循环结果最终汇入此处 volatile 写。
    private static volatile String ACCUM = "";

    static void run(ProbeConfig config) {
        AgentLogger.info("warmup", "starting transparent warm-up of retransformed core classes");
        long start = System.nanoTime();
        int iterations = config.warmupIterations();
        try {
            warmString(iterations);
            warmStringBuilder(iterations);
            warmPrimitives(iterations);
            warmBase64(iterations);
            warmUrlDecode(iterations);
            warmArrays(iterations);
            warmCollections(iterations);
            warmAsync(iterations);
            warmFiles(iterations);
        } catch (Throwable t) {
            AgentLogger.warn("warmup", "warm-up step failed (continuing): " + t);
        }
        double secs = (System.nanoTime() - start) / 1_000_000_000.0;
        AgentLogger.info("warmup", String.format("transparent warm-up finished in %.1fs", secs));
    }

    private static void warmString(int n) {
        String a = "taint-source-";
        String b = "payload-";
        for (int i = 0; i < n; i++) {
            String x = a.concat(b);
            x = x.replace("taint", "T");
            x = x.substring(0, Math.max(1, x.length() - 1));
            x = x.toUpperCase().toLowerCase().trim().strip();
            x = String.format("%s-%d", x, i);
            x = String.join("-", x, "mid");
            String[] parts = x.split("-");
            x = String.valueOf(parts) + String.valueOf(i) + String.valueOf((long) i) + String.valueOf(1.5d);
            x = x.repeat(2);
            x = x.intern();
            String c = new String(x.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
            sinkNoop(x, c);
        }
    }

    private static void warmStringBuilder(int n) {
        for (int i = 0; i < n; i++) {
            StringBuilder sb = new StringBuilder("head");
            sb.append("a").append(i).append((long) i).append(1.5d).append(true).append('c')
                    .append(new char[] { 'x' }).append((Object) "obj");
            sb.insert(0, "pre").insert(1, 'X');
            sb.replace(0, 1, "R");
            sb.appendCodePoint(65);
            String s = sb.toString();
            s = s.substring(0, Math.max(1, s.length()));
            sb = new StringBuilder(s);
            sinkNoop(s);
        }
        for (int i = 0; i < n; i++) {
            StringBuffer sbf = new StringBuffer("x");
            sbf.append(i).append("y");
            sinkNoop(sbf.toString());
        }
        for (int i = 0; i < n; i++) {
            StringJoiner joiner = new StringJoiner(",");
            joiner.add("a").add("b").merge(new StringJoiner("-").add("c"));
            sinkNoop(joiner.toString());
        }
    }

    private static void warmPrimitives(int n) {
        for (int i = 0; i < n; i++) {
            int v = Integer.parseInt("12345");
            long l = Long.parseLong("9876543210");
            double d = Double.parseDouble("3.14159");
            sinkNoop(String.valueOf(v) + String.valueOf(l) + String.valueOf(d));
        }
    }

    private static void warmBase64(int n) {
        byte[] data = "the-quick-brown-fox".getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < n; i++) {
            byte[] enc = Base64.getEncoder().encode(data);
            byte[] dec = Base64.getDecoder().decode(enc);
            String s = Base64.getEncoder().encodeToString(dec);
            sinkNoop(s);
        }
    }

    private static void warmUrlDecode(int n) {
        for (int i = 0; i < n; i++) {
            try {
                sinkNoop(java.net.URLDecoder.decode("a%20b%2Fc", StandardCharsets.UTF_8));
            } catch (Exception ignored) {
            }
        }
    }

    private static void warmArrays(int n) {
        for (int i = 0; i < n; i++) {
            String[] arr = new String[] { "a", "b", "c" };
            String[] cp = java.util.Arrays.copyOf(arr, arr.length);
            String[] rng = java.util.Arrays.copyOfRange(arr, 0, arr.length);
            sinkNoop(cp[0] + rng[0]);
        }
    }

    private static void warmCollections(int n) {
        for (int i = 0; i < n; i++) {
            Map<String, String> m = new HashMap<>();
            m.put("k" + i, "v" + i);
            sinkNoop(String.valueOf(m.get("k" + i)));
        }
    }

    private static void warmAsync(int n) {
        for (int i = 0; i < Math.min(n, 500); i++) {
            final int idx = i;
            try {
                String r = CompletableFuture.supplyAsync(() -> "async-".concat(String.valueOf(idx))).get();
                sinkNoop(r);
            } catch (Exception ignored) {
            }
        }
    }

    private static void warmFiles(int n) {
        try {
            File tmp = File.createTempFile("sec-warmup-", ".txt");
            tmp.deleteOnExit();
            java.nio.file.Files.write(tmp.toPath(), "warmup".getBytes(StandardCharsets.UTF_8));
            byte[] content = java.nio.file.Files.readAllBytes(tmp.toPath());
            String s = java.nio.file.Files.readString(tmp.toPath());
            try (java.io.FileInputStream fis = new java.io.FileInputStream(tmp)) {
                byte[] buf = new byte[64];
                fis.read(buf);
            }
            sinkNoop(s + new String(content, StandardCharsets.UTF_8));
            tmp.delete();
        } catch (Throwable ignored) {
        }
    }

    private static void sinkNoop(String... parts) {
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (p != null) {
                sb.append(p);
            }
        }
        // volatile 写：保证热循环结果被「使用」，阻止 JIT 消除。
        ACCUM = sb.length() == 0 ? "" : sb.substring(0, 1);
    }
}
