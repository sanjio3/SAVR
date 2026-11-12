package com.rasp.probe;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * RASP runtime hook entry points.
 *
 * Two complementary layers:
 *  - Signature/RASP layer ({@code onSink}, {@code onProcessBuilderStart},
 *    {@code onPreparedSink}): every configured sink fires unconditionally and is
 *    reported (MONITOR) or blocked (BLOCK), driven by {@link RaspSemanticEngine}.
 *  - L2 data-flow layer ({@code onGenericSink} → {@link TaintGate}): generic sinks
 *    additionally run a value-level taint scan so a tainted HTTP parameter traced
 *    through String/encoding transformations to a dangerous sink is intercepted
 *    even when the literal payload was disguised ("变形绕过"). Taint is fail-open:
 *    any analysis failure transparently falls through to the signature layer.
 */
public final class HookRuntime {
    private static final int DEFAULT_MAX_SAMPLE_LENGTH = 512;
    private static final ThreadLocal<Integer> REQUEST_DEPTH = ThreadLocal.withInitial(() -> 0);
    private static final Map<Object, PreparedSqlState> PREPARED_SQL = Collections.synchronizedMap(new WeakHashMap<>());
    private static volatile int maxSampleLength = DEFAULT_MAX_SAMPLE_LENGTH;
    // Semantic (policy) RASP layer toggles. authzEnabled drives BOLA correlation;
    // raceEnabled drives the cross-thread TOCTOU detector. Both default off unless
    // the matching hook category is enabled in ProbeConfig.
    private static volatile boolean authzEnabled = false;
    private static volatile boolean raceEnabled = false;

    // 平台 canary（身份段 s4st41<16hex>）线程级载体：请求入口从 X-SASTAI-Trace 头抽取，
    // 请求退出（REQUEST_DEPTH 归零）时清空；SecurityAgent.reportBolaSuspect 据此把平台 canary
    // 回带进 BOLA_SUSPECT 事件，使后端能按 canary 关联回本次重放（授权 hook 语义确认）。
    // 仅当身份段存在时才发射 BOLA_SUSPECT，避免普通业务流量污染 iast_events 且无关联。
    private static final ThreadLocal<String> CURRENT_CANARY = new ThreadLocal<>();
    private static final Pattern CANARY_RE = Pattern.compile("s4st41[0-9a-fA-F]{16}");

    // 设计一①：sink 现场断言载体。resolveCanaryForSink 在危险函数实参里解析到平台 canary 身份段时，
    // 把结果写入 SINK_CANARY，供 SecurityAgent.reportSink/reportTaintEvent 经事件 context 透传
    // canary + canaryState=sink-reached，使后端将其归一到独立的 sink-reached-probe 态——即便 D1 仅
    // 投 canary 探针（attack_degraded）也判有害，不降级。仅请求线程内有效，每次 sink 命中前重写。
    private static final ThreadLocal<String> SINK_CANARY = ThreadLocal.withInitial(() -> "");

    // 值级 canary 载体（与 SINK_CANARY 严格区分）：仅当 canary 身份段**真实出现在 sink 实参文本里**
    // 时由 resolveCanaryForSink 置位。SINK_CANARY 还可能被「请求级兜底」（canaried 请求命中任意 sink，
    // 但 canary 并不在该 sink 实参里）置位——那是 trace 级关联，**不构成值级证据**。
    // （Cookie.setSecure / FileOutputStream.<init> / Cipher.getInstance / Response.addHeader），
    // 只有 11% 是值级（JDBCStatement.execute / ProcessBuilder.start / CoyoteWriter.write 等真漏洞 sink）。
    // 用本载体把值级从 trace 级里择出来，杜绝「到达即确认」的噪声误报。
    private static final ThreadLocal<String> SINK_VALUE_CANARY = ThreadLocal.withInitial(() -> "");

    public static String resolveCanaryInText(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        Matcher m = CANARY_RE.matcher(text);
        return m.find() ? m.group() : "";
    }

    /**
     * 设计一① sink 现场断言：在危险函数实参里解析平台 canary 身份段（s4st41<16hex>）。
     * 命中即证明攻击者可控数据确证穿透到了 sink，返回身份段并写入 SINK_CANARY；否则返回空串。
     * fail-open：任何异常都返回空串，绝不阻断请求。
     */
    public static String resolveCanaryForSink(Object[] args) {
        if (args == null || args.length == 0) {
            SINK_CANARY.set("");
            SINK_VALUE_CANARY.set("");
            return "";
        }
        try {
            for (Object arg : args) {
                String s = resolveCanaryInText(sample(arg));
                if (!s.isEmpty()) {
                    SINK_CANARY.set(s);
                    // 值级命中：canary 身份段确实出现在 sink 实参文本里 → 置值级载体。
                    SINK_VALUE_CANARY.set(s);
                    return s;
                }
            }
        } catch (Throwable ignored) {
            // fail-open: 解析异常不影响业务请求
        }
        // 未在实参里找到 → 本次非值级。SINK_CANARY 可能稍后被「请求级兜底」用 currentCanary 置位，
        // 那是 trace 级；SINK_VALUE_CANARY 保持空，二者据此分离。
        SINK_CANARY.set("");
        SINK_VALUE_CANARY.set("");
        return "";
    }

    public static String currentSinkCanary() {
        String c = SINK_CANARY.get();
        return c == null ? "" : c;
    }

    /** 值级 canary：canary 身份段真实出现在本 sink 实参文本里（值级证据，非 trace 级关联）。 */
    public static String currentSinkValueCanary() {
        String c = SINK_VALUE_CANARY.get();
        return c == null ? "" : c;
    }

    // sink 实参上的消毒器快照（线程级）：格式 "sanitizerId|family1,family2"。
    //
    // 为什么需要：{@link TaintStore#sanitizerOf} / {@code familiesForSanitizer} 早已实现
    // 族分治语义（HTML 转义对 SQL 无效、LDAP 转义对 SQL 无效），但**全探针零消费方**——
    // 消毒器决策被记录在 TaintHub 里却从未读出、更从未进事件 context，导致后端裁决层
    // 拿不到「这个值已被 encodeForLDAP 处理过」这一事实，只能把「到达」当漏洞。
    // 本载体按 SINK_CANARY 的同款模式在 sink 命中时冻结，经事件 context 透传给后端。
    private static final ThreadLocal<String> SINK_SANITIZER = ThreadLocal.withInitial(() -> "");

    public static String currentSinkSanitizer() {
        String s = SINK_SANITIZER.get();
        return s == null ? "" : s;
    }

    /**
     * 在 sink 命中处冻结实参上的消毒器信息（幂等：多个实参取第一个有消毒记录的）。
     * 无消毒记录时写入空串，避免上一次 sink 的残留值被误当成本次 sink 的事实。
     */
    private static void freezeSinkSanitizer(Object[] args) {
        String found = "";
        try {
            if (args != null) {
                for (Object arg : args) {
                    String record = TaintStore.sanitizerOf(arg);
                    if (record != null && !record.isEmpty()) {
                        found = record;
                        break;
                    }
                }
            }
        } catch (Throwable ignored) {
            // fail-open：取不到消毒记录按「无消毒信息」处理，后端按证据缺失而非阴性裁决
        }
        SINK_SANITIZER.set(found);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // L3 语义层：sink 调用结果（是否抛异常）线程级载体
    //
    // 设计：{@link SinkOutcomeAdvice} 在 sink 方法退出时写入，请求退出（exitRequest，
    // depth 归零）时统一发射为独立事件 SINK_OUTCOME。同一请求内可能命中多个 sink，
    // 用 List 累积（上限 8 个，防异常负载下无界增长）；每条记录绑定当时的 sink canary，
    // 后端按 canary 关联回具体 spec。
    //
    // 为什么必须在请求退出时发射而不是 sink 退出时立即发：
    //   ① sink 退出时事件缓冲可能尚未 flush（EventBuffer 有界 + 定时刷）；
    //   ② 同一请求多次 sink 命中会产生多条事件，退出时统一发射可做去重与上限截断；
    //   ③ canary 在请求内可能变更（SINK_CANARY 每次 sink 命中会重写），退出时读的是最终值，
    //      故每条记录在写入时就冻结当时的 canary，避免错配。
    // ─────────────────────────────────────────────────────────────────────────
    private static final int MAX_SINK_OUTCOMES = 8;
    private static final ThreadLocal<List<SinkOutcome>> SINK_OUTCOMES =
            ThreadLocal.withInitial(() -> new ArrayList<SinkOutcome>());

    /** 一次 sink 调用的结果快照（不可变）。 */
    public static final class SinkOutcome {
        public final String target;
        public final boolean threw;
        public final String exceptionClass;
        public final String exceptionMessage;
        public final String canary;

        SinkOutcome(String target, boolean threw, String exceptionClass,
                    String exceptionMessage, String canary) {
            this.target = target == null ? "" : target;
            this.threw = threw;
            this.exceptionClass = exceptionClass == null ? "" : exceptionClass;
            // 异常消息可能很长（含用户 payload 回显），截断防事件表膨胀
            this.exceptionMessage = exceptionMessage == null ? ""
                    : (exceptionMessage.length() > 256 ? exceptionMessage.substring(0, 256) : exceptionMessage);
            this.canary = canary == null ? "" : canary;
        }
    }

    /**
     * {@link BootstrapBridge} 的反射入口（bootstrap 侧类加载器只能用字符串反射调用本方法，
     * {@code Method#getMethod} 精确匹配参数类型，故签名必须是 {@code (String, Object)}）。
     *
     * <p>这里做一次类型分发而不是让反射层处理 {@code Throwable}：{@code getMethod(String, Class[])}
     * 不接受「{@code Object} 声明、实参子类」这种宽松匹配，必须声明为 {@code Object.class}。
     */
    public static void recordSinkOutcome(String target, Object thrown) {
        recordSinkOutcomeInternal(target, thrown instanceof Throwable ? (Throwable) thrown : null);
    }

    /**
     * 由 {@link SinkOutcomeAdvice} / {@code BootstrapBridge} 调用：记录一次 sink 调用的结果。
     *
     * <p>fail-open 三重门控，任何不满足都直接丢弃（宁可证据缺失，不可污染）：
     * <ol>
     *   <li>不在请求上下文 → 丢弃（JVM 自举/后台线程的 sink 调用是噪声）；</li>
     *   <li>本次请求无平台 canary → 丢弃（普通业务流量不观测，避免淹没事件表）；</li>
     *   <li>已达上限 8 条 → 丢弃后续（防无界增长）。</li>
     * </ol>
     *
     * <p>注意：{@code t == null}（没抛异常）同样是一条**有价值**的记录——它与「抛异常」
     * 一起构成 L3 语义层的完整证据（无异常可能意味着注入成功且数据库未报错，
     * 此时需靠响应差分补充判断）。所以两者都记录。
     */
    private static void recordSinkOutcomeInternal(String target, Throwable t) {
        try {
            if (!CircuitBreaker.instrumentationEnabled() || !inRequestContext()) {
                return;
            }
            String canary = currentSinkCanary();
            if (canary.isEmpty()) {
                canary = currentCanary();
            }
            if (canary.isEmpty()) {
                return; // 无 canary = 非平台重放流量，不观测
            }
            List<SinkOutcome> list = SINK_OUTCOMES.get();
            if (list.size() >= MAX_SINK_OUTCOMES) {
                return;
            }
            list.add(new SinkOutcome(target, t != null,
                    t == null ? "" : t.getClass().getName(),
                    t == null ? "" : String.valueOf(t.getMessage()),
                    canary));
        } catch (Throwable ignored) {
            // fail-open：采集失败 = 证据缺失，后端不得据此做阴性裁决
        }
    }

    /**
     * 请求退出时发射本请求累积的全部 sink 结果，并清空载体。
     * 由 {@link SecurityAgent#reportSinkOutcome} 实际入环，故本方法只负责取数与清理。
     */
    public static List<SinkOutcome> drainSinkOutcomes() {
        List<SinkOutcome> list = SINK_OUTCOMES.get();
        if (list.isEmpty()) {
            return Collections.emptyList();
        }
        List<SinkOutcome> copy = new ArrayList<>(list);
        list.clear();
        return copy;
    }

    /**
     * 已安装 hook 清单（A2 插桩覆盖台账的数据源）。
     *
     * <p>存在的意义：此前全平台**没有任何地方记录「哪些 sink 被插桩了」**，导致
     * {@code no-iast-evidence} 无法区分「探针没插到这条路径」与「插到了但这次没触发」，
     * 两者只能靠猜。新增该台账后，归因可二分：不在清单 ⇒ 观测缺失（不得判无漏洞）；
     * 在清单 ⇒ 插到了没触发（真漏报，重放要改）。
     *
     * <p>注册时机：{@link ByteBuddyHookInstaller} 每完成一个 hook 安装即登记。
     */
    private static final Map<String, String> INSTALLED_HOOKS = Collections.synchronizedMap(new LinkedHashMap<String, String>());

    /** 登记一个已安装的 hook：{@code key} 形如 {@code type|class#method}，{@code origin} 为可读来源。 */
    public static void registerInstalledHook(String key, String origin) {
        if (key == null || key.isEmpty()) {
            return;
        }
        try {
            INSTALLED_HOOKS.put(key, origin == null ? "" : origin);
        } catch (Throwable ignored) {
            // fail-open：台账登记失败不影响插桩与业务
        }
    }

    /** 返回已安装 hook 清单的浅拷贝（{@code type|class#method -> origin}）。 */
    public static Map<String, String> installedHooks() {
        synchronized (INSTALLED_HOOKS) {
            return new LinkedHashMap<>(INSTALLED_HOOKS);
        }
    }

    public static int installedHookCount() {
        return INSTALLED_HOOKS.size();
    }

    public static void setCurrentCanary(String canary) {
        if (canary == null || canary.isEmpty()) {
            CURRENT_CANARY.remove();
        } else {
            CURRENT_CANARY.set(canary);
        }
    }

    public static String currentCanary() {
        String c = CURRENT_CANARY.get();
        return c == null ? "" : c;
    }

    public static void clearCanary() {
        CURRENT_CANARY.remove();
    }

    /**
     * 从 servlet 请求对象反射取 X-SASTAI-Trace 头并抽取平台 canary 身份段。fail-open 返回空串：
     * 取不到头/无身份段都不影响请求处理，仅意味着本次请求不会被关联回平台重放。
     */
    public static String extractCanaryFromRequest(Object request) {
        if (request == null) {
            return "";
        }
        try {
            Method m = request.getClass().getMethod("getHeader", String.class);
            Object header = m.invoke(request, "X-SASTAI-Trace");
            if (header instanceof String && !((String) header).isEmpty()) {
                String s = (String) header;
                Matcher mt = CANARY_RE.matcher(s);
                if (mt.find()) {
                    return mt.group();
                }
            }
        } catch (Throwable ignored) {
            // fail-open：取不到 canary 头（非 servlet 请求/无该头）不影响业务
        }
        return "";
    }

    private HookRuntime() {
    }

    public static void configure(ProbeConfig config) {
        if (config != null) {
            maxSampleLength = Math.max(1, config.maxSampleLength());
            authzEnabled = config.authzHooksEnabled();
            raceEnabled = config.raceHooksEnabled();
        }
    }

    public static void enterRequest() {
        int depth = REQUEST_DEPTH.get() + 1;
        REQUEST_DEPTH.set(depth);
        if (depth == 1) {
            // 方案 B 收尾：recordTaintHop 在请求极早期
            // （如 Base64.decode / ObjectInputStream.readObject 早于 servlet 入口触发）发现
            // REQUEST_ID 为 null 时会惰性绑定一个 requestId 作为聚合主键。此处若无条件覆盖为
            // 新 id，那些早期 transform 跳点会被孤立到另一个 rid 桶，最终 taint_path 序列化时
            // 丢失反序列化节点（Base64.decode / resolveClass）。故：若已有（惰性）rid 绑定，
            // 则沿用之，使整个请求的跳点归集到同一主键。
            if (TaintStore.currentRequestId() == null) {
                try {
                    TaintStore.bindRequest(newRequestId());
                } catch (Throwable ignored) {
                    // fail-open: without a request id the store simply falls back to thread scope
                }
            }
        }
    }

    private static String newRequestId() {
        return Long.toHexString(System.nanoTime()) + "-"
                + Integer.toHexString(System.identityHashCode(Thread.currentThread()));
    }

    /**
     * exitRequest 之前）。供事件入环前抑制 JVM 自举噪声使用：无 canary 且不在请求上下文的 SINK_HIT
     * 是 JVM 启动期自身读 jar/建连接/渲染模板触发的框架 sink，与扫描假说无关。fail-open 返回 false。
     */
    public static boolean inRequestContext() {
        try {
            Integer depth = REQUEST_DEPTH.get();
            return depth != null && depth > 0;
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static void exitRequest() {
        try {
            int depth = Math.max(0, REQUEST_DEPTH.get() - 1);
            if (depth == 0) {
                REQUEST_DEPTH.remove();
                // L3 语义层：请求退出前先发射本请求累积的 sink 结果（必须在 clearCanary 之前，
                // 否则每条记录虽已冻结自己的 canary，但请求级 canary 已被清空会让后端关联失锚）。
                try {
                    SecurityAgent.reportSinkOutcome(drainSinkOutcomes());
                } catch (Throwable throwable) {
                    AgentLogger.warn("hook", "sink outcome report failed-open: "
                            + throwable.getClass().getSimpleName());
                }
                if (authzEnabled) {
                    try {
                        SemanticContext.current().evaluateAndReport();
                    } catch (Throwable throwable) {
                        AgentLogger.warn("hook", "bola eval failed-open: " + throwable.getClass().getSimpleName());
                    }
                }
                SemanticContext.clear();
                ConcurrencyContext.clear();
                TaintStore.clearCurrentRequest();
                clearCanary();
                SINK_CANARY.remove();
                SINK_VALUE_CANARY.remove();
                return;
            }
            REQUEST_DEPTH.set(depth);
        } catch (Throwable throwable) {
            REQUEST_DEPTH.remove();
            SemanticContext.clear();
            ConcurrencyContext.clear();
            clearCanary();
            AgentLogger.warn("hook", "request cleanup failed-open: " + throwable.getClass().getSimpleName());
        }
    }

    // L2 source marking: every HTTP parameter/header/cookie value is an untrusted
    // source and is tagged HIGH so the data-flow engine can trace it to any sink.
    // Marking is fail-open and allocation-free in the hot path.
    public static void markHttpSource(String kind, String name, Object value) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (value instanceof Object[]) {
                Object[] arr = (Object[]) value;
                for (Object o : arr) {
                    if (o != null) {
                        TaintStore.markHigh(o);
                    }
                }
            } else if (value instanceof Map<?, ?>) {
                Map<?, ?> map = (Map<?, ?>) value;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    Object v = entry.getValue();
                    markValue(v);
                }
            } else if (value != null) {
                TaintStore.markHigh(value);
            }
            // 源跳点记录放在真实污点标记之后；仅对确实带污点的流输出路径（taintPathJson 内部门控），
            // 普通请求不入路径。
            TaintStore.recordTaintHop("source", "http-source");
        } catch (Throwable ignored) {
            // fail-open: a marking failure must never affect the request.
        }
    }

    public static void markHttpParameterMap(Object value) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (value instanceof Map<?, ?>) {
                Map<?, ?> map = (Map<?, ?>) value;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    markValue(entry.getValue());
                }
            }
        } catch (Throwable ignored) {
        }
    }

    public static void markCookieSources(Object cookies) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (cookies instanceof Object[]) {
                Object[] arr = (Object[]) cookies;
                for (Object c : arr) {
                    // Host-provided javax.servlet.http.Cookie; read value without a
                    // compile-time dependency on the servlet API (fail-open).
                    if (c != null && c.getClass().getName().endsWith("Cookie")) {
                        Object v = invokeGetter(c, "getValue");
                        if (v instanceof String && !((String) v).isEmpty()) {
                            String s = (String) v;
                            TaintStore.markHigh(s);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static Object invokeGetter(Object target, String methodName) {
        try {
            Method m = target.getClass().getMethod(methodName);
            return m.invoke(target);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /** 3-arg 反射取值：用于 getHeader(name) 这类带参 getter。fail-open 返回 null。 */
    private static Object invokeGetterArg(Object target, String methodName, Object arg) {
        try {
            Method m = target.getClass().getMethod(methodName, arg.getClass());
            return m.invoke(target, arg);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static void markValue(Object v) {
        if (v instanceof Object[]) {
            Object[] arr = (Object[]) v;
            for (Object o : arr) {
                if (o != null) {
                    TaintStore.markHigh(o);
                }
            }
        } else if (v != null) {
            TaintStore.markHigh(v);
        }
    }

    /**
     * Mark a byte[]/char[] carrier as an untrusted source. Registers the
     * identity mark AND the decoded content, because {@code new String(bytes)} can never be
     * hooked (String is a non-retransformable primordial class) — the content shadow is the
     * only way the derived String is still recognized at the sink.
     */
    public static void markCarrierSource(Object carrier) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            TaintStore.markHighCarrier(carrier);
        } catch (Throwable ignored) {
        }
    }

    // ---- L2 field-level taint edges ----

    /**
     * {@code Field.get(owner)}: a field read of a tainted container yields a tainted value.
     * Covers the reflective / framework-binding path where user input is stashed in a POJO
     * field and later pulled back out — without this edge the taint chain breaks at the POJO.
     */
    public static void onFieldRead(Object owner, String fieldName, Object value) {
        if (!CircuitBreaker.instrumentationEnabled() || value == null) {
            return;
        }
        try {
            if (owner != null && (TaintStore.isHigh(owner) || TaintStore.isFieldTainted(owner, fieldName))) {
                TaintStore.markHigh(value);
            } else if (owner != null && TaintStore.isLow(owner)) {
                TaintStore.markLow(value);
            }
        } catch (Throwable ignored) {
        }
    }

    /** {@code Field.set(owner, value)}: a tainted value written into a field taints the container. */
    public static void onFieldWrite(Object owner, String fieldName, Object value) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            TaintStore.markFieldTaint(owner, fieldName, value);
        } catch (Throwable ignored) {
        }
    }

    // ---- L2 array reorganisation ----

    /**
     * {@code Arrays.copyOf / copyOfRange / System.arraycopy / clone}: the fresh array inherits
     * the source taint (array-level and per-element), so a tainted element that is reshuffled
     * into a new array still trips the sink deep scan.
     */
    public static void onArrayReorg(Object dest, Object src) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            TaintStore.markArrayFrom(dest, src);
        } catch (Throwable ignored) {
        }
    }

    // ---- L2 sanitizer awareness ----

    /**
     * A sanitizer produced {@code output} from {@code input}. Instead of erasing the taint we
     * record WHICH sink families it is neutralized for plus the sanitizer identity: an
     * HTML-escaped value is safe in a response body yet still lethal inside a SQL statement,
     * so the decision is deferred to the sink family and the sanitizer stays traceable.
     */
    public static void onSanitized(Object output, Object input, String sanitizerId, String families) {
        if (!CircuitBreaker.instrumentationEnabled() || output == null) {
            return;
        }
        try {
            TaintStore.markFrom(output, input);
            TaintStore.markSanitized(output, sanitizerId, families);
        } catch (Throwable ignored) {
        }
    }

    // ---- Semantic (policy) RASP layer: authorization & race reporting ----

    public static void reportAuthzDecision(String principal, boolean ownershipSemantics) {
        reportAuthzDecision((Object) principal, ownershipSemantics);
    }

    public static void reportAuthzDecision(Object principal, boolean ownershipSemantics) {
        if (!CircuitBreaker.instrumentationEnabled() || !authzEnabled) {
            return;
        }
        try {
            SemanticContext.current().recordAuthzDecision(principalOf(principal), ownershipSemantics);
        } catch (Throwable throwable) {
            hookFailure("authz hook failed-open: ", throwable);
        }
    }

    /**
     * Normalize an arbitrary principal (String, MallPrincipal, or any object that
     * exposes uid/username) into a stable identifier for BOLA correlation.
     */
    private static String principalOf(Object principal) {
        if (principal == null) {
            return "anonymous";
        }
        if (principal instanceof String) {
            String s = (String) principal;
            return s.isBlank() ? "anonymous" : s;
        }
        // Best-effort reflection for app-specific principal objects (e.g. MallPrincipal).
        try {
            for (String field : new String[]{"uid", "username", "name", "principal", "id"}) {
                java.lang.reflect.Method m = principal.getClass().getMethod(field);
                Object v = m.invoke(principal);
                if (v != null) {
                    return String.valueOf(v);
                }
            }
        } catch (Throwable ignored) {
            // fall through to toString
        }
        String s = principal.toString();
        return (s == null || s.isBlank()) ? "anonymous" : s;
    }

    public static void reportObjectRead(String resourceKey) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (authzEnabled) {
                SemanticContext.current().recordObjectAccess(resourceKey);
            }
            if (raceEnabled) {
                RaceDetector.recordRead(resourceKey);
            }
        } catch (Throwable throwable) {
            hookFailure("object-read hook failed-open: ", throwable);
        }
    }

    public static void reportObjectWrite(String resourceKey) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (raceEnabled) {
                RaceDetector.recordWrite(resourceKey);
            }
        } catch (Throwable throwable) {
            hookFailure("object-write hook failed-open: ", throwable);
        }
    }

    // ---- 参数化查询感知 ----

    /**
     * {@code Connection.prepareStatement(sql)}: remember the SQL TEMPLATE and, critically,
     * whether the template ITSELF carries taint. That single bit is what separates a real
     * injection from a safe parameterized query:
     * <ul>
     *   <li>template tainted → the SQL text was concatenated from user input → injection.</li>
     *   <li>template clean, parameters tainted → the driver binds/escapes the value, so
     *       {@code ' OR 1=1--} in a parameter is inert. Blocking it would be a false positive.</li>
     * </ul>
     */
    /**
     * 数据库连接池（DBCP / tomcat-dbcp / HSQLDB 等）会把真实语句包成 Delegating 包装对象。
     * 登记模板（rememberPreparedSql）与执行时（onPreparedSink）拿到的「语句实例」可能是不同层级
     * 的包装，导致 PREPARED_SQL 以对象身份为键的查表 miss → 探针误判无模板、不发 canary
     * 真实语句，让两边都能命中同一把键；登记侧也同步登记内层键，双向兜底。
     */
    private static Object unwrapStatement(Object statement) {
        if (statement == null) {
            return null;
        }
        Object cur = statement;
        for (int depth = 0; depth < 8; depth++) {
            Object next = null;
            try {
                // commons-dbcp / tomcat-dbcp：getInnermostDelegate 直达最内层真实语句
                java.lang.reflect.Method m = cur.getClass().getMethod("getInnermostDelegate");
                next = m.invoke(cur);
            } catch (Throwable ignored) {
                // 该类型无此方法（如 HSQLDB JDBCPreparedStatement 已是叶子），忽略
            }
            if (next == null) {
                try {
                    java.lang.reflect.Method m = cur.getClass().getMethod("getDelegate");
                    next = m.invoke(cur);
                } catch (Throwable ignored) {
                    // 叶子节点，无 delegate
                }
            }
            if (next == null || next == cur) {
                break;
            }
            cur = next;
        }
        return cur;
    }

    public static void rememberPreparedSql(Object statement, Object sql) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (statement != null && sql != null) {
                PreparedSqlState st = new PreparedSqlState(sample(sql), templateTainted(sql));
                PREPARED_SQL.put(statement, st);
                // 执行侧拿到内层 JDBC」的包装错层导致查表 miss（见 onPreparedSink / unwrapStatement）。
                Object inner = unwrapStatement(statement);
                if (inner != null && inner != statement) {
                    PREPARED_SQL.put(inner, st);
                }
            }
        } catch (Throwable throwable) {
            hookFailure("prepared sql hook failed-open: ", throwable);
        }
    }

    private static boolean templateTainted(Object sql) {
        try {
            if (TaintStore.isHigh(sql)) {
                return true;
            }
            return sql instanceof String && TaintStore.isContentTainted((String) sql);
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     *
     * <p>{@code prepareCall}/{@code prepareStatement} 的 SQL 模板作为实参在方法入口即可见。当模板
     * 由攻击者可控数据拼接而成（带污点）即证明注入点抵达 SQL 编译 sink，按 sink-reached 上报。污点
     * 经 {@code PropagateBase64Advice} 透传，故即便载荷经 Base64 往返（如 OWASP 02170 的
     * {@code bar = new String(Base64.decode(username))} 再拼进 {@code "{call " + bar + "}"}）仍可识别。
     *
     * <p>这覆盖了「execute* 永不执行」的场景：HSQLDB 在 prepareCall 阶段就拒绝 "{call <payload>}" 这种
     * 非法存储过程调用语法，导致 executeQuery 从未被调用、onPreparedSink 永不触发、运行时恒为
     *
     * <p>判定优先级：① 字面平台 canary 在模板里（D1 直投、未变换）；② 模板带高/低污点（含经 Base64
     * 传播的污点）。任一命中即关联 {@link #currentCanary} 并按 sink-reached 上报。仅对带 canary 的
     * 重放流量生效（currentCanary 非空才进入断言分支），普通业务流量完全不进入，无误报风险；
     * fail-open 不影响业务请求。不做 shouldEnforce 门禁——这是纯检测闭环，不决定拦截。
     */
    public static void onPrepareSqlCanary(String sink, Object sql) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        // 与 onPreparedSink/onGenericSink 一致的门禁：仅在 sink 启用时断言，
        // 避免 sink 关闭时引入新的 FP 类。
        if (!HookMetrics.shouldEnforce("sink." + safe(sink))) {
            return;
        }
        try {
            // 仅对带平台 canary 的重放流量生效（currentCanary 非空），普通业务流量完全不进入，无误报风险。
            if (currentCanary().isEmpty()) {
                return;
            }
            // 重放闭环根治（与 onGenericSink:700 同源）：canaried 重放请求（X-SASTAI-Trace 携带平台 canary）
            // 命中 prepareCall/prepareStatement 即视为「攻击流量抵达 SQL 编译 sink」，直接以 sink-reached
            // 断言闭环，不依赖 execute* 是否真正执行——HSQLDB 在 prepareCall 阶段即拒绝非法 CALL 语法，使
            // Base64 往返的载荷，解码后模板里含 s4st41<16hex> 身份段 → 命中值级、仍断言 sink-reached；
            // 仅当身份段确实不在模板里时才退化为 trace 级关联（只回带 canary、不设 canaryState）。
            resolveCanaryForSink(new Object[]{sql});
            if (SINK_CANARY.get().isEmpty()) {
                SINK_CANARY.set(currentCanary());
            }
            SecurityAgent.reportTaintEvent("TAINT_FLOW", safe(sink), sample(sql));
        } catch (Throwable ignored) {
            hookFailure("prepare sql canary failed-open: ", ignored);
        }
    }

    /**
     * {@code PreparedStatement.setX(index, value)}: a bound parameter. Recorded for evidence
     * and flagged when tainted, but a tainted parameter alone NEVER blocks — see
     * {@link #onPreparedSink}.
     */
    public static void rememberPreparedParameter(Object statement, int index, Object value) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return;
        }
        try {
            if (statement == null) {
                return;
            }
            PreparedSqlState state = PREPARED_SQL.get(statement);
            if (state != null) {
                state.putParameter(index, sample(value), templateTainted(value) || TaintStore.isTainted(value));
            }
        } catch (Throwable throwable) {
            hookFailure("prepared parameter hook failed-open: ", throwable);
        }
    }

    /**
     * PreparedStatement execution. Applies the 参数化查询感知 triage:
     * only a tainted TEMPLATE goes through the taint gate (blockable); a clean template with
     * tainted parameters is reported as a safe parameterized query and the parameter values
     * are deliberately kept OUT of the signature check, because feeding {@code params=[' OR
     * 1=1--]} into the L1 engine is exactly how a correctly-written application gets
     * false-blocked.
     */
    public static void onPreparedSink(String sink, Object statement) {
        if (!CircuitBreaker.instrumentationEnabled() || !HookMetrics.shouldEnforce("sink." + safe(sink))) {
            return;
        }
        try {
            Object key = statement == null ? null : statement;
            PreparedSqlState state = key == null ? null : PREPARED_SQL.get(key);
            if (state == null && key != null) {
                Object inner = unwrapStatement(key);
                if (inner != null && inner != key) {
                    state = PREPARED_SQL.get(inner);
                }
            }
            // 设计一①：在 prepared statement 的 SQL 模板实参里解析平台 canary（canary 经字符串拼接进模板时命中）。
            resolveCanaryForSink(new Object[]{state == null ? statement : state.template()});
            // 设计一① 深化：SQL 模板实参里直接含有平台 canary 身份段（D1 注入的 s4st41<16hex>），
            // 即证明攻击者可控值确证拼进了 SQL 串——与「污点带进 sink 实参」等价。即便 taint-store
            // 未标记该模板（${} 拼接常丢失传播链），也路由到 onGenericSink 走 sink-reached 闭环。
            boolean canaryInTemplate = !SINK_CANARY.get().isEmpty();
            if (state == null) {
                SecurityAgent.reportSink(sink, "prepared-statement");
                return;
            }
            if (state.templateTainted() || canaryInTemplate) {
                // Template built by concatenation → real injection. Route through the taint
                // gate so BLOCK mode intercepts it exactly like a Statement.executeQuery.
                onGenericSink(sink, new Object[]{state.template()});
                return;
            }
            // Static template: signature-check the TEMPLATE only.
            SecurityAgent.reportSink(sink, state.template());
            if (state.hasTaintedParameter()) {
                SecurityAgent.reportTaintEvent("SQL_PARAMETERIZED_SAFE", sink, state.describe());
            }
        } catch (SecurityException securityException) {
            throw securityException;
        } catch (Throwable throwable) {
            hookFailure("prepared sink hook failed-open: ", throwable);
        }
    }

    public static void onGenericSink(String sink, Object[] args) {
        if (!CircuitBreaker.instrumentationEnabled() || !HookMetrics.shouldEnforce("sink." + safe(sink))) {
            return;
        }
        // 探针自身/框架读 jar 等）触发的 sink 不在任何请求上下文内，此时探针内部状态（TaintStore 路径、
        // captureStackTrace、inspectRasp 等）可能尚未就绪 → 走完整断言路径会 NPE（被 FailOpen 捕获打首栈）。
        // 真实 sink 命中永远发生在 servlet 请求上下文内（重放或正常业务）；请求上下文外的 sink 一律视为
        // 噪声，直接返回轻量路径，既消除 NPE 又避免在海量启动/后台写路径上无谓构建调用栈。异步线程经
        // AsyncContext.wrap 重新 enterRequest，仍属请求上下文，不受影响。fail-open 不影响业务。
        if (!inRequestContext()) {
            return;
        }
        // 设计一①：在危险函数实参里解析平台 canary 身份段，结果写入 SINK_CANARY 供后续 emit 透传断言。
        resolveCanaryForSink(args);
        // L3 语义层：冻结本 sink 实参上的消毒器记录（"sanitizerId|families"），随事件透传。
        // 必须在 resolveCanaryForSink 之后、任何 early return 之前，否则拿不到本次 sink 的实参。
        freezeSinkSanitizer(args);
        // 自指防护：探针自身的运维操作（LocalEventLogger 写本地日志
        // → Files.newOutputStream、AgentUpdateManager 下载、读配置…）会命中自己 hook 的 JDK
        // 方法。若不拦截，就把「自己写自己的日志」当成业务 sink 上报，淹没真实事件。判定：整条
        // 调用栈里若没有任何「非探针、非 JDK/ByteBuddy 内部」的帧
        // （即纯探针 + JDK 调用），即视为自指，丢弃。
        if (isSelfOriginated()) {
            return;
        }
        try {
            boolean high = TaintGate.hasHighTaint(sink, args);
            boolean low = !high && TaintGate.hasLowTaint(sink, args);
            // 设计一① 修复：重放请求头（X-SASTAI-Trace）携带的平台 canary 不在攻击载荷实参文本内
            // （resolveCanaryForSink 仅扫 sink 实参），故以请求级 CURRENT_CANARY 兜底关联危险 sink
            // 的现场断言——只要污点确证抵达 sink 即透传 canary + canaryState=sink-reached，后端据此闭环
            // 确认注入族（SQL/命令/XXE…）。无 canary（普通流量）或污点未达 sink 则不断言，避免误报；
            // fail-open 不影响业务。
            boolean canaryInArgs = !SINK_CANARY.get().isEmpty();
            if (canaryInArgs && !currentCanary().isEmpty()) {
                // 设计一① 深化：sink 实参里直接含有平台 canary 身份段，即证明攻击者可控数据
                // （D1 注入的 s4st41<16hex>）确证穿透到了危险函数实参——等价于「污点带进 sink 实参」。
                // 此时无论 taint-store 是否标记该值（MyBatis ${} 拼出的 SQL 串 / Runtime.exec 命令串
                // 常因未走 taint-store 传播链而无 high/low 标记），都直接以 sink-reached 断言闭环，
                // 不再依赖 taint-store 传播，根除「技术/注入族 0 确认」根因。
                SINK_CANARY.set(currentCanary());
            } else if (SINK_CANARY.get().isEmpty() && !currentCanary().isEmpty()) {
                // 重放闭环根治：canaried 重放请求（X-SASTAI-Trace 携带平台 canary）
                // 命中任意 generic sink 即视为「攻击流量抵达危险 sink」，直接以 sink-reached 断言闭环，
                // 不再依赖 taint-store 传播链。污点跨 String→Path/URL/Reader/字节数组 等类型边界常
                // 48/62 技术族 spec 全 no-arrival，而 command-exec/ssrf 因 Runtime/ProcessBuilder/
                // HttpURLConnection 直传命令串得以闭环）。普通业务流量不含 canary（currentCanary 为
                // 空），绝不落入此分支，无误报风险；fail-open 不影响业务。
                SINK_CANARY.set(currentCanary());
            }
            if (high) {
                String sample = TaintGate.sampleTainted(sink, args);
                // 解决过拦：污点到达危险 sink 时，仅当内容确为
                // 攻击 (命中 OBVIOUS_ATTACK / BLOCKING 规则) 才拦截为 RASP_BLOCKED_TAINT；
                // 良性污点值 (如 id=1) 仅观测 TAINT_FLOW，并落回 L1 签名层 onSink。
                if (SecurityAgent.isDangerousContent(sample)) {
                    SecurityAgent.onTaintGate(sink, sample, true);
                } else {
                    SecurityAgent.reportTaintEvent("TAINT_FLOW", sink, sample);
                    onSink(sink, args);
                }
                return;
            }
            if (low) {
                // LOW (numeric) only observes to avoid false-blocking normal numbers.
                SecurityAgent.onTaintGate(sink, TaintGate.sampleTainted(sink, args), false);
                return;
            }
            // 设计一① 深化：canary 已在 sink 实参中（如 ${} 拼出的 SQL 串 / 命令串）但无
            // high/low 污点标记，直接以 sink-reached 形态上报，使后端按 sink-reached-probe 闭环确认
            // 注入族。普通业务流量不含 canary，绝不会落入此分支，无误报风险。
            if (!SINK_CANARY.get().isEmpty() && !currentCanary().isEmpty()) {
                SecurityAgent.reportTaintEvent("TAINT_FLOW", sink, sample(args));
                // 原实现只报 TAINT_FLOW 就 return ⇒ 事件不带 sink_method（库里 sink_method=''），
                // 后端「sink 身份校验」（is_family_relevant_sink / iast_evidence_sink_reached_genuine）
                // 必然拒绝 ⇒ d1.iast_arrivals 恒 0。
                // 实测同一端点同一 canary 对照：不带 X-SASTAI-Trace 头 → 走下方兜底 onSink，
                // 产出 SINK_HIT(CoyoteWriter.write) + sink_reached=1；带该头 → 仅 TAINT_FLOW。
                // 补齐 onSink：重放流量既保留请求级关联，又拿到真 sink 身份。
                // 该分支仅在「带平台 canary 的重放流量」命中，普通业务流量不进，不新增误报类别。
                onSink(sink, args);
                return;
            }
        } catch (SecurityException securityException) {
            throw securityException;
        } catch (Throwable throwable) {
            hookFailure("taint gate failed-open: ", throwable);
        }
        onSink(sink, args);
    }

    public static void onProcessBuilderStart(String sink, Object processBuilder) {
        if (!CircuitBreaker.instrumentationEnabled() || !HookMetrics.shouldEnforce("sink." + safe(sink))) {
            return;
        }
        try {
            Object command = processBuilder == null ? "" : processBuilder.getClass().getMethod("command").invoke(processBuilder);
            // Route through the L2 taint gate so a tainted command list (built from
            // user input) is intercepted on the data-flow, not only by the L1 signature.
            // Taint-free commands fall through to onSink (L1) below.
            onGenericSink(sink, new Object[]{command});
        } catch (SecurityException securityException) {
            throw securityException;
        } catch (Throwable throwable) {
            hookFailure("process builder hook failed-open: ", throwable);
        }
    }

    public static Runnable wrapRunnable(Runnable runnable) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return runnable;
        }
        try {
            return AsyncContext.wrap(runnable);
        } catch (Throwable throwable) {
            hookFailure("async runnable wrap failed-open: ", throwable);
            return runnable;
        }
    }

    public static <T> Callable<T> wrapCallable(Callable<T> callable) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return callable;
        }
        try {
            return AsyncContext.wrap(callable);
        } catch (Throwable throwable) {
            hookFailure("async callable wrap failed-open: ", throwable);
            return callable;
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public static Object wrapAsyncArgument(Object argument) {
        if (!CircuitBreaker.instrumentationEnabled()) {
            return argument;
        }
        try {
            if (argument instanceof Runnable) {
                Runnable runnable = (Runnable) argument;
                return AsyncContext.wrap(runnable);
            }
            if (argument instanceof Callable<?>) {
                Callable<?> callable = (Callable<?>) argument;
                return AsyncContext.wrap(callable);
            }
            if (argument instanceof Supplier<?>) {
                Supplier<?> supplier = (Supplier<?>) argument;
                return AsyncContext.wrap((Supplier) supplier);
            }
            if (argument instanceof Function<?, ?>) {
                Function<?, ?> function = (Function<?, ?>) argument;
                return AsyncContext.wrap((Function) function);
            }
            if (argument instanceof Consumer<?>) {
                Consumer<?> consumer = (Consumer<?>) argument;
                return AsyncContext.wrap((Consumer) consumer);
            }
            if (argument instanceof BiFunction<?, ?, ?>) {
                BiFunction<?, ?, ?> function = (BiFunction<?, ?, ?>) argument;
                return AsyncContext.wrap((BiFunction) function);
            }
            if (argument instanceof BiConsumer<?, ?>) {
                BiConsumer<?, ?> consumer = (BiConsumer<?, ?>) argument;
                return AsyncContext.wrap((BiConsumer) consumer);
            }
        } catch (Throwable throwable) {
            hookFailure("async argument wrap failed-open: ", throwable);
        }
        return argument;
    }

    /**
     * 方法级虚拟补丁判定闸口。
     *
     * <p>由 {@link VirtualPatchAdvice} 在被补丁方法入口调用。判定分两级：
     * <ul>
     *   <li>参数级：指定位置 (或任意位置) 入参含污点、或命中规则 pattern 即判定命中；</li>
     *   <li>调用级：命中方法即判定命中 (误拦面大，故仅 BLOCKING 状态才真拦)。</li>
     * </ul>
     *
     * <p>命中后统一汇入 {@link SecurityAgent#onVirtualPatchHit}，复用既有 MONITOR/BLOCK 模式
     * 与事件落盘，不另立拦截语义。未被补丁拦下的参数级命中会继续落回 L1 签名层
     * {@link #onSink}，使同一条链路上的显式攻击载荷仍按既有规则处理。
     */
    public static void onVirtualPatch(String origin, Object[] args) {
        if (!CircuitBreaker.instrumentationEnabled() || VirtualPatchRegistry.isEmpty()) {
            return;
        }
        java.util.List<VirtualPatchTarget> targets;
        try {
            targets = VirtualPatchRegistry.matching(origin);
        } catch (Throwable throwable) {
            hookFailure("virtual patch lookup failed-open: ", throwable);
            return;
        }
        for (VirtualPatchTarget target : targets) {
            String matched;
            try {
                matched = matchedSample(target, args);
            } catch (Throwable throwable) {
                hookFailure("virtual patch match failed-open: ", throwable);
                continue;
            }
            if (matched == null) {
                continue;
            }
            // 可能抛 SecurityException 完成拦截，刻意置于 try/catch 之外，不得吞掉。
            SecurityAgent.onVirtualPatchHit(target, origin, matched);
            if (target.parameterLevel()) {
                onSink(origin, matched);
            }
        }
    }

    private static String matchedSample(VirtualPatchTarget target, Object[] args) {
        if (target.callLevel()) {
            return args == null || args.length == 0 ? "" : sample(args);
        }
        if (args == null || args.length == 0) {
            return null;
        }
        int index = target.argIndex();
        if (index >= 0) {
            return index < args.length ? argumentHit(target, args[index]) : null;
        }
        for (Object arg : args) {
            String hit = argumentHit(target, arg);
            if (hit != null) {
                return hit;
            }
        }
        return null;
    }

    private static String argumentHit(VirtualPatchTarget target, Object value) {
        String text = sample(value);
        if (target.pattern() != null && !target.pattern().isBlank()) {
            return VirtualPatchRegistry.matchesPattern(target.pattern(), text) ? text : null;
        }
        if (TaintStore.isTainted(value) || TaintStore.isContentTainted(text)) {
            return text;
        }
        return null;
    }

    public static void onSink(String sink, Object payload) {
        if (!CircuitBreaker.instrumentationEnabled() || !HookMetrics.shouldEnforce("sink." + safe(sink))) {
            return;
        }
        // 完整断言，消除启动期 NPE 并省去无谓的调用栈构建。真实命中必在请求上下文内。
        if (!inRequestContext()) {
            return;
        }
        // 设计一①：在 sink 实参里解析平台 canary 身份段（payload 可能是 Object[] 或单值）。
        //
        // SINK_CANARY 与 SINK_VALUE_CANARY（见该方法第 101-102 行）。onGenericSink 已在正确实参
        // 上解析过一次；此处若再用包了一层的 new Object[]{payload} 重解析，一旦扫不到就会把刚
        // 拿到的值级 canary 抹掉 ⇒ SINK_HIT 事件丢 canary ⇒ 后端幂等去重键退化为
        // (event_type, sink_file, 0, "") 常量，与框架样板写入同键，值级证据被挤掉。
        // 故：仅在尚未解析出 canary 时才补解析，且 payload 已是 Object[] 时直接展开，不再多包一层。
        if (currentSinkValueCanary().isEmpty() && currentSinkCanary().isEmpty()) {
            resolveCanaryForSink(payload instanceof Object[] ? (Object[]) payload : new Object[]{payload});
        }
        if (isSelfOriginated()) {
            return;
        }
        try {
            SecurityAgent.reportSink(sink, sample(payload));
        } catch (SecurityException securityException) {
            throw securityException;
        } catch (Throwable throwable) {
            hookFailure("sink hook failed-open: ", throwable);
        }
    }

    // 自指判定：整条调用栈中若没有任何「非探针、非 JDK/ByteBuddy 内部」的帧，说明这次
    // hooked 调用是探针自身（写日志/下载/读配置…）触发，而非业务代码，应丢弃其上报。
    private static boolean isSelfOriginated() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        for (StackTraceElement e : stack) {
            String cn = e.getClassName();
            if (cn.startsWith("com.rasp.probe.")) {
                continue; // 探针自身帧，跳过
            }
            if (cn.startsWith("java.") || cn.startsWith("javax.") || cn.startsWith("sun.")
                    || cn.startsWith("jdk.") || cn.startsWith("com.sun.") || cn.startsWith("net.bytebuddy.")) {
                continue; // JDK / ByteBuddy 内部帧，跳过
            }
            // 其余任何类（应用 com.quote…、三方框架 org.springframework…、库 com.fasterxml…）
            // 都说明这是一次真实业务调用，不是探针自指。
            return false;
        }
        return true;
    }

    static String sample(Object value) {
        if (value == null) {
            return "";
        }
        String raw = rawSample(value);
        // ModSecurity 双向激活闭环(下行方向)— 被服务端标记为关注的会话做全量采样,
        // 跳过 SEC_MAX_SAMPLE_LENGTH 截断,以便 AI 拿到该会话的完整污点路径原文。
        int maxLength = WAFWatchStore.isWatched(TaintStore.currentRequestId())
                ? Integer.MAX_VALUE
                : maxSampleLength;
        return raw.length() > maxLength ? raw.substring(0, maxLength) : raw;
    }

    private static String rawSample(Object value) {
        try {
            if (value instanceof Object[]) {
                Object[] array = (Object[]) value;
                return Arrays.deepToString(array);
            }
            Class<?> type = value.getClass();
            if (type.isArray()) {
                return primitiveArraySample(value);
            }
            String content = extractContentIdentity(value);
            if (!content.isEmpty()) {
                return content;
            }
            // F2 修复：StringReader / ByteArrayInputStream / InputSource(Reader) 等载体类的 toString
            // 只有 class@hash，原 String 内容取不到，canary 在 String->载体 边界丢失。兜底回收载体登记的
            // 源内容影子，使 sink 实参里的 canary 仍能被断言。
            String carrierContent = TaintHub.peekCarrierContent(value);
            if (!carrierContent.isEmpty()) {
                return carrierContent;
            }
            return String.valueOf(value);
        } catch (Throwable throwable) {
            return value.getClass().getName() + "@" + System.identityHashCode(value);
        }
    }

    /**
     * 内容型实参（如 org.xml.sax.InputSource）默认 toString 只有「类名@hash」，其承载的
     * 源标识（systemId，常是被污染的 URL）取不到，XXE 族的 canary 现场断言会漏。
     * 反射提取 systemId 兜底，fail-open：取不到即返回空串，走原 String.valueOf 路径。
     */
    private static String extractContentIdentity(Object value) {
        try {
            Object v = value.getClass().getMethod("getSystemId").invoke(value);
            return v == null ? "" : String.valueOf(v);
        } catch (Throwable ignored) {
            return "";
        }
    }

    private static String primitiveArraySample(Object value) {
        // canary 现场断言修复：byte[]/char[] 原先走 Arrays.toString 输出的是数字序列
        // （如 "[115,52,115,116,52,49,...]"），明文被抹成不可读的数字，导致以字节/字符数组
        // 形式传入 sink 的 canary（SQL 字节参数、XML 字节流、Reader 底层缓冲等）永远解析不到，
        // XXE / 反序列化 / SQLi 等族的 sink 现场断言恒为空、确认层对它们永远为 0。
        // 改为按 UTF-8 / UTF-16 还原原文，使 resolveCanaryForSink 能扫到 s4st41<16hex> 身份段。
        if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
        }
        if (value instanceof char[]) {
            char[] chars = (char[]) value;
            return new String(chars);
        }
        if (value instanceof short[]) {
            short[] shorts = (short[]) value;
            return Arrays.toString(shorts);
        }
        if (value instanceof int[]) {
            int[] ints = (int[]) value;
            return Arrays.toString(ints);
        }
        if (value instanceof long[]) {
            long[] longs = (long[]) value;
            return Arrays.toString(longs);
        }
        if (value instanceof float[]) {
            float[] floats = (float[]) value;
            return Arrays.toString(floats);
        }
        if (value instanceof double[]) {
            double[] doubles = (double[]) value;
            return Arrays.toString(doubles);
        }
        if (value instanceof boolean[]) {
            boolean[] booleans = (boolean[]) value;
            return Arrays.toString(booleans);
        }
        return String.valueOf(value);
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value;
    }

    private static void hookFailure(String message, Throwable throwable) {
        // 并发类异常（CME）只进 HookMetrics 独立计数，不进全局错误预算。
        CircuitBreaker.recordHookError(throwable);
        HookMetrics.error(hookLabel(message));
        AgentLogger.warn("hook", message + throwable.getClass().getSimpleName());
    }

    // Derive a stable hook family label from the fail-open message prefix, e.g.
    // "sink hook failed-open: " -> "sink". Keeps per-hook error counters grouped
    // without threading a label through every advice call site.
    private static String hookLabel(String message) {
        if (message == null || message.isBlank()) {
            return "unknown";
        }
        int space = message.indexOf(' ');
        return space > 0 ? message.substring(0, space) : message;
    }

    private static final class PreparedSqlState {
        private final String sql;
        private final boolean templateTainted;
        private final Map<Integer, String> parameters = new LinkedHashMap<>();
        private volatile boolean taintedParameter;

        private PreparedSqlState(String sql, boolean templateTainted) {
            this.sql = sql;
            this.templateTainted = templateTainted;
        }

        private String template() {
            return sql;
        }

        private boolean templateTainted() {
            return templateTainted;
        }

        private boolean hasTaintedParameter() {
            return taintedParameter;
        }

        private synchronized String describe() {
            if (parameters.isEmpty()) {
                return sql;
            }
            return sql + " params=" + parameters;
        }

        private synchronized void putParameter(int index, String value, boolean tainted) {
            parameters.put(index, value);
            if (tainted) {
                taintedParameter = true;
            }
        }
    }
}
