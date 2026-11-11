package com.rasp.probe;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * L2 data-flow taint store. Injected into the bootstrap class loader so the hot
 * propagation path (every String/StringBuilder op in the JVM) can read/write
 * taint marks without reflecting back into the agent class loader.
 *
 * Design (手册 11.1.x):
 *  - Taint is keyed by the actual application value object (identity), so the data
 *    flow is inherently thread-safe: a tainted String carried into another thread
 *    is still found by object identity in the global table.
 *  - HIGH = blockable taint (HTTP source, propagation, decode). LOW = low-confidence
 *    taint (numeric / primitive-derived, 11.1.7) that only observes, never blocks,
 *    to avoid false-blocking normal numeric parameters.
 *  - REQUEST_TAINTED and the numeric edge table are request-scoped ThreadLocals
 *    cleared at exitRequest (11.1.3 八).
 *  - Content-based shadow (SOURCE_CONTENTS) is the documented deviation/fallback for
 *    String being a non-retransformable primordial class: identity marks lost through
 *    a copy are recovered by substring containment at the sink.
 *  - requestId 归集 (11.1.3 八): content shadows are additionally registered under the
 *    owning requestId in a global table, so (a) a pooled worker thread can inherit the
 *    originating request's shadow across a thread boundary, and (b) exitRequest can
 *    drop the whole request's shadow in one shot — a tainted value that outlives its
 *    request can never be seen as tainted by the next request on the same thread.
 *  - SANITIZED (11.1.5 二): a sanitizer does not blanket-erase taint; it records
 *    WHICH sink family the value was neutralized for plus the sanitizer identity, so
 *    an HTML-escaped value is still blockable at a SQL sink.
 *
 * Hot-path methods perform NO String construction and NO object allocation beyond
 * the WeakHashMap put, so they cannot trigger the very String/StringBuilder hooks
 * they ride on (recursion-safe, single-threaded).
 *
 * 上面的「recursion-safe」只在单线程下成立。探针自身对 {@code java.lang.String} / {@code java.io.File}
 * 等类的插桩，会在 WeakHashMap 计算 {@code key.hashCode} 的过程中被**同步**触发，从而重入
 * {@link #markFrom}/{@link #markHigh}。于是线程会在「已持有 map A 监视器」的状态下申请 map B 的监视器，
 * 而反方向路径持 B 求 A —— 两个 {@code Collections.synchronizedMap} 各自持锁，构成 ABBA 锁序反转。
 *
 * {@code TaintHub.markHigh} → {@code SynchronizedMap.put} 上，应用假死；连带 D1 bootstrap 登录
 * 读超时（10s），全部 TriggerSpec 降级 no-arrival/no_evidence。
 *
 * 修复（见 {@link #HUB_LOCK} / map* 系列辅助方法）：
 *  1) 所有污点容器共用唯一监视器 HUB_LOCK。Java 监视器对同一线程可重入，同线程自插桩重入
 *     只是再次获得同一把锁，「多把锁」这一 ABBA 必要条件被消除。
 *  2) 在**容器操作**这一粒度置位重入深度：WeakHashMap 计算 hashCode/equals 期间由被插桩类
 *     触发的回调一律短路。粒度必须细到单个 map 操作——markFrom 内部本来就要调 markHigh（合法组合），
 *     若在方法粒度一刀切会把正常污点推导一起砍掉。
 *  3) 容器字段改回裸 WeakHashMap，**只允许**经 mapGet/mapPut/mapContainsKey/mapRemove/
 *     mapComputeIfAbsent 访问（WeakHashMap 非线程安全，直连即数据竞争）。
 *
 * 上面 1)~3) 只消除了「容器 ↔ 容器」。真正更难的是「容器锁 ↔ JVM 内部锁」：
 * <pre>
 *   exec-3: 持 HUB_LOCK，等 jimage(SharedImageReader) 锁
 *     TaintHub.mapContainsKey → WeakHashMap.containsKey → key.hashCode
 *     → net.bytebuddy TypeDescription$Generic.hashCode（惰性类型解析）
 *     → TypePool.doResolve → ClassFileLocator → ClassLoader.getResourceAsStream
 *     → jdk.internal.jimage.BasicImageReader.findLocation
 *   exec-5: 持 jimage 锁，等 HUB_LOCK
 *     BasicImageReader.findLocation → ImageStringsReader.get → java.lang.String.<init>（被插桩）
 *     → TaintStore.markFrom → TaintHub.markFrom → mapContainsKey
 * </pre>
 * 实测 201 条线程 BLOCKED、166 条等同一把 HUB_LOCK，应用假死（JVM 活着但端口拒绝连接、
 * 日志完全静默），D2 整批 invalidated。
 *
 * 修复（本次）：4) 见 {@link #FOREIGN_TAINT_KEY_PREFIXES} / {@link #isForeignTaintKey} ——
 * 字节码框架/探针自身/JVM 内部对象一律不得成为容器 key，从源头掐断「持 HUB_LOCK 却去申请
 * JVM 内部锁」这条边。这条边是环成立的**唯一充分条件**：一旦它不存在，反方向线程最多只是
 * 短暂等待 HUB_LOCK，不再构成循环等待。
 */
public final class TaintHub {
    /**
     * 污点容器操作的重入深度。>0 表示当前线程正处于某个容器操作内部，此时由被插桩类触发的一切
     * 回调都必须短路，否则会在 hashCode 计算期间递归回探针（自插桩递归 → 锁序反转）。
     */
    private static final ThreadLocal<Integer> HUB_DEPTH = ThreadLocal.withInitial(() -> 0);

    /** 所有污点容器共用的唯一监视器（见类注释「并发安全」）。 */
    private static final Object HUB_LOCK = new Object();

    /**
     *
     * <p>这些对象一旦作为 key 进入 {@link WeakHashMap}，其 {@code hashCode} 就可能触发
     * 类型解析 / 类加载 / 字符串构造，从而在**持有 HUB_LOCK 的同时**去申请 JVM 内部锁：
     * 典型如 ByteBuddy 的惰性 {@code TypeDescription.hashCode} → {@code TypePool} 惰性解析
     * → {@code ClassLoader.getResourceAsStream} → {@code jdk.internal.jimage.BasicImageReader}
     * 的 {@code SharedImageReader} 监视器。而反方向，持有 jimage 锁的线程会因
     * {@code new String(...)} 被插桩而回调进探针抢 HUB_LOCK —— 两个方向合起来就是循环等待。
     *
     * <p>**不要**把 {@code java.lang.reflect.*} / {@code java.lang.Class} 加进来：反射 sink
     * 检测依赖这些对象作为污点 key（见 {@link TaintGate} 的 DANGEROUS_PREFIXES）。
     */
    private static final String[] FOREIGN_TAINT_KEY_PREFIXES = {
            "net.bytebuddy.",
            "com.rasp.probe.",
            "sun.instrument.",
            "java.lang.instrument.",
            "jdk.internal.",
    };

    /**
     * 该对象是否禁止作为污点容器的 key。
     *
     * <p>只看对象的**类**，绝不触碰对象本身（不调 hashCode/equals/toString），
     * 因此判定过程本身不会触发任何重入。数组按组件类型递归判断。
     */
    private static boolean isForeignTaintKey(Object key) {
        if (key == null) {
            return true;
        }
        Class<?> type = key.getClass();
        while (type.isArray()) {
            type = type.getComponentType();
        }
        if (type.isPrimitive()) {
            return false;
        }
        Package pkg = type.getPackage();
        String name = (pkg == null) ? null : pkg.getName();
        if (name == null) {
            // 默认包 / 取不到包名：一律放行，宁可多几个 key 也不漏判真实污点
            return false;
        }
        for (String prefix : FOREIGN_TAINT_KEY_PREFIXES) {
            if (name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 容器访问闸门。重入时读操作返回安全默认值（未命中），写操作丢弃；
     * 非污点 key（字节码框架/探针自身/JVM 内部对象）一律不进容器。
     * 调用方一律使用下面 5 个辅助方法，不要直接访问容器字段。
     */
    private static <V> V mapGet(Map<Object, V> map, Object key) {
        if (isForeignTaintKey(key)) {
            return null;
        }
        synchronized (HUB_LOCK) {
            if (HUB_DEPTH.get() > 0) {
                return null;
            }
            return mapRead(() -> map.get(key));
        }
    }

    private static <V> V mapPut(Map<Object, V> map, Object key, V value) {
        if (isForeignTaintKey(key)) {
            return null;
        }
        synchronized (HUB_LOCK) {
            if (HUB_DEPTH.get() > 0) {
                return null;
            }
            return mapRead(() -> map.put(key, value));
        }
    }

    private static <V> boolean mapContainsKey(Map<Object, V> map, Object key) {
        if (isForeignTaintKey(key)) {
            return false;
        }
        synchronized (HUB_LOCK) {
            if (HUB_DEPTH.get() > 0) {
                return false;
            }
            return Boolean.TRUE.equals(mapRead(() -> map.containsKey(key)));
        }
    }

    private static <V> V mapRemove(Map<Object, V> map, Object key) {
        if (isForeignTaintKey(key)) {
            return null;
        }
        synchronized (HUB_LOCK) {
            if (HUB_DEPTH.get() > 0) {
                return null;
            }
            return mapRead(() -> map.remove(key));
        }
    }

    /**
     * 重入时返回**游离**对象（{@code fn} 的产物，不落入容器）：调用方仍可安全 size/add，
     * 但探针内部产生的字段边不会污染真实状态，也不会构造第二个 map 的锁请求。
     * 非污点 key 同理 —— 必须回游离对象，否则调用方 NPE。
     */
    private static <V> V mapComputeIfAbsent(Map<Object, V> map, Object key,
                                            java.util.function.Function<Object, V> fn) {
        if (isForeignTaintKey(key)) {
            return fn.apply(key);
        }
        synchronized (HUB_LOCK) {
            if (HUB_DEPTH.get() > 0) {
                return fn.apply(key);
            }
            int previous = HUB_DEPTH.get();
            HUB_DEPTH.set(previous + 1);
            try {
                return map.computeIfAbsent(key, fn);
            } finally {
                restoreHubDepth(previous);
            }
        }
    }

    /**
     * 调用方已持有 HUB_LOCK：只负责重入深度的置位与复位。
     *
     * 内层容器操作结束时会把外层的标志一起清掉，外层剩余代码便在「闸门已开」的状态下运行。
     * 改为递增/递减。
     */
    private static <R> R mapRead(java.util.function.Supplier<R> action) {
        int previous = HUB_DEPTH.get();
        HUB_DEPTH.set(previous + 1);
        try {
            return action.get();
        } finally {
            restoreHubDepth(previous);
        }
    }

    /** 深度复位：归零时 remove()（避免 ThreadLocal 泄漏），否则退回上一层。 */
    private static void restoreHubDepth(int previous) {
        if (previous <= 0) {
            HUB_DEPTH.remove();
        } else {
            HUB_DEPTH.set(previous);
        }
    }

    // Object-identity taint marks. Weak keys expire with their referent objects.
    // 非线程安全：一律经 mapGet/mapPut/mapContainsKey/mapRemove 访问（见类注释「并发安全」）。
    private static final Map<Object, Object> HIGH = new WeakHashMap<>();
    private static final Map<Object, Object> LOW = new WeakHashMap<>();
    private static final ThreadLocal<Boolean> REQUEST_TAINTED = ThreadLocal.withInitial(() -> Boolean.FALSE);
    // Numeric low-confidence edge table: the primitive value itself (long), request-scoped.
    private static final ThreadLocal<Set<Long>> PRIM_LOW = ThreadLocal.withInitial(() -> new HashSet<>());
    // Content-based shadow (request-scoped): the string VALUES of tainted sources. Used as a
    // fallback at the sink to recognize a String whose identity mark was lost through a copy /
    // concatenation (the String/StringBuilder copy hooks can never fire — they are non-
    // retransformable primordial classes). Substring-containment: a sink arg is "content-tainted"
    // if it CONTAINS any recorded source value.
    private static final ThreadLocal<Set<String>> SOURCE_CONTENTS = ThreadLocal.withInitial(() -> new HashSet<>());
    private static final int MIN_CONTENT_LENGTH = 3;
    private static final int MAX_SOURCE_CONTENTS = 64;

    // 类型边界内容影子 (F2 修复): 被污染 String 经 StringReader / ByteArrayInputStream /
    // InputSource(Reader) 等载体类包裹后，载体的 toString/getSystemId 取不到原 String 内容
    // (只剩 class@hash)，导致 sink 处的 canary 现场断言在 String->载体 边界丢失。
    // 这里把原 String 内容按「载体对象身份」登记，sample 在 extractContentIdentity 取空时兜底回收，
    // 使 canary 仍能跨越边界到达 sink 实参被断言。Weak key：随载体 GC 自动过期。
    private static final Map<Object, String> CARRIER_CONTENT = new WeakHashMap<>();
    private static final int MAX_CARRIER_CONTENT = 4096;

    // ---- taint 传播路径（RASP 数据流跳点有序归集）----
    // 探针在污点值经过某个 hook 时，把该 hook 的 origin(class.method) 记入本请求的有序路径。
    // reportSink 时把整条路径回带进事件 context.taint_path（JSON 数组），形成可追溯的数据流
    // 证据链。仅在请求确实已带污点时才输出路径（taintPathJson 内部门控），普通请求零开销零噪声。
    private static final int MAX_TAINT_PATH = 48;
    private static final ThreadLocal<List<String>> TAINT_PATH = ThreadLocal.withInitial(() -> new ArrayList<>());

    // 方案 B 跨线程归集：taint_path 按 requestId 归集，
    // 使控制器线程记录的 transform 跳点（Base64.decode 等早于 source 注册、或跨线程）能
    // 可靠带到 sink 序列化线程——否则同请求跨线程 ThreadLocal 不继承，中间节点会丢失。
    private static final Map<String, List<String>> TAINT_PATH_BY_REQUEST = new ConcurrentHashMap<>();

    // 惰性 requestId 序列（方案 B 兜底，对应 HookRuntime.newRequestId 的进程内等价物）。
    private static final java.util.concurrent.atomic.AtomicLong LAZY_RID_SEQ = new java.util.concurrent.atomic.AtomicLong(0);
    private static String lazyRequestId() {
        return "L" + Long.toHexString(System.nanoTime()) + "-" + Long.toHexString(LAZY_RID_SEQ.incrementAndGet());
    }

    /**
     * 记录一个污点跳点（role=source/transform/sink，origin=class.method）。连续相同去重。
     *
     * <p>跳点一律记录进本请求 ThreadLocal 与跨线程归集表，序列化阶段（sink 时刻）才按
     * 「请求是否带污点」判断是否输出。普通请求即便被记了若干跳点（如良性 base64 解码）也
     * 不会进入 payload，避免噪声与误报。
     */
    public static void recordTaintHop(String role, String origin) {
        if (origin == null || origin.isEmpty()) {
            return;
        }
        List<String> path = TAINT_PATH.get();
        // 连续相同 origin 去重（同一方法被多次进入只记一次，控制路径长度）。
        if (!path.isEmpty()) {
            String last = path.get(path.size() - 1);
            if (last.equals(role + "|" + origin)) {
                return;
            }
        }
        if (path.size() < MAX_TAINT_PATH) {
            path.add(role + "|" + origin);
        }
        // 跨线程归集：把跳点同步写入按 requestId 归集的全局表，
        // 使 sink 序列化线程（可能与记录 transform 的控制器线程不同）也能拼出完整路径，
        // 彻底解决「控制器线程记录的 Base64.decode 等 transform 跳点未带到 sink 序列化线程」的
        // 跨线程 ThreadLocal 丢失问题（此处直接以 requestId 表为权威）。
        // 惰性绑定（方案 B 兜底）：非 servlet 入口流程（如后端自动重放直接调用 controller / 内部调度）
        // 不会经过 ServletServiceAdvice 的 enterRequest→bindRequest，REQUEST_ID 为 null，导致本应
        // 归入请求的 transform 跳点（Base64.decode、ObjectInputStream.resolveClass 等）只落进每线程
        // ThreadLocal，被同线程复用的下一个请求清空而丢失——实测反序列化节点因此进不了 taint_path。
        // 故此处若 rid 尚未绑定，惰性生成一个 requestId 并绑定，使跳点可靠归集；上限保护避免泄漏。
        String rid = REQUEST_ID.get();
        if (rid == null) {
            if (TAINT_PATH_BY_REQUEST.size() < MAX_LIVE_REQUESTS) {
                rid = lazyRequestId();
                bindRequest(rid);
            } else {
                rid = null; // 超出上限：退化为仅 ThreadLocal，不绑定（极端情况下中间节点可能丢失，可接受）
            }
        }
        if (rid != null) {
            List<String> shared = TAINT_PATH_BY_REQUEST.computeIfAbsent(rid,
                    k -> Collections.synchronizedList(new ArrayList<>()));
            synchronized (shared) {
                int sz = shared.size();
                if (sz > 0 && shared.get(sz - 1).equals(role + "|" + origin)) {
                    // 连续重复，跳过去重（控制路径长度 & 避免同一方法反复刷屏）。
                } else if (sz < MAX_TAINT_PATH) {
                    shared.add(role + "|" + origin);
                }
            }
        }
        // 记录本线程本请求触碰过的 rid，供 taintPathJson 合并（消除跨 rid 桶丢失）。
        if (rid != null) {
            THREAD_RIDS.get().add(rid);
        }
    }

    /**
     * 序列化为 JSON 数组字符串 [{"role":..,"origin":..}, ...]。
     *
     * <p>仅在请求确实带污点时回带路径（普通请求返回空串，不污染 payload）。本方法在 sink
     * 时刻调用——此时 source 标记已就绪，完整路径（含此前的 transform 跳点）可被正确序列化。
     */
    public static String taintPathJson() {
        // 收敛到污点流：普通请求的跳点不入 payload，避免噪声与误报。
        if (!isRequestTainted()) {
            return "";
        }
        // 合并两路，去重保序（方案 B 收尾核心）：
        // ① 跨线程归集表 TAINT_PATH_BY_REQUEST（按 requestId 汇总所有线程跳点，专治「控制器线程
        //    记录的 transform 跳点未带到 sink 序列化线程」的跨线程丢失）；
        // ② 当前线程 ThreadLocal 路径（同线程快速路径，且含 REQUEST_ID 尚未绑定时记录的 transform
        //    跳点，如请求极早期的解码）。两路并集，确保 Base64.decode / readObject 等 transform
        //    跳点不丢失——此前只取①会丢掉②里 rid 尚未绑定时的 Base64.decode。
        String rid = REQUEST_ID.get();
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<String> merged = new ArrayList<>();
        if (rid != null) {
            List<String> shared = TAINT_PATH_BY_REQUEST.get(rid);
            if (shared != null) {
                // 否则 recordTaintHop 写线程并发 append 时抛 CME（曾触发全局熔断降级 passthrough，
                // 静默丢失整段证据窗口）。快照后迭代：持锁拷贝，锁外遍历。
                List<String> snapshot;
                synchronized (shared) {
                    snapshot = new ArrayList<>(shared);
                }
                for (String e : snapshot) {
                    if (seen.add(e)) {
                        merged.add(e);
                    }
                }
            }
        }
        // 方案 B 收尾：合并本线程本请求触碰过的所有 rid 桶（惰性 rid / servlet rid），
        // 确保早于 rid 绑定的 transform 跳点（Base64.decode / resolveClass）不被孤立丢失。
        Set<String> rids = THREAD_RIDS.get();
        if (rids != null) {
            for (String r : rids) {
                List<String> shared = TAINT_PATH_BY_REQUEST.get(r);
                if (shared != null) {
                    List<String> snapshot;
                    synchronized (shared) {
                        snapshot = new ArrayList<>(shared);
                    }
                    for (String e : snapshot) {
                        if (seen.add(e)) {
                            merged.add(e);
                        }
                    }
                }
            }
        }
        List<String> local = TAINT_PATH.get();
        if (local != null) {
            for (String e : local) {
                if (seen.add(e)) {
                    merged.add(e);
                }
            }
        }
        if (merged.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < merged.size(); i++) {
            String entry = merged.get(i);
            int bar = entry.indexOf('|');
            String role = bar < 0 ? "hop" : entry.substring(0, bar);
            String origin = bar < 0 ? entry : entry.substring(bar + 1);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"role\":\"").append(jsonEscape(role)).append("\",\"origin\":\"")
              .append(jsonEscape(origin)).append("\"}");
        }
        sb.append("]");
        String json = sb.toString();
        return json;
    }

    /**
     * {@code " \ \r \t} 或其它控制字符，会产出非法 JSON 片段（后端若解析 taint_path 即失败）。
     * 此处按 RFC 8259 转义；与 {@code JsonCodec.quote} 同口径（TaintHub 常驻 bootstrap 类加载器，
     * 不依赖 JsonCodec，故内联一份）。
     */
    private static String jsonEscape(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder b = new StringBuilder(s.length() + 2);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        // 用 char 拼接产出 U+XXXX 转义形式；避免源码里出现裸的 unicode 转义前缀
                        // （javac 词法分析前会处理它，字面量里出现会被误判为非法转义）。
                        b.append('\\').append('u').append(String.format("%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.toString();
    }

    // ---- requestId 归集 (11.1.3 八) ----
    private static final ThreadLocal<String> REQUEST_ID = new ThreadLocal<>();
    // 方案 B 收尾：本请求内本线程触碰过的所有 rid 集合（惰性 rid + servlet rid 等），
    // 供 taintPathJson 一次性合并，彻底消除「早期 transform 跳点落在与 sink 不同的 rid 桶」
    // 导致反序列化节点（Base64.decode / resolveClass）在 taint_path 中丢失的问题。
    // 与 TAINT_PATH_BY_REQUEST 的跨线程归集互补：本集合覆盖同线程内的 rid 切换。
    private static final ThreadLocal<Set<String>> THREAD_RIDS = ThreadLocal.withInitial(() -> new LinkedHashSet<>());
    private static final Map<String, Set<String>> CONTENTS_BY_REQUEST = new ConcurrentHashMap<>();
    private static final int MAX_LIVE_REQUESTS = 4096;

    // ---- sanitizer awareness (11.1.5 二) ----
    // value -> "sanitizerId|family1,family2" ; weak-keyed so it expires with the value.
    private static final Map<Object, String> SANITIZED = new WeakHashMap<>();
    /** Sink families a sanitizer can neutralize. Kept as plain strings (bootstrap-safe, no enum). */
    public static final String FAMILY_HTML = "html";
    public static final String FAMILY_SQL = "sql";
    public static final String FAMILY_SHELL = "shell";
    public static final String FAMILY_XML = "xml";
    public static final String FAMILY_LDAP = "ldap";
    public static final String FAMILY_PATH = "path";
    public static final String FAMILY_JSON = "json";
    public static final String FAMILY_ALL = "*";

    // ---- field-level taint edges (11.1.3 十.1) ----
    // owner object -> names of its fields that hold tainted data (evidence + container inheritance).
    private static final Map<Object, Set<String>> FIELD_EDGES = new WeakHashMap<>();
    private static final int MAX_FIELDS_PER_OWNER = 32;
    /** Per-element walk cap for array reorganisation (11.1.3 十.5) — hot-path bound. */
    private static final int MAX_ARRAY_ELEMENTS = 256;

    private TaintHub() {
    }

    // ---- marking ----
    public static void markHigh(Object o) {
        if (o == null) {
            return;
        }
        mapPut(HIGH, o, Boolean.TRUE);
        REQUEST_TAINTED.set(Boolean.TRUE);
        if (o instanceof String && ((String) o).length() >= MIN_CONTENT_LENGTH) {
            recordContent((String) o);
        }
    }

    public static void markLow(Object o) {
        if (o == null) {
            return;
        }
        mapPut(LOW, o, Boolean.TRUE);
        REQUEST_TAINTED.set(Boolean.TRUE);
    }

    /** Propagate whichever confidence the source carries onto the derived value. */
    public static void markFrom(Object target, Object src) {
        if (target == null || src == null) {
            return;
        }
        if (mapContainsKey(HIGH, src)) {
            markHigh(target);
        } else if (mapContainsKey(LOW, src)) {
            markLow(target);
        }
    }

    /**
     * Clear any taint on a value. Kept for the legacy blanket-clear callers; prefer
     * {@link #markSanitized(Object, String, String)} so the sanitizer decision stays
     * scoped to the sink family it actually neutralizes (手册 11.1.5 二).
     */
    public static void unmark(Object o) {
        if (o == null) {
            return;
        }
        mapRemove(HIGH, o);
        mapRemove(LOW, o);
    }

    // ---- querying ----
    public static boolean isHigh(Object o) {
        return o != null && mapGet(HIGH, o) != null;
    }

    public static boolean isLow(Object o) {
        return o != null && mapGet(LOW, o) != null;
    }

    public static boolean isTainted(Object o) {
        return isHigh(o) || isLow(o);
    }

    public static boolean isHighAny(Object[] args) {
        if (args == null) {
            return false;
        }
        for (Object a : args) {
            if (a != null && mapGet(HIGH, a) != null) {
                return true;
            }
        }
        return false;
    }

    public static boolean isLowAny(Object[] args) {
        if (args == null) {
            return false;
        }
        for (Object a : args) {
            if (a != null && mapGet(LOW, a) != null) {
                return true;
            }
        }
        return false;
    }

    public static boolean isRequestTainted() {
        return REQUEST_TAINTED.get() == Boolean.TRUE;
    }

    /**
     * Re-raise (or lower) the request-tainted flag on the CURRENT thread. Used by the
     * async wrappers (手册 11.1.3 二 / 十.9): the data taint itself rides on object
     * identity and needs no snapshot, but the per-thread short-circuit flag must be
     * re-raised on the pool thread or the gate would skip the deep scan entirely.
     */
    public static void setRequestTainted(boolean tainted) {
        if (tainted) {
            REQUEST_TAINTED.set(Boolean.TRUE);
        } else {
            REQUEST_TAINTED.remove();
        }
    }

    /**
     * Content-based taint fallback (偏离手册「对象身份」模型，为绕开 String 不可重变换的限制):
     * true if {@code s} CONTAINS any recorded tainted source value. A String whose identity
     * mark was lost through a copy/concatenation is still recognized by content containment.
     */
    public static boolean isContentTainted(String s) {
        if (s == null || s.isEmpty()) {
            return false;
        }
        Set<String> contents = SOURCE_CONTENTS.get();
        for (String content : contents) {
            if (s.contains(content)) {
                return true;
            }
        }
        return false;
    }

    // ---- requestId 归集 / 跨线程继承 (11.1.3 八 / 二) ----

    /** Bind the current thread to a request and adopt that request's content shadow. */
    public static void bindRequest(String requestId) {
        if (requestId == null || requestId.isEmpty()) {
            return;
        }
        REQUEST_ID.set(requestId);
        Set<String> shared = CONTENTS_BY_REQUEST.get(requestId);
        if (shared != null && !shared.isEmpty()) {
            // iterator 时必须持集合自身监视器，否则控制器线程并发 recordContent 会抛 CME。
            synchronized (shared) {
                SOURCE_CONTENTS.get().addAll(shared);
            }
            REQUEST_TAINTED.set(Boolean.TRUE);
        }
    }

    public static String currentRequestId() {
        return REQUEST_ID.get();
    }

    private static void recordContent(String s) {
        Set<String> contents = SOURCE_CONTENTS.get();
        if (contents.size() < MAX_SOURCE_CONTENTS) {
            contents.add(s);
        }
        String rid = REQUEST_ID.get();
        if (rid == null) {
            return;
        }
        if (!CONTENTS_BY_REQUEST.containsKey(rid) && CONTENTS_BY_REQUEST.size() >= MAX_LIVE_REQUESTS) {
            return; // bounded: never let a leaked request id table grow without limit
        }
        Set<String> shared = CONTENTS_BY_REQUEST.computeIfAbsent(rid,
                k -> Collections.synchronizedSet(new HashSet<>()));
        if (shared.size() < MAX_SOURCE_CONTENTS) {
            shared.add(s);
        }
    }

    // ---- byte[] / char[] boundary inheritance (11.1.3 七) ----

    /**
     * Mark a byte[]/char[] carrier HIGH and register its decoded content in the shadow,
     * so {@code new String(bytes)} — whose constructor can never be hooked (String is a
     * primordial class) — is still recognized downstream by content containment.
     * Bounded to 4KB so a large upload buffer cannot cost a full copy on the hot path.
     */
    public static void markHighCarrier(Object carrier) {
        if (carrier == null) {
            return;
        }
        markHigh(carrier);
        String decoded = decodeCarrier(carrier);
        if (decoded != null && decoded.length() >= MIN_CONTENT_LENGTH) {
            recordContent(decoded);
        }
    }

    private static final int MAX_CARRIER_BYTES = 4096;

    private static String decodeCarrier(Object carrier) {
        try {
            if (carrier instanceof byte[]) {
                byte[] b = (byte[]) carrier;
                if (b.length == 0 || b.length > MAX_CARRIER_BYTES) {
                    return null;
                }
                return new String(b, java.nio.charset.StandardCharsets.UTF_8);
            }
            if (carrier instanceof char[]) {
                char[] c = (char[]) carrier;
                if (c.length == 0 || c.length > MAX_CARRIER_BYTES) {
                    return null;
                }
                return new String(c);
            }
        } catch (Throwable ignored) {
            // fail-open: a carrier we cannot decode simply keeps its identity mark
        }
        return null;
    }

    /**
     * 类型边界内容登记 (F2): 把被污染源 String 内容按「载体对象身份」登记，供 sink 处
     * {@link #peekCarrierContent} 回收。内容长度下限沿用 MIN_CONTENT_LENGTH，上限 4KB 避免大缓冲全拷贝。
     */
    public static void recordCarrierContent(Object carrier, String content) {
        if (carrier == null || content == null || content.length() < MIN_CONTENT_LENGTH) {
            return;
        }
        if (content.length() > MAX_CARRIER_CONTENT) {
            content = content.substring(0, MAX_CARRIER_CONTENT);
        }
        mapPut(CARRIER_CONTENT, carrier, content);
    }

    /**
     * 回收载体登记的源内容 (F2): 供 HookRuntime.sample 在 extractContentIdentity 取空时兜底。
     * 返回空串表示无登记内容。
     */
    public static String peekCarrierContent(Object o) {
        if (o == null) {
            return "";
        }
        String c = (String) mapGet(CARRIER_CONTENT, o);
        return c == null ? "" : c;
    }

    // ---- array reorganisation (11.1.3 十.5) ----

    /**
     * Inherit taint across an array reorganisation (Arrays.copyOf / copyOfRange /
     * System.arraycopy / clone). Copies the array-level mark and the per-element marks so a
     * tainted element that lands in a fresh array is still found by the sink deep scan.
     */
    // 重入保护：decodeCarrier 内部用 new String(byte[]/char[]) 生成待扫描载体，而 String 构造器本身
    // 被插桩——这会经 Arrays.copyOfRange 再次进入 markArrayFrom，形成无限递归（请求线程 100% 空转）。
    // 用 ThreadLocal 守卫：同一线程已在 markArrayFrom 内时直接返回，断链即可，不丢失外层污点推导。
    private static final ThreadLocal<Boolean> IN_MARK_ARRAY = ThreadLocal.withInitial(() -> Boolean.FALSE);

    public static void markArrayFrom(Object dest, Object src) {
        if (IN_MARK_ARRAY.get()) {
            return;
        }
        IN_MARK_ARRAY.set(Boolean.TRUE);
        try {
        if (dest == null || src == null || dest == src) {
            return;
        }
        boolean srcHigh = mapContainsKey(HIGH, src);
        boolean srcLow = !srcHigh && mapContainsKey(LOW, src);
        if (srcHigh) {
            markHigh(dest);
        } else if (srcLow) {
            markLow(dest);
        }
        if (dest instanceof Object[] && src instanceof Object[]) {
            Object[] s = (Object[]) src;
            Object[] d = (Object[]) dest;
            // Hot-path bound: Arrays.copyOf(Object[]) is also how ArrayList grows, so a
            // tainted request must never pay an unbounded per-element walk here. The first
            // MAX_ARRAY_ELEMENTS entries decide; beyond that the array-level mark (set below
            // when any of the inspected elements was tainted) keeps the deep scan tripping.
            int n = Math.min(Math.min(d.length, s.length), MAX_ARRAY_ELEMENTS);
            boolean elementHigh = false;
            for (int i = 0; i < n; i++) {
                Object e = s[i];
                if (e == null) {
                    continue;
                }
                if (mapContainsKey(HIGH, e)) {
                    markHigh(d[i]);
                    elementHigh = true;
                } else if (mapContainsKey(LOW, e)) {
                    markLow(d[i]);
                }
            }
            // element order may differ after a reorg: if any source element is tainted the
            // destination array itself carries taint so the deep scan still trips.
            if (!srcHigh && !srcLow && elementHigh) {
                markHigh(dest);
            }
        } else if (!srcHigh && !srcLow) {
            String decoded = decodeCarrier(src);
            if (decoded != null && decoded.length() >= MIN_CONTENT_LENGTH && isContentTainted(decoded)) {
                markHighCarrier(dest);
            }
        }
        } finally {
            IN_MARK_ARRAY.set(Boolean.FALSE);
        }
    }

    // ---- sanitizer awareness (11.1.5 二) ----

    /**
     * Record that {@code value} was neutralized by {@code sanitizerId} for the given sink
     * {@code families} (comma-separated, or {@link #FAMILY_ALL}). The taint mark itself is
     * kept: an HTML-escaped value is safe for the response sink but still dangerous for a
     * SQL sink, so the decision is deferred to the sink family (分治) and the sanitizer
     * identity stays available for 溯源 in the event evidence.
     */
    public static void markSanitized(Object value, String sanitizerId, String families) {
        if (value == null) {
            return;
        }
        String id = sanitizerId == null ? "unknown" : sanitizerId;
        String fam = families == null || families.isEmpty() ? FAMILY_ALL : families;
        mapPut(SANITIZED, value, id + "|" + fam);
    }

    /**
     * Map a sanitizer's origin ({@code pkg.Class.method}) to the sink families it actually
     * neutralizes. An HTML escaper defuses the response sink only; a Java/JSON escaper does
     * not defuse SQL; {@code escapeSql}-style helpers defuse SQL only. Anything unrecognized
     * gets the empty set — an unknown sanitizer defuses NOTHING, which is the safe default
     * (it can still be blocked at every sink).
     */
    public static String familiesForSanitizer(String origin) {
        if (origin == null) {
            return "";
        }
        String lower = origin.toLowerCase(java.util.Locale.ROOT);
        if (lower.contains("escapehtml") || lower.contains("htmlescape") || lower.contains("escapehtml4")) {
            return FAMILY_HTML;
        }
        if (lower.contains("escapexml") || lower.contains("xmlescape")) {
            return FAMILY_XML;
        }
        if (lower.contains("escapeecmascript") || lower.contains("escapejavascript")
                || lower.contains("javascriptescape")) {
            return FAMILY_HTML + "," + FAMILY_JSON;
        }
        if (lower.contains("escapejson")) {
            return FAMILY_JSON;
        }
        if (lower.contains("escapesql") || lower.contains("sqlescape")) {
            return FAMILY_SQL;
        }
        if (lower.contains("escapejava") || lower.contains("escapecsv")) {
            return FAMILY_JSON;
        }
        if (lower.contains("escapeldap") || lower.contains("ldapescape")) {
            return FAMILY_LDAP;
        }
        if (lower.contains("cleanpath") || lower.contains("normalizepath") || lower.contains("getcanonicalpath")) {
            return FAMILY_PATH;
        }
        return "";
    }

    /** The sanitizer that neutralized this value, or null. Format {@code id|families}. */
    public static String sanitizerOf(Object value) {
        return value == null ? null : mapGet(SANITIZED, value);
    }

    /** True if this value was neutralized for the given sink family (or for all families). */
    public static boolean isSanitizedFor(Object value, String family) {
        String record = sanitizerOf(value);
        if (record == null) {
            return false;
        }
        int bar = record.indexOf('|');
        String families = bar < 0 ? FAMILY_ALL : record.substring(bar + 1);
        if (FAMILY_ALL.equals(families)) {
            return true;
        }
        if (family == null || family.isEmpty()) {
            return false;
        }
        for (String f : families.split(",")) {
            if (f.equals(family) || FAMILY_ALL.equals(f)) {
                return true;
            }
        }
        return false;
    }

    // ---- field-level taint edges (11.1.3 十.1) ----

    /**
     * A tainted value was written into {@code owner}'s field: the container inherits the
     * taint (so a POJO carrying user input trips the sink deep scan) and the field name is
     * kept as evidence.
     */
    public static void markFieldTaint(Object owner, String fieldName, Object value) {
        if (owner == null || value == null) {
            return;
        }
        boolean high = mapContainsKey(HIGH, value);
        boolean low = !high && mapContainsKey(LOW, value);
        if (!high && !low && value instanceof String && isContentTainted(((String) value))) {
            String s = (String) value;
            high = true;
        }
        if (!high && !low) {
            return;
        }
        if (high) {
            markHigh(owner);
        } else {
            markLow(owner);
        }
        if (fieldName == null) {
            return;
        }
        Set<String> fields = mapComputeIfAbsent(FIELD_EDGES, owner, k -> Collections.synchronizedSet(new HashSet<>()));
        if (fields.size() < MAX_FIELDS_PER_OWNER) {
            fields.add(fieldName);
        }
    }

    /**
     * {@code Field.get(owner)} edge, called from the bootstrap advice. Kept here (instead of
     * inside the advice) so the inlined advice body stays tiny and the reflective-Field cast
     * lives in one place.
     */
    public static void propagateFieldRead(Object owner, Object field, Object value) {
        if (owner == null || value == null) {
            return;
        }
        boolean ownerHigh = mapContainsKey(HIGH, owner);
        if (!ownerHigh && !mapContainsKey(LOW, owner)) {
            return;
        }
        if (ownerHigh) {
            markHigh(value);
        } else {
            markLow(value);
        }
        String name = fieldName(field);
        if (name != null) {
            Set<String> fields = mapComputeIfAbsent(FIELD_EDGES, owner, k -> Collections.synchronizedSet(new HashSet<>()));
            if (fields.size() < MAX_FIELDS_PER_OWNER) {
                fields.add(name);
            }
        }
    }

    /** {@code Field.set(owner, value)} edge, called from the bootstrap advice. */
    public static void propagateFieldWrite(Object owner, Object field, Object value) {
        markFieldTaint(owner, fieldName(field), value);
    }

    private static String fieldName(Object field) {
        try {
            if (field instanceof java.lang.reflect.Field) {
                java.lang.reflect.Field f = (java.lang.reflect.Field) field;
                return f.getName();
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    /** True if any field of this object was recorded as holding tainted data. */
    public static boolean hasFieldTaint(Object owner) {
        if (owner == null) {
            return false;
        }
        Set<String> fields = mapGet(FIELD_EDGES, owner);
        return fields != null && !fields.isEmpty();
    }

    /** True if that specific field of this object was recorded as tainted. */
    public static boolean isFieldTainted(Object owner, String fieldName) {
        if (owner == null || fieldName == null) {
            return false;
        }
        Set<String> fields = mapGet(FIELD_EDGES, owner);
        return fields != null && fields.contains(fieldName);
    }

    // ---- numeric low-confidence edge (11.1.7) ----
    public static void markPrimitiveLow(int v) {
        PRIM_LOW.get().add((long) v);
        REQUEST_TAINTED.set(Boolean.TRUE);
    }

    public static void markPrimitiveLow(long v) {
        PRIM_LOW.get().add(v);
        REQUEST_TAINTED.set(Boolean.TRUE);
    }

    public static boolean isPrimitiveLow(int v) {
        return PRIM_LOW.get().contains((long) v);
    }

    public static boolean isPrimitiveLow(long v) {
        return PRIM_LOW.get().contains(v);
    }

    // ---- request cleanup (11.1.3 八) ----
    public static void clearCurrentRequest() {
        String rid = REQUEST_ID.get();
        if (rid != null) {
            CONTENTS_BY_REQUEST.remove(rid);
            TAINT_PATH_BY_REQUEST.remove(rid);
        }
        REQUEST_ID.remove();
        REQUEST_TAINTED.remove();
        PRIM_LOW.remove();
        SOURCE_CONTENTS.remove();
        TAINT_PATH.remove();
        THREAD_RIDS.remove();
        // HIGH/LOW/SANITIZED/FIELD_EDGES entries are weak-keyed and expire with their referents.
    }

    /**
     * Detach the CURRENT THREAD from whatever request it was serving, WITHOUT dropping the
     * request's归集 shadow. Used by the async wrappers to restore a pooled thread after they
     * temporarily adopted a foreign request's scope — the originating request thread is still
     * running and must keep its shadow (手册 11.1.3 二/八).
     */
    public static void detachThread() {
        REQUEST_ID.remove();
        REQUEST_TAINTED.remove();
        SOURCE_CONTENTS.remove();
        PRIM_LOW.remove();
    }

    /** Drop a request's归集 shadow explicitly (async completion on a foreign thread). */
    public static void clearRequest(String requestId) {
        if (requestId != null) {
            CONTENTS_BY_REQUEST.remove(requestId);
        }
    }

    /** Visible for tests: number of live requestId shadows. */
    public static int liveRequestShadowCount() {
        return CONTENTS_BY_REQUEST.size();
    }
}
