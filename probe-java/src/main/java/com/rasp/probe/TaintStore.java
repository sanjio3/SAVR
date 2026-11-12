package com.rasp.probe;

/**
 * 无状态委托类（方案 B 收尾：类加载器统一）。
 *
 * <p>根因：探针里 {@code TaintStore} 被两个不同的类加载器各加载了一份——bootstrap 类加载器
 * （hook {@code java.base} 类的 advice，如 {@code Base64.decode} / {@code ObjectInputStream.resolveClass}）
 * 与 AppClassLoader（agent 自身代码与 hook 应用类的 advice，如 servlet 源标记 / sink）。两份静态
 * 实例各自持有独立的 taint 路径聚合表，导致反序列化 transform 跳点（落在 bootstrap 那份）无法被
 * sink 时刻的 {@code taintPathJson}（读 AppClassLoader 那份）拼入终态 {@code taint_path}。
 *
 * <p>修复：把所有「共享状态 + 聚合逻辑」下沉到 {@link TaintHub}（仅常驻 bootstrap 类加载器，见
 * {@code SecurityAgent} 入口的 {@code appendToBootstrapClassLoaderSearch}），本类退化为纯委托。
 * 无论调用方处于哪个类加载器，最终都落到唯一一份 {@code TaintHub} 静态实例，彻底消除跨类加载器
 * 状态分裂。本类不再持有任何静态可变状态，因此即便被两个类加载器各加载一份也无害。
 */
public final class TaintStore {
    // 与 TaintHub 保持一致的 sink 家族常量（调用方仍通过 TaintStore.FAMILY_* 引用，零改动）。
    public static final String FAMILY_HTML = "html";
    public static final String FAMILY_SQL = "sql";
    public static final String FAMILY_SHELL = "shell";
    public static final String FAMILY_XML = "xml";
    public static final String FAMILY_LDAP = "ldap";
    public static final String FAMILY_PATH = "path";
    public static final String FAMILY_JSON = "json";
    public static final String FAMILY_ALL = "*";

    private TaintStore() {
    }

    public static void recordTaintHop(String role, String origin) {
        TaintHub.recordTaintHop(role, origin);
    }

    public static String taintPathJson() {
        return TaintHub.taintPathJson();
    }

    public static void markHigh(Object o) {
        TaintHub.markHigh(o);
    }

    public static void markLow(Object o) {
        TaintHub.markLow(o);
    }

    public static void markFrom(Object target, Object src) {
        TaintHub.markFrom(target, src);
    }

    public static void unmark(Object o) {
        TaintHub.unmark(o);
    }

    public static boolean isHigh(Object o) {
        return TaintHub.isHigh(o);
    }

    public static boolean isLow(Object o) {
        return TaintHub.isLow(o);
    }

    public static boolean isTainted(Object o) {
        return TaintHub.isTainted(o);
    }

    public static boolean isHighAny(Object[] args) {
        return TaintHub.isHighAny(args);
    }

    public static boolean isLowAny(Object[] args) {
        return TaintHub.isLowAny(args);
    }

    public static boolean isRequestTainted() {
        return TaintHub.isRequestTainted();
    }

    public static void setRequestTainted(boolean tainted) {
        TaintHub.setRequestTainted(tainted);
    }

    public static boolean isContentTainted(String s) {
        return TaintHub.isContentTainted(s);
    }

    public static void bindRequest(String requestId) {
        TaintHub.bindRequest(requestId);
    }

    public static String currentRequestId() {
        return TaintHub.currentRequestId();
    }

    public static void markHighCarrier(Object carrier) {
        TaintHub.markHighCarrier(carrier);
    }

    /**
     * 类型边界内容登记 (F2): 被污染 String 经载体类包裹后，按载体身份登记源内容，
     * 供 sink 处 sample 兜底回收，使 canary 跨 String->载体 边界被断言。
     */
    public static void recordCarrierContent(Object carrier, String content) {
        TaintHub.recordCarrierContent(carrier, content);
    }

    /** 回收载体登记的源内容 (F2)，无登记返回空串。 */
    public static String peekCarrierContent(Object o) {
        return TaintHub.peekCarrierContent(o);
    }

    public static void markArrayFrom(Object dest, Object src) {
        TaintHub.markArrayFrom(dest, src);
    }

    public static void markSanitized(Object value, String sanitizerId, String families) {
        TaintHub.markSanitized(value, sanitizerId, families);
    }

    public static String familiesForSanitizer(String origin) {
        return TaintHub.familiesForSanitizer(origin);
    }

    public static String sanitizerOf(Object value) {
        return TaintHub.sanitizerOf(value);
    }

    public static boolean isSanitizedFor(Object value, String family) {
        return TaintHub.isSanitizedFor(value, family);
    }

    public static void markFieldTaint(Object owner, String fieldName, Object value) {
        TaintHub.markFieldTaint(owner, fieldName, value);
    }

    public static void propagateFieldRead(Object owner, Object field, Object value) {
        TaintHub.propagateFieldRead(owner, field, value);
    }

    public static void propagateFieldWrite(Object owner, Object field, Object value) {
        TaintHub.propagateFieldWrite(owner, field, value);
    }

    public static boolean hasFieldTaint(Object owner) {
        return TaintHub.hasFieldTaint(owner);
    }

    public static boolean isFieldTainted(Object owner, String fieldName) {
        return TaintHub.isFieldTainted(owner, fieldName);
    }

    public static void markPrimitiveLow(int v) {
        TaintHub.markPrimitiveLow(v);
    }

    public static void markPrimitiveLow(long v) {
        TaintHub.markPrimitiveLow(v);
    }

    public static boolean isPrimitiveLow(int v) {
        return TaintHub.isPrimitiveLow(v);
    }

    public static boolean isPrimitiveLow(long v) {
        return TaintHub.isPrimitiveLow(v);
    }

    public static void clearCurrentRequest() {
        TaintHub.clearCurrentRequest();
    }

    public static void detachThread() {
        TaintHub.detachThread();
    }

    public static void clearRequest(String requestId) {
        TaintHub.clearRequest(requestId);
    }

    public static int liveRequestShadowCount() {
        return TaintHub.liveRequestShadowCount();
    }
}
