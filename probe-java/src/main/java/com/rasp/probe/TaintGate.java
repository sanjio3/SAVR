package com.rasp.probe;

import java.util.Map;

/**
 * L2 taint decision gate (agent class loader).
 *
 * Classifies whether a sink is "dangerous" (手册 11.1.2 全 sink 通用污点, scoped to
 * the high-confidence sink families) and runs the Sink-time deep scan (11.1.3 九)
 * so a tainted value nested inside a container/array still trips the intercept.
 *
 * Performance contract: deep scan is bounded by depth 16 / 4096 elements / 1ms
 * budget; beyond that it fail-open (returns "undecided" → not blocked) so a
 * maliciously nested argument cannot turn the scan itself into a DoS.
 */
public final class TaintGate {
    /**
     * Two layers of classification, because most dangerous sinks are matched by their
     * *interface* (e.g. java.sql.Statement, javax.xml.parsers.DocumentBuilder) but the
     * advice reports the *concrete implementation class* as its origin ("#t.#m").
     * A SQL sink therefore surfaces as
     * {@code com.zaxxer.hikari.pool.HikariProxyStatement.executeQuery}, which does NOT
     * start with "java.sql." — a prefix-only check would let it slip through.
     *
     * DANGEROUS_PREFIXES  — families whose impl stays in the interface's own package
     *   (hibernate, ibatis, spring-expression, ognl, jndi) OR a sink that is a concrete
     *   (non-interface) type whose origin IS the class name (java.lang.Runtime,
     *   java.io.FileInputStream, java.nio.file.Files, ...).
     * DANGEROUS_FAMILY_TOKENS — class-name fragments appearing in the concrete impl of
     *   an interface-based sink (Statement for JDBC, DocumentBuilder/SAXParser/Transformer
     *   for XML). Matched with contains; each fragment is unique to the dangerous type
     *   so it cannot accidentally fire on a benign class.
     */
    private static final String[] DANGEROUS_PREFIXES = {
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "java.sql.",
            "jakarta.persistence.",
            "org.hibernate.",
            "org.apache.ibatis.",
            "org.springframework.expression",
            "ognl.",
            "java.io.ObjectInputStream",
            "javax.xml.",
            "java.lang.reflect.Method",
            "java.lang.reflect.Constructor",
            "java.lang.Class",
            "java.lang.ClassLoader",
            "javax.naming.",
            "sun.net.www.protocol.",
            // concrete (non-interface) file sinks whose origin is the exact class name
            "java.io.FileInputStream",
            "java.io.FileOutputStream",
            "java.io.RandomAccessFile",
            "java.nio.file.Files",
            // ---- M2 盲点家族 (手册 11.4.1 / 11.4.2) ----
            // polymorphic deserialization (Jackson / fastjson / snakeyaml gadget chains)
            "com.fasterxml.jackson.",
            "org.codehaus.jackson.",
            "com.alibaba.fastjson",
            "org.yaml.snakeyaml",
            // NoSQL injection ($where / $regex operator smuggling)
            "com.mongodb.",
            "org.springframework.data.mongodb.",
            // SSTI template engines
            "freemarker.",
            "org.apache.velocity",
            "org.thymeleaf.",
            "javax.el.",
            "jakarta.el.",
            // GraphQL query documents drive resolver execution
            "graphql."
    };

    // Class-name fragments identifying concrete impls of interface-based dangerous
    // sinks. The impl report origin "package.ImplClass.method", so we match on the
    // impl class name fragment rather than the interface package (see note above).
    private static final String[] DANGEROUS_FAMILY_TOKENS = {
            "Statement",      // java.sql.Statement / PreparedStatement impls (Hikari, H2, MySQL, …)
            "DocumentBuilder", // javax.xml.parsers.DocumentBuilder impl
            "SAXParser",      // org.xml.sax.XMLReader / javax.xml.parsers.SAXParser impl
            "Transformer"     // javax.xml.transform.Transformer impl (XSLT)
    };

    /**
     * Intentionally NOT classified dangerous: the Spring HTTP message converter
     * (org.springframework.http.converter...) is the reflected-XSS response sink.
     * Tainting every response body that contains user input would block all normal
     * reflected content, so XSS stays pattern-based (inspectRasp) — only the
     * high-confidence RCE / injection / deserialization / XXE / JNDI / SSRF /
     * file families are taint-blocked.
     */

    private static final int MAX_DEPTH = 16;
    private static final int MAX_ELEMENTS = 4096;
    private static final long SCAN_BUDGET_NANOS = 1_000_000L;

    private TaintGate() {
    }

    public static boolean isDangerous(String sink) {
        if (sink == null) {
            return false;
        }
        for (String prefix : DANGEROUS_PREFIXES) {
            if (sink.startsWith(prefix)) {
                return true;
            }
        }
        for (String token : DANGEROUS_FAMILY_TOKENS) {
            if (sink.contains(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True if a HIGH-confidence taint reaches the sink (→ block in BLOCK mode).
     * Short-circuits on a clean request: {@code REQUEST_TAINTED} is only raised when
     * something was actually marked, so on an untainted request the gate costs a single
     * ThreadLocal read — no sink-argument traversal, no WeakHashMap probe. This is the
     * hot-path performance contract from 手册 11.1.3 八.
     */
    public static boolean hasHighTaint(String sink, Object[] args) {
        if (!isDangerous(sink) || args == null || !TaintStore.isRequestTainted()) {
            return false;
        }
        String family = familyOf(sink);
        int[] budget = {MAX_ELEMENTS};
        long deadline = System.nanoTime() + SCAN_BUDGET_NANOS;
        for (Object arg : args) {
            if (deep(arg, true, 0, budget, deadline, family)) {
                return true;
            }
        }
        return false;
    }

    /** True if only LOW-confidence (numeric) taint reaches the sink (→ observe only). */
    public static boolean hasLowTaint(String sink, Object[] args) {
        if (!isDangerous(sink) || args == null || !TaintStore.isRequestTainted()) {
            return false;
        }
        String family = familyOf(sink);
        int[] budget = {MAX_ELEMENTS};
        long deadline = System.nanoTime() + SCAN_BUDGET_NANOS;
        for (Object arg : args) {
            if (deep(arg, false, 0, budget, deadline, family)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Sanitizer triage (手册 11.1.5 二): map a sink to the family a sanitizer must have
     * neutralized for the taint to be considered defused there. HTML-escaping a value
     * makes it safe for the response body but NOT for a SQL statement, so the sanitizer
     * decision is per-family instead of a blanket un-taint.
     */
    public static String familyOf(String sink) {
        if (sink == null) {
            return "";
        }
        if (sink.startsWith("java.sql.") || sink.contains("Statement")
                || sink.startsWith("org.hibernate.") || sink.startsWith("org.apache.ibatis.")
                || sink.startsWith("jakarta.persistence.")) {
            return TaintStore.FAMILY_SQL;
        }
        if (sink.startsWith("java.lang.Runtime") || sink.startsWith("java.lang.ProcessBuilder")) {
            return TaintStore.FAMILY_SHELL;
        }
        if (sink.startsWith("javax.xml.") || sink.contains("DocumentBuilder")
                || sink.contains("SAXParser") || sink.contains("Transformer")) {
            return TaintStore.FAMILY_XML;
        }
        if (sink.startsWith("javax.naming.")) {
            return TaintStore.FAMILY_LDAP;
        }
        if (sink.startsWith("java.io.File") || sink.startsWith("java.io.RandomAccessFile")
                || sink.startsWith("java.nio.file.Files")) {
            return TaintStore.FAMILY_PATH;
        }
        if (sink.startsWith("com.fasterxml.jackson.") || sink.startsWith("org.codehaus.jackson.")
                || sink.startsWith("com.alibaba.fastjson") || sink.startsWith("com.mongodb.")
                || sink.startsWith("org.springframework.data.mongodb.") || sink.startsWith("graphql.")) {
            return TaintStore.FAMILY_JSON;
        }
        // SSTI / EL: an HTML escaper does NOT defuse a template expression, so these sinks
        // deliberately map to the HTML family only for the response-side escapers that really
        // neutralize markup — a Java/JSON escaper stays blockable here.
        if (sink.startsWith("freemarker.") || sink.startsWith("org.apache.velocity")
                || sink.startsWith("org.thymeleaf.") || sink.startsWith("javax.el.")
                || sink.startsWith("jakarta.el.")) {
            return TaintStore.FAMILY_HTML;
        }
        return "";
    }

    private static boolean deep(Object o, boolean high, int depth, int[] budget, long deadline, String family) {
        if (o == null) {
            return false;
        }
        // Sanitizer-aware skip (11.1.5 二): a value neutralized FOR THIS sink family is not
        // taint-blockable here, but stays blockable at every other family.
        if (TaintStore.isSanitizedFor(o, family)) {
            return false;
        }
        if (high ? TaintStore.isHigh(o) : TaintStore.isLow(o)) {
            return true;
        }
        // Content-based fallback: a String whose identity mark was lost through a copy /
        // concatenation is still HIGH-tainted if its content contains a tainted source value.
        if (high && o instanceof String && TaintStore.isContentTainted((String) o)) {
            return true;
        }
        if (depth >= MAX_DEPTH || budget[0]-- <= 0 || System.nanoTime() > deadline) {
            return false;
        }
        if (o.getClass().isArray()) {
            if (o instanceof Object[]) {
                Object[] arr = (Object[]) o;
                for (Object e : arr) {
                    if (deep(e, high, depth + 1, budget, deadline, family)) {
                        return true;
                    }
                }
            }
            return false;
        }
        if (o instanceof Map<?, ?>) {
            Map<?, ?> m = (Map<?, ?>) o;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (deep(e.getKey(), high, depth + 1, budget, deadline, family)
                        || deep(e.getValue(), high, depth + 1, budget, deadline, family)) {
                    return true;
                }
            }
            return false;
        }
        if (o instanceof Iterable<?>) {
            Iterable<?> it = (Iterable<?>) o;
            for (Object e : it) {
                if (deep(e, high, depth + 1, budget, deadline, family)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    /** First tainted value (HIGH preferred, then LOW) as a sampled String for the event. */
    public static String sampleTainted(String sink, Object[] args) {
        if (args == null) {
            return "";
        }
        for (Object a : args) {
            if (a != null && TaintStore.isTainted(a)) {
                return HookRuntime.sample(a);
            }
        }
        return HookRuntime.sample(args);
    }
}
