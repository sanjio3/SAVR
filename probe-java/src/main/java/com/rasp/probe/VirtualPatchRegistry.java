package com.rasp.probe;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 方法级虚拟补丁注册表 + 可重定义白名单 (手册 11.2.5 二)。
 *
 * <p>运行期由 {@link VirtualPatchAdvice} 查询：按 {@code 类全名.方法名} 直接命中，
 * 未命中时才做一次宽松扫描 (兼容不同 Origin 渲染格式)。注册表为空时立即返回空表，
 * 保证「没有虚拟补丁 = 零额外开销」。
 *
 * <p>白名单是硬边界：JDK 核心类、bootstrap 已加载类、final 类、接口、探针自身与
 * 字节码框架一律拒绝下发并告警，不做任何「尽力而为」的 retransform 尝试。
 */
public final class VirtualPatchRegistry {
    /** 禁止 retransform 的包前缀：JDK 核心 + 字节码框架 + 探针自身 + 测试框架。 */
    private static final String[] DENY_PREFIXES = {
            "java.", "javax.", "jdk.", "sun.", "com.sun.", "org.w3c.", "org.xml.",
            "net.bytebuddy.", "com.rasp.probe.", "org.junit.", "org.mockito."
    };
    private static final int MAX_PATTERN_CACHE = 64;

    private static final Map<String, List<VirtualPatchTarget>> BY_KEY = new ConcurrentHashMap<>();
    private static final Map<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

    private VirtualPatchRegistry() {
    }

    public static void register(VirtualPatchTarget target) {
        if (target == null) {
            return;
        }
        BY_KEY.compute(target.key(), (key, existing) -> {
            List<VirtualPatchTarget> next = new ArrayList<>();
            if (existing != null) {
                for (VirtualPatchTarget item : existing) {
                    if (item.ruleId() != target.ruleId()) {
                        next.add(item);
                    }
                }
            }
            next.add(target);
            return List.copyOf(next);
        });
    }

    public static void unregister(VirtualPatchTarget target) {
        if (target == null) {
            return;
        }
        BY_KEY.compute(target.key(), (key, existing) -> {
            if (existing == null) {
                return null;
            }
            List<VirtualPatchTarget> next = new ArrayList<>();
            for (VirtualPatchTarget item : existing) {
                if (item.ruleId() != target.ruleId()) {
                    next.add(item);
                }
            }
            return next.isEmpty() ? null : List.copyOf(next);
        });
    }

    public static void clear() {
        BY_KEY.clear();
        PATTERN_CACHE.clear();
    }

    public static boolean isEmpty() {
        return BY_KEY.isEmpty();
    }

    public static int size() {
        return BY_KEY.size();
    }

    /** 运行期热路径：按 Origin 字符串取出该方法上生效的补丁。 */
    public static List<VirtualPatchTarget> matching(String origin) {
        if (origin == null || BY_KEY.isEmpty()) {
            return List.of();
        }
        List<VirtualPatchTarget> exact = BY_KEY.get(origin);
        if (exact != null) {
            return exact;
        }
        // 宽松兜底：Origin 渲染成 Method#toString() 之类的完整签名时仍能命中。
        List<VirtualPatchTarget> hits = null;
        for (Map.Entry<String, List<VirtualPatchTarget>> entry : BY_KEY.entrySet()) {
            if (origin.contains(entry.getKey())) {
                if (hits == null) {
                    hits = new ArrayList<>();
                }
                hits.addAll(entry.getValue());
            }
        }
        return hits == null ? List.of() : hits;
    }

    /**
     * 目标类名的白名单判定。返回 null 表示允许，否则返回拒绝原因 (直接进告警事件)。
     */
    public static String rejectReason(String className) {
        if (className == null || className.isBlank()) {
            return "empty-target-class";
        }
        String name = className.trim();
        if (name.indexOf('/') >= 0 || name.indexOf(' ') >= 0) {
            return "malformed-target-class";
        }
        for (String prefix : DENY_PREFIXES) {
            if (name.startsWith(prefix)) {
                return "denied-prefix:" + prefix;
            }
        }
        return null;
    }

    /**
     * 已加载类的白名单判定 (手册 11.2.5 二：非 bootstrap、非 final、有方法体)。
     */
    public static String rejectReason(Class<?> loaded) {
        if (loaded == null) {
            return null;
        }
        if (loaded.getClassLoader() == null) {
            return "bootstrap-loaded-class";
        }
        if (loaded.isInterface()) {
            return "interface-has-no-body";
        }
        if (Modifier.isFinal(loaded.getModifiers())) {
            return "final-class";
        }
        if (loaded.isPrimitive() || loaded.isArray() || loaded.isAnnotation()) {
            return "non-patchable-kind";
        }
        return null;
    }

    /** 规则 pattern 匹配：正则优先，非法正则退化为子串包含 (与 RaspSemanticEngine 同语义)。 */
    public static boolean matchesPattern(String pattern, String text) {
        if (pattern == null || pattern.isBlank() || text == null) {
            return false;
        }
        Pattern compiled = PATTERN_CACHE.get(pattern);
        if (compiled == null) {
            try {
                compiled = Pattern.compile(pattern);
            } catch (PatternSyntaxException ignored) {
                return text.contains(pattern);
            }
            if (PATTERN_CACHE.size() < MAX_PATTERN_CACHE) {
                PATTERN_CACHE.put(pattern, compiled);
            }
        }
        return compiled.matcher(text).find();
    }
}
