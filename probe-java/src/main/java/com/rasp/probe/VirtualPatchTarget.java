package com.rasp.probe;

/**
 * 方法级虚拟补丁目标。
 *
 * <p>规则坐标语法 {@code 类全名.方法名[#参数位置]}，兼容 {@code :} 与 {@code (n)} 两种分隔：
 * <ul>
 *   <li>{@code com.foo.Bar.doIt#1} —— 参数级，第 1 个入参含污点 (或命中 pattern) 即判定；</li>
 *   <li>{@code com.foo.Bar.doIt} + 非空 pattern —— 参数级，任意入参命中 pattern 即判定；</li>
 *   <li>{@code com.foo.Bar.doIt} + 空 pattern —— 调用级，命中方法即判定 (误拦面大，
 *       默认只在 BLOCKING 状态才真拦，AI 产出的规则最高只到 OBSERVING)。</li>
 * </ul>
 *
 * <p>{@code targetClass} 允许把整条坐标打包写入 (此时 {@code targetMethod} 可为空)，
 * 便于 Server 侧规则用单字段下发。
 */
public final class VirtualPatchTarget {
    private final long ruleId;
    private final String className;
    private final String methodName;
    private final int argIndex;
    private final String pattern;
    private final boolean blocking;
    private final String description;

    public VirtualPatchTarget(long ruleId, String className, String methodName, int argIndex, String pattern, boolean blocking, String description) {
        this.ruleId = ruleId;
        this.className = className;
        this.methodName = methodName;
        this.argIndex = argIndex;
        this.pattern = pattern;
        this.blocking = blocking;
        this.description = description;
    }

    public long ruleId() {
        return ruleId;
    }

    public String className() {
        return className;
    }

    public String methodName() {
        return methodName;
    }

    public int argIndex() {
        return argIndex;
    }

    public String pattern() {
        return pattern;
    }

    public boolean blocking() {
        return blocking;
    }

    public String description() {
        return description;
    }



    /** 任意参数位置：pattern 存在但未指定下标。 */
    public static final int ANY_ARG = -1;
    /** 调用级：命中方法即判定，不看参数。 */
    public static final int CALL_LEVEL = -2;

    public boolean callLevel() {
        return argIndex == CALL_LEVEL;
    }

    public boolean parameterLevel() {
        return !callLevel();
    }

    /** 注册表键：与 {@code @Advice.Origin("#t.#m")} 产出的字符串同构。 */
    public String key() {
        return className + "." + methodName;
    }

    public String coordinate() {
        if (argIndex >= 0) {
            return key() + "#" + argIndex;
        }
        return argIndex == ANY_ARG ? key() + "#*" : key();
    }

    /**
     * 从下发规则解析目标；不是 VIRTUAL_PATCH、未激活或坐标不可解析时返回 null (静默忽略，
     * 由调用方决定是否告警)。
     */
    public static VirtualPatchTarget parse(AgentRule rule) {
        if (rule == null || !"VIRTUAL_PATCH".equals(rule.type()) || !rule.active()) {
            return null;
        }
        String coordinate = joinCoordinate(rule.targetClass(), rule.targetMethod());
        if (coordinate.isEmpty()) {
            return null;
        }
        int argIndex = CALL_LEVEL;
        int separator = indexOfSeparator(coordinate);
        if (separator >= 0) {
            String tail = coordinate.substring(separator + 1).replace(")", "").trim();
            coordinate = coordinate.substring(0, separator).trim();
            if ("*".equals(tail)) {
                argIndex = ANY_ARG;
            } else {
                try {
                    argIndex = Math.max(0, Integer.parseInt(tail));
                } catch (NumberFormatException ignored) {
                    argIndex = CALL_LEVEL;
                }
            }
        }
        int lastDot = coordinate.lastIndexOf('.');
        if (lastDot <= 0 || lastDot == coordinate.length() - 1) {
            return null;
        }
        String className = coordinate.substring(0, lastDot);
        String methodName = coordinate.substring(lastDot + 1);
        String pattern = rule.pattern() == null ? "" : rule.pattern().trim();
        // pattern 存在但没写下标：按「任意参数值匹配」处理，而不是退化成误拦面更大的调用级。
        if (argIndex == CALL_LEVEL && !pattern.isEmpty()) {
            argIndex = ANY_ARG;
        }
        return new VirtualPatchTarget(rule.id(), className, methodName, argIndex, pattern,
                "BLOCKING".equals(rule.state()), rule.description() == null ? "" : rule.description());
    }

    private static String joinCoordinate(String targetClass, String targetMethod) {
        String type = targetClass == null ? "" : targetClass.trim();
        String method = targetMethod == null ? "" : targetMethod.trim();
        if (type.isEmpty()) {
            return method;
        }
        if (method.isEmpty()) {
            return type;
        }
        return type + "." + method;
    }

    private static int indexOfSeparator(String coordinate) {
        int hash = coordinate.indexOf('#');
        if (hash >= 0) {
            return hash;
        }
        int paren = coordinate.indexOf('(');
        if (paren >= 0) {
            return paren;
        }
        // ':' 只在最后一段出现时才当分隔符，避免误切 class 名。
        int colon = coordinate.lastIndexOf(':');
        return colon > coordinate.lastIndexOf('.') ? colon : -1;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof VirtualPatchTarget)) {
            return false;
        }
        VirtualPatchTarget that = (VirtualPatchTarget) o;
        return java.util.Objects.equals(ruleId, that.ruleId)
            && java.util.Objects.equals(className, that.className)
            && java.util.Objects.equals(methodName, that.methodName)
            && java.util.Objects.equals(argIndex, that.argIndex)
            && java.util.Objects.equals(pattern, that.pattern)
            && java.util.Objects.equals(blocking, that.blocking)
            && java.util.Objects.equals(description, that.description);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(ruleId, className, methodName, argIndex, pattern, blocking, description);
    }

    @Override
    public String toString() {
        return "VirtualPatchTarget[" + "ruleId=" + ruleId + ", " + "className=" + className + ", " + "methodName=" + methodName + ", " + "argIndex=" + argIndex + ", " + "pattern=" + pattern + ", " + "blocking=" + blocking + ", " + "description=" + description + "]";
    }
}
