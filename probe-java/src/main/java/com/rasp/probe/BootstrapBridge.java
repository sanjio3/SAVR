package com.rasp.probe;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class BootstrapBridge {
    private static final String HOOK_RUNTIME = "com.rasp.probe.HookRuntime";
    private static volatile Class<?> hookRuntimeClass;

    private BootstrapBridge() {
    }

    public static void onGenericSink(String sink, Object[] args) {
        invoke("onGenericSink", new Class<?>[] {String.class, Object[].class}, sink, args);
    }

    public static void onProcessBuilderStart(String sink, Object processBuilder) {
        invoke("onProcessBuilderStart", new Class<?>[] {String.class, Object.class}, sink, processBuilder);
    }

    public static Object wrapAsyncArgument(Object argument) {
        return invokeWithReturn("wrapAsyncArgument", new Class<?>[] {Object.class}, argument);
    }

    // Best-effort event reporting for the L2 taint block (no throw dependency).
    public static void reportTaint(String type, String sink, String payload) {
        invoke("reportTaintEvent", new Class<?>[] {String.class, String.class, String.class}, type, sink, payload);
    }

    /**
     * L3 语义层：转发 sink 调用结果采集（{@link SinkOutcomeAdvice} 专用入口）。
     *
     * <p>{@code SinkOutcomeAdvice} 可能被织入 bootstrap 侧被插桩类（{@code java.lang.Runtime}、
     * {@code javax.naming.*}），那里 {@code HookRuntime} 不可直接引用，故统一经本桥接类按
     * 字符串反射调用，语义与 {@link #onGenericSink} 同源。
     *
     * <p>{@code Throwable} 参数按 {@code Object} 传（{@code getMethod} 精确匹配参数类型，
     * 用 {@code Throwable.class} 声明会在实参为子类时 Method#getMethod 找不到，故用
     * {@code Object.class} 再走 {@code invoke} 的实际类型匹配）。
     */
    public static void recordSinkOutcome(String target, Throwable thrown) {
        invoke("recordSinkOutcome", new Class<?>[] {String.class, Object.class}, target, thrown);
    }

    private static void invoke(String methodName, Class<?>[] parameterTypes, Object... args) {
        try {
            Method method = hookRuntimeClass().getMethod(methodName, parameterTypes);
            method.invoke(null, args);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof SecurityException) {
                throw (SecurityException) cause;
            }
        } catch (Throwable ignored) {
        }
    }

    private static Object invokeWithReturn(String methodName, Class<?>[] parameterTypes, Object... args) {
        try {
            Method method = hookRuntimeClass().getMethod(methodName, parameterTypes);
            return method.invoke(null, args);
        } catch (Throwable ignored) {
            return args.length == 0 ? null : args[0];
        }
    }

    private static Class<?> hookRuntimeClass() throws ClassNotFoundException {
        Class<?> loaded = hookRuntimeClass;
        if (loaded != null) {
            return loaded;
        }
        Class<?> resolved = ClassLoader.getSystemClassLoader().loadClass(HOOK_RUNTIME);
        hookRuntimeClass = resolved;
        return resolved;
    }
}
