package com.rasp.probe;

import net.bytebuddy.asm.Advice;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

/**
 * BOLA / IDOR object-read collection for MyBatis-backed apps (the common case
 * where Spring Data {@code CrudRepository} is NOT used). Every mapper read funnels
 * through {@code MapperProxy.invoke}, so a single advice here captures domain-object
 * reads regardless of the concrete mapper or statement name.
 *
 * The read is reported to {@link HookRuntime#reportObjectRead(String)} which feeds
 * {@code SemanticContext.recordObjectAccess}. Combined with the principal captured
 * by {@code CurrentUserAdvice}, the semantic layer can then decide whether the
 * accessed object belonged to the current user (ownership check) — i.e. surface a
 * BOLA suspect when an object was read without an ownership-level authorization.
 */
public final class MyBatisReadAdvice {

    private MyBatisReadAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.This Object proxy,
                               @Advice.Origin Method method,
                               @Advice.Argument(2) Object[] args) {
        try {
            String entity = entityOf(proxy, method);
            Object id = (args != null && args.length > 0) ? args[0] : null;
            String resourceKey = entity + ":" + (id == null ? "?" : id);
            AgentLogger.info("bola", "mapper-read method=" + method.getName() + " key=" + resourceKey);
            HookRuntime.reportObjectRead(resourceKey);
        } catch (Throwable t) {
            // fail-open: never throw into the instrumented (MyBatis proxy) thread
            AgentLogger.warn("bola", "mapper-read failed: " + t);
        }
    }

    // 必须是 public：advice 代码会被内联进被织入的类（MapperProxy），private 会触发
    // IllegalAccessError 并被 fail-open 静默吞掉。
    public static String entityOf(Object proxy, Method method) {
        // 1) Return type (strip List / Optional / Collection wrappers).
        Class<?> ret = method.getReturnType();
        if (ret != null && !ret.equals(Void.TYPE) && !ret.equals(void.class)) {
            Class<?> elem = elementType(ret, method);
            if (elem != null && !elem.equals(ret)) {
                return elem.getSimpleName();
            }
            if (ret.getPackage() != null && !ret.getPackage().getName().startsWith("java.")) {
                return ret.getSimpleName();
            }
        }
        // 2) Fall back to the mapper interface name: XxxMapper -> Xxx.
        Class<?>[] ifaces = proxy.getClass().getInterfaces();
        for (Class<?> i : ifaces) {
            String n = i.getSimpleName();
            if (n.endsWith("Mapper")) {
                return n.substring(0, n.length() - "Mapper".length());
            }
        }
        return "Unknown";
    }

    // 同 entityOf：内联到目标类后必须可见。
    public static Class<?> elementType(Class<?> container, Method method) {
        Type g = method.getGenericReturnType();
        if (g instanceof ParameterizedType) {
            Type[] act = ((ParameterizedType) g).getActualTypeArguments();
            if (act.length == 1 && act[0] instanceof Class) {
                return (Class<?>) act[0];
            }
        }
        return container;
    }
}
