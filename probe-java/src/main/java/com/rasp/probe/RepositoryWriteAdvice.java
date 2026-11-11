package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Marks a domain-object write (Spring Data {@code save} / {@code saveAndFlush} /
 * {@code delete} / {@code deleteById}) as a write on the resource key, closing
 * the read-modify-write window for the race detector.
 */
public final class RepositoryWriteAdvice {

    private RepositoryWriteAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.This Object repository, @Advice.Argument(0) Object arg) {
        try {
            String resourceKey;
            if (arg instanceof Number || arg instanceof CharSequence) {
                // deleteById — arg is the id
                resourceKey = RepositoryHelper.entityTypeOf(repository) + ":" + arg;
            } else {
                // save / saveAndFlush / saveAll / delete — first arg is the entity
                resourceKey = (arg == null ? "Unknown" : entityUserClass(arg))
                        + ":" + RepositoryHelper.idOf(arg);
            }
            HookRuntime.reportObjectWrite(resourceKey);
        } catch (Throwable t) {
            // fail-open: never throw into the instrumented thread
        }
    }

    /**
     * Resolve the application entity simple name from a possibly Hibernate-proxied or
     * bytecode-enhanced instance, so the write resource key matches the read key
     * (which is derived from the repository interface, e.g. "Order"). Hibernate lazy
     * proxies and Spring enhancement produce class names like
     * {@code Order$HibernateProxy$...}, {@code Order$$EnhancerByCGLIB$$...} or
     * {@code Order$ByteBuddy$...}; we walk up to the first "clean" user class.
     */
    public static String entityUserClass(Object entity) {
        if (entity == null) {
            return "Unknown";
        }
        Class<?> current = entity.getClass();
        while (current != null && current != Object.class) {
            String simple = current.getSimpleName();
            if (isCleanUserClass(simple)) {
                return simple;
            }
            current = current.getSuperclass();
        }
        return entity.getClass().getSimpleName();
    }

    public static boolean isCleanUserClass(String simple) {
        if (simple == null || simple.isEmpty() || simple.contains("$") || simple.contains("$$")) {
            return false;
        }
        String lower = simple.toLowerCase();
        return !lower.contains("proxy") && !lower.contains("javassist") && !lower.contains("bytebuddy")
                && !lower.contains("cglib") && !lower.contains("enhanced") && !lower.contains("hibernate");
    }
}
