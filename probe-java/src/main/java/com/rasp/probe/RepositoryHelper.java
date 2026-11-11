package com.rasp.probe;

import java.lang.reflect.Method;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Reflection helpers for Spring Data repositories. The probe must not take a
 * compile-time dependency on Spring (it is loaded into arbitrary app class
 * loaders), so all Spring types are resolved reflectively and cached per class.
 */
public final class RepositoryHelper {

    private static final Map<Class<?>, String> ENTITY_TYPE_CACHE = new ConcurrentHashMap<>();

    private RepositoryHelper() {
    }

    /** Best-effort entity simple name for a repository instance, e.g. "Order". */
    public static String entityTypeOf(Object repository) {
        if (repository == null) {
            return "Unknown";
        }
        Class<?> repoClass = repository.getClass();
        String cached = ENTITY_TYPE_CACHE.get(repoClass);
        if (cached != null) {
            return cached;
        }
        String result = walkForEntityType(repoClass);
        ENTITY_TYPE_CACHE.put(repoClass, result);
        return result;
    }

    private static String walkForEntityType(Class<?> repoClass) {
        for (Type iface : repoClass.getGenericInterfaces()) {
            String found = entityTypeFromType(iface);
            if (found != null) {
                return found;
            }
            // A raw (non-parameterized) repository interface still carries the
            // parameterized super-interface that binds the entity type, e.g.
            // OrderRepository extends JpaRepository<Order, Long>. Recurse into it
            // so we resolve the concrete entity even when the proxy only exposes
            // the raw interface.
            if (iface instanceof Class<?> && isRepoType(((Class<?>) iface).getName())) {
                Class<?> rawIface = (Class<?>) iface;
                String nested = walkForEntityType(rawIface);
                if (nested != null) {
                    return nested;
                }
            }
        }
        Class<?> superClass = repoClass.getSuperclass();
        if (superClass != null && superClass != Object.class) {
            String found = walkForEntityType(superClass);
            if (found != null) {
                return found;
            }
        }
        return "Unknown";
    }

    private static boolean isRepoType(String name) {
        return name.equals("org.springframework.data.repository.CrudRepository")
                || name.equals("org.springframework.data.jpa.repository.JpaRepository")
                || name.equals("org.springframework.data.repository.PagingAndSortingRepository")
                || name.endsWith("Repository");
    }

    private static String entityTypeFromType(Type type) {
        if (!(type instanceof ParameterizedType)) {
            return null;
        }
        ParameterizedType pt = (ParameterizedType) type;
        Type raw = pt.getRawType();
        if (!(raw instanceof Class<?>)) {
            return null;
        }
        Class<?> rawClass = (Class<?>) raw;
        if (!isRepoType(rawClass.getName())) {
            return null;
        }
        Type[] args = pt.getActualTypeArguments();
        if (args.length >= 1 && args[0] instanceof Class<?>) {
            Class<?> entityClass = (Class<?>) args[0];
            return entityClass.getSimpleName();
        }
        return null;
    }

    /** Extract a stable id string from an entity, falling back to identity hash. */
    public static String idOf(Object entity) {
        if (entity == null) {
            return "null";
        }
        try {
            Method getId = findMethod(entity.getClass(), "getId");
            if (getId != null) {
                Object id = getId.invoke(entity);
                if (id != null) {
                    return String.valueOf(id);
                }
            }
        } catch (ReflectiveOperationException ignored) {
            // try field next
        }
        try {
            java.lang.reflect.Field idField = findField(entity.getClass(), "id");
            if (idField != null) {
                idField.setAccessible(true);
                Object id = idField.get(entity);
                if (id != null) {
                    return String.valueOf(id);
                }
            }
        } catch (ReflectiveOperationException ignored) {
            // fall through
        }
        return "h" + System.identityHashCode(entity);
    }

    private static Method findMethod(Class<?> start, String name) {
        Class<?> c = start;
        while (c != null && c != Object.class) {
            try {
                return c.getDeclaredMethod(name);
            } catch (NoSuchMethodException ignored) {
                // continue up the hierarchy
            }
            c = c.getSuperclass();
        }
        return null;
    }

    private static java.lang.reflect.Field findField(Class<?> start, String name) {
        Class<?> c = start;
        while (c != null && c != Object.class) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                // continue up the hierarchy
            }
            c = c.getSuperclass();
        }
        return null;
    }

    /** True when the attribute set carries object-level (ownership) authorization. */
    public static boolean hasOwnershipSemantics(Object configAttributes) {
        if (!(configAttributes instanceof Collection<?>)) {
            return false;
        }
        Collection<?> attributes = (Collection<?>) configAttributes;
        for (Object attribute : attributes) {
            String value = safeAttribute(attribute);
            if (value == null) {
                continue;
            }
            String lower = value.toLowerCase();
            // hasPermission / hasAnyPermission: explicit object-level check.
            if (lower.contains("haspermission") || lower.contains("hasanypermission")) {
                return true;
            }
            // SpEL referencing a method argument (e.g. @PreAuthorize("hasPermission(#id,...)"))
            // or a bean/expression attribute starting with '@' — object-scoped, not role-scoped.
            if (lower.contains("#") || value.trim().startsWith("@")) {
                return true;
            }
        }
        return false;
    }

    private static String safeAttribute(Object attribute) {
        try {
            Method getAttribute = attribute.getClass().getMethod("getAttribute");
            Object value = getAttribute.invoke(attribute);
            return value == null ? null : value.toString();
        } catch (ReflectiveOperationException ignored) {
            return attribute.toString();
        }
    }

    /** Principal name from a Spring Authentication, reflectively. */
    public static String principalOf(Object authentication) {
        if (authentication == null) {
            return "anonymous";
        }
        try {
            Method getName = authentication.getClass().getMethod("getName");
            Object name = getName.invoke(authentication);
            return name == null ? "anonymous" : name.toString();
        } catch (ReflectiveOperationException ignored) {
            return "anonymous";
        }
    }

    /**
     * Resolve the currently authenticated principal from Spring Security's
     * {@code SecurityContextHolder}, used to enrich a BOLA event when no
     * object-level authorization decision (which would otherwise carry the
     * principal) was recorded for the request. Reflective so the probe takes
     * no compile-time dependency on Spring Security.
     */
    public static String principalFromSecurityContext() {
        try {
            Class<?> holder = loadSecurityClass(
                    "org.springframework.security.core.context.SecurityContextHolder");
            Object context = holder.getMethod("getContext").invoke(null);
            if (context == null) {
                return "anonymous";
            }
            Object authentication = context.getClass().getMethod("getAuthentication").invoke(context);
            return principalOf(authentication);
        } catch (ReflectiveOperationException ignored) {
            return "anonymous";
        }
    }

    /**
     * Resolve a Spring Security class. The probe classes are loaded by the agent
     * class loader, which does NOT have the application's Spring Security on its
     * classpath — so a plain {@link Class#forName(String)} throws
     * {@link ClassNotFoundException}. During a request the thread context class
     * loader is the webapp loader, which CAN see Spring, so we try that first and
     * only fall back to the default loader if it fails.
     */
    private static Class<?> loadSecurityClass(String name) throws ClassNotFoundException {
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        if (tccl != null) {
            try {
                return Class.forName(name, false, tccl);
            } catch (ClassNotFoundException ignored) {
                // fall through to the default (probe) loader
            }
        }
        return Class.forName(name);
    }
}
