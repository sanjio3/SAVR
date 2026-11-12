package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Marks a domain-object read (Spring Data {@code CrudRepository#findById}) for
 * two semantic-layer detections:
 * <ul>
 *   <li>BOLA correlation — the request loaded an object; did it enforce ownership?</li>
 *   <li>Race detection — an open read on the resource key (entityType:id).</li>
 * </ul>
 */
public final class RepositoryReadAdvice {

    private RepositoryReadAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.This Object repository, @Advice.Argument(0) Object id) {
        try {
            String resourceKey = RepositoryHelper.entityTypeOf(repository) + ":" + id;
            HookRuntime.reportObjectRead(resourceKey);
        } catch (Throwable t) {
            // fail-open: never throw into the instrumented thread
        }
    }
}
