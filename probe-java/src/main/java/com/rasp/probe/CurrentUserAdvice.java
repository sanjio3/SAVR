package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Captures the authenticated principal for the current request by hooking the
 * application's {@code CurrentUser.of(HttpServletRequest)} helper. The principal is
 * recovered from the request attribute the app's JWT filter sets, so no compile-time
 * dependency on the app's security classes is needed. It is handed to
 * {@link HookRuntime#reportAuthzDecision(Object, boolean)} so the semantic layer knows
 * who is acting — without implying any object-level (ownership) decision was made.
 * In apps that rely on a custom login-state check rather than Spring Security's
 * {@code AccessDecisionManager}, this is the only principal source, and
 * ownershipDecisionCount stays 0, which is exactly the BOLA precondition (an object
 * was accessed without an ownership-level authorization). The domain-object read
 * itself is captured by {@link MyBatisReadAdvice}.
 */
public final class CurrentUserAdvice {

    private CurrentUserAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.Argument(0) Object request) {
        try {
            if (request == null) {
                return;
            }
            Object principal = request.getClass().getMethod("getAttribute", String.class).invoke(request, "mallUser");
            if (principal != null) {
                AgentLogger.info("bola", "principal captured=" + principal);
                HookRuntime.reportAuthzDecision(principal, false);
            }
        } catch (Throwable t) {
            // fail-open
            AgentLogger.warn("bola", "principal capture failed: " + t);
        }
    }
}
