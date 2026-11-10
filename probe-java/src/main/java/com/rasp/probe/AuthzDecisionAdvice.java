package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Records every Spring Security authorization decision so the semantic layer can
 * tell whether a request that loaded a domain object actually enforced
 * object-level (ownership) authorization. Hooked on
 * {@code AccessDecisionManager.decide(...)} — the single funnel point all
 * method/URL security decisions pass through.
 */
public final class AuthzDecisionAdvice {

    private AuthzDecisionAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.Argument(0) Object authentication,
            @Advice.Argument(2) Object configAttributes) {
        try {
            String principal = RepositoryHelper.principalOf(authentication);
            boolean ownership = RepositoryHelper.hasOwnershipSemantics(configAttributes);
            HookRuntime.reportAuthzDecision(principal, ownership);
        } catch (Throwable t) {
            // fail-open: never throw into the instrumented thread
        }
    }
}
