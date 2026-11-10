package com.rasp.probe;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Per-request correlation context for the semantic (policy) RASP layer.
 *
 * <p>Unlike data-flow taint tracking (removed when the platform became RASP-only), this tracks the
 * <b>authorization decisions</b> and <b>domain-object accesses</b> that occur
 * during a single request so we can detect Business-Logic Authorization flaws
 * (BOLA / BFLA):
 *
 * <ul>
 *   <li>a request loads a domain object (e.g. {@code repository.findById(id)})
 *       but no object-level authorization decision was enforced for it;</li>
 *   <li>the only authz decision present was role/authentication-based, not
 *       ownership-based (hasPermission / SpEL referencing the object id).</li>
 * </ul>
 *
 * <p>The context is request-scoped (cleared on {@code exitRequest}) and purely
 * observational — it never blocks and never throws into the instrumented thread.
 */
public final class SemanticContext {

    private static final ThreadLocal<SemanticContext> CURRENT = ThreadLocal.withInitial(SemanticContext::new);

    private String principal = "anonymous";
    private int authzDecisionCount = 0;
    private int ownershipDecisionCount = 0;
    private final List<String> objectAccesses = new ArrayList<>();

    private SemanticContext() {
    }

    static SemanticContext current() {
        return CURRENT.get();
    }

    void recordAuthzDecision(String principal, boolean ownershipSemantics) {
        if (principal != null && !principal.isBlank()) {
            this.principal = principal;
        }
        authzDecisionCount++;
        if (ownershipSemantics) {
            ownershipDecisionCount++;
        }
    }

    void recordObjectAccess(String resourceKey) {
        if (resourceKey == null || resourceKey.isBlank()) {
            return;
        }
        // 同一请求内同一个对象会被多层重复记录（CachingExecutor→BaseExecutor、4 参→6 参
        // query 重载）。去重，避免 BOLA 证据里同一对象重复出现。
        if (objectAccesses.contains(resourceKey)) {
            return;
        }
        // A repository read is observed twice (Spring Data proxy + SimpleJpaRepository
        // impl). Prefer the resolved "Entity:id" key over the "Unknown:id" one so the
        // BOLA event names the real object type.
        int colon = resourceKey.indexOf(':');
        String idPart = colon >= 0 ? resourceKey.substring(colon) : null;
        if (idPart != null && resourceKey.startsWith("Unknown:")) {
            for (String existing : objectAccesses) {
                if (existing.endsWith(idPart) && !existing.startsWith("Unknown:")) {
                    return;
                }
            }
        } else if (idPart != null) {
            objectAccesses.removeIf(k -> k.startsWith("Unknown:") && k.endsWith(idPart));
        }
        objectAccesses.add(resourceKey);
    }

    /**
     * Evaluate the BOLA precondition for this request and report a suspect event
     * when a domain object was accessed without any ownership-level authorization.
     * Called once on request exit; the context is reused, so callers must clear().
     */
    void evaluateAndReport() {
        // 诊断：暴露判定输入，便于定位「为什么没发射 BOLA_SUSPECT」。
        AgentLogger.info("bola", "eval objects=" + objectAccesses.size()
                + " authzDecisions=" + authzDecisionCount
                + " ownershipDecisions=" + ownershipDecisionCount);
        if (objectAccesses.isEmpty()) {
            return;
        }
        // No object-level authorization was enforced for any accessed object.
        boolean missingOwnership = ownershipDecisionCount == 0;
        if (!missingOwnership) {
            return;
        }
        // The principal is normally set by an ownership decision; when none was
        // recorded (the very condition that makes this a BOLA suspect), recover it
        // from the Spring Security context so the event names who accessed the object.
        String effectivePrincipal = principal;
        if (effectivePrincipal == null || effectivePrincipal.isBlank() || "anonymous".equals(effectivePrincipal)) {
            effectivePrincipal = RepositoryHelper.principalFromSecurityContext();
        }
        SecurityAgent.reportBolaSuspect(effectivePrincipal, new ArrayList<>(objectAccesses));
    }

    static void clear() {
        CURRENT.remove();
    }

    List<String> snapshotObjectAccesses() {
        return Collections.unmodifiableList(objectAccesses);
    }
}
