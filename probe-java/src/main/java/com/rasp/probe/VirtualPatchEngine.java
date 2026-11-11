package com.rasp.probe;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.agent.builder.ResettableClassFileTransformer;
import net.bytebuddy.asm.Advice;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static net.bytebuddy.matcher.ElementMatchers.isAbstract;
import static net.bytebuddy.matcher.ElementMatchers.isMethod;
import static net.bytebuddy.matcher.ElementMatchers.isNative;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;

/**
 * 方法级虚拟补丁引擎 —— 运行时 retransform 织入 (手册 11.2.5)。
 *
 * <p>生命周期：探针启动时 {@link #install} 拿到 {@link Instrumentation} 句柄；此后每次
 * 心跳下发规则，{@link ProbeState#applyConfig} 调用 {@link #onRulesUpdated} 做一次
 * 「期望态 vs 已生效态」差分：
 * <ul>
 *   <li>新增/变更的 VIRTUAL_PATCH 规则 → 白名单校验 → retransform 织入 {@link VirtualPatchAdvice}；</li>
 *   <li>撤销/失活的规则 → {@link ResettableClassFileTransformer#reset} 卸载补丁 (11.2.4 回退)；</li>
 *   <li>白名单外或织入失败的目标 → 不生效 + 落 {@code VIRTUAL_PATCH_REJECTED} 告警事件，
 *       并回滚该规则的注册，绝不留下「注册了但没织入」的半生效态。</li>
 * </ul>
 *
 * <p>整体 fail-open：任何一条规则的失败只影响它自己，既不影响其它补丁，也绝不崩溃宿主。
 */
public final class VirtualPatchEngine {
    private static volatile VirtualPatchEngine current;

    private final Instrumentation instrumentation;
    private final Map<Long, Applied> applied = new ConcurrentHashMap<>();

    private VirtualPatchEngine(Instrumentation instrumentation) {
        this.instrumentation = instrumentation;
    }

    private final class Applied {
        private final VirtualPatchTarget target;
        private final ResettableClassFileTransformer transformer;

        public Applied(VirtualPatchTarget target, ResettableClassFileTransformer transformer) {
            this.target = target;
            this.transformer = transformer;
        }

        public VirtualPatchTarget target() {
            return target;
        }

        public ResettableClassFileTransformer transformer() {
            return transformer;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Applied)) {
                return false;
            }
            Applied that = (Applied) o;
            return java.util.Objects.equals(target, that.target)
                && java.util.Objects.equals(transformer, that.transformer);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(target, transformer);
        }

        @Override
        public String toString() {
            return "Applied[" + "target=" + target + ", " + "transformer=" + transformer + "]";
        }
    }

    /** 探针启动时安装；未开启开关或拿不到 Instrumentation 时整个能力静默关闭。 */
    public static void install(Instrumentation instrumentation, ProbeConfig config) {
        if (instrumentation == null || config == null || !config.virtualPatchEnabled()) {
            return;
        }
        current = new VirtualPatchEngine(instrumentation);
        AgentLogger.info("patch", "virtual patch engine ready");
    }

    /** 测试与热重启用：卸载全部补丁并释放引擎。 */
    public static void shutdown() {
        VirtualPatchEngine engine = current;
        current = null;
        if (engine != null) {
            engine.revokeAll();
        }
        VirtualPatchRegistry.clear();
    }

    static VirtualPatchEngine current() {
        return current;
    }

    /** 规则热下发入口。引擎未安装时是无副作用的空操作 (单测直接调 applyConfig 也安全)。 */
    public static void onRulesUpdated(List<AgentRule> rules) {
        VirtualPatchEngine engine = current;
        if (engine == null || rules == null) {
            return;
        }
        FailOpen.run("virtual-patch-sync", () -> engine.sync(rules));
    }

    void sync(List<AgentRule> rules) {
        Map<Long, VirtualPatchTarget> desired = new LinkedHashMap<>();
        for (AgentRule rule : rules) {
            VirtualPatchTarget target = VirtualPatchTarget.parse(rule);
            if (target == null) {
                continue;
            }
            String reason = VirtualPatchRegistry.rejectReason(target.className());
            if (reason != null) {
                reject(target, reason);
                continue;
            }
            desired.put(target.ruleId(), target);
        }
        // 先卸载：已失活或坐标/状态发生变化的规则一律先复原，再按新目标重新织入。
        for (Map.Entry<Long, Applied> entry : new ArrayList<>(applied.entrySet())) {
            VirtualPatchTarget next = desired.get(entry.getKey());
            if (next == null || !next.equals(entry.getValue().target())) {
                revoke(entry.getKey());
            }
        }
        for (VirtualPatchTarget target : desired.values()) {
            if (!applied.containsKey(target.ruleId())) {
                apply(target);
            }
        }
    }

    private void apply(VirtualPatchTarget target) {
        Class<?> loaded = findLoaded(target.className());
        if (loaded != null) {
            String reason = VirtualPatchRegistry.rejectReason(loaded);
            if (reason == null && !instrumentation.isModifiableClass(loaded)) {
                reason = "not-modifiable";
            }
            if (reason != null) {
                reject(target, reason);
                return;
            }
        }
        VirtualPatchRegistry.register(target);
        try {
            // disableClassFormatChanges 是 retransform 已加载类的硬要求：默认的 REBASE 策略
            // 会新增改名后的原方法，而 JVM 的 retransformClasses 明确禁止增删成员，会直接拒绝
            // 变换 (且被 fail-open 吞掉，表现为「装了但不触发」)。Advice 只改方法体，冻结
            // 重定义完全够用。
            ResettableClassFileTransformer transformer = ByteBuddyHookInstaller.baseBuilder()
                    .disableClassFormatChanges()
                    .type(named(target.className()))
                    .transform((builder, typeDescription, classLoader, module, protectionDomain) -> builder
                            .visit(Advice.to(VirtualPatchAdvice.class)
                                    .on(named(target.methodName())
                                            .and(isMethod())
                                            .and(not(isAbstract()))
                                            .and(not(isNative())))))
                    .installOn(instrumentation);
            applied.put(target.ruleId(), new Applied(target, transformer));
            AgentLogger.info("patch", "virtual patch applied rule-" + target.ruleId()
                    + " on " + target.coordinate() + " state=" + (target.blocking() ? "BLOCKING" : "OBSERVING"));
            SecurityAgent.reportPatchEvent("VIRTUAL_PATCH_APPLIED", "MEDIUM", target, target.coordinate(), "applied");
        } catch (Throwable throwable) {
            // 织入失败：撤销注册并回退，避免注册表留下不会触发的僵尸补丁 (11.2.4 回退)。
            VirtualPatchRegistry.unregister(target);
            reject(target, "retransform-failed:" + throwable.getClass().getSimpleName());
        }
    }

    private void revoke(long ruleId) {
        Applied entry = applied.remove(ruleId);
        if (entry == null) {
            return;
        }
        VirtualPatchRegistry.unregister(entry.target());
        boolean reverted = false;
        try {
            reverted = entry.transformer().reset(instrumentation, AgentBuilder.RedefinitionStrategy.RETRANSFORMATION);
        } catch (Throwable throwable) {
            AgentLogger.warn("patch", "virtual patch reset failed for rule-" + ruleId
                    + ": " + throwable.getClass().getSimpleName());
        }
        AgentLogger.info("patch", "virtual patch revoked rule-" + ruleId
                + " on " + entry.target().coordinate() + " reverted=" + reverted);
        SecurityAgent.reportPatchEvent("VIRTUAL_PATCH_REVOKED", "MEDIUM", entry.target(),
                entry.target().coordinate(), reverted ? "reverted" : "reset-incomplete");
    }

    private void revokeAll() {
        for (Long ruleId : new ArrayList<>(applied.keySet())) {
            revoke(ruleId);
        }
    }

    private void reject(VirtualPatchTarget target, String reason) {
        AgentLogger.warn("patch", "virtual patch rejected rule-" + target.ruleId()
                + " on " + target.coordinate() + ": " + reason);
        SecurityAgent.reportPatchEvent("VIRTUAL_PATCH_REJECTED", "MEDIUM", target, target.coordinate(), reason);
    }

    /**
     * 在已加载类里找目标。刻意不用 {@code Class.forName}：那会触发类加载与静态初始化，
     * 对未加载的目标类是有副作用的行为；未加载时返回 null，由 ByteBuddy 在首次加载时织入。
     */
    private Class<?> findLoaded(String className) {
        try {
            for (Class<?> candidate : instrumentation.getAllLoadedClasses()) {
                if (className.equals(candidate.getName())) {
                    return candidate;
                }
            }
        } catch (Throwable ignored) {
            // fail-open：拿不到已加载类列表时按「未加载」处理。
        }
        return null;
    }

    int appliedCount() {
        return applied.size();
    }
}
