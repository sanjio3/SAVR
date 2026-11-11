package com.rasp.probe;

import com.rasp.stub.PatchVictim;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 方法级虚拟补丁引擎验收 (手册 11.2.5)。
 *
 * <p>分两组：
 * <ul>
 *   <li>规则坐标解析 + 可重定义白名单：纯单元，覆盖参数级/任意参数/调用级三种语法与
 *       JDK 核心类、bootstrap 类、final 类、接口的拒绝路径；</li>
 *   <li><b>活体 retransform</b>：真起 {@link ByteBuddyAgent#install} 拿 Instrumentation，
 *       对已加载的 {@link PatchVictim} 做运行时 retransform，证明「BLOCKING 规则下发 →
 *       方法调用被真拦」以及「规则撤销 → reset 复原、方法恢复正常」。这是手册要求的
 *       「必须有明确织入机制，否则只是口号」的实证。</li>
 * </ul>
 */
class VirtualPatchEngineTest {
    private Object savedState;
    private Object savedEngine;
    private Object savedBuffer;
    private boolean agentInstalled;

    @AfterEach
    void restore() throws Exception {
        VirtualPatchEngine.shutdown();
        if (agentInstalled) {
            setStatic("state", savedState);
            setStatic("raspSemanticEngine", savedEngine);
            setStatic("eventBuffer", savedBuffer);
        }
        CircuitBreaker.resetForTesting();
    }

    // ---------- 一、坐标解析 ----------

    @Test
    void parsesParameterLevelCoordinateWithArgumentIndex() {
        VirtualPatchTarget target = VirtualPatchTarget.parse(rule(7L, "BLOCKING",
                "", "com.foo.Bar", "doIt#1"));

        assertNotNull(target, "com.foo.Bar.doIt#1 必须解析成参数级补丁");
        assertEquals("com.foo.Bar", target.className());
        assertEquals("doIt", target.methodName());
        assertEquals(1, target.argIndex());
        assertTrue(target.parameterLevel());
        assertFalse(target.callLevel());
        assertTrue(target.blocking());
        assertEquals("com.foo.Bar.doIt", target.key(), "注册表键须与 @Advice.Origin(\"#t.#m\") 同构");
    }

    @Test
    void parsesCallLevelCoordinateWhenNeitherIndexNorPatternGiven() {
        VirtualPatchTarget target = VirtualPatchTarget.parse(rule(8L, "OBSERVING",
                "", "com.foo.Bar", "doIt"));

        assertNotNull(target);
        assertTrue(target.callLevel(), "无下标无 pattern = 调用级 (命中方法即判定)");
        assertEquals(VirtualPatchTarget.CALL_LEVEL, target.argIndex());
        assertFalse(target.blocking(), "OBSERVING 规则不得具备拦截力");
    }

    @Test
    void patternWithoutIndexDegradesToAnyArgumentNotCallLevel() {
        // 误拦面控制 (手册 11.2.5 四)：有 pattern 就按「任意参数值匹配」处理，
        // 绝不退化成误拦面更大的调用级。
        VirtualPatchTarget target = VirtualPatchTarget.parse(rule(9L, "BLOCKING",
                "(?i)\\$\\{jndi:", "com.foo.Bar", "doIt"));

        assertNotNull(target);
        assertEquals(VirtualPatchTarget.ANY_ARG, target.argIndex());
        assertTrue(target.parameterLevel());
    }

    @Test
    void acceptsWholeCoordinatePackedIntoTargetClass() {
        VirtualPatchTarget target = VirtualPatchTarget.parse(rule(10L, "BLOCKING",
                "", "com.foo.Bar.doIt(2)", ""));

        assertNotNull(target, "Server 用单字段下发整条坐标时也必须可解析");
        assertEquals("com.foo.Bar", target.className());
        assertEquals("doIt", target.methodName());
        assertEquals(2, target.argIndex());
    }

    @Test
    void ignoresNonVirtualPatchAndInactiveRules() {
        assertNull(VirtualPatchTarget.parse(rule(11L, "BLOCKING", "", "com.foo.Bar", "doIt", "PAYLOAD_BLACKLIST")),
                "PAYLOAD_BLACKLIST 规则不进虚拟补丁引擎");
        assertNull(VirtualPatchTarget.parse(rule(12L, "AI_GENERATED", "", "com.foo.Bar", "doIt")),
                "未审核 (非 OBSERVING/BLOCKING) 的规则不得织入");
        assertNull(VirtualPatchTarget.parse(rule(13L, "BLOCKING", "", "NoPackageClass", "")),
                "不含包名的坐标视为非法");
    }

    // ---------- 二、可重定义白名单 ----------

    @Test
    void whitelistRejectsJdkCoreAndProbeOwnClasses() {
        assertNotNull(VirtualPatchRegistry.rejectReason("java.lang.String"), "JDK 核心类禁止 retransform");
        assertNotNull(VirtualPatchRegistry.rejectReason("javax.naming.InitialContext"));
        assertNotNull(VirtualPatchRegistry.rejectReason("sun.misc.Unsafe"));
        assertNotNull(VirtualPatchRegistry.rejectReason("com.rasp.probe.HookRuntime"), "探针自身禁止 retransform");
        assertNotNull(VirtualPatchRegistry.rejectReason("net.bytebuddy.asm.Advice"));
        assertNotNull(VirtualPatchRegistry.rejectReason(""), "空目标必须拒绝");
        assertNotNull(VirtualPatchRegistry.rejectReason("com/foo/Bar"), "内部名格式必须拒绝");
        assertNull(VirtualPatchRegistry.rejectReason("com.sanjio.mall.OrderService"), "应用类允许 retransform");
    }

    @Test
    void whitelistRejectsBootstrapFinalAndInterfaceLoadedClasses() {
        assertEquals("bootstrap-loaded-class", VirtualPatchRegistry.rejectReason(String.class));
        // 用应用类加载器加载的接口，才能验到 interface 分支 (JDK 接口先被 bootstrap 分支拦下)。
        assertEquals("interface-has-no-body", VirtualPatchRegistry.rejectReason(AppInterface.class));
        assertEquals("final-class", VirtualPatchRegistry.rejectReason(FinalVictim.class));
        assertNull(VirtualPatchRegistry.rejectReason(PatchVictim.class), "普通应用类允许");
    }

    // ---------- 三、活体 retransform ----------

    @Test
    void blockingVirtualPatchInterceptsRealMethodCallAndRevokeRestoresIt() throws Exception {
        Instrumentation instrumentation = ByteBuddyAgent.install();
        PatchVictim victim = new PatchVictim();
        // 补丁前：基线正常返回，且目标类此刻已加载 (走引擎的「已加载类」白名单校验分支)。
        assertEquals("vulnerable:baseline", victim.vulnerable("baseline"));

        ProbeState state = installAgent();
        VirtualPatchEngine.install(instrumentation, config());
        assertNotNull(VirtualPatchEngine.current(), "引擎必须安装成功");

        // 下发调用级 BLOCKING 补丁：命中方法即拦 (手册 11.2.5 一/四)。
        state.applyConfig(Map.of("mode", "BLOCK", "ruleVersion", 1L, "rules",
                List.of(rule(101L, "BLOCKING", "", "com.rasp.stub.PatchVictim", "vulnerable"))));
        assertEquals(1, VirtualPatchEngine.current().appliedCount(), "补丁必须真的织入");

        SecurityException thrown = assertThrows(SecurityException.class,
                () -> victim.vulnerable("any-input"),
                "BLOCKING 虚拟补丁必须实时拦下受害方法调用");
        assertTrue(thrown.getMessage().contains("rule-101"), "拦截原因须带规则 ID 便于取证: " + thrown.getMessage());

        // 补丁不得溢出到同类的其它方法。
        assertEquals("untouched:ok", victim.untouched("ok"));

        // 规则撤销 → reset 复原 (手册 11.2.4 回退)。
        state.applyConfig(Map.of("mode", "BLOCK", "ruleVersion", 2L, "rules", List.of()));
        assertEquals(0, VirtualPatchEngine.current().appliedCount(), "撤销后不得残留已生效补丁");
        assertTrue(VirtualPatchRegistry.isEmpty(), "撤销后注册表须清空");
        assertEquals("vulnerable:after-revoke", victim.vulnerable("after-revoke"),
                "补丁卸载后方法必须恢复正常，不留残余拦截");
    }

    @Test
    void observingVirtualPatchOnlyObservesAndDoesNotBlock() throws Exception {
        Instrumentation instrumentation = ByteBuddyAgent.install();
        PatchVictim victim = new PatchVictim();

        ProbeState state = installAgent();
        VirtualPatchEngine.install(instrumentation, config());
        // AI 产出的规则最高只到 OBSERVING (铁律)：即便探针处于 BLOCK 模式也只观测。
        state.applyConfig(Map.of("mode", "BLOCK", "ruleVersion", 3L, "rules",
                List.of(rule(102L, "OBSERVING", "", "com.rasp.stub.PatchVictim", "vulnerable"))));
        assertEquals(1, VirtualPatchEngine.current().appliedCount());

        assertEquals("vulnerable:observed", victim.vulnerable("observed"),
                "OBSERVING 规则只落事件，绝不拦流量");
    }

    @Test
    void illegalTargetIsRejectedAndNeverApplied() throws Exception {
        Instrumentation instrumentation = ByteBuddyAgent.install();
        ProbeState state = installAgent();
        VirtualPatchEngine.install(instrumentation, config());

        state.applyConfig(Map.of("mode", "BLOCK", "ruleVersion", 4L, "rules",
                List.of(rule(103L, "BLOCKING", "", "java.lang.Runtime", "exec"))));

        assertEquals(0, VirtualPatchEngine.current().appliedCount(),
                "白名单外的 target 必须拒绝下发，不得尝试 retransform");
        assertTrue(VirtualPatchRegistry.isEmpty(), "被拒规则不得留在注册表里 (禁止半生效态)");
    }

    // ---------- 辅助 ----------

    private static final class FinalVictim {
    }

    private interface AppInterface {
    }

    private AgentRule rule(long id, String state, String pattern, String targetClass, String targetMethod) {
        return rule(id, state, pattern, targetClass, targetMethod, "VIRTUAL_PATCH");
    }

    private AgentRule rule(long id, String state, String pattern, String targetClass, String targetMethod, String type) {
        return new AgentRule(id, type, state, pattern, targetClass, targetMethod, 0.9, "cve-patch-" + id);
    }

    private ProbeConfig config() {
        return new ProbeConfig("http://127.0.0.1:1", "agent", "app", 1, 64);
    }

    private ProbeState installAgent() throws Exception {
        savedState = peekStatic("state");
        savedEngine = peekStatic("raspSemanticEngine");
        savedBuffer = peekStatic("eventBuffer");
        agentInstalled = true;
        ProbeState state = new ProbeState();
        ProbeConfig config = config();
        EventBuffer buffer = new EventBuffer(config, new ProbeHttpClient(config));
        setStatic("state", state);
        setStatic("eventBuffer", buffer);
        setStatic("raspSemanticEngine", new RaspSemanticEngine(buffer, state));
        CircuitBreaker.resetForTesting();
        return state;
    }

    private Object peekStatic(String name) throws Exception {
        Field field = SecurityAgent.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private void setStatic(String name, Object value) throws Exception {
        Field field = SecurityAgent.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(null, value);
    }
}
