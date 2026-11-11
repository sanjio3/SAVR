package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * Sink 调用结果采集（L3 语义层证据管道）。
 *
 * <p>背景：此前全平台**没有任何 advice 使用 {@code @Advice.OnMethodExit} + {@code @Advice.Thrown}**，
 * 即「sink 有没有报错、报了什么错」这个事实**根本没有被采集**。而异常恰恰是判定
 * 「payload 是否真的被解释器执行」的直接证据：
 *
 * <ul>
 *   <li>注入成功且数据库报错 → {@code java.sql.SQLSyntaxErrorException}（证明注入改变了语义）</li>
 *   <li>注入成功但 filter 非法 → {@code javax.naming.InvalidSearchFilterException}</li>
 *   <li>payload 类型不匹配 → {@code java.lang.NumberFormatException}（证明注入**未**生效）</li>
 * </ul>
 *
 * <p>本 advice 只做**观测**，不做裁决：把「是否抛异常 + 异常类名 + 异常消息」交给
 * {@code HookRuntime.recordSinkOutcome}（或 bootstrap 侧经 {@link BootstrapBridge} 转发），
 * 由请求退出时统一发射为 SINK_OUTCOME 事件，后端裁决层消费。
 *
 * <p>关键约束：
 * <ul>
 *   <li><b>类加载器安全</b>：本 advice 可能被织入 bootstrap 侧被插桩类（{@code java.lang.Runtime}、
 *       {@code javax.naming.*}），那里 {@code HookRuntime} 不可见。故静态调用点只用
 *       {@link BootstrapBridge}（其内部按字符串反射解析 + fail-open），这是本代码库既有的
 *       跨加载器桥接模式（与 {@link BootstrapGenericSinkAdvice} 同源）。</li>
 *   <li><b>fail-open</b>：采集路径任何异常都不得影响业务；采集不到即不发射事件，
 *       后端按「证据缺失」处理（definitive=False），绝不做阴性裁决。</li>
 *   <li><b>不阻塞</b>：不吞异常、不改返回值（{@code @Advice.Thrown} 默认只读）。</li>
 *   <li><b>仅在有平台 canary 的请求上下文内采集</b>：普通业务流量不发射，避免噪声淹没事件表。</li>
 * </ul>
 */
public final class SinkOutcomeAdvice {
    private SinkOutcomeAdvice() {
    }

    /**
     * 仅对 {@code @Advice.Thrown(readOnly = false)} 会改字节码的场景才需要显式声明；此处
     * 保持只读（不吞异常），因此不需要该参数。{@code onThrowable = Throwable.class} 是让
     * exit advice 在方法抛异常时也执行的关键——缺了它 {@code @Advice.Thrown} 恒为 null。
     */
    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void onExit(@Advice.Thrown Throwable thrown,
                              @Advice.This(optional = true) Object self) {
        try {
            String origin;
            try {
                origin = self == null ? "" : self.getClass().getName();
            } catch (Throwable ignored) {
                // 极端情况：getClass 也失败（类加载已在关闭）。仍尝试记录，origin 留空。
                origin = "";
            }
            BootstrapBridge.recordSinkOutcome(origin, thrown);
        } catch (Throwable ignored) {
            // fail-open：采集失败 = 证据缺失，后端不得据此做阴性裁决
        }
    }
}
