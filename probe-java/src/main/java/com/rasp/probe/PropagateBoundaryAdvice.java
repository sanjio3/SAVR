package com.rasp.probe;

import net.bytebuddy.asm.Advice;

import java.nio.charset.StandardCharsets;

/**
 * 类型边界传播 (F2 修复) —— 构造器形态。
 *
 * <p>被污染 String 经载体类 (StringReader / ByteArrayInputStream / File / URL / InputSource)
 * 构造后，原 String 内容在载体里取不到 (toString 只剩 class@hash)，导致 sink 处 canary
 * 现场断言在「String -> 载体」边界丢失，XXE / 路径穿越 / 文件上传等族永远 no-arrival。
 * 本 advice 在构造完成时刻把源内容按载体身份登记进 TaintHub.CARRIER_CONTENT，
 * 由 HookRuntime.sample() 在 sink 处兜底回收。静态工厂形态（Paths.get）见
 * {@link PropagateBoundaryStaticAdvice}。
 *
 * <p>历史坑（2026-09-14，禁回退）：本类曾同时含 onCtor 与 onStatic 两个 {@code @OnMethodExit}，
 * 被整体绑定到一个匹配器时 ByteBuddy 1.15.11 抛
 * {@code IllegalStateException: Duplicate advice for Delegate to ...onCtor(...) and ...onStatic(...)}，
 * 六个边界类整类插桩失败（watchdog 日志累计 152 次 failed-open）。
 * 第一次拆分把共享逻辑抽到新增类 {@code BoundaryTaintSupport}，结果更糟：bootstrap 域解析不到
 * 该新增类，java.lang.Class / ClassLoader / Method / Field / Thread / Executor* 等一批原本能
 * 插桩的 java.base 类全部 NoClassDefFoundError（9945 次），应用起不来。
 *
 * <p><b>真正的根因（2026-09-14 定位，前两次结论都是错的，禁回退）</b>：不是「advice 不能有两个
 * 方法」也不是「不能引用新增类」，而是 <b>advice 类没有登记到
 * {@code ByteBuddyHookInstaller#injectBootstrapHelpers}</b>。ByteBuddy 把 advice 方法体内联进
 * java.base 目标类，内联后的字节码由 bootstrap 加载器解析，而 {@code sec-probe.jar} 只在 system
 * class path 上 —— bootstrap 看不见任何 {@code com.rasp.probe.*}（除手工挂上去的
 * {@code sec-probe-bootstrap.jar} 里的 TaintHub，以及 injectBootstrapHelpers 显式注入的类）。
 * 因此：只要目标含 java.base 类型，用到的每个 advice/辅助类都必须在那里登记一次；
 * 登记后新增辅助类、拆几个类都无所谓。
 */
public final class PropagateBoundaryAdvice {
    private static final int MAX_DECODE = 4096;
    private static final int MIN = 3;

    private PropagateBoundaryAdvice() {
    }

    /**
     * 构造器形态。注意匹配器必须排除零参构造器：本 advice 读 {@code @Advice.Argument(0)}，
     * 而 java.nio.file.Paths 有一个 private 无参构造器，匹配上去会抛
     * "private java.nio.file.Paths() does not define an index 0"，进而污染 advice 类、
     * 导致 java.lang.Class / ClassLoader / Method / Field / Thread / Executor* 等一批
     * java.base 类 NoClassDefFoundError（实测 9945 次，应用起不来）。
     */
    @Advice.OnMethodExit
    public static void onCtor(@Advice.Origin("#t.#m") String origin,
                              @Advice.This Object self, @Advice.Argument(0) Object src) {
        if (self == null || src == null) {
            return;
        }
        propagate(self, src, origin);
    }

    /** 必须 public static：会被内联进 bootstrap 类，私有方法触发 IllegalAccessError。 */
    public static void propagate(Object carrier, Object src, String origin) {
        if (!TaintStore.isRequestTainted()) {
            return;
        }
        String content = extractContent(src);
        if (content == null || content.length() < MIN) {
            return;
        }
        // 源本身被标记 (high/low) 或源内容命中已登记的污点源值 (子串包含) → 边界继承
        if (TaintStore.isTainted(src) || TaintStore.isContentTainted(content)) {
            TaintStore.recordCarrierContent(carrier, content);
            TaintStore.markHigh(carrier);
        }
        TaintStore.recordTaintHop("transform", origin);
    }

    /** 从 String / byte[] / char[] / 已登记载体中取出可比较的文本内容。 */
    public static String extractContent(Object src) {
        try {
            if (src instanceof String) {
                return (String) src;
            }
            if (src instanceof byte[]) {
                byte[] b = (byte[]) src;
                if (b.length == 0 || b.length > MAX_DECODE) {
                    return null;
                }
                return new String(b, StandardCharsets.UTF_8);
            }
            if (src instanceof char[]) {
                char[] c = (char[]) src;
                if (c.length == 0 || c.length > MAX_DECODE) {
                    return null;
                }
                return new String(c);
            }
            // 源本身已是载体 (如 StringReader 被包进 InputSource)：复用其已登记内容
            return TaintStore.peekCarrierContent(src);
        } catch (Throwable ignored) {
            return null;
        }
    }
}
