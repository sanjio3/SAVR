package com.rasp.probe;

import net.bytebuddy.asm.Advice;

public final class ServletServiceAdvice {
    private ServletServiceAdvice() {
    }

    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void onEnter(@Advice.Argument(0) Object request) {
        // 入口即抽取平台 canary（X-SASTAI-Trace 头里的 s4st41<16hex> 身份段），供本次请求生命周期内
        // 的授权盲点判定（reportBolaSuspect）回带，使后端能按 canary 关联回本次重放。
        HookRuntime.setCurrentCanary(HookRuntime.extractCanaryFromRequest(request));
        HookRuntime.enterRequest();
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void onExit() {
        HookRuntime.exitRequest();
    }
}
