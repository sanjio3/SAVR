package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * SSRF sink advice for java.net.URL. The URL being opened is the receiver; its
 * toString carries the full request URL, which the RASP semantic engine inspects
 * for internal/metadata targets (e.g. 169.254.169.254) before the connection opens.
 */
public final class BootstrapUrlSinkAdvice {
    private BootstrapUrlSinkAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.This Object url) {
        BootstrapBridge.onGenericSink(origin, new Object[] {url});
    }
}
