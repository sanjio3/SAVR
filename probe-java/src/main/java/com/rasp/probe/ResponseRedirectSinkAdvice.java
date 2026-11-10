package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * 响应头写入 / 跳转 sink 织入点。
 *
 * <p>覆盖三类 sink：
 *
 *   - HttpServletResponse.sendRedirect(String location)
 *   - HttpServletResponse.setHeader(String name, String value)
 *   - HttpServletResponse.addHeader(String name, String value)
 *
 * <p><b>2026-09-22 修正（原实现漏覆盖 CRLF / CORS 类响应头族）</b>：原实现对
 * setHeader/addHeader 加了「仅当 name==Location」的闸门，理由是「避免对所有响应头做无谓断言」。
 * 该闸门把整族「把用户可控值写进非 Location 响应头」的漏洞从 IAST 视野里剔除了，实测两处硬证据：
 *
 *   1. CRLF（java-sec-code <code>/crlf/safecode</code>）：端点实现是
 *      <code>response.addHeader("test1", request.getParameter("test1"))</code>；
 *      用带会话的 curl 回放，响应头确实出现 <code>test1: &lt;注入值&gt;</code>，
 *      但本 advice 因 name != Location 不断言 → 该 spec 永远 0 事件（no-arrival）。
 *   2. CORS（<code>/cors/vuln/origin</code>）：sink 是
 *      <code>Response.setHeader("Access-Control-Allow-Origin", &lt;Origin 值&gt;)</code>，
 *      同样是非 Location 头 → 同样落空。
 *
 * <p>去掉闸门不会引入误报：真正的断言过滤在 {@code HookRuntime.onGenericSink} 内部 ——
 * 它要求本次请求携带平台 canary（重放头 X-SASTAI-Trace → CURRENT_CANARY）才断言，
 * 且带自指防护（isSelfOriginated）。普通业务流量没有 canary，即使命中本 advice
 * 也只会走到「无 canary 则不断言」分支。此处仅把「疑似 sink」交给统一闸门判定，
 * 判定权不再由本类以头名硬编码承担。
 */
public final class ResponseRedirectSinkAdvice {
    private ResponseRedirectSinkAdvice() {
    }

    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.AllArguments Object[] args) {
        if (args == null || args.length == 0) {
            return;
        }
        if (origin.endsWith("sendRedirect")) {
            if (args.length >= 1) {
                BootstrapBridge.onGenericSink("javax.servlet.http.HttpServletResponse.sendRedirect", new Object[]{args[0]});
            }
            return;
        }
        // setHeader / addHeader：头名与头值都交给 onGenericSink 统一判定
        // （头名一并入参，便于后端按 sink 细粒度统计，也为将来「哪些响应头算敏感」留出空间）。
        if ((origin.endsWith("setHeader") || origin.endsWith("addHeader")) && args.length >= 2) {
            BootstrapBridge.onGenericSink(origin, new Object[]{args[0], args[1]});
        }
    }
}
