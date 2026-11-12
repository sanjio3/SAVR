package io.netty.handler.codec.http;

/**
 * Test-only stub for the Netty {@code HttpRequest}. The installer matches
 * {@code hasSuperType(named("io.netty.handler.codec.http.HttpRequest"))} on
 * {@code uri}/{@code headers}/{@code toString} as reactive sources.
 */
public class HttpRequest {
    public Object uri() {
        return "http://netty.example/request";
    }

    public Object headers() {
        return "netty-headers";
    }

    @Override
    public String toString() {
        return "netty-http-request";
    }
}
