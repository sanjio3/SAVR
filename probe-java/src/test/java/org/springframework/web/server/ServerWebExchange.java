package org.springframework.web.server;

/**
 * Test-only stub standing in for the WebFlux {@code ServerWebExchange} so the reactive
 * source hooks can be exercised without the real Spring WebFlux runtime on the classpath.
 * The method names mirror the installer's matcher (getQueryParams/getHeaders/getFormData/
 * queryParams/headers/pathVariables) and return a non-null object the source advice taints.
 */
public class ServerWebExchange {
    public Object getQueryParams() {
        return "webflux-query-params";
    }

    public Object getHeaders() {
        return "webflux-headers";
    }

    public Object getFormData() {
        return "webflux-form-data";
    }

    public Object queryParams() {
        return "webflux-query-params-method";
    }

    public Object headers() {
        return "webflux-headers-method";
    }

    public Object pathVariables() {
        return "webflux-path-variables";
    }
}
