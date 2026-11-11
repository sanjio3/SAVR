package org.elasticsearch.client;

/**
 * Test-only stub for the low-level Elasticsearch {@code RestClient}. The installer matches
 * {@code performRequest}/{@code performRequestAsync} as sinks.
 */
public class RestClient {
    public Object performRequest(Object... args) {
        return null;
    }

    public Object performRequestAsync(Object... args) {
        return null;
    }
}
