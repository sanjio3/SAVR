package org.elasticsearch.client;

/**
 * Test-only stub for the Elasticsearch {@code RestHighLevelClient}. The installer matches
 * {@code search}/{@code msearch}/{@code searchAsync}/{@code index}/{@code update}/
 * {@code delete}/{@code bulk} as sinks.
 */
public class RestHighLevelClient {
    public Object search(Object... args) {
        return null;
    }

    public Object msearch(Object... args) {
        return null;
    }

    public Object searchAsync(Object... args) {
        return null;
    }

    public Object index(Object... args) {
        return null;
    }

    public Object update(Object... args) {
        return null;
    }

    public Object delete(Object... args) {
        return null;
    }

    public Object bulk(Object... args) {
        return null;
    }
}
