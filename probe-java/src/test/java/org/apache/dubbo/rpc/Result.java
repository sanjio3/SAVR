package org.apache.dubbo.rpc;

/**
 * Test-only stub for the Dubbo {@code Result} interface. The installer marks
 * {@code getValue()} as a taint source (the deserialized RPC response).
 */
public interface Result {
    Object getValue();
}
