package org.apache.dubbo.rpc;

/**
 * Test-only stub for the Dubbo {@code Invoker} interface. The installer matches
 * {@code hasSuperType(named("org.apache.dubbo.rpc.Invoker"))} on {@code invoke(Invocation)}
 * as a sink and {@code org.apache.dubbo.rpc.Result#getValue} as a source.
 */
public interface Invoker {
    Result invoke(Invocation invocation);
}
