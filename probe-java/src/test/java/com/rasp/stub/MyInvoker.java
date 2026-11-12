package com.rasp.stub;

import org.apache.dubbo.rpc.Invocation;
import org.apache.dubbo.rpc.Invoker;
import org.apache.dubbo.rpc.Result;

/**
 * Verification stub for the Dubbo {@code Invoker} sink. Lives in a package that is NOT
 * ignored by {@code baseBuilder} (which ignores {@code com.rasp.probe.}), so the
 * agent actually transforms it and the {@code invoke(Invocation)} sink advice fires.
 */
public final class MyInvoker implements Invoker {
    @Override
    public Result invoke(Invocation invocation) {
        return new MyResult();
    }
}
