package com.rasp.stub;

import org.apache.dubbo.rpc.Result;

/**
 * Verification stub for the Dubbo {@code Result} source ({@code getValue} returns tainted
 * inbound deserialized data). Lives outside the ignored {@code com.rasp.probe.} package.
 */
public final class MyResult implements Result {
    @Override
    public Object getValue() {
        return "dubbo-result-payload";
    }
}
