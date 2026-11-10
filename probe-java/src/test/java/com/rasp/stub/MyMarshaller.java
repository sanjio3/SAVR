package com.rasp.stub;

import io.grpc.MethodDescriptor;

import java.io.InputStream;

/**
 * Verification stub for the gRPC {@code MethodDescriptor.Marshaller} wire boundary.
 * {@code parse(InputStream)} is the inbound source; {@code stream(Object)} is the outbound
 * sink. Lives outside the ignored {@code com.rasp.probe.} package so the agent
 * transforms it.
 */
public final class MyMarshaller implements MethodDescriptor.Marshaller<String> {
    @Override
    public Object parse(InputStream inputStream) {
        return "grpc-parsed-payload";
    }

    @Override
    public Object stream(Object value) {
        return null;
    }
}
