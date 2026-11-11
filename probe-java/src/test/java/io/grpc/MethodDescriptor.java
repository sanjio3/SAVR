package io.grpc;

import java.io.InputStream;

/**
 * Test-only stub for the gRPC {@code MethodDescriptor.Marshaller}. The installer matches
 * {@code hasSuperType(named("io.grpc.MethodDescriptor$Marshaller"))} on {@code parse(InputStream)}
 * (source, inbound request) and {@code stream} (sink, outbound response).
 */
public class MethodDescriptor {
    public interface Marshaller<T> {
        Object parse(InputStream inputStream);

        Object stream(Object value);
    }
}
