package io.netty.buffer;

/**
 * Test-only stub for the Netty {@code ByteBuf}. The installer matches
 * {@code named("io.netty.buffer.ByteBuf")} on {@code uri}/{@code headers}/{@code toString}
 * as reactive sources (toString is the reliably-present member).
 */
public class ByteBuf {
    @Override
    public String toString() {
        return "netty-byte-buf";
    }
}
