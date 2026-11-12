package org.springframework.data.redis.core;

/**
 * Test-only stub for Spring Data {@code RedisTemplate}. The installer matches
 * {@code execute}/{@code executePipelined}/{@code executeSession} as sinks (raw command exec).
 */
public class RedisTemplate {
    public Object execute(Object... args) {
        return null;
    }

    public Object executePipelined(Object... args) {
        return null;
    }

    public Object executeSession(Object... args) {
        return null;
    }
}
