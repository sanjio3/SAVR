package redis.clients.jedis;

/**
 * Test-only stub for the Jedis client. The installer matches
 * {@code eval}/{@code evalSha}/{@code evalRead}/{@code evalWrite} as sinks (Lua injection).
 */
public class Jedis {
    public Object eval(Object... args) {
        return null;
    }

    public Object evalSha(Object... args) {
        return null;
    }

    public Object evalRead(Object... args) {
        return null;
    }

    public Object evalWrite(Object... args) {
        return null;
    }
}
