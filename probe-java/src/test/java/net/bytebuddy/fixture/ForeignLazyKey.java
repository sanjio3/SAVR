package net.bytebuddy.fixture;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * 测试替身：模拟 ByteBuddy 的惰性类型描述对象。
 *
 * <p>为什么放在 {@code net.bytebuddy.} 包下：{@link com.rasp.probe.TaintHub} 的 key 过滤器是
 * **包前缀**判定（见 FOREIGN_TAINT_KEY_PREFIXES），要验证「这类对象不得成为污点 key」就必须
 * 真的处在被过滤的包里。
 *
 * <p>行为要点：{@code hashCode} 会计数并回调探针 —— 真实场景里字节码框架对象的 hashCode
 * 会触发类型解析、读 JVM 模块镜像（jimage），从而在持有 HUB_LOCK 时去申请 JVM 内部锁。
 * 因此「hashCode 被调用过」就等于「这条死锁边成立」。
 */
public final class ForeignLazyKey {

    /** hashCode() 被调用的次数。修复正确时这个数必须保持 0。 */
    public static final AtomicInteger HASH_CALLS = new AtomicInteger();

    private final int id;

    public ForeignLazyKey(int id) {
        this.id = id;
    }

    public static void reset() {
        HASH_CALLS.set(0);
    }

    @Override
    public int hashCode() {
        HASH_CALLS.incrementAndGet();
        // 模拟「哈希计算期间回调进探针」
        com.rasp.probe.TaintHub.markHigh(new ForeignLazyKey(-id));
        return id;
    }

    @Override
    public boolean equals(Object other) {
        return other == this;
    }
}
