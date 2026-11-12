package com.rasp.probe;

import net.bytebuddy.fixture.ForeignLazyKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 回归测试：第二次死锁（容器锁 ↔ JVM 内部锁）的防线。
 *
 * JVM 内部锁：
 * <pre>
 *   exec-3: 持 HUB_LOCK，等 jimage(SharedImageReader) 锁
 *     mapContainsKey → WeakHashMap.containsKey → key.hashCode
 *     → ByteBuddy 惰性 TypeDescription.hashCode → TypePool.doResolve
 *     → ClassFileLocator → ClassLoader.getResourceAsStream → BasicImageReader.findLocation
 *   exec-5: 持 jimage 锁，等 HUB_LOCK
 *     BasicImageReader.findLocation → ImageStringsReader.get → java.lang.String.<init>（被插桩）
 *     → TaintStore.markFrom → TaintHub.markFrom
 * </pre>
 * 实测 201 条线程 BLOCKED、166 条等同一把 HUB_LOCK，JVM 活着但端口拒绝连接、日志静默，
 * D2 整批 invalidated（189 条 spec）。
 *
 * <p>本测试固化「掐断这条边」的保证：**字节码框架 / 探针自身 / JVM 内部对象一律不得成为
 * 污点容器的 key，因此它们在持有 HUB_LOCK 期间不会被哈希**。
 */
class TaintHubForeignKeyTest {

    @BeforeEach
    void setUp() {
        ForeignLazyKey.reset();
    }

    @AfterEach
    void cleanup() {
        TaintStore.clearCurrentRequest();
    }

    @Test
    void foreignKeyMustNeverBeHashed() {
        ForeignLazyKey key = new ForeignLazyKey(42);

        TaintStore.markHigh(key);
        assertFalse(TaintStore.isHigh(key), "字节码框架对象不得进入污点容器");
        TaintStore.markLow(key);
        assertFalse(TaintStore.isLow(key), "字节码框架对象不得进入污点容器");
        TaintStore.markFrom(new ForeignLazyKey(43), key);
        TaintStore.unmark(key);

        assertEquals(0, ForeignLazyKey.HASH_CALLS.get(),
                "对外来 key 调 hashCode() 就等于「持 HUB_LOCK 去申请 JVM 内部锁」，必须在入容器前拦掉");
    }

    @Test
    void foreignKeyInsideArrayMustAlsoBeSkipped() {
        ForeignLazyKey[] foreign = {new ForeignLazyKey(1), new ForeignLazyKey(2)};
        Object[] plain = {"plain", foreign};

        TaintStore.markHigh(plain);

        assertEquals(0, ForeignLazyKey.HASH_CALLS.get(),
                "数组元素里的外来对象同样不得被哈希（Arrays.copyOf 的逐元素推导正是泄漏入口）");
    }

    @Test
    void legitimateKeysStillWork() {
        // 过滤器只能挡外来 key，不能把真实污点一起挡掉 —— 这是本改动的最大风险点。
        TaintStore.markHigh("tainted-value");
        assertTrue(TaintStore.isHigh("tainted-value"), "普通字符串必须照常标记");
        TaintStore.markFrom("derived", "tainted-value");
        assertTrue(TaintStore.isHigh("derived"), "普通字符串之间的推导必须照常生效");
    }

    @Test
    void concurrentForeignAndLegitimateMarkingMustNotDeadlock() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Callable<Void>> jobs = new ArrayList<>();
                for (int w = 0; w < 8; w++) {
                    final boolean foreign = (w % 2) == 0;
                    final int seed = w;
                    jobs.add(() -> {
                        for (int i = 0; i < 500; i++) {
                            if (foreign) {
                                TaintStore.markHigh(new ForeignLazyKey(seed * 10_000 + i));
                            } else {
                                TaintStore.markHigh("legit-" + seed + "-" + i);
                            }
                            TaintStore.isTainted("probe-" + i);
                        }
                        return null;
                    });
                }
                for (Future<Void> f : pool.invokeAll(jobs)) {
                    f.get();
                }
            } finally {
                pool.shutdownNow();
            }
        }, "外来 key 与正常 key 并发标记出现锁序反转");
    }
}
