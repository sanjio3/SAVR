package com.rasp.probe;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 回归测试：污点容器锁序反转导致的全站假死。
 *
 * <p>事故（2026-09-13，java-sec-code 靶场 run 27）：探针自身对 {@code java.lang.String} /
 * {@code java.io.File} 的插桩，会在 WeakHashMap 计算 {@code key.hashCode()} 期间被同步触发，
 * 重入 {@link TaintHub#markFrom}/{@link TaintHub#markHigh}。修复前 HIGH 与 LOW 各自持一把
 * {@code Collections.synchronizedMap} 监视器，于是：
 * <ul>
 *   <li>线程 A 在 {@code HIGH.put} 内（持有 HIGH）触发回调 → markFrom → 申请 LOW；</li>
 *   <li>线程 B 在 {@code LOW.put} 内（持有 LOW）触发回调 → markFrom → 申请 HIGH；</li>
 * </ul>
 * 形成 ABBA 环路等待，166 个 Tomcat 工作线程永久 BLOCKED，应用假死。
 *
 * <p>修复后所有容器共用唯一监视器（同线程可重入），且在容器操作粒度置位重入短路，
 * 因此既不会成环，也不会出现自插桩递归。本测试即固化该保证。
 */
class TaintHubConcurrencyTest {

    /** 工作线程数：一半走 markHigh（先把 HIGH 拿在手里），一半走 markLow（先拿 LOW）。 */
    private static final int WORKERS = 16;

    /** 每线程迭代次数：足够多次交错以暴露锁序反转，又不至于拖慢构建。 */
    private static final int ITERATIONS = 200;

    /**
     * 模拟「哈希计算期间触发探针回调」的键：WeakHashMap 在 {@code hashCode()} 里回探针。
     * 这正是被插桩的 {@code String.hashCode()/toLowerCase()} 在真实场景下造成的重入。
     */
    private static final class ReentrantKey {
        private final int id;

        ReentrantKey(int id) {
            this.id = id;
        }

        @Override
        public int hashCode() {
            // 重入：读取 + 写入另一个置信度容器。修复前此处会申请对方 map 的监视器。
            TaintHub.markFrom(new ReentrantKey(-id), new ReentrantKey(id));
            TaintHub.markHigh(new ReentrantKey(id + 1_000_000));
            return id;
        }

        @Override
        public boolean equals(Object other) {
            return other == this;
        }
    }

    @Test
    void concurrentMarkingMustNotDeadlock() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            ExecutorService pool = Executors.newFixedThreadPool(WORKERS);
            try {
                List<Callable<Void>> jobs = new ArrayList<>();
                for (int w = 0; w < WORKERS; w++) {
                    final boolean high = (w % 2) == 0;
                    final int seed = w;
                    jobs.add(() -> {
                        for (int i = 0; i < ITERATIONS; i++) {
                            ReentrantKey key = new ReentrantKey(seed * 1_000_000 + i);
                            if (high) {
                                TaintHub.markHigh(key);
                            } else {
                                TaintHub.markLow(key);
                            }
                            // 顺带覆盖查询与推导路径，确保它们同样不参与锁序反转。
                            TaintHub.isTainted(key);
                            TaintHub.markFrom(new ReentrantKey(-key.hashCode()), key);
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
        }, "并发标记出现锁序反转（ABBA 死锁）——容器必须共用唯一监视器");
    }

    @Test
    void reentrantHashMustNotRecurseUnbounded() {
        // 自插桩递归若未被闸门截断，会以 StackOverflowError 结束。
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            ReentrantKey key = new ReentrantKey(7);
            TaintHub.markHigh(key);
            assertTrue(TaintHub.isHigh(key), "闸门只应拦重入，不应拦正常标记");
        }, "哈希计算期间的重入未被闸门截断");
    }
}
