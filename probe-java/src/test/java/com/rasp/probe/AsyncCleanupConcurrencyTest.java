package com.rasp.probe;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发专项：跨线程/协程上下文清洁度（async 上下文与 requestId 归集清理）。
 *
 * <p>钉住四类必须在并发下成立的安全性质：
 * <ol>
 *   <li><b>池线程复用无污染</b>：同一个池线程先服务污点请求、再服务干净请求时，后者的污点态
 *       必须与前者完全隔离（restore 纪律，AsyncContext.Scope.leave + TaintStore.detachThread）。</li>
 *   <li><b>并发请求互不串扰</b>：N 个并发请求各自持有独立 shadow，任何线程的
 *       {@code liveRequestShadowCount} 不得越界（无泄漏）。</li>
 *   <li><b>异步包装正确扩散并还原</b>：AsyncContext.wrap 把污点 scope 带上池线程，
 *       任务结束后线程回到无污点态，脏值不残留给下个任务。</li>
 *   <li><b>Cleanup 后每线程态全清</b>：clearCurrentRequest 后线程的每个 ThreadLocal 维度
 *       （REQUEST_TAINTED / SOURCE_CONTENTS / TAINT_PATH / THREAD_RIDS / REQUEST_ID）均为空，
 *       复用线程不会把旧请求的任何痕迹带给新请求。</li>
 * </ol>
 */
class AsyncCleanupConcurrencyTest {

    @AfterEach
    void cleanup() {
        // 测试专用归集桶：产品设计中 detachThread 刻意不删源请求的共享 shadow（源请求线程还活着），
        // 因此凡在池线程/异步路径上 markHigh 过且未显式 clearRequest 的 rid 会残留全局表，
        // 副作用污染其它测试类（TaintSemanticsTest 断言 liveRequestShadowCount 绝对值）。
        // 这里把测试用到的所有 rid 显式清掉，保证"测试之间无静态态串扰"。
        TaintStore.clearRequest("req-dirty");
        TaintStore.clearRequest("req-clean");
        TaintStore.clearRequest("req-async");
        TaintStore.clearRequest("req-cf");
        TaintStore.clearCurrentRequest();
    }

    // ---- 1. 池线程复用：污点请求不污染下一个干净请求 ----

    @Test
    void pooledThreadReuseDoesNotBleedIntoNextRequest() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            // 第一个请求：带污点，走完整生命周期。
            TaintStore.bindRequest("req-dirty");
            TaintStore.markHigh("secret-token-A");
            TaintStore.detachThread(); // 模拟请求处理完，线程归还池

            // 第二个请求（可能复用同一池线程）：必须完全干净。
            TaintStore.bindRequest("req-clean");
            assertFalse(TaintStore.isRequestTainted(), "复用线程不得继承上一请求的污点标志");
            assertFalse(TaintStore.isContentTainted("prefix secret-token-A suffix"),
                    "上一请求的 content shadow 不得泄漏到复用线程");
            TaintStore.clearCurrentRequest();

            // 异步路径：污点请求在池线程上跑任务，任务结束线程还原。
            TaintStore.bindRequest("req-async");
            TaintStore.markHigh("job-secret");
            AtomicBoolean onPoolThreadSawTaint = new AtomicBoolean(false);
            AtomicBoolean afterTaskClean = new AtomicBoolean(true);
            CountDownLatch latch = new CountDownLatch(1);
            Runnable task = AsyncContext.wrap(() -> {
                onPoolThreadSawTaint.set(TaintStore.isContentTainted("job-secret-here"));
            });
            pool.submit(() -> {
                task.run();
                // 任务结束后，池线程应回到"未绑定任何请求"的干净态。
                afterTaskClean.set(!TaintStore.isRequestTainted()
                        && !TaintStore.isContentTainted("job-secret-here"));
                latch.countDown();
            });
            assertTrue(latch.await(5, TimeUnit.SECONDS), "pool task never ran");
            assertTrue(onPoolThreadSawTaint.get(), "async wrapper must carry the taint scope");
            assertTrue(afterTaskClean.get(), "pool thread must be restored clean after the wrapped task (十.9)");
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- 2. 并发请求互不串扰、shadow 无泄漏 ----

    @Test
    void concurrentRequestsDoNotCrossTaintAndShadowStaysBounded() throws Exception {
        int requests = 200;
        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch done = new CountDownLatch(requests);
            AtomicInteger crossLeak = new AtomicInteger(0);

            for (int i = 0; i < requests; i++) {
                final int id = i;
                pool.submit(() -> {
                    try {
                        start.await();
                        String rid = "conc-req-" + id;
                        TaintStore.bindRequest(rid);
                        // 用可唯一辨识、彼此不构成子串的 token，避免子串包含判定误命中
                        // （如 old 的 "conc-secret-2" 是 "conc-secret-20" 的子串）。
                        String secret = "s|" + id + "|e";
                        TaintStore.markHigh(secret);
                        // 扫描其它请求的 secret：一旦命中即为跨请求泄漏。
                        for (int j = 0; j < requests; j++) {
                            if (j == id) {
                                continue;
                            }
                            if (TaintStore.isContentTainted("payload s|" + j + "|e tail")) {
                                crossLeak.incrementAndGet();
                                break;
                            }
                        }
                        TaintStore.clearCurrentRequest();
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS), "concurrent requests timed out");
            assertEquals(0, crossLeak.get(), "a request must never see another concurrent request's taint");
            // 全部请求已 clearCurrentRequest，全局 shadow 应归零（无 4096 上限泄漏）。
            assertEquals(0, TaintStore.liveRequestShadowCount(),
                    "after all requests exit, no request shadow may leak in the global table");
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- 3. CompletableFuture 链式异步：关联任务扩散与还原 ----

    @Test
    void completableFutureChainPropagatesAndRestoresScope() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            TaintStore.bindRequest("req-cf");
            TaintStore.markHigh("cf-chain-secret");
            AtomicBoolean stageSawTaint = new AtomicBoolean(false);
            AtomicBoolean afterChainClean = new AtomicBoolean(true);

            CompletableFuture<Integer> future = CompletableFuture
                    .supplyAsync(AsyncContext.wrap((java.util.function.Supplier<Integer>) () -> {
                        stageSawTaint.set(TaintStore.isContentTainted("cf-chain-secret-eval"));
                        return 1;
                    }), pool)
                    .thenApplyAsync(AsyncContext.wrap(v -> v), pool);

            future.get(5, TimeUnit.SECONDS);
            assertTrue(stageSawTaint.get(), "supplyAsync on the pool must see the taint scope");
            // 链完成、clearCurrentRequest 后，池线程与主线程都应是干净的。
            TaintStore.clearCurrentRequest();
            pool.submit(() -> afterChainClean.set(!TaintStore.isRequestTainted()
                    && !TaintStore.isContentTainted("cf-chain-secret-eval"))).get(5, TimeUnit.SECONDS);
            assertTrue(afterChainClean.get(), "after the async chain, a reused pool thread stays clean");
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- 4. clearCurrentRequest 全维度清空（线程复用不残留 taint_path / rids）----

    @Test
    void cleanupClearsEveryThreadLocalDimension() {
        TaintStore.bindRequest("req-clear");
        TaintStore.markHigh("cleanup-secret");
        // 制造几条 taint 跳点与 rid 归集，验证清空后不残留。
        TaintStore.recordTaintHop("source", "javax.servlet.http.HttpServletRequest.getParameter");
        TaintStore.recordTaintHop("transform", "java.util.Base64$Decoder.decode");

        assertTrue(TaintStore.isRequestTainted());
        assertTrue(TaintStore.isContentTainted("cleanup-secret-x"));

        TaintStore.clearCurrentRequest();

        assertFalse(TaintStore.isRequestTainted(), "REQUEST_TAINTED must be cleared");
        assertFalse(TaintStore.isContentTainted("cleanup-secret-x"), "SOURCE_CONTENTS must be cleared");
        assertEquals("", TaintStore.taintPathJson(), "TAINT_PATH/THREAD_RIDS must be cleared on cleanup");
        assertEquals(0, TaintStore.liveRequestShadowCount(), "global shadow map must be empty after cleanup");
    }

    // ---- 5. 高并发热循环：线程复用下 shadow 总量稳定（长稳快照） ----

    @Test
    void highConcurrencyLoopKeepsShadowCountStable() throws Exception {
        int rounds = 50;
        int perRound = 20;
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (int r = 0; r < rounds; r++) {
                CountDownLatch done = new CountDownLatch(perRound);
                List<CompletableFuture<Void>> futures = new ArrayList<>();
                for (int i = 0; i < perRound; i++) {
                    final int id = r * perRound + i;
                    futures.add(CompletableFuture.supplyAsync(
                            AsyncContext.wrap((java.util.function.Supplier<Integer>) () -> {
                                String rid = "loop-" + id;
                                TaintStore.bindRequest(rid);
                                TaintStore.markHigh("loop-val-" + id);
                                // 触发归集读，模拟 sink 序列化跨线程路径。
                                boolean ignored = TaintStore.isContentTainted("loop-val-1");
                                TaintStore.clearCurrentRequest();
                                return id;
                            }), pool).thenAccept(i2 -> {
                                // 池线程复用：每个任务结束后都应把线程还回干净态
                                done.countDown();
                            }));
                }
                for (CompletableFuture<Void> f : futures) {
                    f.join();
                }
                done.await();
                // 每轮照完即清，全局 shadow 应始终 ≈ 0（不强依赖 GC，这里是显式 clear）。
                assertEquals(0, TaintStore.liveRequestShadowCount(),
                        "round " + r + ": no shadow may accumulate across the hot loop");
            }
        } finally {
            pool.shutdownNow();
        }
    }
}