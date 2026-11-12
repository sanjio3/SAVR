package com.rasp.probe;

import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ModSecurity 双向激活闭环（探针侧）— 记录服务端下发的"关注会话",命中后探针对
 * 该会话做全量采样(跳过 SEC_MAX_SAMPLE_LENGTH 截断)。与会话标识即探针请求的
 * requestId(=TaintStore.currentRequestId)对齐。
 *
 * <p>热路径优化:全局 {@code anyWatched} 标志由集合大小同步,未被关注的请求走
 * {@link #isWatched} 时先读 volatile 标志短路,避免对非关注会话引入哈希查找。
 */
public final class WAFWatchStore {
    /** 探针本地的关注会话硬上限,防止服务端异常下发撑爆内存。 */
    public static final int MAX_WATCHED = 2048;

    private static final ConcurrentHashMap<String, Boolean> WATCHED = new ConcurrentHashMap<>();
    private static volatile boolean anyWatched = false;

    private WAFWatchStore() {
    }

    /** 接收心跳下发的 watchSessions 列表,整体替换(增量维护由服务端 TTL 负责)。 */
    public static void setWatched(List<String> sessions) {
        WATCHED.clear();
        if (sessions != null) {
            for (String session : sessions) {
                if (session != null && !session.isBlank() && WATCHED.size() < MAX_WATCHED) {
                    WATCHED.put(session, Boolean.TRUE);
                }
            }
        }
        anyWatched = !WATCHED.isEmpty();
    }

    /** 该会话是否被服务端标记为深采样关注。非关注会话热路径为单次 volatile 读。 */
    public static boolean isWatched(String requestId) {
        if (requestId == null || requestId.isBlank() || !anyWatched) {
            return false;
        }
        return WATCHED.containsKey(requestId);
    }

    /** 关注的会话数量 — 供 service 指标/降级观测。 */
    public static int size() {
        return WATCHED.size();
    }

    /** 测试清空。 */
    public static void reset() {
        WATCHED.clear();
        anyWatched = false;
    }

    /** 当前关注的会话快照 — 供诊断/测试断言。 */
    public static Set<String> snapshot() {
        return Set.copyOf(WATCHED.keySet());
    }
}