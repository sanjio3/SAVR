package com.rasp.probe;

import net.bytebuddy.asm.Advice;

/**
 * 参数化查询感知 — 模板登记边 (手册 11.1.5 一).
 *
 * <p>{@code Connection.prepareStatement(sql)} / {@code prepareCall(sql)}: records the SQL
 * TEMPLATE against the returned statement, together with whether the template itself carries
 * taint. That bit is the whole point of parameterized-query awareness:
 *
 * <ul>
 *   <li>A tainted template means the SQL text was concatenated from user input — a real
 *       injection, blockable at execution.</li>
 *   <li>A clean template with tainted parameters is a correctly-written query: the driver
 *       binds the value, so {@code ' OR 1=1--} arriving as a parameter is inert. Without this
 *       distinction the L1 signature engine sees the payload in the parameter list and blocks
 *       a perfectly safe application — the single largest source of RASP false positives.</li>
 * </ul>
 *
 * <p>Application-classloader type (the concrete {@code Connection} impl is the pool/driver
 * class), so it uses the default injection strategy like the other JDBC hooks.
 *
 * <p>2026-09-27 补充（③类A 缺陷修复）：{@code prepareCall}/{@code prepareStatement} 的 SQL 模板
 * 作为实参在方法入口即可见，与 {@code SqlSinkAdvice} 处理 {@code execute(String)} 同理。新增
 * {@link #onEnter} 在「准备」阶段即对模板做平台 canary 断言——覆盖 execute* 永远不被执行的场景
 * （如 HSQLDB 在 prepareCall 阶段就拒绝 "{call <payload>}" 这种非法存储过程调用语法，导致
 * PreparedStatement/CallableStatement.executeQuery 从未被调用、onPreparedSink 永不触发，运行时
 * 恒为 no-arrival）。准备阶段命中 canary 即视为攻击流量抵达 SQL 编译 sink，按 sink-reached 闭环。
 */
public final class PrepareStatementAdvice {

    private PrepareStatementAdvice() {
    }

    /**
     * 准备阶段 canary 断言：SQL 模板实参里含平台 canary（D1 注入的 s4st41<16hex>）即证明攻击者
     * 可控数据确证拼进了 SQL 命令，按 sink-reached 上报。仅对带 canary 的重放流量生效，普通业务
     * 流量（currentCanary 为空）完全不进入此分支，无误报风险；fail-open 不影响业务。
     */
    @Advice.OnMethodEnter
    public static void onEnter(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object sql) {
        HookRuntime.onPrepareSqlCanary(origin, sql);
    }

    @Advice.OnMethodExit(suppress = Throwable.class)
    public static void onExit(@Advice.Origin("#t.#m") String origin, @Advice.Argument(0) Object sql, @Advice.Return Object statement) {
        HookRuntime.rememberPreparedSql(statement, sql);
        // ③类A 闭环（2026-09-27 二次接线）：prepareCall/prepareStatement 阶段即断言 sink-reached，
        // 不等 execute*。覆盖「HSQLDB 在 prepareCall 阶段拒非法 CALL 语法致 executeQuery 永不执行、
        // onPreparedSink 永不触发」的 02170 类 0 到达根因。仅对带平台 canary 的重放流量生效，无误报。
        HookRuntime.onPrepareSqlCanary(origin, sql);
    }
}
