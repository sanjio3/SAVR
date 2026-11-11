/** SAVR 自定义 sink 建模（叠加在官方 java-queries 之上，不改平台主逻辑）。
 *
 * 只补官方查询「没建模到的特殊形态」，不重复官方已覆盖的经典形态：
 * - SQL：Connection.prepareCall(...)、Spring JdbcTemplate/NamedParameterJdbcTemplate 包装
 * - 命令：Runtime.exec 的数组/多参重载、new ProcessBuilder(...)
 * - 路径：new File(File, String)、Paths.get(...)
 * - 格式化：String.format / PrintStream.printf / PrintWriter.format / Formatter.format
 *
 * 注意：CodeQL java-all 7.x 起 MethodAccess 已改名 MethodCall，
 * 构造器调用用 ClassInstanceExpr（而非旧版的 ConstructorCall 判定写法）。
 */

import java

/** SQL 侧特殊形态 sink。 */
predicate isSqlSinkExpr(Expr e) {
  exists(MethodCall mc |
    // sink 必须是**接收污点的实参**，不能是整个 MethodCall——
    // 数据流节点里调用节点代表「返回值」，taint 流入实参不会到达调用节点
    // ⇒ 之前用 mc 当 sink 的形态全都查不出结果（probe 实测 0 条）。改为 arg0。
    // 注：曾尝试追加 Connection.prepareStatement(sql, int[]/String[]) 自动主键重载
    // 以救 01003，但该形态在 Benchmark 上会带出 83 个真值 false 候选（ESAPI 净化
    // 未被官方 Sanitizers 建模），+1 TP 不抵风险，已放弃；待做带屏障的专用查询。
    (mc.getMethod().hasName("prepareCall") and e = mc.getArgument(0))
    or
    // Spring JdbcTemplate 包装（含 NamedParameterJdbcTemplate）
    (
      (
        mc.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate")
        or
        mc.getMethod()
            .getDeclaringType()
            .hasQualifiedName("org.springframework.jdbc.core.namedparam", "NamedParameterJdbcTemplate")
      ) and
      mc.getMethod().getName() in [
          "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet",
          "queryForInt", "queryForLong", "update", "execute", "batchUpdate"
        ] and
      e = mc.getArgument(0)
    )
  )
}

/** 命令执行侧特殊形态 sink。 */
predicate isCommandSinkExpr(Expr e) {
  exists(MethodCall mc | mc = e |
    // exec(String[]) 等数组/多参重载，官方主要建模 exec(String)
    mc.getMethod().hasName("exec") and
    (
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") or
      mc.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.exec", "CommandLine")
    )
  )
  or
  exists(ClassInstanceExpr cie | cie = e |
    cie.getConstructedType().hasQualifiedName("java.lang", "ProcessBuilder")
  )
}

/** 路径侧特殊形态 sink。 */
predicate isPathSinkExpr(Expr e) {
  exists(ClassInstanceExpr cie | cie = e |
    cie.getConstructedType().hasQualifiedName("java.io", "File") and
    // 两参形态：new File(File parent, String child) —— 官方对单参拼接覆盖较好
    exists(cie.getArgument(1))
  )
  or
  exists(MethodCall mc | mc = e | mc.getMethod().hasQualifiedName("java.nio.file", "Paths", "get"))
}

/** 格式化串 sink（printf/format），官方 java-queries 无对应查询。 */
predicate isFormatSinkExpr(Expr e) {
  exists(MethodCall mc | mc = e |
    mc.getMethod().getName() in ["printf", "format"] and
    (
      mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") or
      mc.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintStream") or
      mc.getMethod().getDeclaringType().hasQualifiedName("java.io", "PrintWriter") or
      mc.getMethod().getDeclaringType().hasQualifiedName("java.util", "Formatter")
    )
  )
}
