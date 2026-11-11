/**
 * @name SQL 注入（扩展形态：prepareCall / JdbcTemplate 包装）
 * @description 远程可控数据流入 CallableStatement.prepareCall 或 Spring JdbcTemplate 系列包装方法。
 *              这两个形态官方 SqlInjection 查询未建模。
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id sastai/java/sql-injection-extended
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import SastAiSinks
import SqlInjectionExtendedFlow::PathGraph

module SqlInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { isSqlSinkExpr(sink.asExpr()) }
}

module SqlInjectionExtendedFlow = TaintTracking::Global<SqlInjectionExtendedConfig>;

from SqlInjectionExtendedFlow::PathNode source, SqlInjectionExtendedFlow::PathNode sink
where SqlInjectionExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SAVR 扩展：远程输入流入 SQL 执行点（prepareCall / JdbcTemplate 包装）。"
