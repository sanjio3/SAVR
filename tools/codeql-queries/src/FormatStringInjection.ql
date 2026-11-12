/**
 * @name 格式化串受控（printf / format）
 * @description 远程可控数据作为格式化串（首个参数）流入 String.format / PrintStream.printf /
 *              PrintWriter.format / Formatter.format。可被 %s/%n 等占位符放大为信息泄露或
 *              日志注入，极端情况下触发拒绝服务。官方 java-queries 无对应查询。
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.3
 * @precision medium
 * @id sastai/java/format-string-controlled
 * @tags security
 *       external/cwe/cwe-134
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import SastAiSinks
import FormatStringFlow::PathGraph

module FormatStringConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { isFormatSinkExpr(sink.asExpr()) }
}

module FormatStringFlow = TaintTracking::Global<FormatStringConfig>;

from FormatStringFlow::PathNode source, FormatStringFlow::PathNode sink
where FormatStringFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SAVR 扩展：远程输入作为格式化串流入 printf/format。"
