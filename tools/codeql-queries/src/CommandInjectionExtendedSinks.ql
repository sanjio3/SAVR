/**
 * @name 命令注入（扩展形态：exec(String[]) / ProcessBuilder）
 * @description 远程可控数据流入 Runtime.exec 的数组/多参重载或 ProcessBuilder 构造器。
 *              官方 CommandInjection 只建模了 exec(String)。
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id sastai/java/command-injection-extended
 * @tags security
 *       external/cwe/cwe-078
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import SastAiSinks
import CommandInjectionExtendedFlow::PathGraph

module CommandInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { isCommandSinkExpr(sink.asExpr()) }
}

module CommandInjectionExtendedFlow = TaintTracking::Global<CommandInjectionExtendedConfig>;

from CommandInjectionExtendedFlow::PathNode source, CommandInjectionExtendedFlow::PathNode sink
where CommandInjectionExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SAVR 扩展：远程输入流入命令执行点（exec 重载 / ProcessBuilder）。"
