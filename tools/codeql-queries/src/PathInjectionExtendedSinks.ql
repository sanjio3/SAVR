/**
 * @name 路径注入（扩展形态：new File(File, String) / Paths.get）
 * @description 远程可控数据流入两参 File 构造器或 Paths.get。
 *              官方 TaintedPath 主要覆盖单参拼接形态，对 File(File,String) 与 Paths.get 覆盖不足。
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id sastai/java/path-injection-extended
 * @tags security
 *       external/cwe/cwe-022
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import SastAiSinks
import PathInjectionExtendedFlow::PathGraph

module PathInjectionExtendedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) { isPathSinkExpr(sink.asExpr()) }
}

module PathInjectionExtendedFlow = TaintTracking::Global<PathInjectionExtendedConfig>;

from PathInjectionExtendedFlow::PathNode source, PathInjectionExtendedFlow::PathNode sink
where PathInjectionExtendedFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SAVR 扩展：远程输入流入文件路径构造（File(File,String) / Paths.get）。"
