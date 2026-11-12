"""A1/A2 共享的分析结果数据类。

原先这些类型定义在 ``a1_intelligent_agent.A1RuleAgent`` 内部（自写 yaml 正则引擎），
重构后该引擎已删除（注入类统一走 CodeQL + AI 语义整合）。为避免 ``a2_intelligent_agent``
等模块依赖已删除的引擎，把 ``Confidence`` / ``CallGraphNode`` / ``AnalysisResult`` 抽到
本共享模块，供 A1 语义整合、A2 语义分析等复用。
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class Confidence(Enum):
    """漏洞置信度"""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class CallGraphNode:
    """调用图节点"""
    function_name: str
    line: int
    file: str
    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """分析结果（A1 注入类语义整合 / A2 语义分析共用）。"""
    vulnerabilities: List[Any] = field(default_factory=list)
    false_positives: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    confidence: Confidence = Confidence.MEDIUM
    reasoning: str = ""
