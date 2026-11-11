"""
Unified A1 facade (重构后：注入类走 CodeQL + AI 语义整合，业务逻辑类由 A1BusinessLogicAIAgent 处理)。

原 ``A1Agent`` / ``A1RuleAgent``（自写 yaml 正则引擎，src/agents/a1_intelligent_agent.py）已删除。
注入类主链路改为 ``CodeQLAdapter`` 做数据流 + ``A1CodeQLSemanticAgent`` 做 AI 语义整合；
业务逻辑类主链路改为 ``A1BusinessLogicAIAgent``（LLM 语义识别）。

本类保留 ``A1Agent`` 命名以满足历史导出与契约（src/agents/__init__.py、test_runtime_contract.py），
并作为 A1 注入类能力的一个可用入口；阶段级编排请优先用 ``src.pipeline.a1.service.A1PipelineService``。
"""
from typing import Dict, Optional

from .a1_codeql_semantic_agent import A1CodeQLSemanticAgent


class A1Agent(A1CodeQLSemanticAgent):
    """A1 阶段统一门面/兼容名。注入类 = CodeQL 数据流 + AI 语义整合。"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
