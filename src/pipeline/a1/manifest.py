from src.pipeline.stage_contract import StageManifest, StageSkill, StageTool


A1_MANIFEST = StageManifest(
    stage_name="a1",
    implementation="src.agents.a1_codeql_semantic_agent.A1CodeQLSemanticAgent",
    skills=(
        StageSkill(
            name="codeql-dataflow",
            responsibility="外接 CodeQL 做注入类数据流分析，产出 SARIF 告警（参数→危险 sink 是否经过校验）",
            implementation="src.agents.a1_codeql_adapter.CodeQLAdapter.scan",
        ),
        StageSkill(
            name="ai-semantic-integration",
            responsibility="对 CodeQL 告警做 AI 语义整合（去重/误报裁剪/业务上下文标注/HTTP 入口判定）",
            implementation="src.agents.a1_codeql_semantic_agent.A1CodeQLSemanticAgent.integrate",
        ),
        StageSkill(
            name="business-logic-ai",
            responsibility="业务逻辑漏洞 AI 语义识别（主链路：LLM 理解敏感操作+缺失控制点）",
            implementation="src.agents.a1_business_logic_ai_agent.A1BusinessLogicAIAgent.analyze_sources",
        ),
    ),
    tools=(
        StageTool(
            name="codeql-cli",
            responsibility="外接 CodeQL CLI 做多语言数据流分析",
            kind="external-binary",
        ),
        StageTool(
            name="model-gateway",
            responsibility="LLM 语义整合/识别（离线降级确定性映射）",
            kind="python-runtime",
        ),
    ),
)
