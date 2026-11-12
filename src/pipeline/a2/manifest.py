from src.pipeline.stage_contract import StageManifest, StageSkill, StageTool


A2_MANIFEST = StageManifest(
    stage_name="a2",
    implementation="src.agents.a2_intelligent_agent.A2SemanticAgent",
    skills=(
        StageSkill(
            name="semantic-reasoning",
            responsibility="使用大模型做漏洞可达性、业务语义和调用链推理",
            implementation="src.agents.a2_intelligent_agent.A2SemanticAgent.scan_file",
        ),
        StageSkill(
            name="anchor-normalization",
            responsibility="将 AI 给出的模糊位置重锚到真实代码并做 canonical 去重",
            implementation="src.agents.a2_intelligent_agent.A2SemanticAgent._deduplicate_a2_vulnerabilities",
        ),
    ),
    tools=(
        StageTool(
            name="prompt-pack",
            responsibility="A2 语义分析提示词和输出约束",
            kind="config",
            path="src/prompts/audit_prompts.yaml",
        ),
        StageTool(
            name="llm-clients",
            responsibility="Qwen / Claude / Doubao / MiniMax 客户端",
            kind="external-api",
        ),
        StageTool(
            name="code-index",
            responsibility="跨文件调用链和入口点补充上下文",
            kind="internal",
        ),
    ),
)
