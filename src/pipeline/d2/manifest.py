from src.pipeline.stage_contract import StageManifest, StageSkill, StageTool


D2_MANIFEST = StageManifest(
    stage_name="d2",
    implementation="src.agents.d2_facade.D2Agent",
    skills=(
        StageSkill(
            name="attack-planning",
            responsibility="根据漏洞族和业务语义生成验证策略与 payload 形态",
            implementation="src.agents.d2_planning.D2PlanningMixin",
        ),
        StageSkill(
            name="bundle-output",
            responsibility="把已验证结果整理成 POC、payload、exp 和结果包",
            implementation="src.agents.d2_bundle.D2BundleMixin",
        ),
    ),
    tools=(
        StageTool(
            name="runtime-endpoints",
            responsibility="D2 探测入口和默认健康检查路径",
            kind="config",
            path="src/config/runtime/endpoints.yaml",
        ),
        StageTool(
            name="exploit-scripts",
            responsibility="漏洞族专项 exploit / probe 脚本",
            kind="resource",
            path="src/pipeline/d2/resources/tools/exploits",
        ),
        StageTool(
            name="payload-templates",
            responsibility="XML/XPath 等 payload 模板",
            kind="resource",
            path="src/pipeline/d2/resources/tools/payloads",
        ),
        StageTool(
            name="java-helper",
            responsibility="Map 反序列化辅助生成器",
            kind="resource",
            path="src/pipeline/d2/resources/tools/java/MapDeserializationPayloadGenerator.java",
        ),
        StageTool(
            name="ysoserial",
            responsibility="Java 反序列化 gadget 生成依赖",
            kind="resource",
            path="src/pipeline/d2/resources/tools/ysoserial-all.jar",
        ),
        StageTool(
            name="docker-runtime",
            responsibility="容器构建、运行、清理和端口探测",
            kind="system",
        ),
    ),
)
