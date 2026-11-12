# skills

该目录用于放置项目本地技能（skills），用于补充 Agent 的项目知识、固定流程和工具用法。

建议结构：

- `skills/<skill-name>/SKILL.md`
- `skills/<skill-name>/references/`
- `skills/<skill-name>/scripts/`

示例：

- `skills/java-deser/SKILL.md`
- `skills/docker-debug/SKILL.md`
- `skills/d2-zero-audit/SKILL.md`

建议把以下内容沉淀成 skill：

- 常见漏洞类型的项目内利用链
- 本项目特有的 Docker / 端口 / 路由约定
- 反序列化、命令执行、路径穿越等固定验证流程
- 常用第三方工具的调用方式
