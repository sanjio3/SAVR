# tools

该目录用于放置可被 Agent 直接调用的外部工具。

## 本仓库不携带这些文件

本仓库**不携带**下列第三方二进制与外部探测脚本，也不把它们放进版本库：

- `tools/ysoserial-all.jar` —— 第三方二进制，体积大且有独立再分发许可。
- `tools/exploits/*.py`、`tools/java/*.java`、`tools/payloads/**` —— 族级验证器、payload 生成器与 payload 模板，属于本地部署时另行放置的工具集。
- `tools/burpsuite/`、`tools/nuclei/`、`tools/sqlmap/` —— 第三方工具。

获取第三方二进制用仓库内脚本，它会从各项目官方发布页下载并打印 SHA256：

```bash
python scripts/fetch_tools.py --dest /opt/SAVR-tools
export SAST_AI_TOOLS_DIR=/opt/SAVR-tools
```

Windows 下用 `set SAST_AI_TOOLS_DIR=D:/SAVR-tools`。

工具缺失时**不会阻断流程**，行为由 `src/core/tool_paths.py` 保证：

- ysoserial 缺失：反序列化 payload 只输出生成指令，不伪造 payload。
- nuclei / ffuf / feroxbuster 缺失：返回 `None`，调用方按 skipped 处理。

## 目录约定

第三方工具统一放在这里，不要散落到仓库根目录：

- `tools/ysoserial-all.jar`
- `tools/burpsuite/`
- `tools/nuclei/`
- `tools/sqlmap/`
- `tools/exploits/`
- `tools/java/`
- `tools/python/`
- `tools/payloads/`

需要 Java/JAR 的工具优先保留原始文件名，代码里统一从 `tools/` 解析。工具需要额外配置时，在同名子目录下放 `README.md` 或示例配置。

## 扩展方向

- `tools/exploits/` —— 漏洞族级验证器，例如 `java_*_ssti.py`、`python_*_ssti.py`、`node_*_probe.py`、`xxe_probe.py`。
- `tools/java/` —— Java 辅助类、payload 生成器、编译后的辅助依赖。
- `tools/python/` —— Python 侧的模板与探测脚本公共模块。
- `tools/payloads/` —— 按漏洞族分类的 payload 模板库，例如 `ssti/`、`xss/`、`xml/`。

## XML / XXE / XPath 工具族约定

- `tools/exploits/generic_xml_probe.py` —— 支持 GET/POST/PUT；支持 body / param / json / header；支持 `--header` 附加请求头和 `--expected-regex`。
- `tools/exploits/generic_xpath_probe.py` —— 支持 param / json / header；内置 baseline -> attack 对比结果，便于跨语言复用。
- `tools/payloads/xml/` 与 `tools/payloads/xpath/` —— 放公共 payload 模板，后续 Java / Python / PHP / Node 直接复用。
