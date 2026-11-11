<div align="center">

# SAVR

**S**can · **A**nalyze · **V**erify · **R**eplay（扫描 · 分析 · 验证 · 重放）

自动化白盒漏洞扫描与验证流水线：静态分析产生候选告警，大模型给出研判与机器可用的触发规格；
确定性重放对运行中的目标发起验证，告警是否成立仅由结构化危害证据判定。
模型不接触目标，验证过程确定、可复现、可审计。

[![CI](https://github.com/sanjio3/SAVR/actions/workflows/ci.yml/badge.svg)](https://github.com/sanjio3/SAVR/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Java](https://img.shields.io/badge/probe-JDK%2011%2B-orange.svg)](probe-java/)

[Releases](https://github.com/sanjio3/SAVR/releases) · [Issues](https://github.com/sanjio3/SAVR/issues) ·
[安全公告](https://github.com/sanjio3/SAVR/security/advisories)

[English](README.md) | 中文

</div>

---

## 扫描流程

```mermaid
flowchart LR
  subgraph S1["A1 · 静态分析"]
    A1["CodeQL 官方套件<br/>+ 自定义 .ql 查询<br/>+ 确定性启发式兜底"]
  end
  subgraph S2["A2 · LLM 分析"]
    A2["每个 sink 文件调一次<br/>→ 判定 + 机器可用的触发规格<br/>路由 / 参数 / 载荷 / 绕过"]
  end
  subgraph S3["D1 / D2 · 确定性重放"]
    D["构造请求并投出<br/>IAST 探针事件<br/>族级判据<br/>带外回调"]
  end
  S1 --> S2 --> S3
  S3 -->|"结构化危害证据"| YES["confirmed_exploitable"]
  S3 -->|"无证据"| NO["保留终态 + 失败归因<br/>绝不丢弃"]
  S2 -.->|"analysis_error 占位<br/>计入阶段契约"| NO
  I2["I2 · LLM 反馈闭环<br/>可选，默认关"] -.-> S3
```

- A1 跑 CodeQL 官方套件，加上针对官方查询不建模形态的自定义查询（`prepareCall`、Spring `JdbcTemplate`、弱哈希算法），并带一条确定性的启发式兜底，保证 CodeQL 建库失败不会静默产出一份空报告。
- A2 每个 sink 文件调一次 LLM，同时返回判定和机器可用的触发规格，经 JSON 校验并带一轮修复。失败的文件记为 `analysis_error` 占位并在阶段契约里计数，绝不丢弃——因为被丢掉的文件和本来就干净的文件，在最终报告里长得一模一样。
- D1/D2 执行重放。确认必须有结构化危害证据：sink 上的探针事件、族级判据（SQL 布尔对、路径穿越文件特征、表达式求值、反射），或带外回调。「到达 sink」和「模型说有害」这两者本身都不够。
- 未确认的候选保留终态与失败归因，因此「漏了一个漏洞」和「目标应用挂了」「端点在 404」「载荷没送到」可以区分开。
- 确定性重跑始终开启。I2 是一个根据重放差分重新判定的 LLM 反馈闭环，需要显式开启（`SAST_AI_CLOSED_LOOP=1`）。

---

## 环境要求

- Python 3.12+
- Node.js 20+（前端）
- JDK 11+ 与 Maven（构建 IAST 探针；探针是构建产物，不包含在仓库内）
- CodeQL CLI（静态分析阶段用）。`uv run python scripts/fetch_tools.py --dest tools --only codeql` 会把 bundle 解包到 `tools/codeql/`；也可以设 `CODEQL_BIN`，或把 `codeql` 放进 `PATH`。bundle 约 1GB，不入库。
- 本地 LLM，由 Ollama 提供（默认 `qwen3:8b`），或任何 OpenAI 兼容端点
- 一个运行中的 HTTP 目标应用，并挂载本项目自带的 IAST java agent。目标应用、JDK、Tomcat 与第三方二进制不在本仓库内分发，需要你自己提供

主开发平台是 Windows。Linux 与 macOS 理论可用但未实测。

---

## 安装

```bash
git clone https://github.com/sanjio3/SAVR.git && cd SAVR
uv sync --frozen --group dev
cp .env.example .env
uv run python scripts/fetch_tools.py --dest tools --only codeql
ollama pull qwen3:8b
```

按你的主机、端口和探针 token 改 `.env`。**SAVR 不会自动读取 `.env`**：要么像下面这样用 `uv run --env-file .env` 传入，要么在 shell 里 export 同样的变量。启动后端：

```bash
uv run --env-file .env python -m src.cli.service_server
```

`uv.lock` 锁定全部依赖，`pyproject.toml` 是权威声明。仓库根目录就是导入根，不需要安装成包。本文档里的命令统一用 `uv run`；把虚拟环境加进 `PATH` 后直接调 `python` 也可以。

后端监听 `127.0.0.1:8000`。前端单独跑：`cd frontend && npm ci && npm run dev`，监听 `127.0.0.1:5173`。Windows 下 `scripts/dev_all.ps1` 一次起两端，`scripts/dev_backend.ps1` 与 `scripts/dev_frontend.ps1` 分别起单个服务。

---

## 第一次运行

### 构建探针

IAST 探针是构建产物，不包含在仓库内；源码在 `probe-java/`。需要 JDK 11 与 Maven：

```bash
mvn -B -DskipTests -f probe-java/pom.xml clean package
jar cf probe-java/target/sec-probe-bootstrap.jar -C probe-java/target/classes com/rasp/probe/TaintHub.class
```

第一条产出 `sec-probe.jar`（探针主体），第二条产出 `sec-probe-bootstrap.jar`。后者只含
`TaintHub` 一个类，必须放进 `-Xbootclasspath/a`：探针要在 JDK 类加载器启动之前就能看到它，
否则 bootstrap 期的插桩拿不到共享状态。**两条命令都要跑，`mvn` 不会自动生成 bootstrap jar。**
构建前先停掉目标 JVM，否则 jar 被占用无法覆盖。

挂载参数如下（取自 `scripts/launch/launch_java_quote.py`，可直接照抄）：

```bash
java -Xbootclasspath/a:probe-java/target/sec-probe-bootstrap.jar \
     -javaagent:probe-java/target/sec-probe.jar \
     -Dsec.server.url=http://127.0.0.1:8000 \
     -Dsec.agent.id=<agent-id> \
     -Dsec.app.name=<app-name> \
     -Dsec.agent.token=<DB 里的 probe_token> \
     -Dsec.app.packages=<你的业务包前缀，如 com.example> \
     -Dsec.network.timeout.ms=5000 \
     -jar your-target.jar
```

四个必须对的点：

- `-Dsec.app.packages` 写**真实业务包前缀**。写错不会报错，只是零插桩、一个事件都没有，
  这是最常见的「扫描跑完了但什么都没发现」。
- `-Dsec.server.url` 用 `127.0.0.1` 而不是 `localhost`。后者在部分环境解析到 `::1`，
  而后端只监听 IPv4。
- `-Dsec.agent.token` 必须与数据库 `iast_sessions.probe_token` 一致。不一致时摄取接口
  返回 HTTP 200 且 `accepted=0`，看起来像成功。
- 探针只能在 JVM **启动前**挂载，不支持运行时 attach。

挂完先自检，`ready=true` 才算接上：

```bash
uv run python tools/probe_preflight.py --workspace-id <id> --http
```

它同时校验会话行存在、心跳新鲜、`X-Agent-Token` 握手被接受且返回非空 `session_id`。
它不写事件、不刷新心跳，所以不会把已经死掉的心跳伪装成活的。

### 接入你自己的目标应用

本仓库不分发任何目标应用源码，也不内置测试目标。接入方式是写一个启动脚本，把探针按上面的
参数挂到你自己的应用上。`scripts/launch/launch_java_quote.py` 是最小完整示例：它起一个
Spring Boot 应用、解析探针 jar 路径、从数据库取 token、拼好 JVM 参数。照它改成你的启动
命令即可。

`scripts/launch/launch_stack.py` 启动的是 SAVR 自己（后端 + 前端看门狗），与目标应用无关。

两个环境变量有用：`SAST_AI_PROBE_JAR` 改写探针 jar 路径，`SAST_AI_TOOLS_DIR` 指向
`scripts/fetch_tools.py` 下载第三方工具的目录。

### 提交一次扫描

先注册一个指向目标应用源码的工作区：在界面里「工作区 → 新建」，或调 `POST /api/workspaces`（字段 `name`、`target_path`）。挂好探针后提交任务，先用 `--dry-run` 看看将要写入的内容：

```bash
uv run --env-file .env python scripts/submit_scan_task.py --name my-first-scan --dry-run
```

去掉 `--dry-run` 即真正提交；工作区不是默认那个就补 `--workspace-id <id>`。执行已提交任务的 runner 也可以单独跑，用于调试：

```bash
uv run --env-file .env python -m src.cli.scan_task_runner --task-id <id> --target /path/to/target/src \
  --output-dir output/run1 --no-sca
```

`--shard-file <path>` 可选：指向一个 JSON 分片清单，把扫描范围收窄到清单内的入口；
不给就扫全量。分片清单的格式见 `src/core/scan_scope.py` 的加载逻辑。

在把一轮指向目标应用之前，先确认探针会话与 token 确实对得上。对不上时，摄取接口会返回 HTTP 200 且 `accepted=0`，很容易被误读成成功：

```bash
uv run python tools/probe_preflight.py --workspace-id <id> --http
```

`ready=true` 表示会话行存在、心跳新鲜，且带 `X-Agent-Token` 的握手被接受并返回了非空 `session_id` 且无 `errors`。这个检查不写任何事件，也不刷新心跳，所以它不会把已经死掉的心跳弄成活着的。

---

## 配置

配置以环境变量优先。`.env.example` 列出核心运行键及其默认值；模型超参在 `config/model_capabilities.yaml`。

选模型三步：

1. `cp config/config.example.yaml config.yaml`。该副本被 gitignore 排除，因为它可能存放凭据。
2. 把 `api.provider` 与 `api.model` 指向样例里的某个段：`ollama`（默认，不需密钥）、`qwen`、`doubao`、`minimax`、`deepseek`、`openai-compatible`、`claude`、`anthropic-compatible`。
3. 填该段。本地 `ollama` 只需 `base_url` 与 `model`；云端段需 `base_url`、`api_key`、`model`。任何值都可以写成 `"${ENV_VAR}"`，让密钥留在环境变量里。

不要提交 `.env`、`config.yaml` 或任何数据库。

环境变量沿用项目早期名称的 `SAST_AI_` 前缀。这个前缀属于运行契约的一部分，刻意保持不变以维持向后兼容。

---

## 仓库结构

```
SAVR/
├── src/                     # 后端：agents、流水线、IAST 桥接、CLI
│   ├── agents/              # A1 静态、A2 LLM 分析、D2 执行器
│   ├── pipeline/            # a1 / a2 / d2 阶段契约
│   ├── iast/                # 探针摄取、覆盖率、族级判据
│   ├── core/                # 共享原语：配置、族映射、阶段缓存
│   └── cli/                 # 服务端、扫描任务执行器、基准 CLI
├── probe-java/              # IAST/RASP 探针（Java + ByteBuddy）—— 构建产物，不包含在仓库内
├── frontend/                # Vue 3 + Vite 控制台
├── tools/                   # 发布卫生检查、CI 门禁、探针自检、CodeQL 查询
├── scripts/                 # 入口：fetch_tools、submit_scan_task、launch/
├── config/                  # 随仓库分发、不含凭据的配置
└── .github/workflows/       # CI：static / test / frontend 三项必需检查
```

---

## 提 issue

先跑这两个检查，它们能解决很大一部分报告：

1. `uv run python tools/probe_preflight.py --workspace-id <id> --http` —— 如果不是 `ready=true`，事件正在被丢弃，每次重放都会看起来像漏检。
2. `uv run --frozen python tools/ci_gate.py` —— 确认问题不是本机环境造成的。

开 issue 时请附上：

- 你期望什么、实际发生了什么，一两句话。
- 用的模型与提供方（通过 Ollama 的 `qwen3:8b`，或你自己的端点）、目标应用、探针怎么挂的，以及你设了哪些 `run_env` 键。
- 该规格的终态 `verification_status` 与 `failure_attribution`，若涉及 LLM 阶段再加上 `stage_results.a2.contract`。这三个字段能解释大部分漏检，不需要对方看源码。
- 相关日志行，不是整份日志。

## 许可

Apache License 2.0。完整条款见 [LICENSE](LICENSE)；第三方组件的署名声明见 [NOTICE](NOTICE)。

该许可允许使用、修改与再分发，包括用于闭源产品，前提是保留版权与许可声明、标明所做修改，且不得用项目名或贡献者姓名为衍生作品背书。许可中包含贡献者给出的明示专利授权。

选择宽松许可是刻意的：本工具的定位是被嵌入既有安全流水线，而非独立使用。
