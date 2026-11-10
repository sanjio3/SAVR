# 贡献指南

[English](CONTRIBUTING.md) | 中文

感谢你愿意花时间参与。这是一个安全工具，正确性与可复现性比合并速度重要得多。

## 开发环境

```bash
uv sync --frozen --group dev
uv run --frozen python tools/ci_gate.py
```

要求 Python 3.12+ 与 Node 20+。门禁是一个跨平台脚本，环境变量与 pytest 参数只在脚本里定义；CI 跑的是同一条命令，只是拆成三步执行（`--step static`、`--step test`、`--step build`）。全量门禁约 4 分钟，不需要 LLM、CodeQL CLI 或运行中的靶场。只有真的要启动服务时才需要 `cp .env.example .env`。

只跑某一步用 `uv run --frozen python tools/ci_gate.py --step test`。测试步骤会写出 `output/ci/junit.xml`；在 CI 里该文件会作为 artifact 上传，并把通过/失败统计写到运行页面上。

`uv.lock` 是依赖版本的唯一权威。不要在功能 PR 里放宽它；依赖升级由 Dependabot 以独立 PR 提出。

静态门禁还会对 `tools/ci_gate.py::LINT_FILES` 列出的自研工具文件跑 `ruff check` 与 `ruff format --check`。要扩大这份白名单请单独开 PR，不要把它当功能改动的副作用。

本地开发还有两个可选入口：

```bash
uv run --frozen python tools/ci_gate.py --fast       # 不跑 external/benchmark 标记的用例
uv run --frozen python tools/clean_clone_check.py    # 在干净 HEAD 检出里跑门禁
```

干净 clone 自检回答的是「别人刚 clone 下来能不能跑过」：它用 HEAD 的游离 worktree，不从你的工作树复制任何文件。

## 拉取请求规则

1. 测试是硬要求。任何对 `src/` 的改动都必须保持全量门禁全绿（`uv run --frozen python tools/ci_gate.py`）。不要只跑你改到的那几个文件——跨阶段回归在这个代码库里很常见，而且确实发生过。
2. 把 LLM 拴住。模型可以判定、可以写规格，但不能对靶场执行动作。任何接触靶场的新行为都走确定性重放器。
3. 不允许新增静默兜底。当某个能力不可用时（缺二进制、CodeQL 建库失败、探针事件缺失），必须显式降级并记录原因。绝不把失败变成「没有发现」。
4. 指标必须有分母。召回、精确率、误报数要报在具名分片上，不要报「成功率」。如果改动影响检测行为，请说明它对 README 里两行校准结果（常规布局与盲化布局）的预期影响。
5. 中文可以。代码注释与 `docs/` 可以用中文，标识符和公开接口保持英文。

## 验证分层

PR 门禁就是 L0，也是拉取请求唯一必需的一层：CI 会跑 `uv run --frozen python tools/ci_gate.py`，三项检查全绿才允许合并。`compat` 矩阵 job 只是补充信号：Ubuntu + Python 3.13 跑全量 pytest，两个 Windows 组合只做冒烟（静态门禁加一小组平台无关的测试）。部分历史测试依赖已配置好的开发机（控制台编码、本机 subprocess 工具），干净 Windows runner 暂时跑不过全量，这是已知边界。这些都不是必需检查，分支保护仍钉在 `static`、`test`、`frontend` 三项上。

下面的 L1 到 L3 是仅维护者执行的基准重跑，从 `.github/workflows/benchmark.yml` 手动触发（`workflow_dispatch`，填层级、profile 和名称）。它需要带本地靶场、CodeQL CLI、LLM 端点与扫描数据库的自托管 runner（标签 `self-hosted` 与 `savr-benchmark`）；GitHub 托管 runner 过不了预检，在未注册该 runner 之前任务只会排队。它不阻塞任何 PR。`tools/ci_benchmark.py` 把报告写到 `output/benchmark/`，只作为 CI artifact 上传，不入库。

- L0：每次拉取请求。约 4 分钟，跑全量门禁（卫生检查、lint、语法检查、pytest、前端构建）。
- L1：小的语义改动。约 15 分钟，20 例冒烟分片。
- L2：两处及以上语义改动，或任何触及登记/确认链路的改动。约 1.5 小时，130 例分片。
- L3：发布。数小时，2740 例全量。

语义改动请批量提交：一次 L2 最多三处，并逐条写明预期影响。

## 提交信息

用约定式提交（`feat:`、`fix:`、`chore:`、`docs:`、`test:`）。一次提交只做一件逻辑上的事；如果改动来自某一轮基准运行，把本轮的任务 id 写进提交信息。`feat/...`、`fix/...` 这类分支名只是命名约定，不改变合并规则；分支保护作用于 `main`，在仓库设置里管理。

## 测试记录

不要把测试输出提交进仓库。JUnit XML、基准报告、验证轮记录都只作为 CI artifact；`.gitignore` 已排除 `output/ci/`、`output/benchmark/`、`*.junit.xml` 和 `docs/validation_run_*.md`。PR 里带结果文件会被要求移除。
