# 发布验收标准

本文件定义一次发布必须满足的技术条件。任意一条未满足时，不创建 tag、不发布 release。
条件面向维护者与贡献者，用于复核能力表述、回归结果与可复现性，与具体开发环境无关。
每项都给出可复算的判定入口，避免用主观判断代替实测。

## G0-1 代码侧真问题清零

- 迟到的值级证据补回只对当前靶场真值表内的点升级为 `confirmed_exploitable`；真值表外的真实 sink 只记 `sink_reached`，不触发红线。
- A2 组件稳定性：LLM 调用必须有可配置超时、有限重试与熔断；单文件失败必须保留 `analysis_error` 占位而不是静默丢弃；生成超时（socket 读超时）不重试，直接计入 `exhausted`。判定口径（prompt / temperature / seed / 输出契约）不得借稳定性修复漂移。
- 有效轮判定：`tools/check_effective_round.py` 只读且 fail-closed。任一轮 `status` 非 `completed`，或 `transport.{exhausted, generation_timeouts, circuit_broken}` 非 0，或 `file_failures.failed_files` 非 0，或 `transport.truncated` 字段缺失，或重放层环境硬条件不满足（404 率不高于 10%、404 端点不超过 4 个、错误体格式不超过 1 种、IAST 事件大于 0、认证态请求占比不低于 90%），本轮判 INVALID，不得计入验收。
- 四档读数必须由项目 `.venv` 解释器生成；`tools/jsc_four_tier.py` 的依赖预检发现缺依赖时 fail-closed，禁止用系统 Python 生成正式读数。

## G0-2 红线清零

- 全量重扫后，每个有效轮的确认级误报 `fp_replay` 扣除预登记例外后必须为 0。
- 口径：`confirmed_exploitable` 且非 `framework:` 前缀、存在 `replay_attempts`、且不属于按 `(applies_to, file_basename, family)` 预登记的例外。例外范围不覆盖 R0 与 `L2_cross_target`。
- 口径变更必须如实披露，不得把口径收紧造成的计数下降写成缺陷修复。

## G0-3 泛化链完整且不退化

- 四层验证：R0 基线重扫、L1 盲化路由、L3 两轮稳定性、L2 跨靶场。每层使用自己的真值表，四档工具须透传 `--truth`。
- 有效轮之间 `src/`、`run_env`、真值表、靶场状态与 A2 contract 必须一致；分母与静态侧读数一致，逐点差可解释，disqualifiers 全部排除。
- 预登记例外按 spec 特征匹配，每轮最多放行 1 条，不得绑定具体 `task_id`；例外只覆盖 `L1_blind_route` 与 `L3_stability`，不外溢到 `L2_cross_target`。
- 已知限制必须如实披露：同配置两轮重放实测为 24/24 与 23/24（正负 1 点），根因是迟到值级证据通道；`log4j.java/xss` 是真值表未覆盖的真实反射 XSS，在 L1 与 L3 均会出现，不补真值、不收紧 late-evidence、不为消掉红线改判据门。
- 靶场端口被并发会话抢占即命中 disqualifier，本轮直接判 INVALID，不得再按「可解释方差」主观放行。

## G0-4 回归基线不退化

- 全量 pytest 0 failed，且通过数不低于上一次发布基线。
- 卫生门禁 `tools/check_oss_hygiene.py` 通过：无硬编码凭据、无开发机绝对路径、无内部过程文件入库。
- 可分发文档的引用完整性检查零悬空。

## G0-5 开源卫生与发布形态

- 发布产物必须是干净快照：只用当前 `.gitignore` 规则允许分发的文件，由维护者在导出目录做单一初始提交；源工作树的历史不带入公开仓库。
- 导出结果须再跑一次卫生门禁，确认 `.env`、私钥、凭据零命中。
- 运行时产物（数据库、日志、扫描输出、工作区副本）不得进入公开仓库；可复现性所需的真值表与最小分片须保留。
- 导出工具 `tools/export_clean_snapshot.py` 默认 dry-run，只有显式 `--apply --dest` 才复制，且不执行 `git init` / commit / tag。

## G0-6 README 能力表述与实测对齐

- README 的靶场、漏洞族、确认率口径须与实测数据一致；未经实测不得声称 100% 全族覆盖。
- 稳定性结论须写明波动区间与已知限制，不得写成稳定 100%；无效轮不得列入能力表。
- 中英文 README 的关键数字、章节结构与复算命令须逐项对齐。

## G0-7 工作树收口

- 全部验收通过后再统一提交、打 tag、写 release notes；未通过前不得发布。
- release notes 须列出本次的能力边界、已知限制与复现命令，与 CHANGELOG 保持一致。

## 复算入口

- 有效轮判定：`python tools/check_effective_round.py --task-id <id> --verbose`
- 泛化对比：`python tools/generalization_compare.py --json`
- 四档读数：`python tools/run_validation_round.py --help`
- 卫生门禁：`python tools/check_oss_hygiene.py`
- 导出盘点：`python tools/export_clean_snapshot.py`
