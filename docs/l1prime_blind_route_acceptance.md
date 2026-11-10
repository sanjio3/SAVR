# L1' 泛化第一层对账

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

2026-11-08。L1' 是 组件修复、冻结基线重置到 R0''之后的第一次盲化路由重扫。本文按 Gate 0 顺序记录有效轮判定、四档、逐点归因、warning 对账与停链排查。结论：**G0-3 的 L1' 条款全部通过**，链推进到 L3 两轮；发布动作按发布验收标准执行。

## 一、执行与终态

任务 `jsc-L1-blind-route-20261108c`，`--workspace-id 4`，`--task-timeout-minutes 150`，后台任务 `D8wNaY`，日志 `logs/validation_L1p.log`。02:49:43 提交，03:40:13 `completed`，耗时约 50.5 分钟，`error_message` 为空，pipeline 各阶段 completed。

6 项 `run_env` 与 R0'' 严格一致（`SAST_AI_D1_DUMP_PATH / SAST_AI_D1_DUMP_REQ / SAST_AI_DESER_YSOSERIAL / SAST_AI_SHIRO_KEY / SAST_AI_STAGE_CACHE / YSO_JAVA_HOME`），仅把 D1 dump 换成 `logs/d1_req_dump_L1p.jsonl`，**无第 7 项**；`num_predict` 等是组件默认值。`--truth` 留空用 jsc 主真值表，主真值表零改动。

环境前置在提交前全部复核：`blind --apply` 后 jar md5 `39556957…`、workspace 4 `target_path` 与 IAST session 8 `code_path` 指向盲化树、8080 healthy；带登录会话实测盲化端点 `/bd31933/b7400f8/vuln?id=1` = 400、原路由 `/sqli/jdbc/vuln?id=1` = 404、`/login` 200 / `/logout` 302。A1 为 `heuristic-fallback`、95 files、133 findings、43.26 秒，与历史 L1（635）完全一致，不是本轮退化；盲化树 CodeQL 建库失败是该变体的长期已知行为。

## 二、有效轮判定（Gate 0 第一步）

`python tools/check_effective_round.py --task-id 638` → **EFFECTIVE**（exit 0），硬条件全过：

| 判据 | 实测 |
| --- | --- |
| `status` | `completed` |
| `transport.exhausted` / `generation_timeouts` / `circuit_broken` | 0 / 0 / 0 |
| `transport.timeouts` / `retries` / `recovered` | 0 / 0 / 0 |
| `file_failures.failed_files` | 0 |
| `transport.truncated` | 7（必需可观测字段，只给 1 条 warning） |

A2 contract：`calls=95 / first_pass=89 / retried=6 / recovered=1 / failed=5 / compliance_rate=93.68%`。A2 全程约 10 分钟跑完 95/95，零超时零熔断，的 `num_predict` 硬闸在盲化树这一轮同样成立。`failed=5` 是「输出不合 JSON 数组契约」的模型产物计数，不是文件丢失；`file_failures=0` 才是准确性底线。

## 三、四档与泛化比较

四档（`data/validation_runs/jsc-L1-blind-route-20261108c.four_tier.txt`）：静态·文件级 30/31 = 96.8%、文件+族 29/31 = 93.5%；动态·文件级 23/31、文件+族 22/31；动态口径（可重放 24 点）重放·文件级 22/24 = 91.7%、文件+族 **21/24 = 87.5%**；`confirmed` 52（静态自动确认 8、真实重放确认 40）；确认级误报 5/52 = 9.6%；红线 `confirmed_replay` **0/40 = 0.0%**。

`tools/generalization_compare.py --baseline 637 --variant 638 --mode blind`：

| 指标 | 637（R0''） | 638（L1'） | 变化 |
| --- | --- | --- | --- |
| 静态·文件+族 | 24/24 = 100.0% | 23/24 = 95.8% | -4.2pp |
| 动态·文件+族 | 24/24 = 100.0% | 21/24 = 87.5% | -12.5pp |
| 重放·文件+族 | 24/24 = 100.0% | 21/24 = 87.5% | -12.5pp |
| 严格重放 | 24/24 = 100.0% | 21/24 = 87.5% | -12.5pp |
| 红线 `confirmed_replay` | 0/65 | 0/40 | 原始 0 → 有效 0，通过 |

逐点差：新命中 0、退步 3，分别是 `fileupload.java / file_upload`（未确认态 `sink-reached-probe`）、`jsonp.java / jsonp_referer`（`sink-reached`）、`websockets.java / xss`（无未确认态）。三点全在真值表 `in_scope`，且都是路由语义强相关端点，与「去 URL 布局先验」的实验目的一致。严格重放 21/24 与四档重放 21/24 相等，**gap = 0**，没有靠静态确认撑数。

**与历史 L1 的复刻性**：`--baseline 631 --variant 632 --mode blind` 得到静态 -4.2pp、动态/重放/严格各 -12.5pp、新命中 0、退步同为上述三点。两组数字与三个退步点完全一致，说明 修好 A2 后，L1' 精确复刻了 632 的泛化行为；635 那次 `19/24` 掉点确由 A2 超时假掉点造成，不是新的能力退化。

## 四、红线口径如实披露

638 的 `0/40` 是**新口径 `confirmed_replay` 的读数**，不等于「历史那条已知红线被修好了」。四档文件同时给出 `重放[旧口径] 1/43 = 2.3%` 并明确提醒「有 1 条旧口径红线误报因零重放被新口径排除，属口径收紧，不是修复」；对照 632 的新旧口径分别是 `1/47` 与 `2/50`。

`pre_registered_exceptions` 中的 `L1_log4j_xss`（`(L1_blind_route, log4j.java, xss)`）本轮**未命中**，因为新口径下没有产生需要放行的红线。用 `--no-exceptions` 跑原始口径对照，输出与默认完全一致，证实本轮通过不依赖例外放行。例外仍保留在配置中，继续只适用于 `L1_blind_route`，不外溢到 L3 / L2。

## 五、截断 warning 逐文件对账

`truncated=7` 的 7 条 `model_runs`（`output_tokens=1024`、`done_reason=length`）逐条定位如下，均为 `qwen3:8b` 在主分析或契约重试时生成到硬闸上限仍不产 EOS，单次耗时 25.1~29.4 秒：

| model_run | 输入 token | 文件 | 性质 |
| --- | --- | --- | --- |
| 182259 / 182260 | 1678 / 2869 | `ClassDataLoader.java` | 主分析 + 契约重试 |
| 182267 / 182268 | 2332 / 3523 | `Deserialize.java` | 主分析 + 契约重试 |
| 182270 / 182271 | 3257 / 4448 | `Fastjson.java` | 主分析 + 契约重试 |
| 182294 | 5279 | `XXE.java` | 主分析 |

四个文件都在主真值表 `in_scope`（`ClassDataLoader / Deserialize / Fastjson` 为 `deserialization`、`XXE` 为 `xxe`），但三点结论支持不否决本轮：

- `file_failures.failed_files = 0`，截断后走「保留首次解析结果」，没有静默丢文件；之前这些文件是被 180 秒超时直接 `specs=[]` 丢弃的，637 的同类对账已证明这一点。
- 三个退步点（`fileupload.java` / `jsonp.java` / `websockets.java`）与四个截断文件**完全不重叠**，截断不解释掉点。
- 四档分母仍是 31 条真值点、24 个可重放点、静态 30/31，与 637 的静态侧分母一致；`XXE.java` 在 637 也有 1 次截断且三点 `confirmed_exploitable` 全保住，本轮同样未见该族掉点。

对照 R0''（637）的 `truncated=3`（`ClassDataLoader` ×2、`XXE` ×1），盲化树多出 `Deserialize.java` ×2 与 `Fastjson.java` ×2，原因是路由盲化后 A2 prompt 内容变化导致反序列化族更容易不产 EOS。这是生成侧瑕疵的可观测表现，不是环境故障；按 Gate 0 校准后的口径记为 warning 并要求逐文件对账，本文即为该对账。

## 六、disqualifiers 排查

| 检查项 | 实测 | 结论 |
| --- | --- | --- |
| 登录墙全 302 | `status_code` 分布 `200=980 / 302=53 / 404=24 / 500=15 / 101=5`；302 中仅 9 条响应含 login 字样 | 未命中 |
| `auth_state` 失效 | `authenticated=1069 / reauthed=3 / 空=5`，`expired` 与 `reauth_failed` 均为 0 | 未命中 |
| 探针未织入 | IAST session 8 累计 66291 条事件；四档未确认 spec 有 `sink-reached` / `no-arrival` 等完整状态分布 | 未命中 |
| 靶场重启 / h2 profile 丢失 | 切换发生在提交前 8 分钟，8080 healthy、认证链路正常、盲化端点可达；扫描期间无重启 | 未命中（切换属设计内前置） |

`trigger_specs` 103 条、`findings` 152 条，任务终态 completed、无 failed 阶段、无熔断。

## 七、工具修复（不动 `src/`，不重置冻结基线）

真实对账首次调用 `--json` 时，`generalization_compare.py` 在文本报告完整打印后抛 `TypeError: keys must be str, int, float, bool or None, not tuple`，机器可读结果没写出来、EXIT=1。根因是 `measure()['attrib']` 用 `(base, family)` 元组作 key 供 `render()` 查逐点归因，`json.dump(..., default=list)` 不接受非字符串 dict key。

修复只在序列化侧：新增 `to_jsonable()`，把 tuple key 归一成 `"base|family"`、把 set / tuple 转成 list；`--json` 分支改为 `json.dump(to_jsonable(payload), ...)`。`measure()` 返回结构、`render()` 查询方式、红线判定与例外放行逻辑一律不变。真实复跑 `--baseline 637 --variant 638 --mode blind --json data/validation_runs/l1prime_compare.json` 成功，`gate.redline_pass=true / fp_replay_raw=0 / fp_replay_effective=0 / exception_matched=[]`，与文本报告一致。新增 `tests/test_generalization_compare_json.py` 5 例，连同 `test_generalization_compare_exceptions.py` 11 例共 16 passed。

这次只改 `tools/` 与测试/文档，**不动 `src/`、不改判据、不重置冻结基线**，按 Gate 0 G0-1 的既定规则处理。

## 八、判定与后续

G0-3 的 L1' 条款逐条对账：有效轮 EFFECTIVE（通过）、重放 21/24 ≥ 21/24（通过）、`strict_vs_replay_gap = 0`（通过）、红线扣除例外后为 0（通过）、静态侧分母与基线一致（通过）、逐点差可归因到路由先验且与历史 L1 完全复刻（通过）、disqualifiers 全排除（通过）。**L1' 通过，链推进到 L3。**

后续严格按顺序：`restore --apply` 把环境还原到 original（必须给 300 秒以上超时，JVM 冷启动约 130 秒）→ 复核原 jar md5、workspace 4 / session 8 `code_path`、8080 健康与 JVM token → L3 两轮串行（`STAGE_CACHE=0`、两轮之间 `src/` 冻结不变）→ L2 RuoYi（`--truth data/ruoyi_451_truth.csv`）。执行设计按发布验收标准 G0-3 执行。任一环新红线、任务 failed、disqualifier 命中或有效轮条件不满足即停链。

发布动作按 docs/gate0_release_criteria.md 执行；干净快照导出与 README 能力表述定稿在整链全绿后进行。
