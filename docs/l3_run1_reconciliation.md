# L3 run1 稳定性第一轮对账与停链判定

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

2026-11-08。L3 是同配置连跑两轮量 late-evidence 抖动的稳定性实验。run1 在有效轮与四档上完全对齐基线，但出现 **1 条红线 `log4j.java/xss`**。按 `config/generalization.yaml` 的 `stop_on_redline: true` 与 Gate 0 G0-3「例外不外溢到 L3 / L2」，**链停在 L3 run1**：不启动 run2、不进 L2、不改闸门、不改代码、`src/` 冻结不变。本文记录证据与口径冲突，供决议。

## 一、执行与终态

任务 `jsc-L3-run1-20261108c`，`--workspace-id 4`，`--task-timeout-minutes 150`，后台任务 `XyUFV5`，日志 `logs/validation_L3_run1.log`。03:52:43 提交、04:54:14 `completed`，耗时约 61.5 分钟，`error_message` 空、pipeline 各阶段 completed。6 项 `run_env` 与 637 / 638 一致（D1 dump 为 `logs/d1_req_dump_L3r1c.jsonl`），`STAGE_CACHE=0` 落下，无第 7 项；`--truth` 留空。环境在 03:51:01 已由 `restore --apply` 完整还原到 original，两轮之间不得改动。

## 二、有效轮与四档（红线以外的部分全部通过）

`tools/check_effective_round.py --task-id 639` → **EFFECTIVE**（exit 0）：`transport.exhausted / generation_timeouts / circuit_broken = 0`、`file_failures.failed_files = 0`、`truncated = 3`（warning，逐文件对账见第六节）。A2 contract `calls=95 / first_pass=91 / retried=4 / recovered=1 / failed=3 / compliance_rate=95.79%`，`transport.timeouts / retries / recovered` 全 0，与 637 的 A2 读数几乎逐项相同。

四档：静态·文件级 **31/31**、文件+族 30/31；动态·文件级 25/31、文件+族 25/31；动态口径下重放·文件级 **24/24**、文件+族 **24/24**；`confirmed` 77（静态自动确认 8、真实重放确认 62）；确认级误报 6/77；红线 `confirmed_replay` **1/62 = 1.6%**（旧口径 1/67）。

`tools/generalization_compare.py --baseline 637 --variant 639 --mode stability`：

| 指标 | 637 | 639 | 变化 |
| --- | --- | --- | --- |
| 静态·文件+族 | 24/24 | 24/24 | +0.0pp |
| 动态·文件+族 | 24/24 | 24/24 | +0.0pp |
| 重放·文件+族 | 24/24 | 24/24 | +0.0pp |
| 严格重放 | 24/24 | 24/24 | +0.0pp |
| 红线 `confirmed_replay` | 0/65 | **1/62** | 新增 `log4j.java/xss` |

逐点差：新命中 0、退步 0、分母与静态侧完全一致。工具输出「原始 1 条 → 有效 1 条，未通过（1 条）」，并明确「预登记例外（层=L3_stability）：本轮未命中」。**稳定性本身是完美的，停链只由这一条红线触发。**

## 三、红线根因：同一条已披露限制，不是新缺陷

四轮的 `log4j.java/xss` spec 逐字段对照（同一端点 `/log4j?token=` 或盲化后的 `/b496e96?token=`）：

| task | spec id | verification_status | iast_state | failure_attribution | positive_evidence_rule | 红线 |
| --- | --- | --- | --- | --- | --- | --- |
| 632（历史 L1） | 239481 | `confirmed_exploitable` | `late-evidence-recovered` | `confirm_gate_late_evidence` | 空 | 1/47 |
| 637（R0''） | 240051 | `confirmed_code_property` | `confirm-gate:sink-reached` | `true_miss` | `framework:spring_reflected_return` | 0/65 |
| 638（L1'） | 240214 | `confirmed_code_property` | `confirm-gate:sink-reached` | `true_miss` | `framework:spring_reflected_return` | 0/40 |
| **639（L3 run1）** | **240334** | **`confirmed_exploitable`** | **`late-evidence-recovered`** | **`confirm_gate_late_evidence`** | 空 | **1/62** |

639 与 632 的状态逐字段一致，637 / 638 则是另一条通道。根因是 `confirm_gate_recheck` 的迟到证据回补存在二选一抖动：同一条真实反射 XSS 在证据按 `framework:` 静态通道确认时为 `confirmed_code_property`（被红线口径的「非 `confirmed_exploitable` + 非 framework 前缀」排除），在迟到 IAST 证据回补生效时升为 `confirmed_exploitable`（`(log4j.java, xss)` 不在真值 `in_scope` 集合，计入红线）。**这正是 L3 设计要量化的 late-evidence 抖动本身**，不是组件退化，也不是新出现的误报。

配置里早有预判：`config/generalization.yaml` 第 28-29 行写明「离线复核：632 的 50 条 confirmed 口径下 in_truth=50/50、降级 0（Log4j.java 本身在真值表内，族 jndi_injection），故该 xss 红线必然重现，泛化是复刻而非放宽」。的口径是「迟到证据回补只把真值表内点升 `confirmed_exploitable`」，`Log4j.java` 确在表内（族 `jndi_injection`），而 `xss` 族未登记，所以只要回补通道被选中该红线必然出现。639 是这一预判的实测兑现。

排除项：四档确认级误报 6/77（637 为 5/83），除 `log4j.java/xss` 外无其他新增红线；A2 零超时零熔断；静态与重放全部 24/24，无掉点。

## 四、口径冲突（需单独评审）

2026-11-07 决议的「选项 C」本意是「把 `log4j.java/xss` 如实披露为已知限制后解除 L1 停链，继续 L3 / L2」，决议明确不补真值、不收紧 late-evidence、不为消红线改判据门。但 Gate 0 G0-3 与 `config/generalization.yaml` 把预登记例外的 `applies_to` 写成 `[L1_blind_route]`，并在 Gate 0 第 42 行写明「**不外溢到 L3 / L2**」。这个范围是为防止例外掩盖别层新问题而设的约束，隐含假设是「L3 / L2 不会出现这条红线」；639 证伪了该假设。

于是现状是：同一条已披露的真实限制，在 L1 被放行、在 L3 又被判成「新红线」并触发硬闸。**按现行文字标准必须停链**；修正范围属于发布验收口径变更，不是组件修复，不作自动变更，待评审。

## 五、截断 warning 与 disqualifiers

`truncated=3` 的 `model_runs`：`182362` `ClassDataLoader.java`（输入 1822 token）、`182363` 同一文件的契约重试（3013 token）、`182396` `XXE.java`（7319 token），单次 25.1~31.9 秒。**与 637 的三次截断文件完全相同**；两文件均在主真值表 `in_scope`，但 `file_failures=0`、静态 31/31、重放 24/24 全部保持，不影响分母也不解释红线（红线在 `log4j.java`）。

disqualifiers 全排除：`status_code` 分布 `200=1733 / 302=135 / 404=35 / 500=28 / 101=6 / 403=3`，非登录墙全 302；`auth_state` `authenticated=1930 / reauthed=4 / 空=6`，`expired` 与 `reauth_failed` 均 0；`trigger_specs` 151 条、`findings` 389 条；扫描期无靶场重启、探针织入正常。

## 六、可选路径

| 路径 | 做法 | 代价 / 风险 |
| --- | --- | --- |
| A · 修正例外范围 | 把 `L1_log4j_xss` 的 `applies_to` 扩到 `[L1_blind_route, L3_stability]`，Gate 0 G0-3 同步修订并如实披露；仍按 `(file_basename, family)` 严格匹配、每轮最多 1 条、其他新红线照旧停链。然后启动 L3 run2、完成两轮稳定性比较，再进 L2 | 改的是发布验收口径，必须评审通过；发布材料需写明 L3 两轮均出现同一条已披露限制 |
| B · 维持现行闸门 | 按 `stop_on_redline: true` 停链，不跑 run2、不进 L2；G0-3 未通过，不发布。639 作为 L3 单轮实测数据如实记录，README / release notes 明确「L3 稳定性与 L2 跨靶场未验证」 | 链不完整，能力表述受限；但零口径变更、零返工风险 |
| C · 修组件消抖动 | 深挖 `confirm_gate_recheck` 为何在 framework 静态通道与迟到 IAST 回补之间二选一，若判定为可修的稳定性缺陷则改 `src/` | 改 `src/` 会重置冻结基线，R0'' → L1' → L3 两轮 → L2 整链重跑（约 4~5 小时）；且两种通道本身都可能「正确」，改动有判定口径漂移风险 |

建议 A：639 与 632 是同一 spec 特征、配置里早有「必然重现」预判，放行的是同一条已登记限制而非新例外；工具已支持按层映射且用文件+族严格匹配 + 每轮 1 条上限，扩范围不会掩盖其他新红线。但这是闸门变更，**未经评审不执行**。

## 七、决议前的动作边界（04:54~05:05）

停链期间未启动 run2、未进 L2、未改 `pre_registered_exceptions`、未改 Gate 0 验收线、未改 `src/` 与真值表、未改判据门、未执行发布动作。`src/` 冻结基线仍为 R0''（637），639 的 `run_env` 与之一致。以下第八节为评审后的执行结果。

## 八、例外范围修正路径 A：修正例外范围到 L3（2026-11-08 05:05 起）

**批准内容**：把 `L1_log4j_xss` 的 `match.applies_to` 从 `[L1_blind_route]` 扩为 `[L1_blind_route, L3_stability]`，Gate 0 G0-2 / G0-3 与 `### Changed` 段落如实披露。放行的仍是**同一条已批准限制**，不是新增例外、不是放宽红线。

**改了什么**：`config/generalization.yaml` 的 `applies_to` + `decision_3` 记录；Gate 0 G0-2 口径行、G0-3 例外范围与范围修正理由、L3 条款；停链条件与验收线；`CHANGELOG.md` 新增 `### Changed` 段并改写 Known Issues 的 L3 条目；`tests/test_generalization_compare_exceptions.py` 把「stability 不放行」改为「L3 放行」，新增四例（L3 放行同源限制 / L3 每轮 1 条上限 / L3 其他新红线仍拦截 / `cross-target` 绝不外溢），删掉过时的 stability 参数化用例。

**没改什么**：`confirmed_replay` 红线定义、确认判据门、`data/java_sec_code_truth_v2.csv`、`src/` 任何文件、6 项 `run_env`、`stop_on_redline: true`、`max_count_per_round: 1`、`(file_basename, family)` 严格匹配、`L2_cross_target` 的非豁免状态。发布材料仍须写明该限制在 L1 / L3 均会出现，不得宣称「红线已修好」。

**复跑结果**：`tools/generalization_compare.py --baseline 637 --variant 639 --mode stability` → 「预登记例外（层=L3_stability）：`L1_log4j_xss` 放行 `log4j.java/xss`」「原始 1 条 → 有效 0 条，通过」；`--json` 输出 `gate.redline_pass=true / fp_replay_raw=1 / fp_replay_effective=0 / exception_violations=[]`。定向回归锁 `test_generalization_compare_exceptions.py` + `test_generalization_compare_json.py` 共 **19 passed**。

**两项隔离验证（保证 L3「同配置两轮」语义不破）**：全仓只读检索确认 `config/generalization.yaml` / `pre_registered_exceptions` 只被 `tools/generalization_compare.py` 引用，`src/` 与 `scripts/` 零引用，即该配置**不参与扫描进程**，只影响发布对账；按 mtime 核查 `src/**/*.py` 在 03:52（run1 启动）之后**零修改**，`src/` 冻结基线仍为 637。两轮的 6 项 `run_env` / 真值表 / 靶场状态保持一致，方差测量不受口径变更影响。

**后续**：全量 pytest 复跑（`logs/pytest_full_20261108_r4.log`）通过后，串行启动 L3 run2（`jsc-L3-run2-20261108c`，仅换任务名与 D1 dump 路径），两轮都完成后跑 `--baseline <run1> --variant <run2> --mode stability`。任一**扣除例外后**仍非 0 的新红线、任务 failed、disqualifier 或有效轮不满足即停链。发布动作继续冻结。
