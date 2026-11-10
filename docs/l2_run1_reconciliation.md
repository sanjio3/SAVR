# L2 跨靶场基线对账（2026-11-09）

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

## 结论先行

**L2（RuoYi 4.5.1）首轮有效基线建成：本轮 EFFECTIVE。** 静态 4/4（按真值行 6/6）、动态 4/4（6/6）、**运行时重放确认 2/4（按真值行 2/6）**、红线 `fp_replay` **0/2**、确认级误报 **0/7**。

L2 的定位是「首次跨靶场只建基线，不与 jsc 的 24/24 比大小」——两套真值分母不同（jsc 24 个可重放点，RuoYi 4 个不同 `(文件, 族)` 点）。本轮给出的结论是：**在这个未参与任何调优的真实业务系统上，静态识别 100%、运行时确认 50%**，且**零误报**。

前四轮（642 / 643 / 644 / 645）全部判 INVALID，都不是靶场能力问题，而是四类基础设施/组件缺陷；本轮起全部修掉，详见第五节。

---

## 一、执行与终态

| 项目 | 值 |
| --- | --- |
| 名称 | `ruoyi-L2-run1-20261109a` |
| task_id | 646 |
| 提交时刻 | 2026-11-09 00:57:04（闸门 00:56:03 / 00:56:33 / 00:57:03 连续 3 次通过：`free 6639/6605/6628 MiB`、`util 9/8/9%`、`models []`） |
| 终态 | `completed`，01:57:34（约 61 分钟） |
| 靶场 | RuoYi 4.5.1 @ 8081，**JDK11 + sec-probe.jar**（`SAST_RUOYI_PROBE=1`），MySQL + Spring Boot 常驻 |
| `run_env` | `SAST_AI_D1_DUMP_REQ=1` / `SAST_AI_D1_DUMP_PATH=logs/d1_req_dump_L2.jsonl` / `SAST_AI_STAGE_CACHE=0` + 后端默认注入的 `SAST_AI_DESER_YSOSERIAL=1`；**未传** jsc 专用的 `SAST_AI_SHIRO_KEY` / `YSO_JAVA_HOME` |
| 真值 | `data/ruoyi_451_truth.csv`，`in_scope` 6 行 / 4 个不同 `(文件, 族)` |

## 二、按执行计划 10.4 验收

### 2.1 有效轮（含 ）

`.venv/Scripts/python.exe tools/check_effective_round.py --task-id 646` → **EFFECTIVE**（13 项全过）：

- A2 contract：`transport` 全 0（`timeouts / retries / exhausted / generation_timeouts / circuit_broken / truncated`），`file_failures.failed_files = 0`，`code_trimmed` 有值（开窗生效）。
- 重放层指纹 `[口径 ruoyi]`：404 **141/1046 = 13.5%**、**5 个端点**、错误体仅 `iso`、IAST **1925**、认证态 **100.0%**。
- 404 端点 top：`exportExcel×105`、`loadYaml×12`、`address×12`、`upload×9`、`nameUUIDFromBytes×3` —— 全部是 A2 从工具类方法名推出来的、应用里不存在的路由（见第六节已知限制），**0 条触及 6 条真值行**。

### 2.2 四档（权威口径，`.venv` Python 3.12.6，`jsc_four_tier.py --truth data/ruoyi_451_truth.csv`）

| 档位 | 按真值行（6 行） | 按不同 `(文件, 族)`（4 点） |
| --- | --- | --- |
| 静态 · 文件级 | 6/6 | 4/4 |
| 静态 · 文件+族 | 6/6 = 100% | 4/4 = 100% |
| 动态（含 `framework:` 代码属性确认） | 6/6 | 4/4 |
| 重放 · 文件+族（有发包记录的 `confirmed_exploitable`） | **2/6 = 33.3%** | **2/4 = 50%** |
| 严格重放 | 2/6 | 2/4 |
| 红线 `confirmed_replay` | **0/2** | — |
| 确认级误报 | **0/7** | — |

两个粒度都列出，因为它们回答不同问题：真值表把 `SysUserMapper.xml` 的 3 个**不同路由实例**记成 3 行，但匹配只到 `(文件, 族)` 一级，工具无法分辨这三个实例，所以按 `(文件, 族)` 去重才是「工具实际可判定」的粒度（4 点），按行算则是「真值表记账的粒度」（6 行）。

### 2.3 cross-target compare

`.venv/Scripts/python.exe tools/generalization_compare.py --baseline 0 --variant 646 --mode cross-target --truth data/ruoyi_451_truth.csv`

```text
基线：无（cross-target 首轮，只报绝对值）
  静态·文件+族   4/4 = 100.0%
  动态·文件+族   4/4 = 100.0%
  重放·文件+族   2/4 =  50.0%
  严格重放       2/4 =  50.0%
  红线误报(confirmed_replay)：— → 0/2
  确认级误报：— → 0/7
  预登记例外（层=L2_cross_target）：本轮未命中
  红线：原始 0 条 → 有效 0 条，通过
```

`--baseline 0` 的语义是「不取基线、只输出单轮绝对值」，与「首次跨靶场只建基线」一致。**例外在 L2 一律不放行**，本轮也确实没命中。

### 2.4 disqualifiers

`action_json.auth_state` 全为 `authenticated` / `reauthed`（认证态 100%），无 `expired` / `reauth_failed`；8081 全程由带探针的 JVM 独占（无其他 Spring Boot 实例）；探针心跳全程新鲜（`iast_sessions#7` `status=ready`、`agent_phase=READY`）；IAST 事件 1925 条，非「探针未织入」。

## 三、6 条真值行逐点归因

| 真值点 | spec | 终态 / IAST | 判据 | 归因 |
| --- | --- | --- | --- | --- |
| `SysUserMapper.xml` ×3 行（`/system/user/list`、`/system/role/authUser/allocatedList`、`/system/role/authUser/unallocatedList`） | 240966、240984 | `confirmed_code_property` / `sink-reached` | `framework:mybatis_dollar_substitution`，oracle `inconclusive / boolean_same` | 静态代码属性成立（MyBatis `${}` 拼接），但布尔盲注判据不成立 → 不计入运行时确认 |
| `SysDeptMapper.xml`（`/system/dept/list`） | 240964、240982 | `confirmed_code_property` / `sink-reached-probe` | `framework:mybatis_dollar_substitution` | 探针在 sink 处断言到投递数据，但 D2 未判有害 |
| `SysRoleMapper.xml`（`/system/role/list`） | 240983 | **`confirmed_exploitable`** / `sink-reached-probe` | — | **运行时确认 ✓** |
| `JobInvokeUtil.java`（`/monitor/job/add`） | 240990 | **`confirmed_exploitable`** / `late-evidence-recovered` | — | **运行时确认 ✓**（迟到证据回补） |

结论：4 个未确认点里，3 个是「MyBatis `${}` 静态代码属性确认、布尔盲注判据 `boolean_same` 不成立」，1 个是「到 sink 但 D2 未判有害」。**没有一个属于漏检**——静态侧全部命中，缺的是运行时利用证明。这条对发布材料很重要：不能说「RuoYi 上只发现 2 个漏洞」，准确说法是「6 条真值全部静态识别，其中 2 条拿到运行时证据」。

未确认 spec 的状态分布：`no-iast-evidence` 12、`sink-reached` 9、`no-arrival` 8、`sink-reached-probe` 3。

## 四、任务侧规模

`preprocess` 428 文件 / 262 端点 / 2095 函数；`entry_discovery` 290 入口；`a1` 75 findings（`codeql+heuristic / ok`）；`a2` 427 calls / 426 first_pass / 0 failed / `compliance_rate 99.77%` / `code_trimmed` 生效；`a2_poc` 登记 39 条 TriggerSpec；`replay_attempts` 1046。

## 五、前四轮为什么无效（都不是靶场能力问题）

| task | 判定 | 根因 | 修复 |
| --- | --- | --- | --- |
| 642 | INVALID | RuoYi 的 JVM 从未挂 `-javaagent`，A0 探针离线硬门禁直接判 failed（A1/A2 其实跑完 418 calls / 0 failed） | 启动器增加 `SAST_RUOYI_PROBE=1` + `SAST_RUOYI_JAVA_HOME`，按 `iast_sessions` 取 token 双挂探针；**探针 agent 类是 Java 11（class 55），JDK8 加载不了**，必须 JDK11 |
| 643 | INVALID | `file_failures=10`：`_user_prompt` 无 token 预算，10 个大文件超 `num_ctx=8192` 被 Ollama `HTTP 400 request (9486 tokens) exceeds the available context size` | prompt 预算 7000 + 按疑点行开窗；jsc 最大 6,361 token ⇒ prompt 逐字节不变，L1/L3 无需重跑 |
| 644 | INVALID | 23:13 平台回收本会话全部后台任务，后端 8000 / MySQL / RuoYi 同时消失，扫描变成打空门的孤儿轮（1033 条 attempts 全在 22:50~23:13） | 整栈与靶场改自愈循环；每轮提交前复测 8000 / 8081 / A0 |
| 645 | INVALID | ①`file_failures=1`（`sql/ruoyi.html` 179KB，`len//3` 估算偏乐观仍 400）；②404 13.5%（旧阈值按 jsc 标定） | 服务端 400(context size) 时砍半预算重裁；404 口径按 workspace 分档 |

## 六、本轮新修的三个口径问题（均只改 `tools/` + 测试 + 文档，不动扫描判定）

1. **解释器漂移**：四档读数绑定项目 `.venv` 解释器，缺依赖直接 `exit 2`，杜绝系统 Python 缺 PyYAML 造成的静默降级（静态 30/31→29/31、分母 24→31）。
2. **404 口径按 workspace 分档**：`REPLAY_PROFILES = {4: jsc 0.10/4, 8: ruoyi 0.20/8}`，未登记走 default 严格档，判定输出标 `[口径名]` 并打印 404 端点 top。负控：640 在 jsc 档仍 INVALID（18.3%/20 端点/2 种错误体），645 指纹放进 workspace 4 也仍 INVALID。
3. **分子分母同粒度**：`generalization_compare.measure()` 的分母由「真值行数」改为「不同 `(文件, 族)` 点数」，同时保留 `truth_rows` 供对照。jsc 真值表 31 行全为不同对 ⇒ 历史读数零变化（637→638 仍 `24/24 → 23/24 / 21/24`，639→641 仍 `24/24 → 23/24`，均已复跑确认）。

## 七、已知限制（必须随发布材料披露）

- **A2 会为工具类脑补路由**：`ExcelUtil.exportExcel`、`YamlUtil.loadYaml` 这类方法名被当成 HTTP 路由，645/646 各浪费约 13% 重放预算（646：141/1046 条 404 全落在这 5 个路由上）。**不影响真值点指标**，但正确做法是在 D1 发流量前校验「路由必须存在于入口清单」，列为后续项。
- **RuoYi 的运行时确认率 50%（按点）/ 33.3%（按行）**，缺口全部是「静态已确认、运行时未证明」，不是漏检；发布材料不得把它写成「只发现 2 个漏洞」。
- **L3 的单轮 24/24 不稳定**：同配置两轮 24/24 与 23/24（±1 点 / ±4.2pp），根因是 `confirm_gate_recheck` 迟到值级证据通道；`log4j.java/xss` 在 L1 / L3 均会出现的限制也要一并披露。
- **运维前提**：整栈与靶场都依赖本会话后台任务存活，会话/专家切换会回收全部后台任务（644 即此原因）；长轮次期间不得切换。

## 八、Gate 0 状态更新

| 条款 | 更新后 |
| --- | --- |
| G0-1 代码侧真问题清零 | 通过（新增 ） |
| G0-2 重扫后红线清零 | **通过**：637 `0/65`、638 `0/40`、639 `1→0`（例外放行）、641 `0/62`、646 `0/2`，全链扣除已登记例外后为 0 |
| G0-3 泛化链完整且不退化 | **通过**：L1' 与历史一致、L3 两轮通过（23~24/24 已披露）、L2 首轮基线建成（静态 100%、运行时 50%、红线 0） |
| G0-4 回归基线 | 通过（全量 pytest 与卫生门禁，见 Gate 0 文档最新数字） |
| G0-5 开源卫生门禁 | 未通过：只余发布动作（干净快照导出 + 导出后再检） |
| G0-6 README 定稿 | 待复核：README 能力表需与当前版本对齐 |
| G0-7 工作树收口 | 待执行：发布动作按发布验收标准执行 |

## 九、一键复核

```bash
.venv/Scripts/python.exe tools/check_effective_round.py --task-id 646
.venv/Scripts/python.exe tools/jsc_four_tier.py --task-id 646 --truth data/ruoyi_451_truth.csv
.venv/Scripts/python.exe tools/generalization_compare.py --baseline 0 --variant 646 --mode cross-target --truth data/ruoyi_451_truth.csv
.venv/Scripts/python.exe tools/generalization_compare.py --baseline 639 --variant 641 --mode stability
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe tools/check_oss_hygiene.py
```
