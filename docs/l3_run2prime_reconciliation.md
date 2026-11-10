# L3 run2' 对账与两轮稳定性结论（2026-11-08）

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

## 结论先行

**L3 两轮稳定性通过，但结论必须如实写成「23~24/24，±1 点抖动」，不能宣称「单轮 24/24 稳定」。**

639（run1）与 641（run2'）都是 EFFECTIVE，分母同为 24、静态·文件+族同为 30/31、`src/` / 6 项 `run_env` / 主真值表 / 靶场状态全部不变，重放层环境指纹几乎逐项一致。两轮之间唯一的逐点差是 `ssti.java/ssti`：重放 24/24 → 23/24（-4.2pp），归因到 `confirm_gate_recheck` 的迟到值级证据通道，与已批准的 `log4j.java/xss` 已知限制同源。红线 639 为 `1/62`（预登记例外放行为有效 0）、641 为 `0/62`，**无新红线**，`stop_on_redline` 未触发。

本轮另发现一个与扫描结果无关但影响读数准确性的工具链缺陷：发车用的系统 Python 3.13 缺 PyYAML，导致四档工具三处降级分支静默生效，落盘四档文件写成错误的 `23/31 = 74.2%`。已修并用项目 `.venv` 重生成权威读数 `23/24 = 95.8%`。**数据库里的扫描结果自始至终没有被改过，改的只是读数的计算环境与产物文件。**

---

## 一、执行与终态

| 项目 | 值 |
| --- | --- |
| 名称 | `jsc-L3-run2-20261108d` |
| task_id | 641 |
| 发车命令下发 | 2026-11-08 16:55:45 |
| GPU 闸门 | 16:55 起因 Minecraft 占卡（`free 5514~5712 MiB < 6200`）等待；用户关游戏后 17:19:19 / 17:19:49 / 17:20:19 连续 3 次通过 `free 6221/6211/6232 MiB`、`util 39%`、`models []`，未放宽 `--min-free-mib` |
| 提交时刻 | 2026-11-08 17:20:21（DB `created_at` 09:20:21 UTC） |
| 终态 | `completed`，2026-11-08 18:21:21（DB `finished_at` 10:21:14 UTC），耗时约 61 分钟 |
| 6 项 `run_env` | 与 639 完全一致，仅 `SAST_AI_D1_DUMP_PATH` 为 `logs/d1_req_dump_L3r2d.jsonl` |
| 后台 / 日志 | `Wgyb1k` / `logs/validation_L3_run2d.log` |

`run_env` 落库核对：`SAST_AI_DESER_YSOSERIAL=1`、`SAST_AI_SHIRO_KEY`、`YSO_JAVA_HOME`、`SAST_AI_D1_DUMP_REQ=1`、`SAST_AI_D1_DUMP_PATH`、`SAST_AI_STAGE_CACHE=0`。`num_predict` 等是组件默认值，不是第 7 项。

---

## 二、按执行计划 10.1 顺序验收

### 2.1 有效轮判定

`.venv/Scripts/python.exe tools/check_effective_round.py --task-id 641` → **EFFECTIVE**。

- A2 contract：`transport` 的 `exhausted / generation_timeouts / circuit_broken / timeouts / retries` 全 0，`truncated=3`（warning），`file_failures.failed_files=0`。
- 重放层环境：attempts 1937，404 35 条 = **1.8%**、**3 个端点**、错误体仅 `epoch`、IAST 事件 **5116**、认证态 **99.7%**；六项硬条件全过。
- warning 逐文件对账：`truncated=3` 分别落在 `ClassDataLoader.java` 主分析、同文件契约重试、`XXE.java` 主分析（`model_runs` id 182566 / 182567 / 182600，均 `output_tokens=1024`）。与 637（182157 / 182158 / 182191）、639（182362 / 182363 / 182396）**逐文件、逐顺序一致**。这三个文件都在主真值表内，但 `file_failures=0`，截断后走「保留首次解析结果」，没有文件级丢失；`XXE.java` 的 3 条确认在 641 仍保持（compare 无该点退步）。

### 2.2 四档读数（权威口径，`.venv` Python 3.12.6）

| 档位 | L3 run2'|
| --- | --- |
| 静态 · 文件级 | 31/31 |
| 静态 · 文件+族 | 30/31 |
| 动态 · 文件+族（可重放族 24 点） | 23/24 = 95.8% |
| 重放 · 文件+族 | 23/24 = 95.8% |
| 严格重放 | 23/24 = 95.8% |
| `strict_vs_replay_gap` | 0 |
| 红线 `confirmed_replay` | **0/62** |
| 确认级误报 | 5/78 |
| 物理不可达豁免 | 4 个（crlfinjection / ooxmlxxe / classdataloader / websecurityconfig） |

### 2.3 与 639 的 stability compare

`.venv/Scripts/python.exe tools/generalization_compare.py --baseline 639 --variant 641 --mode stability --json data/validation_runs/l3_run2prime_compare.json`

```text
基线 run 639 → 变体 run 641 ｜ 可重放分母 24
  静态·文件+族   24/24=100.0% -> 24/24=100.0%   +0.0pp
  动态·文件+族   24/24=100.0% -> 23/24= 95.8%   -4.2pp
  重放·文件+族   24/24=100.0% -> 23/24= 95.8%   -4.2pp
  严格重放       24/24=100.0% -> 23/24= 95.8%   -4.2pp
  红线误报(confirmed_replay)：1/62 → 0/62
  确认级误报：6/77 → 5/78
  重放口径 · 新命中 0 / 退步 1
    - 退步 ssti.java ssti 未确认态=no-arrival,sink-reached
  预登记例外（层=L3_stability）：本轮未命中
  红线：原始 0 条 → 有效 0 条，通过
```

`gate.redline_pass=true`、`exception_matched=[]`、`exception_violations=[]`。**注意：这个 true 只代表红线口径，不代表 L3 通过**；L3 判定还须叠加 2.1 的 EFFECTIVE、分母/静态一致、逐点差可解释。

### 2.4 disqualifiers

四条全部排除：`action_json.auth_state` 无 `expired` / `reauth_failed`（`authenticated` 1927、`reauthed` 4、空 6）；`replay_attempts.status_code` 分布 200:1730 / 302:135 / 404:35 / 500:28 / 101:6 / 403:3，与 639 的 1733/135/35/28/6/3 几乎逐项一致，不是整片 302 登录墙；8080 由带 `sec-probe.jar` 的 `java-sec-code-1.0.0.jar` 独占、无并发会话起停；IAST 事件 5116，探针正常织入。

---

## 三、`ssti.java/ssti` 逐点归因

### 3.1 两轮 spec 证据对照

| | 639（run1） | 641（run2'） |
| --- | --- | --- |
| spec 240299 / 240643（`src\...\SSTI.java`，a1+a2，`#set($e=...)s4st41…PAYLOAD…`，9 次重放） | `confirmed_exploitable` / `sink-reached-probe`；`d2_evidence.value_hit = hit=True, form=hit_live, definitive=True, harmful=True`；`confirm_gate.admitted=True / runtime_arrival`（04:39:07） | `unconfirmed` / `no-arrival`；`value_hit = {}`；`confirm_gate` 字段不存在 |
| spec 240350 / 240694（CodeQL 描述，3 次重放） | `unconfirmed` / `no-arrival` | `sink_reached` / `sink-reached`；`value_hit.hit=False, form=miss` |
| spec 240451 / 240795（`.codeql-db` 路径，15 次重放） | `confirmed_exploitable` / `late-evidence-recovered`；`recovered=True`、`reason="late-arrival value_hit gate B"` | `sink_reached` / `sink-reached`；`value_hit.hit=False, form=miss` |
| ssti 相关 IAST 事件 | 34 条：`sink-reached-probe` **16**、`sink-reached` 8、空 10 | 18 条：`sink-reached` 12、空 6、**`sink-reached-probe` 0** |

639 的确认建立在「带 canary 的模板实参在 `Velocity.evaluate` 被值级复现」（`value_hit gate B`）之上；641 里探针只记录了不带 canary 的框架级 `sink-reached` 事件（`{{7*7}}` / `#{7*7}`），值级证据没有在确认闸门的观测窗口内到达，于是三条 spec 全部停在 `sink_reached` / `unconfirmed`。**这是迟到证据通道的时序抖动，不是 A2 漏判、不是 payload 构造失败、也不是靶场被抢占。**

### 3.2 排除「全局通道退化」

| 指标（全 task） | 637 | 639 | 640 | 641 |
| --- | --- | --- | --- | --- |
| IAST `sink-reached-probe` | 845 | 778 | 414 | **902** |
| `d2_evidence.value_hit.hit=True` 的 spec | 21 | 21 | 19 | **22** |
| `recovered=True`（迟到回补）的 spec | 4 | 3 | 3 | **1** |
| `confirmed_exploitable` | 72 | 68 | 65 | 66 |

641 的值级命中通道是四轮里最强的，只是 `confirm_gate_recheck` 迟到回补次数少了一次，恰好落在 `ssti.java/ssti`。同一机制已在此前被识别并登记为 `L1_log4j_xss` 已知限制（`docs/l3_run1_reconciliation.md` 第八节）。L3 的设计目标本就是「量化 late-evidence 抖动，判断单轮 24/24 是否稳定」，实测答案是否定的：**重放在 23/24 ~ 24/24 之间波动**。

### 3.3 两轮条件一致性

| 条件 | 639 | 641 |
| --- | --- | --- |
| `status` | completed | completed |
| `check_effective_round` | EFFECTIVE | EFFECTIVE |
| `stage_results.a2.contract.transport` | 全 0，`truncated=3` | 全 0，`truncated=3`（逐字节一致） |
| `file_failures.failed_files` | 0 | 0 |
| `run_env` 6 项 | 一致 | 一致（仅 D1 dump 路径按设计不同） |
| 主真值表 md5 | `c5026cc162aa7f259d61977bdd655134` | 同 |
| `config/known_unreachable.yaml` md5 | `43c63f6ffb88e05c15f404d286573022` | 同 |
| 重放层 404 / 端点 / 错误体 / IAST / 认证 | 1.8% / 3 / epoch / 5182 / 99.7% | 1.8% / 3 / epoch / 5116 / 99.7% |
| `src/` | 03:52 后零修改 | 同 |

---

## 四、四档落盘读数的解释器漂移（独立问题）

### 4.1 现象

`run_validation_round.py` 为 641 落盘的 `data/validation_runs/jsc-L3-run2-20261108d.four_tier.txt` 写的是「静态·文件+族 29/31、动态分母 31/31、重放 23/31 = 74.2%」，且没有「物理不可达 4 个」豁免段；而直接跑 `.venv/Scripts/python.exe tools/jsc_four_tier.py --task-id 641` 得到「30/31、24/31 中可重放 24 点、重放 23/24 = 95.8%」。

### 4.2 根因

`run_validation_round.py` 原来写 `PY = sys.executable`。本轮发车命令用的是系统 `python` 3.13.14（未装 PyYAML），而 `.venv` 是 Python 3.12.6（PyYAML 6.0.3）。`jsc_four_tier.py` 有三处 `try/except` 降级：

- `from src.core.normalize import normalize_family` → 失败后退回小写直比，族别名不归一，静态·文件+族 30/31 → 29/31；
- `from src.core.spec_state_normalize import is_dynamic_eligible` → 失败后 `dyn_eligible=True`，属性/配置族不再剔除，动态分母 24 → 31；
- `load_known_unreachable()` 里 `import yaml` → 失败后返回 `{}`，4 个物理不可达豁免丢失。

实测系统 Python 下三条依赖的失败信息都是 `No module named 'yaml'`，说明是同一个根依赖缺失连带三处降级。**降级本身是静默的，且 `four_tier()` 完全忽略子进程 `returncode`**，错误读数因此被当成正式产物落盘。

### 4.3 影响面

只读复核 `data/validation_runs/*.four_tier.txt`：历史 9 个文件（含 631/632/634/635/637/638/639/640）分母均为 24、静态侧与文档一致，**只有 641 这一个文件受污染**。数据库扫描结果、compare 结论、红线判定均基于 `.venv` 复核，未受影响；`docs/` 里引用的 641 数字在 之前尚未写死。

### 4.4 修复（只改 `tools/` + tests + docs，不动 `src/`、不重置冻结基线）

- `tools/run_validation_round.py`：新增 `project_python()`，优先解析项目 `.venv/Scripts/python.exe`（Windows）/ `.venv/bin/python`，找不到才回退 `sys.executable`；`four_tier()` 在子进程 `returncode != 0` 时先落盘证据再抛 `RuntimeError`，不再把失败/降级读数当正式产物；`main()` 首行日志记录实际使用的解释器。
- `tools/jsc_four_tier.py`：新增 `dependency_report()` 预检 `yaml` / `normalize_family` / `is_dynamic_eligible`；缺依赖时默认打印 `[fatal]` 并 `exit 2`，仅显式 `--allow-degraded` 才放行且输出自带「不得作为正式口径引用」警告；判定与渲染逻辑零改动。
- `tests/test_four_tier_interpreter_guard.py`：新增 9 例回归锁（解释器绑定、回退、子进程失败 fail-closed、成功落盘、依赖预检、默认拒绝、显式放行标记、缺属性报告）。

验证：系统 Python 3.13 跑四档现在直接 `exit 2` 并列出三条缺失依赖；`.venv` 3.12 正常输出 30/31；定向 28 passed（含 `test_validation_round_truth_passthrough` / `test_truth_addendum` / `test_jsc_four_tier_replay_strict` / `test_generalization_compare_json` 零回归）。

### 4.5 权威产物重生成

用 `rr.four_tier(641, "jsc-L3-run2-20261108d")`（内部已绑定 `.venv`）重写 `data/validation_runs/jsc-L3-run2-20261108d.four_tier.txt`，现为 30/31、豁免 4 个、动态分母 24、重放 23/24、红线 0/62。结果 JSON 只记录路径，无需改动。

---

## 五、L3 验收判定

| G0-3 L3 条款 | 判定 | 依据 |
| --- | --- | --- |
| 两轮之间 `src/` / `run_env` / 真值表 / 靶场状态不变 | 通过 | 第三节 3.3；D1 dump 路径按执行计划每轮不同，不属条件变化 |
| 任一扣除例外后仍非 0 的新红线立即停链 | 通过 | 639 的 1/62 是已登记的 `L1_log4j_xss`（`applies_to` 含 `L3_stability`），641 为 0/62；例外本轮未命中 |
| 两轮都须 EFFECTIVE（含 重放层一致性） | 通过 | 2.1、2.4 |
| 分母与静态·文件+族一致 | 通过 | 分母 24 / 24，静态·文件+族 30/31 / 30/31 |
| 逐点差可解释 | 通过 | 第三节：唯一退步 `ssti.java/ssti`，迟到 `value_hit gate B` 证据未回补 |
| 靶场端口被并发会话抢占即 INVALID | 未触发 | 641 的 404 1.8% / 3 端点 / epoch；640 已按此判 INVALID 并作废 |

**G0-3 的 L3 条款通过，链推进到 L2。** 必须随发布材料如实披露：同配置两轮重放为 24/24 与 23/24，波动 ±1 点 / ±4.2pp，来源是 `confirm_gate_recheck` 迟到值级证据通道；`log4j.java/xss` 已知限制在 L1 / L3 均会出现；不得把单轮 24/24 写成「稳定 100%」。L2 仍不放行该例外。

---

## 六、冻结边界与后续

- 不变：`src/` 冻结、`data/java_sec_code_truth_v2.csv` 零改动、6 项 `run_env`、`rescan_baseline_task_id: 637` 唯一基线、639 是 L3 唯一有效 run1、640 INVALID。
- 只改 `tools/` + `tests/` + `docs/`，**不重置冻结基线**，不需要重跑 R0/L1/L3。
- 发布动作按 docs/gate0_release_criteria.md 执行，整链验收通过后由维护者发起。
- 下一步 L2：按 L2 验收线启动 RuoYi 4.5.1 靶场（`launch_ruoyi_full.py` 必须常驻存活）、`--workspace-id 8`、`--idor-app-id workspace-8`、`--truth data/ruoyi_451_truth.csv`、`--baseline 0`；提交前须 `--check-only` 与 8081 `/login` 200 双确认。

---

## 七、一键复核

```bash
.venv/Scripts/python.exe tools/check_effective_round.py --task-id 639
.venv/Scripts/python.exe tools/check_effective_round.py --task-id 641
.venv/Scripts/python.exe tools/jsc_four_tier.py --task-id 641
.venv/Scripts/python.exe tools/generalization_compare.py --baseline 639 --variant 641 --mode stability --json data/validation_runs/l3_run2prime_compare.json
.venv/Scripts/python.exe -m pytest -q tests/test_four_tier_interpreter_guard.py tests/test_validation_round_truth_passthrough.py
.venv/Scripts/python.exe tools/check_oss_hygiene.py
```

本机复跑历史读数时一律用 `.venv/Scripts/python.exe`；系统 Python 3.13 缺 PyYAML，起会直接拒绝输出而不是给降级数字。
