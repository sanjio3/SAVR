# R0'' 验收对账

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

## 结论

`jsc-R0prime2-20261108a`按 Gate 0 顺序验收**全部通过**，已回填
`config/generalization.yaml` 的 `rescan_baseline_task_id: 637`，作为 L1' / L3
唯一 compare 基线。这是 修复后第一个有效轮，也是第一个用
`tools/check_effective_round.py` 判定的轮次。

## 执行与终态

| 项 | 值 |
| --- | --- |
| 提交 | 2026-11-08 01:38:13，R0''|
| 完成 | 2026-11-08 02:35:37，`completed / completed`，无 error_message |
| 总耗时 | 57.4 分钟（后台任务 `Z0wN5m` 实测 58m32s） |
| GPU 闸门 | 3 次采样 `free 7208 MiB / util 1% / models []` 通过 |
| `run_env` | 6 项，与 R0b / 636 一致，仅 D1 dump 路径换名；无第 7 项 |
| A1 | `codeql+heuristic / ok`，423 findings |
| A2 | 01:39:13 → 01:48:41，95/95 文件，约 9.5 分钟 |
| 四档 | `data/validation_runs/jsc-R0prime2-20261108a.four_tier.txt` |

## ① 有效轮判定（Gate 0 G0-1）

`python tools/check_effective_round.py --task-id 637` → **EFFECTIVE**，exit 0。
七项硬条件全 OK，一条 warning：

- `status = completed`；`a2.contract` 中 `transport` 与 `file_failures` 齐备。
- `transport.exhausted = 0`、`generation_timeouts = 0`、`circuit_broken = 0`。
- `transport.truncated = 3`（可观测项，非零只给 warning）。
- `file_failures.failed_files = 0`。
- `[WARN] transport.truncated=3`：须逐个列出被截断文件、是否为真值点、是否影响四档分母 —— 见下节，已闭合。

A2 contract 完整读数：`calls=95 / first_pass=91 / retried=4 / recovered=1 /
failed=3 / compliance_rate=95.79%`；`transport.timeouts=0, retries=0,
recovered=0, exhausted=0, consecutive_exhausted=0, circuit_broken=0,
generation_timeouts=0, truncated=3`；`file_failures={failed_files:0, files:[]}`。

## ② 四档结果（G0-2 / G0-3 的 R0 条款）

| 口径 | 637（R0''） | 634（R0b，历史对照） |
| --- | --- | --- |
| 静态 · 文件级 | **31/31 = 100.0%** | 31/31 |
| 静态 · 文件+族 | **30/31 = 96.8%** | 30/31 |
| 动态 · 文件级 / 文件+族 | 25/31 / 25/31 | 25/31 / — |
| 动态（可重放族 24 点）· 文件+族 | **24/24 = 100.0%** | 24/24 |
| 重放 · 文件级 / 文件+族 | **24/24 / 24/24 = 100.0%** | 24/24 / 24/24 |
| 严格重放 vs 重放 gap | **0** | 0 |
| 红线 `fp_replay`（新口径） | **0/65 = 0.0%** | 0/62 |
| 红线（旧口径，仅对照） | 0/71 | — |

任务侧 `findings 389 / specs 151`，`confirmed 83`（静态自动确认 11、真实重放确认 65）。
物理不可达豁免 4 个（`crlfinjection / ooxmlxxe / classdataloader /
websecurityconfig`），已从动态分母剔除、静态仍计入，与历史口径一致。
未确认 spec 状态分布：27 `sink-reached`、19 `no-arrival`、
13 `no-iast-evidence`、4 `sink-reached-probe`、4 `payload_unavailable`、
1 `late-evidence-recovered`。

## ③ warning 逐文件对账（3 次截断）

| `model_runs` ID | 时间(UTC) | 文件 | 输入/输出 token | 耗时 | 真值表 | 影响 |
| --- | --- | --- | --- | --- | --- | --- |
| 182157 | 17:40:36 | `ClassDataLoader.java` 主分析 | 1822 / 1024 | 24.0s | `deserialization / in_scope / static_sink` | 走「保留首次解析结果」；四档已列为物理不可达豁免，不在 24 点重放分母内 |
| 182158 | 17:41:01 | 同文件契约重试 | 3013 / 1024 | 24.6s | 同上 | 重试仍不合契约，保留首次解析结果，无文件级丢失 |
| 182191 | 17:45:09 | `XXE.java` 主分析 | 7319 / 1024 | 30.5s | `xxe / in_scope / static_sink` | 真值点，需核对确认态是否保持，见下 |

**`XXE.java` 三点核对（本轮唯一风险点，已排除）**：634 有 4 条 `XXE.java`
spec、其中 3 条 `confirmed_exploitable`；637 有 5 条、其中 **3 条
`confirmed_exploitable`**（`240020 / 240139 / 240138`，另 1 条 csrf 与 1 条 xxe
为 `unconfirmed`，均 `replayable=1`）。三点全保住，重放 24/24 未掉点。
两个截断文件在 634 / 635 的 `model_runs` 里都是**零 A2 调用**（旧版 180s 超时
静默丢弃），637 反而多拿到产物，符合 `docs/r0prime_invalid_round_postmortem.md`
里判据校准的依据。

## ④ disqualifiers 核查

- `replay_attempts.status_code` 分布：200 = 1736、302 = 130、404 = 35、500 = 29、101 = 6、403 = 3，**不是登录墙全 302**。
- `action_json` 中 `expired` / `reauth_failed`：**0 条**。
- 靶场未重启，8080 `/login` 200，`mode: original` 全程未变。
- 探针已织入：重放 24/24、65 条真实重放确认、IAST 事件齐备。

四条 disqualifier 全部排除。

## ⑤ 与 634 / 636 的对照

- 634（R0b）是  修复前的历史对照，四档同样是 31/31、24/24、红线 0；但它的 `a2.contract` 缺 transport 与 `file_failures`，工具判「不可验证 → INVALID」，不作验收基线。
- 636（R0'）是无效轮：A2 跑 58 分钟仅 48/95，3 组 300s 超时、6 次重试全部再次超时，已主动终止并保留证据。
- 637 的 A2 只用 9.5 分钟（634 为 17.5 分钟），零超时零熔断、零文件失败，的组件修复在真实全量轮上得到确认。

## 后续

`rescan_baseline_task_id = 637` 已回填，链推进到 L1'：`blind --apply` →
全量扫描 → 四档与 `tools/generalization_compare.py --baseline 637 --mode blind`
→ `restore --apply`。L1' 验收线：重放 ≥ 21/24、gap 0、红线扣除
`L1_log4j_xss` 后为 0，且先过 `tools/check_effective_round.py`。任一环新红线、
任务 failed、disqualifier 命中或有效轮不满足即停链。

发布动作按 docs/gate0_release_criteria.md 执行；README 能力表述
（G0-6）等 L1' / L3 / L2 全绿后定稿。
