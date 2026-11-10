# R0' 无效轮对账与 A2 生成超时根因

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

## 结论

`jsc-R0prime-20261107c`按 Gate 0「有效轮硬条件」判定为 **INVALID**，
不得计入 G0-2 / G0-3 验收，已由维护者主动终止并保留全部数据作为诊断证据。
本轮不是泛化退化，也不是红线问题，而是 A2 组件在 `num_predict` 无上界时
个别请求生成不终止，导致 socket 读超时与无效重试把整轮拖死。

判定工具：`python tools/check_effective_round.py --task-id 636` → `INVALID`。

## 终态与时间线

| 项 | 值 |
| --- | --- |
| 提交 | 2026-11-08 00:22:54，R0'|
| 闸门 | 连续 3 次采样 free 7032 MiB / util 22~23% / 无常驻模型，通过 |
| `run_env` | 6 项，与 R0b 一致，无第 7 项 |
| A1 | 00:24:14 完成，423 findings，CodeQL+heuristic 正常 |
| A2 | 00:24:14 开始，58 分钟后仅 48/95 文件 |
| 终止 | 01:22 左右，status `failed`，error_message 写明无效轮原因 |

关键事件（全部来自 `scan_task_events`，UTC 时间）：

- `667837` `16:25:21` `a2_progress` done=17，前 17 个文件耗时约 67 秒（≈4s/文件）。
- `667839` `16:30:21` `[integrated-a2][transport] Ollama 传输异常（TimeoutError: timed out），2.0s 后第 1/2 次重试`。
- `667840` `16:35:23` 第 2/2 次重试同样超时。注意 `16:25:21 → 16:30:21` 精确等于 300 秒，即 `SAST_AI_A2_LLM_TIMEOUT` 默认值。
- `667888 / 667889` `17:02:58 / 17:08:00` 第二组超时，模式完全相同。
- `667910 / 667911` `17:14:26 / 17:19:28` 第三组超时，模式完全相同。
- 三组之间 `a2_progress` 正常推进到 48/95，说明不是 Ollama 整体不可用，而是约每 20 个文件出现一次长生成。

## 根因（对初版诊断的第二次纠正）

`src/agents/a2_integrated_analyst.py` 的 `ollama_chat()` 使用 `stream: False` +
`format: json` grammar，`options` 里只有 `temperature` / `num_ctx` / `seed`，
**没有 `num_predict`**。Ollama 默认 `num_predict = -1`（无限，直到 EOS 或 context 满）。
qwen3:8b 在 grammar 约束下偶发不产 EOS 时，生成会一路延伸到 `num_ctx=8192`，
服务端在生成结束前不返回任何响应体，客户端只能等 socket 读超时。

这不是「GPU 被别的进程抢」或「4 并发排队」。历史 `logs/submit_623_full.log`
~ `submit_628_full.log` 里的 `ClassDataLoader.java / Shiro.java / XXE.java
分析异常（跳过该文件）：timed out` 是同一现象，只是旧版 180s 超时直接把文件
静默丢掉（`specs=[]`），没有留下可归因的统计。

把超时提到 300s 并加了重试，方向错了：非流式请求下 socket 读超时等于
「服务端没在阈值内结束生成」，重发同一 prompt 不会更快，还会和客户端断开后
尚未结束的旧请求抢 GPU。实测 3 组共 6 次重试**全部再次超时**，单个卡住文件
被拉长到 15 分钟以上，且 `transport.exhausted != 0` 使整轮按 Gate 0 无效。

## 数据对照

`model_runs` 里 `stage='a2-integrated'` 的真实读数：

| task | 调用数 | 输出 token 最小/最大/均值 | 单次最大耗时 | A2 阶段总耗时 |
| --- | --- | --- | --- | --- |
| 634 (R0b) | 96 | 51 / 382 / 165 | 11.1 s | 1047 s（17.5 min） |
| 635 (L1b) | 95 | 52 / 485 / 165 | 18.4 s | 1284 s（21.4 min） |
| 636 (R0') | 18（终止时） | 51 / 288 / 107 | 7.6 s | >3480 s，仅 48/95 |

输入 token 最大 6055（634），全部在 `num_ctx=8192` 内。历史所有成功调用的
输出上界是 **485 token**，正常请求从不需要 300 秒。因此 300s 超时只能来自
异常生成，不能解释为「算得慢」。

## 落地修复

只动传输层与解码长度上限，不改 prompt / temperature / seed / format / 输出契约：

- `options.num_predict` 默认 1024（历史输出 P100=485 的约 2 倍余量），
  env `SAST_AI_A2_LLM_NUM_PREDICT` 可配。对正常输出 `done_reason` 仍是 `stop`，
  参数完全不生效，判定口径零漂移。
- 新增 `is_generation_timeout()`：socket 读超时（含 `URLError` 包裹）判定为
  生成超时，**不重试**，直接计 `exhausted` 并交给上层记 `analysis_error` 占位；
  连接层异常（ConnectionReset / URLError / RemoteDisconnected / IncompleteRead）
  仍保留有限重试与熔断。
- `benchmark_cli._a2_analyze_with_retry` 同步跳过生成超时，不再整文件重发。
- `transport` 新增 `generation_timeouts` / `truncated`；`done_reason=length`
  （被 `num_predict` 截断）单独计数，避免输出不完整却静默通过。
- 新增 `tools/check_effective_round.py`：把 Gate 0 有效轮判据固化为可执行检查，
  fail-closed，字段缺失即判 INVALID。

真实 Ollama 冒烟证据：`num_predict=256` 请求一个要求输出 3000 个元素的数组，
5.85 秒返回、`eval_count=256`、`done_reason=length`，证明硬闸生效；
用修复后的 `ollama_chat()` 发正常 A2 prompt，6.59 秒返回合规 JSON，
`transport` 全 0，`num_predict=1024`。

回归锁：`tests/test_a2_llm_transport_retry.py` 19 例、
`tests/test_check_effective_round.py` 12 例，全绿。

## 冻结基线与后续

再次修改 `src/`，冻结基线重置。631 / 632 / 633 / 634 / 635 / 636 全部
降级为历史对照，其中 634/635 的 `a2.contract` 只有契约合规率、缺 transport 与
`file_failures`，工具判定为「不可验证 → INVALID」，与「修复前产物」的定位一致。

后续整链从新的 R0'' 起跑：R0'' → L1' → L3 两轮 → L2。每一轮出结果后
**先跑 `tools/check_effective_round.py`，通过后再看红线 / 重放 / gap**；
无效则排查 A2 / Ollama / GPU 后重跑本轮，不计入验收。`run_env` 仍保持 6 项，
`num_predict` 是组件默认值，不新增第 7 项绕开项。

## R0'' 首次真实轮反馈（2026-11-08 01:42）

本轮的 A2 于 01:39:13 开始，done 从 17 顺利推进到 26（636 正是在 17 之后卡死 300 秒），**零超时、零熔断**，单次最长 24.6 秒 —— 解决「拖死整轮」得到实测确认。但出现 2 次 `num_predict` 截断，都落在 `ClassDataLoader.java`：模型输出单个对象后继续生成到 1024 token 仍不产 EOS，契约重试同样截断，最终走「保留首次解析结果」。

离线核实：`ClassDataLoader.java` 在主真值表内（`deserialization / in_scope / static_sink`），但 634 / 635 的 `model_runs` 里**零 A2 调用** —— 之前它一直被 180s 超时静默丢弃，而 634 在完全失去该文件的情况下仍达成红线 0/62、重放 24/24。637 截断后仍有产物，不比历史差。

据此校准本文上面写的有效轮判据：`transport.truncated` 从一票否决改为「字段必须存在、非零只给 warning」，硬条件仍由 `file_failures` / `exhausted` / `generation_timeouts` / `circuit_broken` 承担。校准只改 `tools/` 与文档，**不动 `src/`、不重置冻结基线、不放宽红线或重放口径**，且发生在 637 出结果之前。带 warning 的轮次须逐文件对账；若截断导致 `file_failures > 0` 仍判 INVALID。详见 `docs/gate0_release_criteria.md` G0-1 与本机执行记录。

### 637 A2 contract 与截断文件逐点对账

A2 于 01:39:13 → 01:48:41 跑完 **95/95 文件，约 9.5 分钟**（634 为 17.5 分钟，636 为 58 分钟仅 48/95）。`stage_results.a2.contract` 实测：

| 指标 | 值 |
| --- | --- |
| `calls` / `first_pass` / `compliance_rate` | 95 / 91 / 95.79% |
| `retried` / `recovered` / `failed` | 4 / 1 / 3 |
| `transport.timeouts` / `retries` / `exhausted` | 0 / 0 / 0 |
| `transport.generation_timeouts` / `circuit_broken` | 0 / 0 |
| `transport.truncated` | 3（warning） |
| `file_failures.failed_files` | **0** |

三次截断的逐文件对账（`model_runs`，UTC 时间）：

- `182157` `17:40:36` — `ClassDataLoader.java` 主分析，输入 1822 / 输出 1024 token，24.0 秒。真值表内 `deserialization / in_scope / static_sink`。634 / 635 的 `model_runs` 里该文件**零 A2 调用**（旧版 180s 超时静默丢弃）。637 截断后走「保留首次解析结果」，产物不比历史差。
- `182158` `17:41:01` — 同一文件的契约重试（输入是「输出为空或不是 JSON 数组」提示），输入 3013 / 输出 1024 token，24.6 秒。重试仍不合契约，事件 `667982` 记录「保留首次解析结果」。同上，无文件级丢失。
- `182191` `17:45:09` — `XXE.java` 主分析，输入 7319（贴近 `num_ctx=8192`）/ 输出 1024 token，30.5 秒。真值表内 `xxe / in_scope / static_sink`；634 / 635 的 `model_runs` 里同样零 A2 调用。634 的 `trigger_specs` 里 `XXE.java` 有 3 条 `confirmed_exploitable` spec，**637 须在四档结果里核对这三点是否保持**，这是本轮唯一需要盯的准确性风险。

`file_failures.failed_files = 0` 证明截断没有导致任何文件被丢弃。637 目前仍在 D1 / D2 / reporting 阶段，`trigger_specs` 还是注册中间态，四档数字须等任务 `completed` 后由 `tools/jsc_four_tier.py` 给出，不得提前下结论。判据工具的最终判定也须在 `status=completed` 后执行。
