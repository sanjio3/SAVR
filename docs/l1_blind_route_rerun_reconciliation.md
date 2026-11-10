# L1b 盲化路由重跑对账（2026-11-07 22:29）

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

## 结论：按 G0-3 未通过，链停在 L1

L1b（`jsc-L1-blind-route-20261107b`）终态 `completed`，数据完整、无执行故障，但**重放 `19/24`，低于 G0-3 明文要求的「不低于历史 L1 的 `21/24`」**。红线 `1/39` 只有 1 条且特征完全命中预登记例外 `L1_log4j_xss`，`strict_replay` 与 `replay_family` 差值为 0，四条 disqualifier 全部排除。

按闸门 0 的 `stop_on_redline: true` 与 G0-3，此处**停链，不进 L3、不执行 `restore --apply`**，发布动作按发布验收标准执行。是否需要再跑一轮或修订验收线，待评审，不自动放宽标准。

## 执行配置

- 扫描任务，2026-11-07 21:31:25 提交、22:29:26 `completed`；任务耗时约 58 分钟，执行器计时 59m02s（含提交前 3 次 GPU 闸门采样）。比 R0b 的 86.6 分钟短，原因是盲化树 A1 走 `heuristic-fallback`，不跑 CodeQL 建库。
- 6 项 `run_env` 全部落库核对通过（含 `SAST_AI_STAGE_CACHE=0`），与 R0b 同组；GPU 闸门连续 3 次通过（空闲 6438 MiB / 利用率 6~9% / 无常驻模型）。
- `src/` 冻结基线为 634（修复后），本轮未改任何评测代码、未改真值表、未补真值；`compare` 基线 634，历史对照 631。
- 盲化环境于 21:25 由 `tools/jsc_blind_switch.py blind --apply` 切换完成，IAST session 8 token takeover；带会话实证盲化端点 400/200、原路由 404。

## 四档结果（真值 `data/java_sec_code_truth_v2.csv`，in_scope 31 条）

- 静态 · 文件级 `30/31` = 96.8%；静态 · 文件+族 `29/31` = 93.5%。
- 动态 · 文件级 `21/24` = 87.5%；动态 · 文件+族 `20/24` = 83.3%。
- 重放 · 文件级 `19/24` = 79.2%；**重放 · 文件+族 `19/24` = 79.2%**（`replay_family`）。
- 严格重放 `19/24` = 79.2%，与 `replay_family` 差值 **0**。
- 确认级误报 `5/51` = 9.8%；**红线 `1/39` = 2.6%**；旧口径红线 `2/41`。
- 任务侧 151 findings / 103 specs；`confirmed` 51（静态自动确认 9，真实重放确认 39）。

对照：历史 L1（632）`replay_family` `21/24`、`strict_replay` `21/24`、红线 `1/47`；R0b（634）`24/24`、红线 `0/62`。

## G0-3 逐条判定

- **重放不低于历史 L1 的 21/24：未通过**。`19/24`，差 2 点。
- **`strict_replay` 与 `replay_family` 差值 0：通过**。两者同为 `19/24`，没有靠静态确认撑数。
- **红线除 `L1_log4j_xss` 外为 0：通过**。唯一 1 条是 `Log4j.java / xss / sink-reached-probe`，落在 `L1_blind_route`，`file_basename=log4j.java`、`family=xss`，每轮最多 1 条的限制未突破，未外溢。
- **同冻结 `src/`、同 6 项 `run_env`、compare 基线 634：通过**。泛化例外按 spec 特征登记后，白名单不再绑定旧 task_id，本轮没有出现「已知限制被误判为新红线」的停链。
- **四条 disqualifier：全部排除**。两轮 `replay_attempts.status_code` 分布逐项同构（200 为 972/971、302 为 53/53、404 为 24/24、500 为 15/15、101 为 5/5）；`auth_state` 为 `authenticated` 1061/1060、`reauthed` 3/3，无 `expired` / `reauth_failed`；302 不是「全 302 且指向 /login」；无靶场重启、无 `h2` profile 丢失；`no-arrival` 反而从 21 降到 19，探针已织入。

## 掉点根因：确认态判定方差，不是代码回归

逐真值点复算 `rep_fam`，632 → 635 只掉了 2 个点：

- `xxe.java / xxe`：632 有 3 条 `confirmed_exploitable / sink-reached-probe`，635 同点位 3 条全部停在 `sink_reached`（到了 sink、D2 未确认有害）。
- `fileupload.java / path_traversal`：632 有 2 条 confirmed（其中 1 条 `late-evidence-recovered`），635 同点位 0 条 confirmed。

支撑「不是回归」的证据：

- 的表外降级分支在本轮**一次都没触发**：`failure_attribution='confirm_gate_late_evidence_out_of_truth'` 计数 0，`late-evidence-recovered` 8 → 6 是迟到证据本身少了 2 条，不是被 降级。
- 两轮执行层几乎同构：specs 104 / 103，attempts 1069 / 1068，IAST events 3522 / 3625（635 更多）。不是「少发包」或「探针没织入」。
- A2 文件超时差异是唯一显见的执行层变量：631 超时 3 个（含 `XXE.java`）、632 超时 2 个（**不含 `XXE.java`**）、634 超时 3 个（含 `XXE.java`）、**635 超时 4 个（`ClassDataLoader` / `Deserialize` / `Fastjson` / `XXE`）**。`XXE.java` 正好是掉点之一；`Fastjson.java` 为本轮新增。
- 因此 `confirmed` 50 → 43、`replay_family` 21/24 → 19/24 最合理的归因是 **A2 LLM 超时 + D2 确认态抖动**，属同配置重跑的采样方差。

但必须强调：**G0-3 的 disqualifier 白名单里没有「A2 文件超时」这一条**，且历史 L1 只跑过一次、没有稳定性分布，`21/24` 是单次采样值。所以这 2 点不能自动判为「环境干扰」而放行——护栏触发时应当停链，这正是闸门 0「先定标准、避免发布返工」该起作用的地方。

## 顺带查出一个隐藏返工点

`tools/generalization_compare.py` 第 161 行把验收线硬写成 `fp_replay == 0`，**不读 `config/generalization.yaml` 的 `pre_registered_exceptions`**。因此该工具对任何 L1 轮次都会打印「红线误报必须为 0；当前 未通过（1 条）」，与闸门 0 已批准的例外决议直接冲突。发布后若有人复跑官方比较工具，会看到 FAIL 并质疑发布结论。这一项无论后续如何决议都必须补齐（工具读取例外并单独标注 `passed_with_registered_exception`），否则 G0-3 无法自洽。

## 待评审方向

- **再跑一轮 L1b'**：同冻结 `src/`、同 6 项 `run_env`、盲化环境不动，验证 19/24 是否抖动。若回到 ≥21/24 且红线仍只有例外，则继续 L3；若仍在 20/24 附近，说明 `21/24` 本身不可复现，需改用「区间/容差」验收线。耗时约 58~87 分钟，需重新过 GPU 闸门。
- **修订 G0-3 验收线**：把「≥21/24」改为「≥19/24 且 gap 0 且红线仅例外」，并在 README / release notes 如实披露 L1 重放 `19/24` 与 A2 超时影响。风险是公开记录里出现「为过闸而下调标准」的观感，需明确批准。
- **停链先查 A2 超时根因**：查 LLM 超时阈值与并发配置，修完再跑。代价最大——会动 `src/` 冻结，L3 基线需重置，且 R0b/L1b 两轮结果要重新对齐。

在此之前保持现状：盲化环境不还原（还原动作属于「L1 通过后才进 L3」的下一步）、主真值表零改动；发布动作按发布验收标准执行。

## A2 超时根因（停链后只读诊断）

评审「停链先查 A2 超时根因」后，本轮只做只读核查，**未改任何 `src/`、未改配置、未重跑、未还原盲化环境**。

### 根因链（初版只读诊断；并发项与 L0 方案已被文末「后续复核纠正」推翻）

- `src/cli/benchmark_cli.py:1778` 与 `:3109` 都用 `IntegratedAnalyst()` 无参实例化，`src/agents/a2_integrated_analyst.py:706` 的签名是 `timeout: float = 180.0`，180 秒硬编码在函数默认值里。
- `ollama_chat()`（`a2_integrated_analyst.py:563`）向本地 Ollama 发 `stream: False` 的 `/api/chat`（`:580`），**等完整响应才返回**；底层是 `urllib.request.urlopen(req, timeout=timeout)`（`:608`），即 socket 读超时。只要 180 秒内一个字节都没回来就抛 `timed out`。
- 这条原生 Ollama 路径**不走 `src/core/llm_gate.py` 的并发准入闸门**（全文件无 `llm_gate` 引用）。A2 集成分析默认 `SAST_AI_INTEGRATED_WORKERS=4`（`benchmark_cli.py:3144`），4 个请求同时压给 Ollama；而 `llm_gate.py` 头部注释已明确记录本机 `OLLAMA_NUM_PARALLEL=2` 时「并发再多也不会增加吞吐，只会线性拉长排队」。排队 + 长 prompt prefill + JSON 生成一起落在同一个 180 秒窗口里。
- `benchmark_cli.py:1852-1854` 捕获异常后 **`specs = []`，整个文件跳过，不重试、不降级、不告警升级**。一次超时就等于永久丢掉该文件的 A2 语义产物。

### 为什么 635 多超时 2 个：180 秒边界上的随机抖动，不是配置分水岭

- 四轮 `task_log` 里 `[stage_cache]` 命中日志 **0 条**，说明 `SAST_AI_STAGE_CACHE` 不是分水岭：632（未设 `=0`）与 635（设 `=0`）的 A2 都是全量真跑，缓存没帮 632 省掉 LLM 调用。
- 两轮同为盲化树、同 4 并发、同 180 秒超时；只改 D2 的 `confirm_gate_recheck`，不碰 A2。所以差异只能是排队与生成时长在阈值附近的随机波动。A2 阶段耗时 632 为 44.4 分钟、635 为 54.7 分钟（+10.3 分钟），与「更多请求贴近或越过 180 秒」一致。
- 631（3 个超时含 `XXE.java`）、634（3 个含 `XXE.java`）也超时 `XXE.java` 却仍 `24/24`：原靶场该点有 A1 / 探针通道补足，盲化树更依赖 A2 语义，所以同一个超时在 L1 才表现为掉点。

### 掉点与超时的直接对应（逐 spec 核对）

- `XXE.java`：632 未超时，9 条 spec 中 3 条 `xxe / confirmed_exploitable / sink-reached-probe`；635 超时，9 条 spec 全在（A1 静态通道仍登记），但 3 条 xxe 全部停在 `sink_reached / sink-reached`。**spec 没丢，丢的是 A2 语义与探针断言，D2 因此不升级**。
- `Fastjson.java`：632 有 2 条（含 1 条 `late-evidence-recovered`），635 只剩 1 条。
- 这解释了为什么两轮 `replay_attempts` 数量与 `status_code` 分布几乎完全一致：重放执行层没问题，是上游确认态少升了 2 个点。

### 三个修复方向，代价差一个量级

- **L0 纯 `run_env`（推荐，零代码改动）**：`SAST_AI_INTEGRATED_WORKERS` 是 env 可调（`benchmark_cli.py:3144`），`scripts/submit_scan_task.py --env` 无白名单，`src/cli/scan_task_runner.py:300-324` 在子进程启动时把 `options_json.run_env` 全量注入 `os.environ`。把并发从 4 降到 2（或 1）即可减少 Ollama 排队、把单请求拉回 180 秒内，**不动 `src/` 冻结、不动真值表、不动闸门标准**。代价是 A2 阶段变长（4→1 最坏数倍，但 Ollama 本就近似串行，估计 +20~40%）。
- **L1 改 `src/`（代价最大）**：把 `IntegratedAnalyst` 的 timeout 改成 env 可配、超时重试 1 次并降级、让原生 Ollama 路径走 `llm_gate`。注意 `SAST_AI_LLM_TIMEOUT` **对这条路径无效**——它只被 `src/agents/a2_ai_agent.py:27` 读取，改超时必须动 `benchmark_cli.py` 或 `a2_integrated_analyst.py`。这会重置 `src/` 冻结、L3 基线要重设、R0b 与 L1b 两轮要重新对齐。
- **L2 改 Ollama（影响整栈）**：提高 `OLLAMA_NUM_PARALLEL` 并重启 serve，8GB 显存下与别的 GPU 任务抢卡风险高，且改变所有阶段的执行环境。

### L0 与闸门 0 的一处口径冲突，必须先确认

G0-3 明文要求 L1「用同一组 **6 项** `run_env`」执行。追加 `SAST_AI_INTEGRATED_WORKERS` 会变成 7 项，严格读是破坏「同配置」前提，compare 基线 634 的执行环境也不再完全一致。这一项只影响 A2 并发、不改评测口径与真值，但**是否把它定义为「允许的执行层稳定性参数」需单独评审**，不自动解释闸门。确认后才启动 L1b' 重跑。

### 当前状态

链仍停在 L1。本轮诊断未修改任何代码、配置或数据；盲化环境保持、未 `restore --apply`；发布动作按发布验收标准执行。

## 后续复核纠正（2026-11-07，代码侧落地时）

用户随后授权「自行分析、只求组件的正确稳定性以及扫描效果的准确性，看情况落地」。落地前复核调用链时发现**初版诊断里「4 并发排队」与「L0 零代码绕开」两条对 R0b / L1b 均不成立**，必须纠正，否则发布记录会带错根因。

### 真实调用路径

- 主路径是 `src/cli/benchmark_cli.py:11021-11028` 的 `executor.submit(run_a2_integrated_scan, ...)`；该函数（`:1759`）**顺序逐文件**调用 `an.analyze()`，全程只有一个 A2 请求在飞，**不读 `SAST_AI_INTEGRATED_WORKERS`**。
- 4 并发的 `_run_integrated_analyst`（`:3095`）只在 `a2_poc` 阶段、且 `stage_cache` 命中旧产物（无集成 spec）时补跑（`:11107-11123`）。R0b / L1b 都设 `SAST_AI_STAGE_CACHE=0`，A2 阶段已置 `_a2_integrated_done=True`，该路径**从未执行**。
- 所以 `--env SAST_AI_INTEGRATED_WORKERS=2` 对这两轮零作用，第 88 条的 L0 方案不成立；第 94 条「6 项 vs 7 项 `run_env`」的口径冲突也随之消失——本轮不采用任何 `run_env` 绕开，直接修组件。

### 修正后的根因

顺序路径上，`IntegratedAnalyst(timeout=180)` → `ollama_chat(stream=False)` → `urlopen(timeout=180)`，单次请求超过 180 秒即抛 `TimeoutError`；`except Exception: specs = []` 把整个文件的 A2 语义产物静默丢弃，D2 因此少升确认态。触发超时的外部条件是本机 GPU 同时被其它项目占用（闸门采样常见「无模型常驻但利用率 23~40%」），Ollama 推理变慢、长 prompt 文件贴近 180 秒边界；632 与 635 的差异仍是阈值附近的抖动，但与 A2 自身并发无关。

### 已落地的组件修复

- `src/agents/a2_integrated_analyst.py`：超时改 env 可配（`SAST_AI_A2_LLM_TIMEOUT`，默认 300，与 `a2_ai_agent` 对齐）；`ollama_chat` 只对传输类异常做有限重试（`SAST_AI_A2_LLM_RETRIES`，默认 2）+ 退避；连续耗尽熔断（`A2LLMUnavailable`）快速失败；`contract_stats()` 暴露 transport 读数。
- `src/cli/benchmark_cli.py`：主路径失败不再 `specs = []`，改保留 `analysis_error` 可诊断占位并累计 `a2_analysis_error_stats()`；熔断冒泡让整轮判 failed；`stage_results.a2.contract` 写入 `transport` 与 `file_failures`，发布闸门可直接判定本轮是否有效。备用 4 并发路径默认并发对齐改为 2，并对失败文件串行重跑一次。
- 不改 prompt / temperature / seed / 输出契约 ⇒ LLM 判定口径零漂移，只动传输与失败处理。
- 回归锁 `tests/test_a2_llm_transport_retry.py`，13 passed。

### 代价与后续

改 `src/` 会重置 G0-3 的 `src/` 冻结基线，R0b（634）与 L1b（635）两轮结果不能再作为新代码的验收依据，必须从 R0' 起整链重跑（R0' → L1 → L3 两轮 → L2）。冻结重置条款与「有效轮」判定见 `docs/gate0_release_criteria.md` G0-1 / G0-3，具体执行设计锚在本机执行记录（不随仓库分发）。

## 第二次复核纠正（2026-11-08，复测后）

落地后启动的 R0'证明上面「修正后的根因」仍不完整，的
「超时可配 + 有限重试」方向本身也是错的。完整证据、数据对照与修复见
`docs/r0prime_invalid_round_postmortem.md`，此处只记录需要纠正的结论。

- 「外部 GPU 占用让长 prompt 贴近 180 秒边界」不是主因。636 的超时精确落在
  300 秒（的新默认值），三组共 6 次重试全部再次超时；而 634/635 共 191 次
  A2 成功调用输出上界仅 485 token、单次最长 18.4 秒，不存在「算得慢」的空间。
- 真根因是 `stream:False` + `format:json` grammar 下 `options` 缺 `num_predict`
  上限，qwen3:8b 偶发不产 EOS 时生成无限延伸到 `num_ctx` 耗尽，服务端不返回
  完整响应。历史 `submit_623~628_full.log` 里 `ClassDataLoader / Shiro / XXE
  timed out` 是同一现象，当时被 `specs=[]` 静默丢文件，所以只表现为掉点。
- 非流式请求下 socket 读超时等于「服务端没在阈值内结束生成」，重发同一 prompt
  不会更快，还可能与客户端断开后未结束的旧请求抢 GPU。的重试把单个卡住
  文件从 180 秒放大到 15 分钟以上，并让 `exhausted != 0` 使整轮按 Gate 0 无效。
- 已改正：`num_predict` 硬上限（默认 1024）+ 生成超时不重试 + 截断可观测，
  冻结基线再次重置，整链从 R0'' 起跑。本文件保留两版诊断的演进痕迹，避免发布
  记录把已被证伪的归因当成最终结论。
