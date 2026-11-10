# L3 run2无效轮对账：重放层靶场被并发会话抢占

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

2026-11-08。结论先行：**本轮不得计入 G0-3 的 L3 稳定性验收**。它不是「同配置两轮之间 -4.2pp 的可解释方差」，而是扫描进行到 14:56 时 8080 端口被另一个 Spring Boot 实例接管，393 条重放请求落到异构 404、IAST 事件掉 21%，最终把 `ssrf.java/ssrf` 的两条 `oracle:error_reflect` 确认打掉。旧版 `check_effective_round.py` 只查 A2 contract，把这一轮误判为 EFFECTIVE —— 真正要修的是这个门禁漏检，不是扫描组件，也不是闸门口径。

## 一、执行与终态

| 项目 | 值 |
| --- | --- |
| 轮次 | `jsc-L3-run2-20261108c` → L3 run2|
| 提交 | 14:23:05，GPU 闸门连续 3 次采样通过（free 6709/6759/6760 MiB，util 9/9/8%，无常驻模型） |
| 终态 | 15:37:06 `status=completed`，四档 15:37:07 落盘 |
| `run_env` | 6 项，与 639 完全一致，仅 `SAST_AI_D1_DUMP_PATH` 换为 `logs/d1_req_dump_L3r2c.jsonl` |
| `options_json` diff | 仅 `run_env.SAST_AI_D1_DUMP_PATH` 一项，其余 20 个键逐字段相同 |
| A2 contract | 与 637 / 639 **逐字节一致**：95 calls / 91 first_pass / 4 retried / 1 recovered / 3 failed / `truncated=3` / `file_failures.failed_files=0` / transport 全 0 |
| 静态产物 | findings 389 条、trigger_specs 151 条，与 637 / 639 数量及 source 分布一致 |

即 A1 / A2 三层输出完全确定性，掉点不可能来自 LLM 生成或静态建库。

## 二、初验读数（旧判据下曾判通过）

四档 `data/validation_runs/jsc-L3-run2-20261108c.four_tier.txt`：静态·文件级 31/31、静态·文件+族 30/31、动态 23/24、重放·文件+族 23/24、严格重放 23/24、红线 `confirmed_replay` 0/61（旧口径 0/65）。

`generalization_compare.py --baseline 639 --variant 640 --mode stability`：分母同为 24、静态·文件+族同为 24/24、红线原始 0 条 → 有效 0 条、预登记例外未命中、`gate.redline_pass=true`。唯一异常是动态 / 重放 / 严格重放各从 24 掉到 23（-4.2pp），退步点为 `ssrf.java/ssrf`。

按当时 Gate 0 的 L3 条款，两轮都 EFFECTIVE、分母与静态侧一致、红线清零，只差「逐点差可解释」。就是因为这一条没放过，才继续下钻并发现了下面的环境证据。

## 三、逐点归因：`ssrf.java/ssrf` 的 1 点

`measure()['rules']` 在该真值点上的 `n_confirmed_replay`：639 为 **2**，640 为 **0**。两条确认 spec 的去向如下。

| 端点 | 639 spec | 640 spec |
| --- | --- | --- |
| `/ssrf/urlConnection/vuln` | 240412 `confirmed_exploitable` / `oracle=exploitable` / `positive_evidence_rule=oracle:error_reflect` / 8 次重放 | 240584 `unconfirmed` / `oracle=inconclusive` / `no_ssrf_effect` / sink-reached / 18 次重放 |
| `/ssrf/HttpSyncClients/vuln` | 240417 `confirmed_exploitable` / `late-evidence-recovered` / `oracle:error_reflect` / 8 次重放 | 240589 `unconfirmed` / `oracle=inconclusive` / `no_ssrf_effect` / no-arrival / 18 次重放 |

两轮都发出了带 `java.net.UnknownHostException: evil.example.com` 错误反射的 200 响应，但 640 的 IAST 证据没到（`no-arrival`）或只到 sink，oracle 因此判 `inconclusive`。整体 oracle 分布也从 639 的 `47 exploitable / 39 inconclusive` 漂到 640 的 `44 / 53`，`confirmed_exploitable` spec 从 68 降到 65 —— 不是单点抖动，是一条通道整体变弱。

## 四、重放层环境指纹（决定性证据）

| 轮次 | attempts | 404 | 404 率 | 404 端点数 | Spring 错误体格式 | IAST 事件 | 认证态 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 634 | 2271 | 43 | 1.9% | 3 | epoch | 6169 | 99.6% |
| 635 | 1068 | 24 | 2.2% | 2 | epoch | 3625 | 99.5% |
| 637 | 1939 | 35 | 1.8% | 3 | epoch | 4976 | 99.5% |
| 638（盲化树） | 1077 | 24 | 2.2% | 2 | epoch | 3988 | 99.7% |
| 639 | 1940 | 35 | 1.8% | 3 | epoch | 5182 | 99.5% |
| **640** | **2336** | **428** | **18.3%** | **20** | **epoch 35 + iso 393** | **4071** | **99.6%** |

两种 404 响应体是不同应用实例的指纹：

```text
epoch（java-sec-code 本体，正常）
{"timestamp":1794120134425,"status":404,"error":"Not Found","message":"No message available"}

iso（14:56 起出现，带 path 字段）
{"timestamp":"2026-11-08T06:56:37.863+00:00","status":404,"error":"Not Found","path":"/ssrf/urlConnection/vuln"}
```

按 10 分钟桶看 640 的 404 演进，切换点非常干净：

| 时段 | 请求数 | 404 | iso 格式 |
| --- | --- | --- | --- |
| 14:40 | 1305 | 24 | 0 |
| 14:50 | 737 | 113 | 105 |
| 15:00 | 142 | 142 | 142 |
| 15:10 | 146 | 146 | 146 |
| 15:20 | 6 | 3 | 0 |

15:00 与 15:10 两个桶**全部请求 404**，跨 17 个端点（`/ssrf/*`、`/xlsx-streamer/readxlsx`、`/classloader`、`/rce/groovy`、`/deleteCookie`、`/login` 等）。登录态仍为 `authenticated`，302 数量 130 与 639 的 135 持平，可排除「登录墙全 302 / auth_state expired」这类已知 disqualifier；问题不是认证，是应答方换了。

## 五、并发会话证据

640 结束后查 8080 占用，发现本机同时有另一个 AI IDE 会话在操作同一端口：

```text
PID 20088  15:46:05  java -jar target/java-feed-1.0.jar
PID 59184  15:46:08  java -jar target/elegant-spell.jar
           父进程：Trae CN 的 PowerShell 命令执行（命令行含 java -jar target/elegant-spell.jar）
PID 57548  15:50:40  java -javaagent:sec-probe.jar ... -Dserver.port=8080 \
           -jar <java-sec-code 靶场目录>/target/java-sec-code-1.0.0.jar
```

`data/blind_variants/jsc_l1_state.json` 仍为 `mode: original`，原 jar md5 仍为 `73be1cb1d1b201d2cc9df9aa7ade576f`，说明**不是本项目 L1 盲化切换残留**。

**一处探活更正（不影响结论）**：15:5x 首次复探 8080 一度返回 502 / `code=000`，事后查明是本机 `HTTP_PROXY=http://127.0.0.1:19186` 让 curl 走了代理，叠加 15:50:40 才拉起的 JVM 尚在冷启动（约 130 秒）。改用 `curl --noproxy '*'` 后 `/login` 200，`netstat` 显示 8080 唯一 listener 为 PID 57548（带 `sec-probe.jar` 的 `java-sec-code-1.0.0.jar`），另两个 jar 进程已退出。**640 的 404 证据全部来自 `replay_attempts.resp_body_head` 落库记录，由扫描进程直接写入，不经过 curl / 代理**，故无效轮判定不受影响。当前靶场已恢复独占，但距另一个会话起停仅十余分钟、稳定时长不足，且 GPU 闸门未过，本轮不发车。

结论：640 违反 Gate 0 L3「两轮之间靶场状态全部不变」，命中 disqualifier「靶场重启 / 被替换」。这一轮的 23/24 是环境读数，不是稳定性结论。

## 六、把漏检的判据补上

`tools/check_effective_round.py` 增加「重放层环境一致性」硬条件，从 `replay_attempts` / `iast_events` 只读抽取指纹：

- 404 率 ≤ 10%、404 端点 ≤ 4、Spring 错误体格式 ≤ 1 种、IAST 事件 > 0、认证态请求占比 ≥ 90%；
- fail-closed：DB / 表 / 本轮 attempts 缺失即 INVALID；
- `--no-replay-env` 仅供历史对照，输出 `[EXEMPT]` 且 `check_replay_env=false`，不得用于 Gate 0 新轮次；
- 新增 `--db`，`--json` 输出 `replay_env` 明细与 `check_replay_env` 标记。

阈值不是拍脑袋：634/635/637/638/639 的实测上界是 2.2% / 3 端点 / 单一 epoch，盲化变体 638 也在其中，无需为 L1 单独开豁免；640 是 18.3% / 20 端点 / 两种格式，分离清晰。

回归锁 `tests/test_check_effective_round_replay_env.py`（20 例，含真实 sqlite 构造、`_error_body_shape` 代际识别、640 真实指纹回放、638 不得误伤、CLI 强制检查与豁免）。`tests/test_check_effective_round.py` 的 `_contract_from_db` monkeypatch 同步适配新增的 `db_path` 参数，语义不变。定向合计 **35 passed**。

真实库复判（下列三位数是数据库里的运行轮次 ID，与工程流程编号无关）：

```text
run 636: INVALID（非 completed + A2 contract 缺失，历史无效轮，判定不变）
run 637: EFFECTIVE  replay_env.error_body_shapes = ['epoch']
run 638: EFFECTIVE  replay_env.error_body_shapes = ['epoch']   ← 盲化轮未误伤
run 639: EFFECTIVE  replay_env.error_body_shapes = ['epoch']
run 640: INVALID    replay_env.error_body_shapes = ['epoch', 'iso']
                     failed: not_found_ratio / not_found_endpoints / error_body_shapes
```

## 七、判定与后续

- **640 判 INVALID**，不计入 G0-2 / G0-3；`l3_stability_compare.json` 降级为被污染轮的证据，不作稳定性结论。
- **L3 需要在环境干净后重跑**。639 仍是有效 run1；重跑至少补一轮有效 run2 并复做 `--mode stability`。若期间 8080 再出现异构 404，按新门禁直接判无效，不再做「可解释方差」的主观判断。
- **前置**：确认 8080 只由带 `sec-probe.jar` 的 `java-sec-code-1.0.0.jar` 独占、无其他会话起停靶场、带会话探活原路由正常、GPU 闸门通过。并发会话的进程不属于本项目，不做清理。
- **当时环境**：8080 探活返回 200、无 running/pending 任务，GPU 空闲显存低于闸门 6200 MiB 下限，因此本轮未启动。运行期读数仅作复现条件记录，不作为结论。
- **不变项**：`src/**/*.py` 零改动、主真值表零改动、6 项 `run_env` 不变、`rescan_baseline_task_id=637` 不变、不重置冻结基线。只改 `tools/` + 测试 + 文档。
- **不采取的动作**：不把 23/24 当作方差放行，不放宽红线 / 重放口径，不新增预登记例外；发布动作按 docs/gate0_release_criteria.md 执行。
