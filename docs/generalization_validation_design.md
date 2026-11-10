# 泛化验证实验设计（三层）

状态：**2026-11-07 02:20 冻结**。R0与 L1已执行，L1 红线 1/47 触发 `stop_on_redline: true` 停链；L3 / L2 未执行，这两层数值仍标「待测」。实验设计部分按原样保留；机器可读状态见 `config/generalization.yaml`，L1 完整对账见 `docs/l1_route_blinding_reconciliation.md`。

## 为什么必须做

628 在四档口径下拿到可重放 24/24、红线误报 0/60。但 623→628 连续五轮都是对着同一套 31 点 jsc 真值逐点修出来的，属于「看着答案调参」：族路由、oracle 探测臂、payload 首发弹、认证兜底都针对这套靶场调过。这套数据已经失去盲测资格，只能冻结为回归集，不能再拿它证明「换个项目也行」。

README 里对 OWASP Benchmark 做过 blind-layout 消融、主动披露 8.9pp 的 URL 布局依赖，那套诚实做法应当同样应用到 jsc。泛化验证要回答的不是「还能不能拿 100%」，而是「这 100% 里有多少是能力、有多少是对靶场的记忆」，以及「换环境后是否稳定」。

## 统一口径与判定前置

三层共用 `tools/generalization_compare.py`，指标固定为静态·文件+族、动态·文件+族、重放·文件+族、严格重放、红线误报 `fp_replay`，避免各层自己另算一套。严格重放是在 `confirmed_exploitable` 且非 `framework:` 之外额外要求该 spec 确有 `replay_attempts`，用来防止换靶场后靠零重放的静态确认撑数（628 已出现 3 条）。

掉点不能直接算「先验依赖」。命中以下任一条即判为执行层干扰，必须剔除并重跑，而不是写进结论：

- 该点 `replay_attempts.status_code` 全 302 且 `Location` 指向 `/login`
- `action_json.auth_state` 为 `expired` 或 `reauth_failed`（这是本轮 D1 认证守卫新落的观测字段，正好用于此处的归因排除）
- 靶场进程重启、h2 profile 丢失、探针未织入（`no-arrival` 且无对应 sink 事件）

红线误报 `fp_replay` 在每一轮都必须为 0，这是不可让步的硬闸。

## 第一层 · 同靶场去 URL 布局先验

目标是量出 24/24 里有多少来自路由语义。jsc 的类级前缀 `/sqli`、`/spel`、`/qlexpress` 本身就携带族信息，A1/A2 可能直接据此推族。

变体生成工具 `tools/jsc_make_blind_variant.py` 已写好并在本地跑过一次（纯文件操作，不占 GPU）。它统一按「注解路径首段」做确定性盲化，把 `/sqli/jdbc/vuln` 变成无语义段；真值表按文件+族记账、源码文件名不变，因此 `data/java_sec_code_truth_v2.csv` 原样复用。

本层有四个容易踩空、已在工具里处理掉的点。一是 jsc 的注解形态混杂，除 `@RequestMapping` 外还有 `@RestController(value="/qlexpress")` 和「类级无路径、方法级写全路径」，只认第一种会漏掉约 40% 路由，残留语义会让结论偏乐观；当前实测覆盖率 146/146 = 100%（分母已扣除两个认证段）。二是 `application.properties` 里 `joychou.no.need.login.url` 与 `csrf.exclude.url` 按路径前缀配置，只改注解不改这两份，盲化后原本免登录的端点会突然变登录墙，302 会被误读成召回下降；当前 12 项白名单已同步改写。生成时只复制 `src` / `pom.xml` / README，排除 `.codeql-db*`（本机实测整树 891M、3.8 万文件，且 CodeQL 库里存着旧路由，留在变体里等于把族语义又泄漏回 A1）。第三、四个坑见下方「2026-11-07 勘误」。

本地生成结果（2026-11-07 重建）：93 个首段映射、146 处注解、12 项白名单、6 处路径字面量、39 个改动文件，原靶场源码树未被改动。已用 JDK 11 + `mvn -o -DskipTests package` 离线编译通过，产出 98 MB fat jar；抽查 `SQLI.class` 只含 `/bd31933` 不含 `/sqli`，`Login.class` 与 `WebSecurityConfig.class` 仍含 `/login`、`/logout`。**变体已编译、已部署并跑完 L1，随后 `restore --apply` 回原靶场**。

执行步骤（2026-11-06 23:43 授权；基线改用 R0 轮）：

```bash
python tools/jsc_blind_switch.py status          # 只读核对
python tools/jsc_blind_switch.py blind --apply   # 同时切靶场 jar 与 workspace 4 的 target_path
python scripts/submit_scan_task.py --name jsc-blind-L1 --workspace-id 4 --idor-app-id workspace-4 --no-sca --no-idor
python tools/jsc_four_tier.py --task-id <L1_ID>
python tools/generalization_compare.py --baseline 631 --variant <L1_ID> --mode blind
python tools/jsc_blind_switch.py restore --apply # 跑完必须还原，否则 L3 两轮不同环境
```

### 2026-11-07 勘误：初版设计的两个失效前提

初版把 `/login`、`/logout` 也纳入盲化，生成出 `/bc42c80`、`/bc94d04`。workspace 4 的 `settings_json.login.url` 与 `csrf.fetch_url` 都指向 `/login`，D1 的 `_login_wall_paths()` 与 `_logout_paths()` 同样硬依赖这两个字面量。若照初版部署，D1 拿不到会话、`/logout` 的预期跳转会被误判成认证故障，掉点会全部落在登录墙 302 上，正好命中配置里列出的 disqualifier，L1 无法回答「有多少来自路由先验」。`PROTECTED_SEGMENTS = {"/login", "/logout"}` 现在把这二者排除在 `seg_map` 之外，生成器另有硬自检：`WebSecurityConfig.java` 里 `loginPage("/login")`、`logoutUrl("/logout")` 被改写就直接 SystemExit。这两个段对应的 `Login.java` 本来就不在真值表里，保留它们不损失盲测强度。

初版还只写了「停 8080 原靶场、换盲化 jar」，没提 workspace 4 的 `target_path`。只换靶场而不换扫描源码根时，A1/A2 读到的仍是带 `/sqli`、`/spel` 的原仓库（先验根本没去掉），D1 还会按旧路由发包导致大面积 404，L1 结论无效。离线核对两棵树的扫描文件集完全一致（各 95 个文件 / 78 个 `.java`，仅根前缀不同），且 `tools/jsc_four_tier.py` 按 basename 匹配真值，换根不改变分母。`tools/jsc_blind_switch.py` 把「jar 交换 + target_path 更新 + 靶场重启」收成一次可逆操作，状态外置在 `data/blind_variants/jsc_l1_state.json`，`blind` / `restore` 默认 dry-run。

验收条件：`fp_replay` 待测、必须为 0；重放·文件+族允许下降，但每个退步点都要逐点归因到路由先验而非前述执行层干扰；严格重放与四档重放的差值不得扩大，扩大说明是靠静态确认撑数。

## 第二层 · 换未参与调优的靶场

目标是证明能力不只在 jsc 上成立。本期只接 RuoYi 4.5.1，理由是真值表 `data/ruoyi_451_truth.csv` 的列结构与 `jsc_four_tier.load_truth()` 完全一致（已本地验证：6 条 `in_scope`，族为 `sql_injection` / `command_execution`，全部动态可计），workspace 8 已配好 8081 与 Shiro `auth`，换项目的同时也换掉了认证形态。

Juliet CWE89 pilot 本期**不落地**：`data/juliet_truth.csv` 用 `(test name, category, real vulnerability, cwe)` 记账，缺 case→源码文件路径映射，四档口径按文件+族算不了。强行写一个猜测式适配只会制造假基线，故在配置里明确标 `blocked`，等映射表补齐再开。

待人工执行的步骤：

```bash
# 1) 启动 RuoYi 靶场并确认 8081 健康检查（launch_ruoyi_full.py）
python scripts/submit_scan_task.py --name ruoyi-L2-run1 --workspace-id 8 --idor-app-id workspace-8 --no-sca --no-idor
python tools/generalization_compare.py --baseline 0 --variant <L2_TASK_ID> --mode cross-target --truth data/ruoyi_451_truth.csv
```

验收条件：`fp_replay` 待测、必须为 0；首次跨靶场只建立基线，两套真值分母不同（24 vs 6），**不与 jsc 的 24/24 直接比大小**；报告里要写明哪些族完全没有 oracle 覆盖，避免把「没有判据」读成「没检出」。

## 第三层 · 同配置连跑两轮看方差

目标是量化 late-evidence 抖动。623→628 之间本来就有波动，628 是单轮结果，不能默认它稳定。两轮之间 `src/` 必须冻结，`run_env` 与 628 的五项开关完全一致。

待人工执行的步骤：

```bash
python scripts/submit_scan_task.py --name jsc-L3-run1 --workspace-id 4 --idor-app-id workspace-4 --no-sca --no-idor
python scripts/submit_scan_task.py --name jsc-L3-run2 --workspace-id 4 --idor-app-id workspace-4 --no-sca --no-idor
python tools/generalization_compare.py --baseline <L3_ID1> --variant <L3_ID2> --mode stability
```

验收条件：分母与静态·文件+族两轮必须一致（A1 静态侧不受抖动影响，不一致说明环境或代码被改动，本轮作废）；重放侧逐点列出波动并归因；两轮 `fp_replay` 都必须为 0。

## 排期与显存闸门

第一层的变体生成不占 GPU，已完成；但它最终那轮全量扫描、第二层、第三层的每一轮都要跑 A2 LLM。按此前约定，跑之前必须确认没有别的项目在用卡，闸门同时看 `nvidia-smi` 利用率与空闲显存，实验峰值要留约 3 GB 给对方，不能只看 Ollama 有没有模型常驻。建议顺序：先 L1 一轮，再 L3 两轮，L2 排在最后（要额外拉 RuoYi 靶场）。

## 已知限制

第一层的 `--scope class` 对**每个带路径注解的首段**都做 hash，方法级全路径注解同样受影响：`SQLI.java` 的 `@RequestMapping("/jdbc/vuln")` 变成 `/b7400f8/vuln`，完整路径从 `/sqli/jdbc/vuln` 变成 `/bd31933/b7400f8/vuln`。因此 L1 实测的 -12.5pp 是「路由语义先验 + 路径层结构可解析性变化」的合计上界，不能纯归因到语义记忆。要严格隔离语义可用 `--scope class-only`（只改类级注解首段、方法级路径原样），该选项已实现并有回归锁 `tests/test_jsc_blind_variant_class_only.py`，但**尚未用于实测**，不能与 632 的数字混用；`--scope all` 会把后续段也 hash，更依赖 forward 一致性，同样未验证。第二层 RuoYi 只有 6 个可计真值点，样本很小，只能作为「非 jsc 目标能否跑通链路」的存在性证据，不足以算稳定召回率。第三层两轮仍共用同一套 jsc 真值，测的是稳定性不是泛化性，不要把它和前两层混为一谈。

R0 与 L1 已出实测：R0 轮红线 0/61、重放 24/24；L1 轮重放 21/24、红线 1/47，按硬闸停链。L3 / L2 结果仍为「待测」，未启动。执行纪律不变：每轮跑前过 GPU 闸门，跑完先 `restore --apply` 再对账；L1 的逐点归因与三个待评审的口径选项见 `docs/l1_route_blinding_reconciliation.md`。
