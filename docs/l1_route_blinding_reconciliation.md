# L1 路由语义盲化验证对账

> 口径：文中的数字是数据库里的运行轮次 ID，用于定位证据，不含工程流程编号。

基线 R0 轮（红线清零轮），变体 L1 轮 `jsc-L1-blind-route-20261107`，真值 `data/java_sec_code_truth_v2.csv`。执行时间 2026-11-07 01:29—02:16，耗时约 46 分钟。

## 一、结论

**闸门未通过，验证链停在 L1，未进入 L3 / L2。** 红线 `fp_replay` 从 0/61 变成 1/47，不满足执行配置里 `stop_on_redline: true` 的硬闸。L1 完成后已 `tools/jsc_blind_switch.py restore --apply` 还原原靶场与扫描源码根，环境回到 R0 状态。

同时确认：掉点不能归因到认证、探针或靶场故障（见第三节），所以 -12.5pp 是有效读数，不是执行层噪声。但红线那一条不是平台幻觉，详见第五节；它的定性会决定下一步该修代码还是修口径，留待评审。

## 二、四档与红线

- 静态 · 文件级：31/31 → 30/31；文件+族：30/31 → 29/31。
- 动态 · 文件级：25/31 → 23/31；文件+族：25/31 → 22/31。
- 可重放族（分母 24）：动态 24/24 → 22/24；文件+族 24/24 → 21/24。
- 新口径重放：24/24 → 21/24；严格重放：24/24 → 21/24。两者差值没有扩大，说明掉点不是靠静态确认撑数。
- 红线 `fp_replay`：**0/61 → 1/47（2.1%）**；旧口径 0/67 → 2/50。
- `confirmed` 总数 78 → 59，其中静态自动确认 8 → 7、真实重放确认 61 → 47、零重放确认 6 → 3。
- 候选规模：findings 388 → 152、specs 149 → 104、replay_attempts 1920 → 1069、`logs/d1_req_dump_L1.jsonl` 397 行。

`generalization_compare.py --baseline 631 --variant 632 --mode blind` 给出逐点差集：静态·文件+族 -4.2pp，动态/重放/严格重放各 -12.5pp，新命中 0、退步 3。

## 三、disqualifier 排除（掉点不是环境干扰）

- 登录墙 302：631 共 135 次 302、其中 Location 落 `/login` 9 次；632 共 53 次 302、落 `/login` 同样 9 次。绝对量与占比都没有恶化。
- `auth_state`：两轮全部 302 记录的 `action_json.auth_state` 都是 `authenticated`，无 `expired` / `reauth_failed`。D1 per-request 认证守卫与「认证段不参与盲化」的修复按预期工作。
- 404：35 → 24，不升反降；没有出现「D1 按旧路由大面积发包」的迹象，runner 的 `--target` 也确认指向盲化树。
- 探针：632 的未确认 spec 分布为 sink-reached 20、no-arrival 17、no-iast-evidence 4、payload_unavailable 2、sink-reached-probe 2；no-arrival 与 631 的 19 条同量级。L1 前已实证探针事件落在 `session_id=8, workspace_id=4`。
- 靶场：L1 全程 8080 PID 45372 未变，h2 profile 与 `-javaagent` 参数不变；restore 后才重启为 PID 50832。

四条 disqualifier 全部排除。这一层的掉点是真实的能力变化读数。

## 四、三个退步点逐点归因

- `websockets.java / xss`：631 有两条 `confirmed_exploitable` spec，都靠 `technique_oracle:xss_reflected` 命中，端点 `/websocket/cmd`；632 **完全没有生成该 spec**。这是最干净的一例：源码没变、sink 没变，仅路由名从 `/websocket/cmd` 变成无语义段，A2 就不再把它识别成反射 XSS 候选。静态侧 24/24 → 23/24 掉的那一分也在这里。
- `jsonp.java / jsonp_referer`：631 一条 spec（`/jsonp/vuln/referer`，6 次重放）被 `technique_oracle:jsonp_reflect` 确认；632 生成了两条 spec，一条端点 `/bfaab7d/b2dbf7f` 判 `unconfirmed/sink-reached`，另一条 `/bfaab7d/bf33785/referer` 判 `sink_reached`。正确路径是后者，但 technique oracle 没拿到回显证据。表现为「端点选择发散 + 探测臂没落在正确路由」。
- `fileupload.java / file_upload`：631 是 `sink-reached-probe`、10 次重放、端点 `/file/upload` 并确认；632 是 `sink-reached`、仅 2 次重放、端点 `/b0a63e1/b868347`。探测臂数量骤减，与两步重放里「读端点定位」依赖路由布局有关。

三例共同指向 I1 路由解析与 A2 候选生成对路径语义的依赖，而不是 D1 投递或 D2 判据失效。

## 五、红线误报的定性（与 629 不同）

误报 spec 是 239481：`log4j.java / xss`，端点 `/b496e96`，参数 `token`（query），12 次重放，`iast_state=late-evidence-recovered`，`verification_status=confirmed_exploitable`。真值表里 `log4j.java` 的 in_scope 族是 `jndi_injection`，没有 `xss`，因此按四档口径判误报。

但查盲化源码 `Log4j.java` 的控制器方法：

```java
@RequestMapping(value = "/b496e96")
public String log4j(String token) {
    logger.error(token);
    return token;
}
```

`return token;` 是原样回显，D1 的 XSS 弹在响应体里逐字命中（`<sastxsscb9c>…`、`oracle:reflect` 的 `<sastxss1>` 全部回显）。所以从 DAST 证据看，这是一个真实存在的反射型 XSS，只是真值表没有为该文件登记 `xss` 族。R0 里同一条是 `confirmed_code_property` + `confirm-gate:sink-reached`，没有升级；L1 去掉 `/log4j` 这个语义提示后，A2 不再把它锁在 JNDI，动态回显证据反而把它推到了 XSS。

也就是说，这条红线是「真值口径未覆盖的附带漏洞」，不是 629 那种 `tomcatfiltermemshell.java/command_execution` 的族错配幻觉。路由先验在这里的作用恰好相反：它抑制了一个超出真值表的动态发现。把它简单当成「平台退化、修完重跑」会掩盖这一点。

## 六、本层设计的局限（必须写进结论）

生成器 `--scope class` 对每个带路径注解的**首段**都做 hash。jsc 里存在大量「类级无路径、方法级写全路径」的写法，例如 `SQLI.java` 的 `@RequestMapping("/jdbc/vuln")` 被改成 `/b7400f8/vuln`，类级 `/sqli` 被改成 `/bd31933`，完整路径从 `/sqli/jdbc/vuln` 变成 `/bd31933/b7400f8/vuln`。

因此 L1 量到的 -12.5pp 是「路由语义先验 + 路径层结构可解析性变化」的**合计上界**，不能纯归因到语义记忆。要严格只隔离语义，需要一个「保留路径形状与层数、只把段名换成等长无语义词、方法级子路径不动」的变体，这是后续可选的改造，本轮没有做。README 与设计文档里原来写的「只盲化路径首段，方法级子路径仍保留语义」与生成器实际行为不符，已在本次勘误中修正说明。

## 七、下一步（待评审）

2026-11-07 补：为让决议有实测数字而不是空口讨论，新增只读影子口径能力：`tools/jsc_four_tier.py --truth-addendum` 与批量复算脚本 `tools/truth_addendum_impact.py`，候选行放在 `config/truth_addendum_l1_log4j_xss.csv`，明确标 PROPOSED / NOT ADOPTED，主真值表 `data/java_sec_code_truth_v2.csv` 未改一个字节。628 / 629 / 631 / 632 四轮复算的完整输出见 `docs/truth_addendum_impact_20261107.md`。

- 选项 A：把 `log4j.java/xss` 作为真值补充登记，重算 631/632 两轮口径后再判红线。实测代价：632 红线 `1/47 → 0/47`，闸门立即通过；但 `in_scope` 分母 31→32、动态分母 24→25 会作用到**所有**历史轮次，628 重放 23/24→23/25（-3.8pp）、629 同样 -3.8pp、**631 R0 从 24/24 = 100% 掉到 24/25 = 96%（-4.0pp）**，632 自己 21/24→22/25（+0.5pp）。根因是 R0 原路由下这个点并没有动态确认，补进去等于凭空新增一个全历史漏报点。所以这不是零代价的「修正口径」，而是把一次真实发现换成四轮账面退步。
- 选项 B：收紧 late-evidence 通道，要求动态升级的族与静态侧登记族一致或有值级交叉证据。代价是会压制「动态发现真值表外新族」的能力，可能把这次的正确发现一起压掉。
- 选项 C：把这条红线作为 L1 的已知限制如实披露，放宽闸门继续 L3 / L2，先拿到稳定性与跨靶场数据，再回头处理口径。

三个选项都涉及口径或闸门变更，需单独评审。建议选 C：先如实披露并放宽闸门拿到 L3 / L2 数据，把真值口径作为独立议题单独处理，避免为了过闸改评测标准。当前环境已还原，发布动作按 docs/gate0_release_criteria.md 执行。
