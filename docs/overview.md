# R24 任务总览（2026-09-11）

## 本轮做了什么

四条指令全部落地，并在复查 #11/#8 时又发现并修掉两个真实漏洞（破坏性闸门绕过路径、A2 行号归因导致的漏绑）。

1. F1 门禁默认值 14 → 16（`check_r23_acceptance.py` + 文档 + 生成器三处同步）。
2. `a1_calculation_logic_analyzer.py` 由「含 @XxxMapping 一律跳过」改为「按方法名去重」，
   恢复控制器层通用 4.1/4.2 覆盖且不新增假说污染。
3. 破坏性重放：补全双维度闸门（payload 文本 + 端点操作语义），并补强 4 条「真实 id 仍会被发出」的绕过路径。
4. 端到端重跑：run 13 因 runner 早于本轮改动而作废，改用最终代码重提 run 14 并跑到终态；
   回查 #8 SSTI（A2 payload 带 `tpl=` 前缀）与 #11 SSRF `/admin/fetch`（A2 行号落错）。

## 关键结论

- **#11 不是「类级兜底吃掉方法级路由」**：是 A2 语义正确但行号落错（SSRF finding 挂在 ping 的 javadoc 行 40），
  按 line 解析回落到 dashboard 的 `/admin`。解析器本身正确（line 55 能出 `/admin/fetch`）。
  已按「文本点名的方法名」在同文件内纠偏。
- **#8 是 A2 把「参数名=值」整串当 payload**：注入后成 `tpl=tpl=[[...]]`，Thymeleaf 按字面渲染永不触发。
  已加前缀剥离 + exec 内破坏性命令中和。
- **破坏性闸门首版有洞**：`replay_vertical` 会回填受害者真实 uid、`replay_bola/race` 会把 `VICTIM_FROM_POOL`
  解析成真实对象 id。已补强（id 参数强制钉哨兵、victim_resource_id 含哨兵一律钉死、非 id 参数承载变更则 skip、
  rep params 兼容 DB 键形）。

## 交付物

- `round-24-fix-plan.md`：R24 轮次产物（四条指令 + 两个新发现漏洞的修法与验证）。
- `round-24-failure-reconciliation.md`：24 项既有测试失败的逐条对账与排期建议。
- `round-24-targets-review.md`：35 条真值四分类逐条对账（含 F1 定档 16 的推导）。
- 代码：`src/iast/attack_context.py`、`src/application/d1_service.py`、`src/iast/business_logic.py`、
  `src/core/param_resolver.py`、`src/agents/a1_calculation_logic_analyzer.py`、
  验收脚本。
- 测试：`tests/test_destructive_operation_guard.py`（63）、`tests/test_route_method_hint.py`（7）。

## 验证状态

- 回归：全量 `pytest tests/ --ignore=tests/e2e` = 24 failed / 1170 passed / 1 skipped；
  24 项失败经决定性隔离证明与 R24 无关（详见对账文档）。
- R24-G 爆破半径干跑（176 条真实 spec）：37 条带方法名点名，**仅 3 条改绑且全是纠正、零误伤**
  （`/admin`→`/admin/fetch`、`/order/buy`→`/order/{id}`、`/order/{id}`→`/order/import-xml`）。
- 端到端：run 13 的 runner 早于本轮改动（跑的是加固前闸门，无法验证 #11），已终止作废；
  **run 14（R24-final-guard-hardened，最终代码）已跑到终态**，读数见下节。
- 靶场终态体检：T_USER=4 / T_COMMENT=2 / T_ADDRESS=2 / T_PRODUCT=6 / T_COUPON=4（种子态）。

## run 14 终态读数（端到端验证结论）

- **F2 PASS（无 missing），F1 FAIL（业务 confirmed 5 < 16，诚实读数）**；A1/A2/B/C/D 判据全 PASS。
- 技术 18：confirmed 14 / spec-unconfirmed 2（#3、#4）/ finding-only 2（#7 SpEL、#11 SSRF）。
- 业务 17：confirmed 5（#19 IDOR `/order/{id}/pay`、#20 IDOR `/address/{id}`、#21 垂直越权 `/admin`、
  **#22 垂直越权·删用户 `/ops/user/delete`**、#23 垂直越权·审单 `/ops/order/review`）、
  spec-unconfirmed 12（#24–#35，`no-iast-evidence`）。
  run 11 诚实读数为 3 → **run 14 为 5**。

### #8：已修且端到端确认

SSTI `/marketing/preview` **confirmed**（`sink-reached-probe`）。前缀剥离 + exec 内破坏性命令中和生效。

### #11：定因已明，但瓶颈不在路由

- 修复（R24-G 方法名纠偏）在 run 14 实际生效 4 次（FrameworkProbeController `/api/fw`→`/api/fw/redis`、
  `/api/fw/es`→`/api/fw/breakchain`），且干跑 176 条 spec 零误伤。
- 但 run 14 里 **A2 没产出 AdminController 的 SSRF finding**（该控制器只有 line 31/43/55/65/71 的
  vertical_privesc 5 条），所以 ssrf 族仍无 `/admin/fetch`。R24-G 无法凭空造 finding。
- 对照：run 13 里 A2 出了这条，但 line 落在 ping 的 javadoc（40）→ 绑成 `/admin`；
  本轮干脆没出。**真正的瓶颈是 A2 对 controller 逐方法出条的稳定性/完整性**，应从 A2 侧解决。
- 该端点本身已被覆盖：spec 2067 `vertical_privesc /admin/fetch`（GET url）已 confirmed_exploitable，
  只是族标签不是 ssrf。

### 破坏性闸门：加固生效且靶场零破坏（本轮最关键的成功）

run 14 共 100 条闸门事件，`absent-id POST /ops/user/delete（params=uid, victim_resource_id）`
+ `http-absent-id ... json_body`；`skip POST /profile/update` / `POST /profile/password`。
**#22 垂直越权·删用户被确认为 confirmed_exploitable，而 T_USER 仍是 4** ——
「哨兵换掉真实 uid、越权判据保留、零持久化变更」在真实环境成立。
靶场体检全部种子态：T_USER=4 / T_ADDRESS=2 / T_COMMENT=2 / T_COUPON=4 / T_PRODUCT=6
（T_ORDER 394 为下单类追加写入，非破坏）。

## 需要你决策的一点（召回代价）

加固后闸门在 run 13 的 176 条 spec 上处置为 **138 放行 / 21 钉哨兵仍投放 / 17 skip**。
skip 的 6 个端点（`/profile/update`、`/profile/password`、`/wallet/withdraw`、`/wallet/transfer`、
`/api/comment/moderate`）对应约 6 条业务真值，会从 confirmed 变成 **`skipped_destructive_guard`（诚实 skip）**。
这是「安全换召回」的有意取舍。若要把这部分召回找回来，建议改用**非破坏性判据**
（越权读端点 / 幂等 GET / 靶场只读对照端点），而不是放开对有真实副作用的端点投放。
