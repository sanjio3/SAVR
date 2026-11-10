# 统一命名度量衡（NAMING_STANDARDS）

扫描日期：2026-09-04
范围：src/ 全量（字段名 / 表名 / 函数名 不统一导致的匹配断点）
目的：在动手改代码前先把所有"同一个概念多种叫法"列清，给出每簇的规范名与收敛建议，避免越修越接不上、上下文压缩后命名漂移。

## 核心结论（先讲最危险的三处）

1. 漏洞族名（family）有 7 种字段名 + 多套大小写/中英文取值同时并存，是全项目最大的"度量衡"混乱源，也是召回漏斗里"检测到但没确认"的部分根因（族名归一失败 → A2 过检/漏检 → D2 门禁挡掉）。
2. 端点字段有 6 种叫法（target_endpoint / entry_point / route / endpoint / entry_route / http_path），且 `target_url` 常被重载成"目标应用基址"而非"漏洞路径"，历史修复多次因字段名错位而白做。
3. canary 概念在 spec 里叫 `taint_marker`、在探针事件里叫 `canary`、在常量里叫 `TRACE_HEADER`、派生前缀叫 `canary_identity`，四名字指同一物，读代码必须知道它们是同一个值。

下方按概念分簇。每簇给出：规范名、别名变体（含 file:line）、断点危害、收敛建议。

---

## 簇一：漏洞族名（vulnerability family）—— 最高优先

同一漏洞类别在本项目里同时用以下字段名携带，且取值大小写/中英文/缩写各不相同。

### 规范名（唯一真相源）

- 规范 token 集合：`DIFFERENTIAL_PROOF_FAMILIES`，定义于 `src/core/exploit_spec.py:28`。
  集合内容：`bola` `idor` `vertical_privesc` `cross_module_privesc` `state_machine` `race` `calculation_logic` `auth_session` `abuse_dos`。
- 唯一归一函数：`canonical_business_logic_family(raw)`（`exploit_spec.py:105`）、`is_business_logic_family(norm)`（`:122`）。
- 别名表：`_BUSINESS_LOGIC_FAMILY_ALIASES`（`exploit_spec.py:32`，含 72 条中英文别名 + 连字符/下划线防御形态）。
- 唯一判据：下游一切"是否业务型"判定必须经 `is_business_logic_family` / `derive_flow_type`（`exploit_spec.py:126`），不得各自硬编码族列表。

### 承载该概念的字段名（全部别名）

- `vuln_type`：A1 离线分析器使用，取值为大写，如 `"BOLA"`、`"VERTICAL_PRIVESC"`、`"STATE_MACHINE"`、`"MASS_ASSIGNMENT"`。
  - `src/agents/a1_bola_analyzer.py:163`
  - `src/agents/a1_vertical_privexpansion_analyzer.py:85`
  - `src/agents/a1_state_machine_analyzer.py:67`
  - `src/agents/a1_bola_analyzer.py:179`
- `family`：A1 分析器与 exploit_spec 同时使用的字段名，取值为连字符小写，如 `"IDOR"`、`"mass-assignment"`。
  - `a1_bola_analyzer.py:164`（`"family": "IDOR"`，注释明写"BOLA→IDOR 以便 vuln_hash 对齐"）
  - `a1_bola_analyzer.py:180`（`"family": "mass-assignment"`）
  - `exploit_spec.py:149`（`resolve_spec_family` 读 `spec.get("family")`）
- `category`：双重歧义字段。
  - 在 A1 离线分析器里是中文描述串，如 `"不安全对象存储"`（`a1_bola_analyzer.py:181`）；
  - 在 A2 / trigger_specs / D2 里是规范小写 token，如 `"bola"` `"vertical_privesc"`（`a1_vertical_privexpansion_analyzer.py:86`、`a2_intelligent_agent.py:1622`、`trigger_specs.category` 列 `db.py:677`）。
  - 即同一个字段名 `category`，在不同模块含义完全不同，且没有任何转换层强制归一。
- `payload_family`：A2 语义分析主输出字段，取值如 `"idor"` `"ssrf"` `"auth-bypass"`（`a2_intelligent_agent.py:1585`、`a2_contract_planner.py:910/979/1021`、`d2_strategy.py:88`）。
- `business_logic_category`：trigger_specs 列（`db.py:678`）+ D2 路由字段（`d2_facade.py:307` `_resolve_business_logic_category` 优先读此字段）。
- `display_family`：评估报告里出现的字段名（`evaluation_service.py:25` `"display_family": "idor"`），与 `payload_family` / `family` 又是一套别名。
- `business_logic`（布尔）：`d2_facade.py:452/481` 用作"是否走差分重放"的布尔标记，与 `business_logic_category`（字符串）名字相近但类型/语义不同，易混淆。

### 取值层面的别名分裂（同一概念多种写法）

- 水平越权：`BOLA`（vuln_type）/ `IDOR`（family 别名，历史对齐用）/ `bola`（规范 token）/ `idor`（payload_family，D1 重放路由特例 `d2_facade.py:26` `_BL_ROUTE_OVERRIDES={"idor":"bola"}`）。
- 垂直越权：`VERTICAL_PRIVESC`（vuln_type，**拼写错误**，缺 L）/ `vertical_privesc`（规范 token）/ `vertical`（别名）/ `privesc`（别名）。注意 A1 分析器文件名是 `a1_vertical_privexpansion_analyzer.py`，"privexpansion" 亦非标准拼写。
- 状态机：`STATE_MACHINE`（vuln_type）/ `state_machine`（规范 token）。
- 批量赋值：`MASS_ASSIGNMENT`（vuln_type）/ `mass-assignment`（family）/ `calculation_logic`（规范 token，别名表把 mass-assignment 归到 calculation_logic，`exploit_spec.py:60`）。
- 金额/计算：`calculation_logic`（规范 token）/ `amount-tampering` / `quantity-tampering`（别名）。

### 断点危害

- A1 分析器一个假说同时带 `vuln_type`+`family`+`category` 三个字段，下游没人统一消费，常各取一个 → 跨阶段去重（vuln_hash）按 `vulnerability_hash_v2` 对齐，但族名维度对不齐时会出现"同漏洞多族分裂"或"族名空导致门禁误杀"。
- `VERTICAL_PRIVESC` 拼写错误若流入 DB 或报告，后续按 `vertical_privesc` 查询会查不到（已靠别名表兜底，但源头脏）。
- `category` 中文/英文双义：A1 写中文、A2 写英文 token，若某处用 `category` 做路由而上游给的是中文，直接落空。

### 收敛建议（已按 2026-09-04 执行记录校正）

- 规范 token 集合不变：`bola` / `idor` / `vertical_privesc` / `cross_module_privesc` / `state_machine` / `race` / `calculation_logic` / `auth_session` / `abuse_dos`。任何模块产出族名，必须经 `canonical_business_logic_family()` 归一后再落库/传递（已在 repositories.py `_upsert_vulnerability_instance` 落库点加归一）。
- **`display_family` 是事实上的规范展示族名字段，不删除**（2026-09-04 复核纠正：此前"删除 display_family"的建议基于不完整的 grep；实测 `display_family` 被 report_manager / repositories / metrics / ticketing / vuln_hash 等 15+ 处作为规范归一族名消费，是 findings 层最稳定的族名字段）。收敛方向改为：**`payload_family` / `family` / `category` / `vuln_type` 均为源字段，最终都归一进 `display_family`**；`vuln_type` 仅人类可读展示（大写 BOLA 等）。
- `vuln_type` 拼写修正：`VERTICAL_PRIVESC` → `vertical_privesc`（已在 a1_vertical_privesc_analyzer.py 修正），分析器历史文件名 `a1_vertical_privexpansion_analyzer.py` → `a1_vertical_privesc_analyzer.py`（已重命名并同步 import 与注释）。
- `business_logic`（布尔/结构标记）**保留不重命名**：它是验证结果/攻击证据等多处结果 dict 共用的"是否业务型差分验证"标记键（vr / ae / a1_evidence / dast_impact_evidence 多 dict 共用），与字符串族名 `business_logic_category` 语义不同。统一以 `business_logic` 为规范标记键，避免局部改名反而制造更多分歧。
- A1 离线分析器产出物经 `canonical_business_logic_family` 归一后再落库（落库点已加归一，见 repositories.py）。

---

## 簇二：受害者资源 id（victim resource id）

### 规范名

- `victim_resource_id`：trigger_specs 列（`db.py:681`）、exploit_spec.prerequisites（`exploit_spec.py:219`）、A2 产出（`a2_intelligent_agent.py:1819/1822/1836`）、D1 重放回写（`d1_service.py:990`）。
- 配套列表字段：`victim_identifiers`（trigger_specs 列 `db.py:682`；D1 差分"泄露判定"用 `d1_service.py:935/957`）。

### 别名变体

- `resource_id`：在 `d1_service.py:863` 被当作 `victim_resource_id` 的兜底读取（`spec.get("victim_resource_id") or spec.get("resource_id") or ""`）。
  - 注意：`db.py:300` 的 `resource_id` 是另一张表（iast 会话/DAST 流量采样）的列，表示"DAST 资源 id"，与"受害者资源 id"语义不同。此处同名是潜在碰撞点：若某 spec dict 误带 DAST 的 `resource_id`，会被误当受害者 id。
- `VICTIM_FROM_POOL`：哨兵值（`a2_intelligent_agent.py:1822`），表示"运行时由账户池解析真实受害者 id"，由 `d1_service.py:874` 消费。
- `victim_id`：曾出现在历史修复说明里，当前 grep 仅见 `d1_service.py:863` 附近作为变量名 `victim_id`，非独立字段名（已核实当前代码无 `spec.get("victim_id")` 读取，此条为变量名，非字段名冲突）。

### 断点危害

- A2 把真实 id 写在 `exploit_spec.prerequisites.victim_resource_id`，但历史业务重放路径 `_build_business_logic_spec` 只读 `ae.victim_resource_id` / `vuln.victim_resource_id`，不读 prerequisites → 受害者 id 恒空 → URL 拼成 `/address/`（空 id）→ 探针 `ExecutorQueryAdvice` 碰不到 `findById` → BOLA_SUSPECT 永不为 0。这正是"检测到但没确认"的业务型根因（已在  修复，本次审计确认修复点已接回 prerequisites 三源）。
- `resource_id` 兜底读取与 DAST `resource_id` 同名不同义，是隐蔽的语义陷阱。

### 收敛建议

- 全项目统一字段名 `victim_resource_id`；删除 `resource_id` 作为受害者 id 的兜底（或改名 `dast_resource_id` 以区分 DAST 语义）。
- 哨兵 `VICTIM_FROM_POOL` 保留，但需在文档中明确"仅在双账户差分重放且未解析出具体 id 时使用"。
- `victim_identifiers` 与 `victim_resource_id` 用途不同（前者是泄露判定用的标识集合，后者是重放注入的具体对象 id），命名已清晰，保持。

---

## 簇三：端点 / 路由（endpoint / route）

### 规范名

- 漏洞路径权威字段：`trigger_specs.target_endpoint`（`db.py:624/798/803`）。
- exploit_spec 内部结构：`entry.route` / `entry.method`（`exploit_spec.py:201` `empty_exploit_spec`）。
- 唯一解析真相源函数：`resolve_endpoint_full`（`trigger_spec_registry.py:295`），统一调 `resolve_trigger_endpoint` + 越权真实路由纠正 + 业务族 Service→Controller 推导。

### 别名变体（同一"漏洞 HTTP 路径"概念的叫法）

- `target_endpoint`：trigger_specs 列；benchmark_cli 写回（`benchmark_cli.py:2016` 优先 `_route` 否则 `ae.target_endpoint`/`vuln.entry_point`/`vuln.target_endpoint`）。
- `entry_point`：vuln 对象/字典字段；report_manager 大量读取（`report_manager.py:379/380/551/684/727/813/1379/1412`）；benchmark_cli `all_vulns` 透传（`:2171`）。格式多为 `"文件:行号"` 或 `"METHOD /path"`。
- `route`：exploit_spec.entry.route、discovery 产物 item（`benchmark_cli.py:1409/1471/1483/1506/1537`）、chain_builder（`chain_builder.py:78/84/168/191`）。
- `endpoint`：trigger_spec_detail 透传字段（`report_manager.py:1530` `_entry['route'] = _tsd['endpoint']`）、benchmark_cli（`:2487` `_ts.get('target_endpoint')` 与 `:2830` `endpoint` 混用）。
- `entry_route`：chain_builder 派生（`:168` `ep["route"]`）、report_manager（`:518/602` `routes['entry_route']`）。
- `http_path`：code_retriever 回退读取（`code_retriever.py:146` `fv.get("http_path")`）。
- `target_url`：语义被重载——多数地方是"目标应用基址"（如 `task_service` 的 `target_url`、`benchmark_cli:2610/2654/2676/2765`），但在 report_manager POC 生成里又被拼成完整攻击 URL（`report_manager.py:518/521/524/602`）。两义混用，是历史上"端点没接上"反复出现的坑。

### 断点危害

- 解析真相源 `resolve_endpoint_full` 在业务重放路径长期被旁路（本次 已修复接回），旧路径从 `ae.target_endpoint or vuln.entry_point or vuln.target_endpoint` 取端点，常为空 → 端点空 → 重放打不到 findById。
- `_pre_resolve_a2_endpoints`（`benchmark_cli.py:1689`）历史上只在 `resolvable=True`（route 且 param_name 双非空）时写回，否则清空 entry 全部 key，会抹掉已探明的 ground truth 路由（业务类无"参数名"概念，整条被清空）。**该清 key 行为已于 benchmark_cli.py:1740-1745 移除**：失败分支现在只写 `entry["entry_resolution_failure"]` 原因、不清空任何 key，门禁改由该字段显式判定；"清 key 副作用"不再是当前问题。
- `target_url` 重载导致"端点"和"基址"分不清，POC 拼 URL 时容易把基址当路径或反之。

### 收敛建议（已按 2026-09-04 执行记录校正）

- 区分两类语义，二者不混用、不强行合并：
  - `entry_point` = **代码定位**（"文件:行号" 或 "METHOD /path"），用于报告展示与人工溯源；保留。
  - `target_endpoint`（trigger_specs 列）与 `entry.route`（exploit_spec 内部键） = **HTTP 路径**，是重放与 D2 路由用的规范路径；二者经 `resolve_endpoint_full`（`trigger_spec_registry.py:295`）唯一桥接。
- 业务重放 spec 一律经 `resolve_endpoint_full(code_root=..., discovered_routes=...)` 取端点（已落地），禁止在业务路径另起直接取 `ae.target_endpoint`/`vuln.entry_point` 的解析（旧字段仅作 `resolve_endpoint_full` 失败时的保底回退，不得作为主路径）。
- `endpoint`（trigger_spec_detail.endpoint）、`entry_route`、`http_path` 均为 `target_endpoint`/`entry.route` 的别名视图，消费端统一归一读取；不新增独立落库字段。
- `target_url` 语义仅作"目标应用基址"（与 `service_url` 同义），**不得**兼表漏洞路径；路径一律用 `target_endpoint`。代码库存在混合使用，列为已知技术债，待下次相关改动时梳理，不在本轮大改。

---

## 簇四：canary / 污点标记

### 规范名

- canary 本体（完整随机串）：在 trigger_spec / spec 里字段名是 `taint_marker`；在探针事件表 `iast_events.canary` 列里叫 `canary`；二者是同一值。
- 注入头常量：`TRACE_HEADER = "X-SASTAI-Trace"`（`attack_context.py:32`），D1 重放把 `taint_marker` 注入此头（`d1_service.py:623/625/895`）。
- 派生身份段：`canary_identity`（取 `s4st41`+16hex 前缀，`attack_plan_service.py:108`；`CanaryMatcher.find_identity` 归一，`d2_facade.py:374`）。

### 别名变体 / 相关字段

- `taint_marker`：spec 字段（D1 读取 `d1_service.py:529/892/1108/1190`；D2 读取 `d2_facade.py:373` `trigger_spec.get("taint_marker")`）。
- `canary`：iast_events 列（`db.py:583` 起）、`CanaryMatcher` 入参、`poll_events_by_canary` / `poll_authz_blindspots` 查询键（`d2_facade.py:165/379`、`d1_service.py:1046`）。
- `canary_state` / `canary_match`：iast_events 列，表示命中状态（`attack_plan_service.py:78/79`、D2 判定 `d2_judge.py:261-263`）。

### 断点危害

- `taint_marker`（spec 侧）与 `canary`（事件侧）名字不同，新人极易误以为是两个值。历史修复多次因"业务 spec 漏绑 taint_marker → IAST 消费端读空 canary → fail-open 跳过"而踩坑（本次 的 `_attach_business_canary` `benchmark_cli.py:2028` 已修复绑定）。
- `canary_identity` 仅 22 字符前缀，前端展示用；若误把整串当 identity 或反之，关联查询失效。

### 收敛建议

- 文档中明确：`taint_marker` ≡ `iast_events.canary`，是同一个完整随机串；`canary_identity` 是其 22 字符前缀，仅用于展示与粗粒度关联。
- 变量命名建议统一：D2/D1 内部统一用 `canary`（完整值），避免混用 `taint_marker`/`canary` 两名字；spec 落库字段保持 `taint_marker` 但加注释"≡ canary"。

### canary_state 取值增补（设计一① 引入）

- `sink-reached`：Python 侧被动兜底态——仅在事件文本里命中平台 canary 身份段、但无探针 sink 现场显式断言时由 `agent_bridge._translate_probe_event` 兜底标 `sink-reached`。
- `sink-reached-probe`：探针在 sink 现场（canary 确证位于危险函数实参）经 `HookRuntime.resolveCanaryForSink` 显式断言后透传的**独立**态，由 `agent_bridge` 把探针正抵达态（`sink-reached`/`arrived`/`arrival-sanitized`）统一归一到 `sink-reached-probe`。`no-arrival` 尊重探针判否、不归一。
- 二者不可混用：`sink-reached-probe` 是 D2 即便 `attack_degraded`（D1 仅投 canary）也判有害、不降级的依据；`sink-reached` 仅作无探针断言时的兜底。后端 `d2_facade._verify_sink_result` 以 `probe_asserted = (iast_state == "sink-reached-probe")` 区分。

### 业务确认证据子字段（设计二② 引入）

- `business_confirmed`：VerificationResult 顶层布尔 verdict（当时的类型定义文件新增），表示业务型漏洞经"双账户差分重放 + 可观测副作用快照"确认；是 `diff_confirmed or iast_reached or side_effect_confirmed` 的归一结果，落库 findings 时经 `attack_plan_service._lookup_finding_verdict` 取用。
- `observed_side_effect`：业务确认证据的**唯一规范子字段**，承载 before/after 可观测状态快照的差分结论（如账户余额、订单数、资源归属、权限位的变化），是 `side_effect_confirmed` 判定的事实来源。统一经 `d1_service._diff_observable_state` 产出。
- 收敛规则：副作用证据一律走 `observed_side_effect` 键，禁止各模块另起 `side_effect`/`effect`/`diff`/`snapshot` 等别名字段；`business_confirmed` 为归一布尔 verdict，`side_effect_confirmed` 仅为其三个子源之一（另两个为 `diff_confirmed` 业务状态差、`iast_reached` IAST 运行时抵达）。

---

## 簇五：表名 / 列名

### 表名规范与别名

- `findings`（遗留 SAST findings 表，`db.py:76`）vs `vulnerability_instances`（归一化实例表，`db.py:106`）：两张"漏洞"表并存。
  - `findings` 用列 `finding_type`（`:80`）承载漏洞类型；
  - `vulnerability_instances` 用列 `family`（`:111`）承载漏洞类型。
  - 即"漏洞类型"在两表叫法不同（`finding_type` vs `family`），且 `family` 在此处又是簇一的族名字段，与 exploit_spec 的 `family` 语义一致——但 `findings.finding_type` 没有统一归一。
- `trigger_specs`：原为 `iast_trigger_specs`，`db.py:764-767` 已 RENAME，但注释/旧文档仍偶见旧名（`db.py:651` 注释、"该表实为 A2 预测 poc 假说，非 IAST 专属"）。
- DAST 族表：`dast_apps` / `dast_accounts` / `dast_apis` / `dast_traffic_samples` / `dast_scan_runs` / `dast_findings`（命名规范，前缀统一）。
- IAST 族表：`iast_sessions` / `iast_events`（命名规范，前缀统一）。

### 列名别名（跨表同义）

- 漏洞类型：`finding_type`（findings）/ `family`（vulnerability_instances）/ `category`（trigger_specs）/ `vulnerability_family`（部分报告层）。
- 端点：`target_endpoint`（trigger_specs）/ `entry_point`（findings 透传的 vuln）/ `route`（exploit_spec）/ `resource_path`（个别 DAST 表）。
- 资源 id：`victim_resource_id`（trigger_specs）/ `resource_id`（dast_traffic_samples `db.py:300`、iast_sessions）——同名不同义，见簇二。

### 收敛建议（已按 2026-09-04 执行记录校正）

- `vulnerability_instances.family` 是规范化族名字段，落库点 `_upsert_vulnerability_instance`（repositories.py:491）已加 `canonical_business_logic_family` 归一（对已是规范 token 输入幂等）。读取端统一认 `family` 概念。
- `findings.finding_type` 列实测绑定的是 `display_title`/`type`（历史 misnomer，值为展示标题而非族名），与 `vulnerability_instances.family` 不是同义字段——**不重命名该列以免触发迁移回归**，仅在文档中明确其语义（展示标题），族名以 `display_family`/`family` 为准。
- `trigger_specs` 旧名 `iast_trigger_specs` 仅在 db.py 迁移注释中出现，保留（属历史迁移说明），新代码一律用 `trigger_specs`。
- 跨表"漏洞类型"读取统一走 `display_family`（findings 层）与 `family`（instances 层），二者均经 `canonical_business_logic_family` 归一，可互相等价消费。

---

## 簇六：端点解析相关函数名

### 现有函数（多入口，未统一收敛）

- `resolve_endpoint_full`（`trigger_spec_registry.py:295`）：规范"解析真相源"，应作为唯一入口。
- `resolve_trigger_endpoint`（`param_resolver.py:579`）：被 `resolve_endpoint_full` 调用，做 sink 驱动解析。
- `_resolve_controller_route_by_entity`（`param_resolver.py:264`）：Mapper→Controller 实体回落（业务类真实路由推导）。
- `_pre_resolve_a2_endpoints`（`benchmark_cli.py:1689`）：A2 结果的端点写回（通道 B）。历史清 key bug 已修：失败只写 `entry_resolution_failure`，不清空 key（见簇三修正）。
- `_build_business_logic_spec`（`benchmark_cli.py:1972`）：业务重放 spec 构造，本次 已接回 `resolve_endpoint_full`。
- `_attach_business_canary`（`benchmark_cli.py:2028`）：业务 spec 绑 canary。

### 断点危害

- 端点解析有 3 个独立入口（trigger_spec_registry / param_resolver / benchmark_cli），各有一套回退逻辑，行为不完全一致，导致"同一漏洞在不同阶段解析出不同端点"。
- `_pre_resolve_a2_endpoints` 的清 key 副作用曾是端点填充率忽高忽低的历史根因（与 `resolve_endpoint_full` 的"保底不清空"原则冲突）；该清 key 已于 benchmark_cli.py:1740-1745 移除，冲突不再存在。

### 收敛建议

- 明确 `resolve_endpoint_full` 为唯一端点解析入口；`resolve_trigger_endpoint` / `_resolve_controller_route_by_entity` 降为内部被调用实现，不在业务路径直接调用。
- `_pre_resolve_a2_endpoints` 已改为"调用 `resolve_endpoint_full` 后合并，解析失败只补不删"（benchmark_cli.py:1740-1745 仅写 `entry_resolution_failure`），清 key 副作用已消除。
- 业务重放 spec 一律经 `resolve_endpoint_full(code_root=..., discovered_routes=...)` 取端点（本次 已落地），不得再从 `ae.target_endpoint`/`vuln.entry_point` 直取。

---

## 簇七：HTTP 方法与参数名相关字段

### 字段名别名

- 方法：`http_method`（trigger_specs 列 `db.py:624/798/803`、report_manager POC）/ `method`（exploit_spec.entry.method、route dict、chain_builder）。
- 参数名：`param_name`（trigger_specs 列，规范）/ `parameter_name`（report_manager `:1581` `entry.get("parameter_name")`、`proof_obligations`/`a2` 部分读取）。
- 参数位置：`param_location`（规范）/ `param_loc`（d1_service 局部变量 `:900/926`）/ `location`（旧代码）。
- 参数来源：`param_name_source`（trigger_specs 列 `db.py:672`）。

### 收敛建议（已按 2026-09-04 执行记录校正）

- 两套 schema 是**有意的双轨**，经 `resolve_endpoint_full` / `param_resolver._field` 翻译桥接，不强行合并：
  - exploit_spec 契约（`src/core/exploit_spec.py`）：`entry.parameter_name` / `entry.parameter_location` / `entry.method`（A2 产出、重放器消费）。
  - trigger_specs 落库列：`param_name` / `param_location` / `http_method`（D2 登记、报告、前端消费）。
- 翻译是单向且集中的：`register_trigger_spec` 把 exploit_spec 的 `parameter_name` 映射到落库 `param_name`；`resolve_endpoint_full` 反向回填。新增代码必须走此桥接，禁止在某一侧另起字段名（如直接读 `entry.parameter_name` 写报告而不经 `param_name`）。
- 方法：`http_method`（落库）与 `method`（exploit_spec 内部）经同一桥接；参数位置：`param_location` 为规范落库名，`parameter_location` 为 exploit_spec 内部名，统一桥接。
- 局部变量 `param_loc` / `location` 为函数内缩写，不落库，无需全局改名，仅要求翻译时归一到 `param_location`。
- 本轮**未**做字段名批量重命名（会破坏 exploit_spec 契约与历史落库数据），收敛以"桥接层唯一化 + 新增代码走桥接"为准。

---

## 统一度量衡总表（项目硬规范）

下列概念全项目以"规范名"为准；其余为源字段/别名，必须在读取点经归一函数转换、写入点经归一函数收敛。违规即回归风险。

- 漏洞族名 → 规范 token 取自 `DIFFERENTIAL_PROOF_FAMILIES`（`exploit_spec.py:28`）；任何产出/落库必经 `canonical_business_logic_family()`。源字段 `vuln_type`（仅大写展示）/ `family` / `category` / `payload_family` 归一为规范 token；**`display_family` 是 findings 层规范展示族名字段（保留，不删除）**；`business_logic_category` 是 trigger_specs 层规范业务族字段。
- 受害者资源 id → `victim_resource_id`（唯一规范名）；**禁用 `resource_id` 作其别名**（与 DAST `dast_traffic_samples`/`iast_sessions` 的 `resource_id` 同名不同义）。
- 漏洞路径 → `target_endpoint`（落库）+ `http_method`（落库）；内部 exploit_spec 用 `entry.route`/`entry.method`；二者经 `resolve_endpoint_full` 唯一桥接。`entry_point` 仅作代码定位展示（"文件:行"），不与路径混用。
- canary → 完整值 spec 落库字段 `taint_marker` ≡ `iast_events.canary`（同一完整串，由 `CanaryFactory.build` 生成）；22 字符前缀称 `canary_identity`（=`s4st41`+16hex，全局唯一，见 `canary.py`）。注入头常量 `TRACE_HEADER="X-SASTAI-Trace"`。
- 端点解析 → 唯一入口 `resolve_endpoint_full`；业务重放 spec 必经之取端点，旧 `ae.target_endpoint`/`vuln.entry_point` 仅作失败保底回退。
- 表"漏洞类型"列 → `vulnerability_instances.family` 与 `findings.display_family` 均经 `canonical_business_logic_family` 归一，等价消费；`findings.finding_type` 实为展示标题列（历史 misnomer，不重命名）。
- HTTP 方法 → 落库 `http_method` / 内部 `method`；参数名 → 落库 `param_name` / exploit_spec `parameter_name`（双轨经桥接）；参数位置 → 落库 `param_location` / exploit_spec `parameter_location`。

## 执行记录（2026-09-04 落地）

按用户指令对簇一/二/三/四/五/七执行收敛，簇六仅讨论不收敛。实际落地（全 `py_compile` 通过）：

1. 簇一：修正 `VERTICAL_PRIVESC`→`vertical_privesc`（a1_vertical_privesc_analyzer.py:85/87，含 docstring CROSS_MODULE_PRIVESC→cross_module_privesc）；重命名文件 `a1_vertical_privexpansion_analyzer.py`→`a1_vertical_privesc_analyzer.py` 并同步 import（a1_business_logic_ai_agent.py:27）与注释（business_logic.py:44/50）。**纠正**：原"删除 display_family / 重命名 business_logic 布尔"建议作废——display_family 是事实规范字段、business_logic 是多结果 dict 共用标记键，均保留。
2. 簇二：`d1_service.py:863` 删除 `or spec.get("resource_id")` 兜底，统一 `victim_resource_id`（消除与 DAST resource_id 同名不同义误配）。
3. 簇三/七：业务重放已统一经 `resolve_endpoint_full`；明确 `entry_point`(代码定位) 与 `target_endpoint`(HTTP 路径) 双语义不合并，`parameter_name`(exploit_spec)/`param_name`(落库) 为有意双轨经桥接，不做批量重命名以免破坏契约。
4. 簇四：`attack_context.py` TRACE_HEADER 处补充 canary token 唯一性说明（身份段 s4st41+16hex≈64bit 熵、run_nonce 分区、taint_marker≡canary、canary_identity 仅前缀）。
5. 簇五：`repositories.py:491` `_upsert_vulnerability_instance` 落库 `family` 加 `canonical_business_logic_family` 归一。
6. 簇六（仅讨论，见下「端点解析函数讨论」）：未改动任何代码。旧版文档把 `_pre_resolve_a2_endpoints` 清 key 标为"已知技术债"已过时——该清 key 实际已于 benchmark_cli.py:1740-1745 移除（"只补不删"已落地），本轮在讨论区更正，未动 .py。

### 端点解析函数讨论（簇六，不收敛）

- **`_resolve_controller_route_by_entity` 降为内部被调用实现是什么意思？**
  它（param_resolver.py:264）是 `resolve_endpoint_full` 内部的一个推导子步骤（Mapper/DAO→同名 *Controller 推 `/{id}` 入口），本就不该被业务重放路径单独直接调用。实为两层内部调用：`resolve_endpoint_full`(trigger_spec_registry.py:295) → `resolve_trigger_endpoint`(param_resolver.py:579，全仓唯一外部调用点在 trigger_spec_registry.py:321) → `_resolve_controller_route_by_entity`(param_resolver.py:264，全仓唯一调用点在 param_resolver.py:866，位于 `resolve_trigger_endpoint` 内部)。**代码现状已满足"已内部化"**（只有 1 个调用点且是内部），无需改代码；规范上固化"禁止业务路径直接 import 它"，外部一律只调 `resolve_endpoint_full`。
- **「解析失败只补不删」是什么意思？**
  指 `_pre_resolve_a2_endpoints`(benchmark_cli.py:1689，通道 B 写回点) 在 `resolve_endpoint_full` 解析失败时，只把解析出的部分字段（如已探明的 route）合并补写进 entry，**绝不清空 entry 原有 key**。旧实现在 `resolvable=False` 时 `for _k in list(entry.keys()): entry[_k]=''`，抹掉 ground truth 路由，是端点填充率忽高忽低的历史根因。
  **当前状态：该清 key 已移除（benchmark_cli.py:1740-1745）**——失败分支只写 `entry["entry_resolution_failure"]=原因`，不覆盖 A2 已给的 entry_route/源码路径，门禁改由该字段显式判定。即"只补不删"**已经落地**（旧版 NAMING_STANDARDS 把此处标为"已知技术债"已过时，本版更正）。`resolve_endpoint_full` 本身也一直只读 vuln、返回新 dict、不 mutate entry，与"保底不清空"一致。
- **业务重放已统一经 `resolve_endpoint_full` 取端点，原先的 `ae.target_endpoint`/`vuln.entry_point` 怎么处理？**
  二者保留为**失败保底回退**，放在优先级链最末端，不再作为主路径被"直取"：
  - 业务重放 spec 构造 `_build_business_logic_spec`(benchmark_cli.py:1972，落地) 的取法：优先在 `code_root or discovered_routes` 存在时调 `resolve_endpoint_full(vuln, ae, code_root, discovered_routes)` 取 `_route`(benchmark_cli.py:1988-2001)；异常则记 warning 并回落旧字段。
  - 回退链（benchmark_cli.py:2016）：`target_endpoint = _route or ae.get("target_endpoint") or vuln.get("entry_point") or vuln.get("target_endpoint") or ""`。`resolve_endpoint_full` 成功→用 `_route`、旧字段被忽略；只有它解析不出（无 code_root / 无 discovered_routes / A2 未给合法结构化入口）才回退旧字段。
  - 另外 `resolve_endpoint_full` 的 Tier 3.5(param_resolver.py:896-915) 里 `ae.target_endpoint` 也作最后兜底，但须过 `is_valid_route` 守门（HTTP 路由才锁，源码路径 `OrderService.java:118` 之类绝不当 route）。故不会再有空端点/源码路径打到靶机 404/405。

## 落地优先级

1. 簇一（族名）与簇三（端点）——直接关系"检测到但没确认"召回率，最优先。本次  已修业务路径断点，下一步按本表把 A1 分析器 `vuln_type`/`family`/`category` 三字段收敛、删除 `display_family`、修 `VERTICAL_PRIVESC` 拼写。
2. 簇四（canary 命名）文档化 + `taint_marker`/`canary` 注释对齐，低成本高收益。
3. 簇五/六/七 随下次相关改动作伴随重构，不单独大改以免引入回归。
