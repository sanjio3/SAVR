# D1 per-request 认证守卫 + auth_state 落地记录

> **状态提示（2026-11-07）：本文记录的是全量扫描授权之前的状态，第 6 节「全量待测」与末尾「仍未执行」已过期。** 后续离线回归锁补齐到 32 passed，R0 轮与 L1 轮已完成两轮全量 LLM 扫描；L1 的 `auth_state` 全为 `authenticated`、登录墙 302 未恶化，守卫在真实全量任务中生效。当前状态见 `config/generalization.yaml` 与 `docs/l1_route_blinding_reconciliation.md`。以下正文按原样保留作历史记录。

2026-11-06。首轮用户授权「可以推进先落地修改」，明确先不要启动验证，当时只改代码并做 `py_compile` 语法自检。后续用户指令「直接推进验证吧」后已完成离线验证与一轮缺口修补，见第 7 节；当时全量 LLM / GPU 扫描尚未启动。

## 改动文件

- `src/application/d1_service.py` — 主体
- `.gitignore` — 开源侧补充忽略项
- `.github/workflows/ci.yml` — 修正干净环境的依赖安装方式

## 1. 认证守卫

新增模块级常量与判据：

- `_AUTH_WALL_CODES = {301,302,303,307,308}`、`_AUTH_GUARD_MAX_RELOGIN = 3`
- `_login_wall_paths()`：读 `SAST_AI_LOGIN_PATHS`，默认 `/login`，逗号分隔可配多个
- `_is_login_wall_response(status, headers)`：**只认 3xx 且 `Location` 路径落在登录路径，或明确的 401**。刻意不把任意 302 当登录墙，避免误伤 `/file/status` 业务跳与 `url_redirect` 族靠 302 取证的重定向（628 的 190 次 302 里这两类占 130 次）

新增 `D1Service` 方法：

- `_auth_guard_enabled()` — 开关 `SAST_AI_D1_AUTH_GUARD`，默认开，置 `0/false/off` 可关
- `_auth_guard_relogin(cookies, baseline)` — 从 `replay()` 挂的上下文取 `target` 与缓存键，失效 `_tech_session_cache` 对应项 → `force=True` 重新登录 → **就地刷新** `cookies` 与 oracle 的基线 `c0`。每条 spec 最多重登 3 次，避免登录接口挂掉时全批重登风暴
- `_guarded_request(...)` — 包装 `requests.request`：发一次 → 命中登录墙 → 重登 → 用同一字典里的新 cookie 重发一次 → 返回 `(response, auth_state)`

`_fallback_auth_cookies()` 增加 `force: bool = False`：为真时先 `get_manager(settings).for_base(base_url).invalidate()`，强制清掉进程级会话单例的 TTL 缓存再取 cookie。否则重发拿到的还是旧 JSESSIONID，等于把同一个 302 再打一遍。

`replay()` 唯一入口挂 `_auth_guard_ctx`（`target` / `spec` / `cache_key` / `relogin_count`），因为发包链路的签名里没有 `target`，守卫需要它才能重登。

## 2. 覆盖边界（重要）

`d1_service.py` 里共有 18 处 `requests.request` / `requests.get`。守卫接了**三条链路**：

1. `_replay_attack()` 内联主重放循环 — **真正的主重放入口**（第 7 节补齐）
2. `_send_one()` — IDOR / two-step / business_logic 等走它的辅助发包
3. `_run_family_oracle()` — 族级 oracle 探测臂（628 里 45 次登录墙 302 就在这里）

首轮误把 `_send_one` 当成主重放，只接了 2、3 两条；实际 `replay()` → `_replay_attack()` 在 `_send_one` 之外自己跑了一个 3 次重试的内联 `requests.request` 循环，628 那 60 次登录墙 302 里非 oracle 臂的部分正出自这里。该缺口在续跑验证时定位并修复。

未接入：主重放循环之外的基线请求、抗抖动补投、方法回退补投、绕过变体补投，以及 followup 补发、状态快照、business_logic 双账户差分、WebSocket 注册请求等。这些通道不改主判定，且在 628 的登录墙分布里没有出现；方法 docstring 里已写明边界，后续若要全覆盖需逐点替换。

## 3. auth_state 落点

值域：`anonymous`（无 cookie）/ `authenticated`（带 cookie 未触发登录墙）/ `reauthed`（重登并补发成功）/ `reauth_failed`（触发登录墙但未拿到新会话或补发失败）。

- `DastImpact.auth_state` — **正式字段**（第 7 节从动态属性升级），`to_dict()` 输出，随 `raw_dast_impact` 落库；`_aggregate_dast()` 聚合时失败态 `reauth_failed` / `expired` 优先，不被成功态掩盖
- `replay_attempts.action_json` — 新增 `_attempt_action(auth_state)`，保留原有 `source: d1_replay` 并追加 `auth_state`；`_record_replay_attempt(..., auth_state="")` 为可选参数，主重放与 oracle 臂均已传入

首轮把 `auth_state` 写成动态实例属性，但 `DastImpact.to_dict()` 是字段白名单式序列化，动态属性根本进不了 `raw_dast_impact` —— 观测字段实际只活在内存里。第 7 节已修。数据库表结构始终未改，不需要 migration。

## 4. 一个必须同步修的计时陷阱

oracle 探测臂原先在 `_guarded_request` 外层用 `_t0` 计时。若守卫触发重登，登录耗时会被算进 `delay` 臂的 `elapsed_ms`，可能伪造出 `elapsed >= 2000` 的 `sqli_time / time_delay` 假阳性 —— 修 bug 反而制造假证据。

故 `_guarded_request` 只记**最后一次真实 HTTP 往返**耗时到 `self._guarded_request_ms`，oracle 臂优先读它、异常时才回退外层 `_t0`。

## 5. 工程侧同步调整

- `.gitignore` 补齐运行时产物与本地配置的忽略规则，避免数据库、日志、扫描输出进入版本库。
- `.github/workflows/ci.yml` 改为 `pip install -r requirements.txt`：`pyproject.toml` 没有 `[build-system]` 或 `setup.py`，`pip install -e .` 在干净环境里不可靠。
- CI 增加卫生门禁，检查硬编码凭据、开发机绝对路径与可复现性文件是否缺失。

## 6. 验收线（离线部分已执行，活靶场/全量待测）

```bash
# 1) 单元测试：登录墙识别、重登限次、cookie 就地刷新、计时口径
.venv/Scripts/python.exe -m pytest tests/ -q

# 2) 活靶场单点复验（不跑全量 LLM）
#    失效会话能被重登自愈、oracle 臂不再全 302
#    布尔对有真实差异（oracle_signal=boolean_diff / technique=sqli_boolean）
#    SLEEP 臂在 h2 profile 下物理不成立（H2 无 SLEEP()），不得拿它当时延验收线

# 3) 全量（需你按显存决定）
#    sqli.java 不再依赖零重放的 business-logic-confirmed 撑命中
#    replay_attempts.action_json 里能看到 auth_state
```

回归风险点：`_guarded_request` 默认开启，会把所有 3xx+`/login` 的请求重发一次。若某靶场把 `/login` 当作业务重定向路径，可能多发一次请求 —— 用 `SAST_AI_LOGIN_PATHS` 收窄或 `SAST_AI_D1_AUTH_GUARD=0` 关闭。

## 7. 续跑验证与缺口修补（同日，用户「直接推进验证吧」）

先做不占显存、不依赖服务的部分，过程中查出一处会让整轮扫描白跑的缺口。

离线验证结果：

- `tests/test_d1_auth_guard.py` + `tests/test_d1_auth_config_fallback.py`：29 passed
- 全量 `pytest tests/`：3580 passed / 3 skipped
- 补齐缺口并新增回归锁后：`test_d1_auth_guard.py` 25 passed、全量 3584 passed / 3 skipped，零失败
- `py_compile`：`d1_service.py`、`orchestrator.py` 通过
- L1 盲化变体离线编译：`mvn -o -DskipTests package`（JDK 11）成功，产出 `data/blind_variants/jsc-blind/target/java-sec-code-1.0.0.jar`（98 MB）；注解里无旧族语义路由残留，12 项登录/CSRF 白名单已同步改写

静态审查定位的四个缺口，已一次性修完：

- **主重放没接守卫**：`replay()` → `_replay_attack()` 的内联 `requests.request` 循环是真正的主重放，首轮只接了 `_send_one` 与 oracle 臂。现改为 `_guarded_request`，并记录 `_main_auth_state`
- **主重放计时会造假时延**：外层 `_t0` 会把重登耗时算进 `elapsed_ms`，被 D2 时间盲注双阈值门读成 `time_delay` 假阳性。现与 oracle 臂统一改用 `_guarded_request_ms`（最后一次真实 HTTP 往返）
- **`auth_state` 落不了库**：动态属性进不了 `DastImpact.to_dict()` 白名单。现升为正式字段、进 `to_dict()`、`_aggregate_dast()` 失败态优先；主重放的 `_record_replay_attempt` 也传入该字段
- **cookies 为空时重发不带新会话**：`_guarded_request` 现将非 dict 的 cookies 归一化为内部 dict，`kw` 持有同一引用，重登就地刷新后重发自动带上新会话

新增回归锁覆盖：登录墙严格判据、可配置登录路径、重登就地刷新/限次/失败、守卫开关、业务跳不重发、重登耗时不进 oracle delay、`cookies=None` 自愈、`auth_state` 序列化与聚合、主重放走守卫且 `auth_state` 同时落 `DastImpact` 与 `replay_attempts.action_json`。

**验证范围**：本节记录改动与回归锁，未包含整栈联调与全量扫描数据。需要整栈验证时，先确认后端、靶场与模型服务的资源与运行条件，再按发布验收标准执行。
